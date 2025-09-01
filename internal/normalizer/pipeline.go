// filename: internal/normalizer/pipeline.go
package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/models"
	"github.com/novasec/novasec/internal/normalizer/parsers"
)

// Pipeline представляет pipeline нормализации событий // v1.0
type Pipeline struct {
	config     *Config
	logger     *logging.Logger
	nats       *nats.Client
	parser     parsers.Parser
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// Config конфигурация pipeline // v1.0
type Config struct {
	BatchSize        int           `yaml:"batch_size"`
	BatchTimeout     time.Duration `yaml:"batch_timeout"`
	MaxWorkers       int           `yaml:"max_workers"`
	ClickHouseURL    string        `yaml:"clickhouse_url"`
	ClickHouseDB     string        `yaml:"clickhouse_db"`
	ClickHouseTable  string        `yaml:"clickhouse_table"`
}

// NewPipeline создает новый pipeline нормализации // v1.0
func NewPipeline(config *Config, logger *logging.Logger, natsClient *nats.Client) *Pipeline {
	return &Pipeline{
		config:   config,
		logger:   logger,
		nats:     natsClient,
		parser:   parsers.NewParserRegistry(),
		stopChan: make(chan struct{}),
	}
}

// Start запускает pipeline нормализации // v1.0
func (p *Pipeline) Start(ctx context.Context) error {
	p.logger.Info("Starting normalization pipeline")

	// Подписываемся на события events.raw
	err := p.nats.SubscribeToEvents("events.raw", p.handleRawEvent)
	if err != nil {
		return fmt.Errorf("failed to subscribe to events.raw: %w", err)
	}

	// Запускаем воркеры для обработки событий
	for i := 0; i < p.config.MaxWorkers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	// Ждем завершения контекста или сигнала остановки
	select {
	case <-ctx.Done():
		p.logger.Info("Context cancelled, stopping pipeline")
	case <-p.stopChan:
		p.logger.Info("Stop signal received, stopping pipeline")
	}

	// Останавливаем воркеры
	close(p.stopChan)
	p.wg.Wait()

	return nil
}

// Stop останавливает pipeline // v1.0
func (p *Pipeline) Stop() {
	close(p.stopChan)
}

// handleRawEvent обрабатывает сырое событие из NATS // v1.0
func (p *Pipeline) handleRawEvent(data []byte) error {
	var rawEvent models.Event
	if err := json.Unmarshal(data, &rawEvent); err != nil {
		return fmt.Errorf("failed to unmarshal raw event: %w", err)
	}

	p.logger.WithFields(map[string]interface{}{
		"event_id": rawEvent.GetDedupKey(),
		"host":     rawEvent.Host,
		"category": rawEvent.Category,
		"source":   rawEvent.Source,
	}).Debug("Processing raw event")

	// Нормализуем событие
	normalizedEvent, err := p.normalizeEvent(&rawEvent)
	if err != nil {
		p.logger.WithFields(map[string]interface{}{
			"event_id": rawEvent.GetDedupKey(),
			"error":    err.Error(),
		}).Error("Failed to normalize event")
		return err
	}

	// Публикуем нормализованное событие
	if err := p.publishNormalizedEvent(normalizedEvent); err != nil {
		return fmt.Errorf("failed to publish normalized event: %w", err)
	}

	// Сохраняем в ClickHouse
	if err := p.saveToClickHouse(normalizedEvent); err != nil {
		p.logger.WithFields(map[string]interface{}{
			"event_id": normalizedEvent.GetDedupKey(),
			"error":    err.Error(),
		}).Error("Failed to save event to ClickHouse")
		// Не прерываем выполнение, продолжаем обработку
	}

	return nil
}

// normalizeEvent нормализует событие // v1.0
func (p *Pipeline) normalizeEvent(rawEvent *models.Event) (*models.Event, error) {
	// Копируем базовые поля
	normalized := &models.Event{
		TS:       rawEvent.TS,
		Host:     rawEvent.Host,
		AgentID:  rawEvent.AgentID,
		Env:      rawEvent.Env,
		Source:   rawEvent.Source,
		Severity: rawEvent.Severity,
		Category: rawEvent.Category,
		Subtype:  rawEvent.Subtype,
		Message:  rawEvent.Message,
		User:     rawEvent.User,
		Network:  rawEvent.Network,
		File:     rawEvent.File,
		Process:  rawEvent.Process,
		Hashes:   rawEvent.Hashes,
		Labels:   make(map[string]string),
		Enrich:   rawEvent.Enrich,
		Raw:      rawEvent.Raw,
	}

	// Копируем существующие метки
	for k, v := range rawEvent.Labels {
		normalized.Labels[k] = v
	}

	// Добавляем базовые метки
	normalized.Labels["service"] = "novasec"
	normalized.Labels["normalized"] = "true"
	normalized.Labels["normalized_at"] = time.Now().Format(time.RFC3339)

	// Если есть source, добавляем метку
	if rawEvent.Source != "" {
		normalized.Labels["source_type"] = rawEvent.Source
	}

	// Если есть env, добавляем метку
	if rawEvent.Env != "" {
		normalized.Labels["environment"] = rawEvent.Env
	}

	// Применяем парсер для обогащения события
	if p.parser != nil {
		enrichedEvent, err := p.parser.ParseEvent(rawEvent)
		if err != nil {
			p.logger.WithFields(map[string]interface{}{
				"event_id": rawEvent.GetDedupKey(),
				"error":    err.Error(),
			}).Warn("Parser failed, using basic normalization")
		} else if enrichedEvent != nil {
			// Объединяем обогащенные поля
			if enrichedEvent.Category != "" {
				normalized.Category = enrichedEvent.Category
			}
			if enrichedEvent.Subtype != "" {
				normalized.Subtype = enrichedEvent.Subtype
			}
			if enrichedEvent.Severity != "" {
				normalized.Severity = enrichedEvent.Severity
			}
			
			// Объединяем метки
			for k, v := range enrichedEvent.Labels {
				normalized.Labels[k] = v
			}

			// Объединяем обогащение
			if enrichedEvent.Enrich != nil {
				if normalized.Enrich == nil {
					normalized.Enrich = &models.Enrichment{}
				}
				if enrichedEvent.Enrich.Geo != "" {
					normalized.Enrich.Geo = enrichedEvent.Enrich.Geo
				}
				if enrichedEvent.Enrich.ASN != nil {
					normalized.Enrich.ASN = enrichedEvent.Enrich.ASN
				}
				if enrichedEvent.Enrich.IOC != "" {
					normalized.Enrich.IOC = enrichedEvent.Enrich.IOC
				}
			}
		}
	}

	// Устанавливаем timestamp нормализации
	normalized.TS = time.Now()

	return normalized, nil
}

// publishNormalizedEvent публикует нормализованное событие в NATS // v1.0
func (p *Pipeline) publishNormalizedEvent(event *models.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal normalized event: %w", err)
	}

	// Публикуем в subject events.normalized
	err = p.nats.PublishEvent("events.normalized", data)
	if err != nil {
		return fmt.Errorf("failed to publish to events.normalized: %w", err)
	}

	p.logger.WithFields(map[string]interface{}{
		"event_id": event.GetDedupKey(),
		"subject":  "events.normalized",
	}).Debug("Published normalized event")

	return nil
}

// saveToClickHouse сохраняет событие в ClickHouse // v1.0
func (p *Pipeline) saveToClickHouse(event *models.Event) error {
	// В реальной реализации здесь будет вставка в ClickHouse
	// Пока логируем успешную "вставку"
	p.logger.WithFields(map[string]interface{}{
		"event_id": event.GetDedupKey(),
		"host":     event.Host,
		"category": event.Category,
		"subtype":  event.Subtype,
	}).Debug("Event saved to ClickHouse")

	return nil
}

// worker воркер для обработки событий // v1.0
func (p *Pipeline) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	p.logger.WithFields(map[string]interface{}{
		"worker_id": id,
	}).Info("Worker started")

	// В реальной реализации здесь будет обработка событий из очереди
	// Пока просто ждем сигнала остановки
	select {
	case <-ctx.Done():
		p.logger.WithFields(map[string]interface{}{
			"worker_id": id,
		}).Info("Worker context cancelled")
	case <-p.stopChan:
		p.logger.WithFields(map[string]interface{}{
			"worker_id": id,
		}).Info("Worker stop signal received")
	}
}

// GetStats возвращает статистику pipeline // v1.0
func (p *Pipeline) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"status":      "running",
		"workers":     p.config.MaxWorkers,
		"batch_size":  p.config.BatchSize,
		"batch_timeout": p.config.BatchTimeout.String(),
	}
}
