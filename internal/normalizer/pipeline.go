// filename: internal/normalizer/pipeline.go
package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"novasec/internal/common/ch"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/models"
	"novasec/internal/normalizer/parsers"
)

// Pipeline представляет pipeline нормализации событий // v1.0
type Pipeline struct {
	config     *Config
	logger     *logging.Logger
	nats       *nats.Client
	clickhouse *ch.Client
	parsers    []parsers.Parser
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.RWMutex
	eventQueue chan *models.Event
	stats      *PipelineStats
}

// Config конфигурация pipeline // v1.0
type Config struct {
	MaxWorkers   int           `yaml:"max_workers"`
	BatchSize    int           `yaml:"batch_size"`
	BatchTimeout time.Duration `yaml:"batch_timeout"`
	QueueSize    int           `yaml:"queue_size"`
	ProcessDelay time.Duration `yaml:"process_delay"`
}

// PipelineStats представляет статистику pipeline // v1.0
type PipelineStats struct {
	mu                sync.RWMutex
	eventsReceived    int64
	eventsProcessed   int64
	eventsNormalized  int64
	eventsSaved       int64
	errors            int64
	startTime         time.Time
	lastEventTime     time.Time
	queueSize         int
	workerUtilization float64
}

// NewPipeline создает новый pipeline нормализации // v1.0
func NewPipeline(config *Config, logger *logging.Logger, natsClient *nats.Client, chClient *ch.Client) *Pipeline {
	// Инициализируем парсеры
	parsersList := []parsers.Parser{
		parsers.NewLinuxAuthParser(),
		parsers.NewNginxAccessParser(),
		parsers.NewWindowsEventLogParser(),
	}

	return &Pipeline{
		config:     config,
		logger:     logger,
		nats:       natsClient,
		clickhouse: chClient,
		parsers:    parsersList,
		stopChan:   make(chan struct{}),
		eventQueue: make(chan *models.Event, config.QueueSize),
		stats: &PipelineStats{
			startTime: time.Now(),
		},
	}
}

// Start запускает pipeline нормализации // v1.0
func (p *Pipeline) Start(ctx context.Context) error {
	p.logger.Info("Starting normalization pipeline")

	// Подписываемся на события events.raw
	if err := p.subscribeToRawEvents(ctx); err != nil {
		return fmt.Errorf("failed to subscribe to raw events: %w", err)
	}

	// Запускаем воркеры для обработки событий
	for i := 0; i < p.config.MaxWorkers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	// Запускаем сборщик статистики
	p.wg.Add(1)
	go p.statsCollector(ctx)

	p.logger.Info("Normalization pipeline started successfully")
	return nil
}

// Stop останавливает pipeline // v1.0
func (p *Pipeline) Stop() error {
	p.logger.Info("Stopping normalization pipeline")

	// Отправляем сигнал остановки
	close(p.stopChan)

	// Ждем завершения всех воркеров
	p.wg.Wait()

	// Закрываем каналы
	close(p.eventQueue)

	p.logger.Info("Normalization pipeline stopped")
	return nil
}

// subscribeToRawEvents подписывается на сырые события из NATS // v1.0
func (p *Pipeline) subscribeToRawEvents(ctx context.Context) error {
	// Подписываемся на subject events.raw
	// В реальной реализации здесь будет подписка на NATS
	p.logger.Info("Subscribed to events.raw events")
	return nil
}

// ProcessRawEvent обрабатывает сырое событие из NATS // v1.0
func (p *Pipeline) ProcessRawEvent(rawEvent *models.Event) error {
	p.logger.WithFields(map[string]interface{}{
		"event_id": rawEvent.GetDedupKey(),
		"host":     rawEvent.Host,
		"category": rawEvent.Category,
		"subtype":  rawEvent.Subtype,
	}).Debug("Processing raw event")

	// Добавляем событие в очередь для обработки
	select {
	case p.eventQueue <- rawEvent:
		p.updateStats("events_received", 1)
		p.updateStats("queue_size", 1)
	default:
		// Очередь переполнена, логируем предупреждение
		p.logger.WithField("event_id", rawEvent.GetDedupKey()).Warn("Event queue is full, dropping event")
		p.updateStats("dropped_events", 1)
	}

	return nil
}

// worker воркер для обработки событий // v1.0
func (p *Pipeline) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	p.logger.WithFields(map[string]interface{}{
		"worker_id": id,
	}).Info("Worker started")

	// Обрабатываем события из очереди
	for {
		select {
		case <-ctx.Done():
			p.logger.WithFields(map[string]interface{}{
				"worker_id": id,
			}).Info("Worker context cancelled")
			return
		case <-p.stopChan:
			p.logger.WithFields(map[string]interface{}{
				"worker_id": id,
			}).Info("Worker stop signal received")
			return
		case event, ok := <-p.eventQueue:
			if !ok {
				// Канал закрыт
				return
			}

			// Обрабатываем событие
			startTime := time.Now()
			if err := p.processEvent(event); err != nil {
				p.logger.WithFields(map[string]interface{}{
					"worker_id": id,
					"event_id":  event.GetDedupKey(),
					"error":     err.Error(),
				}).Error("Failed to process event")
				p.updateStats("errors", 1)
			} else {
				processingTime := time.Since(startTime)
				p.updateStats("events_processed", 1)
				p.updateStats("processing_time", processingTime)
			}

			// Обновляем размер очереди
			p.updateStats("queue_size", len(p.eventQueue))
		}
	}
}

// processEvent обрабатывает одно событие // v1.0
func (p *Pipeline) processEvent(event *models.Event) error {
	// Нормализуем событие
	normalizedEvent, err := p.normalizeEvent(event)
	if err != nil {
		p.logger.WithFields(map[string]interface{}{
			"event_id": event.GetDedupKey(),
			"source":   event.Source,
			"error":    err.Error(),
		}).Debug("Parser failed, using original event")

		// Если парсинг не удался, используем оригинальное событие
		normalizedEvent = event
	}

	// Устанавливаем timestamp нормализации
	normalizedEvent.TS = time.Now()

	// Публикуем нормализованное событие
	if err := p.publishNormalizedEvent(normalizedEvent); err != nil {
		return fmt.Errorf("failed to publish normalized event: %w", err)
	}

	// Сохраняем в ClickHouse
	if err := p.saveToClickHouse(normalizedEvent); err != nil {
		return fmt.Errorf("failed to save event to ClickHouse: %w", err)
	}

	p.updateStats("events_normalized", 1)
	p.updateStats("events_saved", 1)
	return nil
}

// normalizeEvent нормализует событие // v1.0
func (p *Pipeline) normalizeEvent(event *models.Event) (*models.Event, error) {
	// Ищем подходящий парсер
	var bestParser parsers.Parser

	for _, parser := range p.parsers {
		// Проверяем, поддерживает ли парсер источник события
		for _, supportedSource := range parser.GetSupportedSources() {
			if supportedSource == event.Source {
				bestParser = parser
				break
			}
		}
		if bestParser != nil {
			break
		}
	}

	if bestParser == nil {
		return nil, fmt.Errorf("no suitable parser found for event source: %s", event.Source)
	}

	// Парсим событие
	normalized, err := bestParser.ParseEvent(event)
	if err != nil {
		return nil, fmt.Errorf("parser failed: %w", err)
	}

	// Если есть source, добавляем метку
	if event.Source != "" {
		if normalized.Labels == nil {
			normalized.Labels = make(map[string]string)
		}
		normalized.Labels["parser"] = event.Source
		normalized.Labels["source"] = event.Source
	}

	// Если есть env, добавляем метку
	if event.Env != "" {
		if normalized.Labels == nil {
			normalized.Labels = make(map[string]string)
		}
		normalized.Labels["environment"] = event.Env
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
	if p.clickhouse == nil {
		return fmt.Errorf("ClickHouse client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := p.clickhouse.InsertEvent(ctx, event); err != nil {
		p.logger.WithFields(map[string]interface{}{
			"event_id": event.GetDedupKey(),
			"host":     event.Host,
			"category": event.Category,
			"subtype":  event.Subtype,
			"error":    err.Error(),
		}).Error("Failed to save event to ClickHouse")
		return fmt.Errorf("failed to save event to ClickHouse: %w", err)
	}

	p.logger.WithFields(map[string]interface{}{
		"event_id": event.GetDedupKey(),
		"host":     event.Host,
		"category": event.Category,
		"subtype":  event.Subtype,
	}).Debug("Event saved to ClickHouse")

	return nil
}

// statsCollector собирает статистику pipeline // v1.0
func (p *Pipeline) statsCollector(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	p.logger.Info("Stats collector started")

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Stats collector context cancelled")
			return
		case <-p.stopChan:
			p.logger.Info("Stats collector stop signal received")
			return
		case <-ticker.C:
			p.updatePerformanceStats()
		}
	}
}

// updatePerformanceStats обновляет метрики производительности // v1.0
func (p *Pipeline) updatePerformanceStats() {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()

	// Обновляем размер очереди
	p.stats.queueSize = len(p.eventQueue)

	// Обновляем утилизацию воркеров
	if p.stats.eventsProcessed > 0 {
		uptime := time.Since(p.stats.startTime)
		p.stats.workerUtilization = float64(p.stats.eventsProcessed) / uptime.Seconds()
	}

	// Логируем метрики
	p.logger.WithFields(map[string]interface{}{
		"events_received":    p.stats.eventsReceived,
		"events_processed":   p.stats.eventsProcessed,
		"events_normalized":  p.stats.eventsNormalized,
		"events_saved":       p.stats.eventsSaved,
		"queue_size":         p.stats.queueSize,
		"worker_utilization": fmt.Sprintf("%.2f", p.stats.workerUtilization),
		"errors":             p.stats.errors,
		"uptime":             time.Since(p.stats.startTime).String(),
	}).Debug("Performance stats updated")
}

// updateStats обновляет статистику // v1.0
func (p *Pipeline) updateStats(metric string, value interface{}) {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()

	switch metric {
	case "events_received":
		p.stats.eventsReceived++
	case "events_processed":
		p.stats.eventsProcessed++
	case "events_normalized":
		p.stats.eventsNormalized++
	case "events_saved":
		p.stats.eventsSaved++
	case "errors":
		p.stats.errors++
	case "processing_time":
		// Можно добавить логику для отслеживания времени обработки
		_ = value
	case "queue_size":
		if size, ok := value.(int); ok {
			p.stats.queueSize = size
		}
	}

	p.stats.lastEventTime = time.Now()
}

// GetStats возвращает статистику pipeline // v1.0
func (p *Pipeline) GetStats() map[string]interface{} {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()

	return map[string]interface{}{
		"status":        "running",
		"workers":       p.config.MaxWorkers,
		"batch_size":    p.config.BatchSize,
		"batch_timeout": p.config.BatchTimeout.String(),
		"queue_size":    p.stats.queueSize,
		"metrics": map[string]interface{}{
			"events_received":    p.stats.eventsReceived,
			"events_processed":   p.stats.eventsProcessed,
			"events_normalized":  p.stats.eventsNormalized,
			"events_saved":       p.stats.eventsSaved,
			"worker_utilization": fmt.Sprintf("%.2f", p.stats.workerUtilization),
			"errors":             p.stats.errors,
			"uptime":             time.Since(p.stats.startTime).String(),
			"last_event_time":    p.stats.lastEventTime.Format(time.RFC3339),
		},
	}
}
