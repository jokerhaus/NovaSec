// filename: internal/correlator/engine.go
package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/correlator/dsl"
	"novasec/internal/models"

	"gopkg.in/yaml.v3"
)

// Engine представляет движок корреляции // v1.0
type Engine struct {
	config   *Config
	logger   *logging.Logger
	nats     *nats.Client
	compiler *dsl.Compiler
	rules    map[string]*dsl.CompiledRule
	state    StateManager
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

// Config конфигурация движка корреляции // v1.0
type Config struct {
	MaxWorkers        int           `yaml:"max_workers"`
	EventBufferSize   int           `yaml:"event_buffer_size"`
	RuleCheckInterval time.Duration `yaml:"rule_check_interval"`
	AlertTTL          time.Duration `yaml:"alert_ttl"`
}

// StateManager интерфейс для управления состоянием // v1.0
type StateManager interface {
	// GetWindowState возвращает состояние окна для правила и группы
	GetWindowState(ruleID, groupKey string) (*dsl.WindowState, error)

	// UpdateWindowState обновляет состояние окна
	UpdateWindowState(ruleID, groupKey string, state *dsl.WindowState) error

	// CleanupExpiredWindows очищает истекшие окна
	CleanupExpiredWindows() error

	// GetStats возвращает статистику состояния
	GetStats() map[string]interface{}
}

// NewEngine создает новый движок корреляции // v1.0
func NewEngine(config *Config, logger *logging.Logger, natsClient *nats.Client, stateManager StateManager) *Engine {
	return &Engine{
		config:   config,
		logger:   logger,
		nats:     natsClient,
		compiler: dsl.NewCompiler(),
		rules:    make(map[string]*dsl.CompiledRule),
		state:    stateManager,
		stopChan: make(chan struct{}),
	}
}

// Start запускает движок корреляции // v1.0
func (e *Engine) Start(ctx context.Context) error {
	e.logger.Logger.Info("Starting correlation engine")

	// Подписываемся на нормализованные события
	err := e.nats.SubscribeToEvents("events.normalized", func(data []byte) {
		if err := e.handleNormalizedEvent(data); err != nil {
			e.logger.Logger.WithError(err).Error("Failed to handle normalized event")
		}
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to events.normalized: %w", err)
	}

	// Запускаем воркеры для обработки событий
	for i := 0; i < e.config.MaxWorkers; i++ {
		e.wg.Add(1)
		go e.worker(ctx, i)
	}

	// Запускаем очистку истекших окон
	e.wg.Add(1)
	go e.cleanupWorker(ctx)

	// Ждем завершения контекста или сигнала остановки
	select {
	case <-ctx.Done():
		e.logger.Logger.Info("Context cancelled, stopping engine")
	case <-e.stopChan:
		e.logger.Logger.Info("Stop signal received, stopping engine")
	}

	// Останавливаем воркеры
	close(e.stopChan)
	e.wg.Wait()

	return nil
}

// Stop останавливает движок корреляции // v1.0
func (e *Engine) Stop() {
	close(e.stopChan)
}

// LoadRule загружает и компилирует правило // v1.0
func (e *Engine) LoadRule(ruleID string, yamlData string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Парсим YAML в Rule
	var rule dsl.Rule
	if err := yaml.Unmarshal([]byte(yamlData), &rule); err != nil {
		return fmt.Errorf("failed to parse rule YAML: %w", err)
	}

	// Компилируем правило
	compiledRule, err := e.compiler.CompileRule(&rule)
	if err != nil {
		return fmt.Errorf("failed to compile rule %s: %w", ruleID, err)
	}

	// Сохраняем скомпилированное правило
	e.rules[ruleID] = compiledRule

	e.logger.Logger.WithField("rule_id", ruleID).Info("Rule loaded and compiled")

	return nil
}

// UnloadRule выгружает правило // v1.0
func (e *Engine) UnloadRule(ruleID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.rules[ruleID]; !exists {
		return fmt.Errorf("rule %s not found", ruleID)
	}

	delete(e.rules, ruleID)

	e.logger.Logger.WithField("rule_id", ruleID).Info("Rule unloaded")

	return nil
}

// GetRules возвращает список загруженных правил // v1.0
func (e *Engine) GetRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]string, 0, len(e.rules))
	for ruleID := range e.rules {
		rules = append(rules, ruleID)
	}

	return rules
}

// handleNormalizedEvent обрабатывает нормализованное событие // v1.0
func (e *Engine) handleNormalizedEvent(data []byte) error {
	var event models.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("failed to unmarshal normalized event: %w", err)
	}

	e.logger.Logger.WithFields(map[string]interface{}{
		"event_id": event.GetDedupKey(),
		"host":     event.Host,
		"category": event.Category,
		"subtype":  event.Subtype,
	}).Debug("Processing normalized event")

	// Обрабатываем событие всеми правилами
	e.mu.RLock()
	rules := make([]*dsl.CompiledRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		if err := e.processEventWithRule(&event, rule); err != nil {
			e.logger.Logger.WithFields(map[string]interface{}{
				"event_id": event.GetDedupKey(),
				"rule_id":  rule.Rule.ID,
				"error":    err.Error(),
			}).Error("Failed to process event with rule")
			// Продолжаем с другими правилами
		}
	}

	return nil
}

// processEventWithRule обрабатывает событие с конкретным правилом // v1.0
func (e *Engine) processEventWithRule(event *models.Event, rule *dsl.CompiledRule) error {
	// Проверяем, соответствует ли событие условиям правила
	if !rule.Matcher.Match(event) {
		return nil
	}

	// Получаем ключ группы для события
	groupKey := rule.Evaluator.GetGroupKey(event)

	// Получаем состояние окна
	windowState, err := e.state.GetWindowState(rule.Rule.ID, groupKey)
	if err != nil {
		return fmt.Errorf("failed to get window state: %w", err)
	}

	// Добавляем событие в окно
	triggered := rule.Evaluator.AddEvent(event)

	// Обновляем состояние окна
	if err := e.state.UpdateWindowState(rule.Rule.ID, groupKey, windowState); err != nil {
		return fmt.Errorf("failed to update window state: %w", err)
	}

	// Если правило сработало, создаем алерт
	if triggered {
		if err := e.createAlert(rule, event, groupKey); err != nil {
			return fmt.Errorf("failed to create alert: %w", err)
		}
	}

	return nil
}

// createAlert создает алерт на основе сработавшего правила // v1.0
func (e *Engine) createAlert(rule *dsl.CompiledRule, event *models.Event, groupKey string) error {
	// Генерируем ключ дедупликации
	dedupKey := fmt.Sprintf("%s:%s:%s",
		rule.Rule.ID,
		groupKey,
		rule.Rule.Severity)

	// Создаем алерт
	alert := &models.Alert{
		ID:        generateAlertID(),
		TS:        time.Now(),
		RuleID:    rule.Rule.ID,
		Severity:  rule.Rule.Severity,
		DedupKey:  dedupKey,
		Payload:   make(map[string]interface{}),
		Status:    "new",
		Env:       event.Env,
		Host:      event.Host,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Заполняем payload
	alert.Payload["event_count"] = 1
	alert.Payload["group_key"] = groupKey
	alert.Payload["last_event"] = event.GetDedupKey()
	alert.Payload["message"] = fmt.Sprintf("Rule %s triggered for group %s", rule.Rule.ID, groupKey)

	// Публикуем алерт в NATS
	alertData, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	if err := e.nats.PublishEvent("alerts.created", alertData); err != nil {
		return fmt.Errorf("failed to publish alert: %w", err)
	}

	e.logger.Logger.WithFields(map[string]interface{}{
		"alert_id":  alert.ID,
		"rule_id":   rule.Rule.ID,
		"severity":  rule.Rule.Severity,
		"group_key": groupKey,
	}).Info("Alert created and published")

	return nil
}

// worker воркер для обработки событий // v1.0
func (e *Engine) worker(ctx context.Context, id int) {
	defer e.wg.Done()

	e.logger.Logger.WithFields(map[string]interface{}{
		"worker_id": id,
	}).Info("Correlation worker started")

	// В реальной реализации здесь будет обработка событий из очереди
	// Пока используем простую логику ожидания
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.logger.Logger.WithFields(map[string]interface{}{
				"worker_id": id,
			}).Info("Worker context cancelled")
			return
		case <-e.stopChan:
			e.logger.Logger.WithFields(map[string]interface{}{
				"worker_id": id,
			}).Info("Worker stop signal received")
			return
		case <-ticker.C:
			// В реальной реализации здесь будет обработка событий из очереди
			// Пока просто проверяем состояние каждые 100ms
			// TODO: Добавить логику обработки событий из очереди
			// TODO: Добавить метрики производительности
			continue
		}
	}
}

// cleanupWorker очищает истекшие окна // v1.0
func (e *Engine) cleanupWorker(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.RuleCheckInterval)
	defer ticker.Stop()

	e.logger.Logger.Info("Cleanup worker started")

	for {
		select {
		case <-ctx.Done():
			e.logger.Logger.Info("Cleanup worker context cancelled")
			return
		case <-e.stopChan:
			e.logger.Logger.Info("Cleanup worker stop signal received")
			return
		case <-ticker.C:
			if err := e.state.CleanupExpiredWindows(); err != nil {
				e.logger.Logger.WithField("error", err.Error()).Error("Failed to cleanup expired windows")
			}
		}
	}
}

// GetStats возвращает статистику движка корреляции // v1.0
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := map[string]interface{}{
		"status":       "running",
		"workers":      e.config.MaxWorkers,
		"loaded_rules": len(e.rules),
		"event_buffer": e.config.EventBufferSize,
		"alert_ttl":    e.config.AlertTTL.String(),
	}

	// Добавляем статистику состояния
	if e.state != nil {
		stateStats := e.state.GetStats()
		for k, v := range stateStats {
			stats["state_"+k] = v
		}
	}

	return stats
}

// generateAlertID генерирует уникальный ID для алерта // v1.0
func generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}
