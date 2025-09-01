// filename: internal/correlator/engine.go
package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/correlator/dsl"
	"novasec/internal/correlator/state"
	"novasec/internal/models"
)

// Engine представляет движок корреляции событий // v1.0
type Engine struct {
	config     *config.Config
	logger     *logging.Logger
	nats       *nats.Client
	compiler   *dsl.Compiler
	state      *state.MemoryStateManager
	rules      map[string]*dsl.CompiledRule
	mu         sync.RWMutex
	wg         sync.WaitGroup
	stopChan   chan struct{}
	eventQueue chan *models.Event
	metrics    *EngineMetrics
}

// EngineMetrics представляет метрики производительности движка // v1.0
type EngineMetrics struct {
	mu                sync.RWMutex
	eventsProcessed   int64
	alertsGenerated   int64
	rulesTriggered    int64
	processingTime    time.Duration
	lastEventTime     time.Time
	queueSize         int
	workerUtilization float64
	errorCount        int64
	startTime         time.Time
}

// NewEngine создает новый движок корреляции // v1.0
func NewEngine(config *config.Config, logger *logging.Logger, natsClient *nats.Client) *Engine {
	compiler := dsl.NewCompiler()
	stateManager := state.NewMemoryStateManager()

	return &Engine{
		config:     config,
		logger:     logger,
		nats:       natsClient,
		compiler:   compiler,
		state:      stateManager,
		rules:      make(map[string]*dsl.CompiledRule),
		stopChan:   make(chan struct{}),
		eventQueue: make(chan *models.Event, 1000), // Дефолтный размер очереди
		metrics: &EngineMetrics{
			startTime: time.Now(),
		},
	}
}

// Start запускает движок корреляции // v1.0
func (e *Engine) Start(ctx context.Context) error {
	e.logger.Logger.Info("Starting correlation engine")

	// Загружаем правила из базы данных или файлов
	if err := e.loadRules(); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Подписываемся на события из NATS
	if err := e.subscribeToEvents(ctx); err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Запускаем воркеры для обработки событий
	for i := 0; i < 5; i++ { // Дефолтное количество воркеров
		e.wg.Add(1)
		go e.worker(ctx, i)
	}

	// Запускаем воркер очистки
	e.wg.Add(1)
	go e.cleanupWorker(ctx)

	// Запускаем сборщик метрик
	e.wg.Add(1)
	go e.metricsCollector(ctx)

	e.logger.Logger.Info("Correlation engine started successfully")
	return nil
}

// Stop останавливает движок корреляции // v1.0
func (e *Engine) Stop() error {
	e.logger.Logger.Info("Stopping correlation engine")

	// Отправляем сигнал остановки
	close(e.stopChan)

	// Ждем завершения всех воркеров
	e.wg.Wait()

	// Закрываем каналы
	close(e.eventQueue)

	e.logger.Logger.Info("Correlation engine stopped")
	return nil
}

// loadRules загружает правила корреляции // v1.0
func (e *Engine) loadRules() error {
	// В реальной реализации здесь будет SQL запрос к таблице rules
	// SELECT id, name, severity, description, yaml_content, enabled, created_at, updated_at FROM rules WHERE enabled = true
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()

	// Пока используем встроенные правила для демонстрации
	builtinRules := []dsl.Rule{
		{
			ID:          "login_bruteforce",
			Name:        "SSH Brute Force Detection",
			Severity:    "high",
			Description: "Detects multiple failed SSH login attempts",
			Enabled:     true,
			Window: dsl.WindowConfig{
				Duration: 5 * time.Minute,
				Sliding:  true,
			},
			Threshold: dsl.ThresholdConfig{
				Count: 5,
				Type:  "unique",
				Field: "user",
			},
			Conditions: []dsl.Condition{
				{
					Field:    "user",
					Operator: "count_unique",
					Value:    "5",
				},
			},
			Actions: []dsl.Action{
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "high",
						"message":  "Multiple failed SSH login attempts detected for user {{user}}",
					},
				},
			},
		},
		{
			ID:          "fim_critical",
			Name:        "Critical File Changes",
			Severity:    "critical",
			Description: "Detects changes to critical system files",
			Enabled:     true,
			Window: dsl.WindowConfig{
				Duration: 1 * time.Minute,
				Sliding:  false,
			},
			Threshold: dsl.ThresholdConfig{
				Count: 1,
				Type:  "count",
				Field: "file.path",
			},
			Conditions: []dsl.Condition{
				{
					Field:    "file.path",
					Operator: "matches",
					Value:    "/etc/(passwd|shadow|sudoers|hosts|resolv.conf)",
				},
			},
			Actions: []dsl.Action{
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "critical",
						"message":  "Critical system file {{file.path}} was modified",
					},
				},
			},
		},
	}

	// Компилируем каждое правило
	for _, rule := range builtinRules {
		compiledRule, err := e.compiler.CompileRule(&rule)
		if err != nil {
			e.logger.Logger.WithFields(map[string]interface{}{
				"rule_id": rule.ID,
				"error":   err.Error(),
			}).Warn("Failed to compile rule")
			continue
		}

		e.rules[compiledRule.Rule.ID] = compiledRule
		e.logger.Logger.WithField("rule_id", rule.ID).Info("Rule compiled and loaded")
	}

	e.logger.Logger.WithField("rules_loaded", len(e.rules)).Info("Rules loaded successfully")
	return nil
}

// subscribeToEvents подписывается на события из NATS // v1.0
func (e *Engine) subscribeToEvents(ctx context.Context) error {
	// Подписываемся на subject events.normalized для получения нормализованных событий
	err := e.nats.SubscribeToEvents("events.normalized", func(data []byte) {
		var event models.Event
		if err := json.Unmarshal(data, &event); err != nil {
			e.logger.Logger.WithField("error", err.Error()).Error("Failed to unmarshal normalized event")
			return
		}

		// Обрабатываем событие
		if err := e.ProcessEvent(&event); err != nil {
			e.logger.Logger.WithFields(map[string]interface{}{
				"event_id": event.GetDedupKey(),
				"error":    err.Error(),
			}).Error("Failed to process normalized event")
		}
	})

	if err != nil {
		return fmt.Errorf("failed to subscribe to events.normalized: %w", err)
	}

	e.logger.Logger.Info("Successfully subscribed to events.normalized events")
	return nil
}

// ProcessEvent обрабатывает нормализованное событие // v1.0
func (e *Engine) ProcessEvent(event *models.Event) error {
	e.logger.Logger.WithFields(map[string]interface{}{
		"event_id": event.GetDedupKey(),
		"host":     event.Host,
		"category": event.Category,
		"subtype":  event.Subtype,
	}).Debug("Processing normalized event")

	// Добавляем событие в очередь для обработки
	select {
	case e.eventQueue <- event:
		e.updateMetrics("queue_size", 1)
	default:
		// Очередь переполнена, логируем предупреждение
		e.logger.Logger.WithField("event_id", event.GetDedupKey()).Warn("Event queue is full, dropping event")
		e.updateMetrics("dropped_events", 1)
	}

	return nil
}

// worker воркер для обработки событий из очереди // v1.0
func (e *Engine) worker(ctx context.Context, id int) {
	defer e.wg.Done()

	e.logger.Logger.WithFields(map[string]interface{}{
		"worker_id": id,
	}).Info("Correlation worker started")

	// Обрабатываем события из очереди
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
		case event, ok := <-e.eventQueue:
			if !ok {
				// Канал закрыт
				return
			}

			// Обрабатываем событие
			startTime := time.Now()
			if err := e.processEvent(event); err != nil {
				e.logger.Logger.WithFields(map[string]interface{}{
					"worker_id": id,
					"event_id":  event.GetDedupKey(),
					"error":     err.Error(),
				}).Error("Failed to process event")
				e.updateMetrics("error_count", 1)
			} else {
				processingTime := time.Since(startTime)
				e.updateMetrics("events_processed", 1)
				e.updateMetrics("processing_time", processingTime)
			}
		}
	}
}

// processEvent обрабатывает одно событие // v1.0
func (e *Engine) processEvent(event *models.Event) error {
	e.mu.RLock()
	rules := make([]*dsl.CompiledRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	e.mu.RUnlock()

	// Проверяем событие против всех правил
	for _, rule := range rules {
		// Проверяем, соответствует ли событие правилу
		if !rule.Matcher.Match(event) {
			continue
		}

		// Обрабатываем правило
		if err := e.evaluateRule(rule, event); err != nil {
			e.logger.Logger.WithFields(map[string]interface{}{
				"rule_id":  rule.Rule.ID,
				"event_id": event.GetDedupKey(),
				"error":    err.Error(),
			}).Error("Failed to evaluate rule")
			continue
		}

		e.updateMetrics("rules_triggered", 1)
	}

	return nil
}

// evaluateRule оценивает правило для события // v1.0
func (e *Engine) evaluateRule(rule *dsl.CompiledRule, event *models.Event) error {
	// Получаем групповой ключ для события
	groupKey := e.getGroupKey(rule, event)

	// Проверяем временное окно
	triggered := rule.Evaluator.AddEvent(event)

	// Если правило сработало, выполняем действия
	if triggered {
		if err := e.executeActions(rule, event, groupKey); err != nil {
			return fmt.Errorf("failed to execute actions: %w", err)
		}
	}

	return nil
}

// getGroupKey генерирует групповой ключ для события // v1.0
func (e *Engine) getGroupKey(rule *dsl.CompiledRule, event *models.Event) string {
	// В реальной реализации здесь будет логика группировки событий
	// Пока используем простую группировку по хосту
	return fmt.Sprintf("host:%s", event.Host)
}

// executeActions выполняет действия правила // v1.0
func (e *Engine) executeActions(rule *dsl.CompiledRule, event *models.Event, groupKey string) error {
	// Создаем алерт
	alert := &models.Alert{
		ID:       generateAlertID(),
		TS:       time.Now(),
		RuleID:   rule.Rule.ID,
		Severity: rule.Rule.Severity,
		DedupKey: fmt.Sprintf("%s:%s:%s", rule.Rule.ID, event.Host, rule.Rule.Severity),
		Payload: map[string]interface{}{
			"message":  fmt.Sprintf("Rule %s triggered for group %s", rule.Rule.ID, groupKey),
			"event_id": event.GetDedupKey(),
			"host":     event.Host,
			"category": event.Category,
			"subtype":  event.Subtype,
		},
		Status:    "new",
		Env:       event.Env,
		Host:      event.Host,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Выполняем действия
	for _, action := range rule.Actions {
		if err := action.Execute(alert); err != nil {
			e.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"action":   action.GetType(),
				"error":    err.Error(),
			}).Error("Failed to execute action")
			continue
		}
	}

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

	e.updateMetrics("alerts_generated", 1)
	return nil
}

// cleanupWorker очищает истекшие окна // v1.0
func (e *Engine) cleanupWorker(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(1 * time.Minute) // Дефолтный интервал
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

// metricsCollector собирает метрики производительности // v1.0
func (e *Engine) metricsCollector(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	e.logger.Logger.Info("Metrics collector started")

	for {
		select {
		case <-ctx.Done():
			e.logger.Logger.Info("Metrics collector context cancelled")
			return
		case <-e.stopChan:
			e.logger.Logger.Info("Metrics collector stop signal received")
			return
		case <-ticker.C:
			e.updatePerformanceMetrics()
		}
	}
}

// updatePerformanceMetrics обновляет метрики производительности // v1.0
func (e *Engine) updatePerformanceMetrics() {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	// Обновляем размер очереди
	e.metrics.queueSize = len(e.eventQueue)

	// Обновляем утилизацию воркеров
	if e.metrics.eventsProcessed > 0 {
		uptime := time.Since(e.metrics.startTime)
		e.metrics.workerUtilization = float64(e.metrics.eventsProcessed) / uptime.Seconds()
	}

	// Логируем метрики
	e.logger.Logger.WithFields(map[string]interface{}{
		"events_processed":   e.metrics.eventsProcessed,
		"alerts_generated":   e.metrics.alertsGenerated,
		"rules_triggered":    e.metrics.rulesTriggered,
		"queue_size":         e.metrics.queueSize,
		"worker_utilization": fmt.Sprintf("%.2f", e.metrics.workerUtilization),
		"error_count":        e.metrics.errorCount,
		"uptime":             time.Since(e.metrics.startTime).String(),
	}).Debug("Performance metrics updated")
}

// updateMetrics обновляет метрики // v1.0
func (e *Engine) updateMetrics(metric string, value interface{}) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	switch metric {
	case "events_processed":
		e.metrics.eventsProcessed++
	case "alerts_generated":
		e.metrics.alertsGenerated++
	case "rules_triggered":
		e.metrics.rulesTriggered++
	case "error_count":
		e.metrics.errorCount++
	case "processing_time":
		if duration, ok := value.(time.Duration); ok {
			e.metrics.processingTime = duration
		}
	case "queue_size":
		if size, ok := value.(int); ok {
			e.metrics.queueSize = size
		}
	}

	e.metrics.lastEventTime = time.Now()
}

// GetStats возвращает статистику движка корреляции // v1.0
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	stats := map[string]interface{}{
		"status":       "running",
		"workers":      5, // Дефолтное количество воркеров
		"loaded_rules": len(e.rules),
		"event_buffer": 1000, // Дефолтный размер буфера
		"alert_ttl":    "1h", // Дефолтный TTL алертов
		"metrics": map[string]interface{}{
			"events_processed":   e.metrics.eventsProcessed,
			"alerts_generated":   e.metrics.alertsGenerated,
			"rules_triggered":    e.metrics.rulesTriggered,
			"queue_size":         e.metrics.queueSize,
			"worker_utilization": fmt.Sprintf("%.2f", e.metrics.workerUtilization),
			"error_count":        e.metrics.errorCount,
			"uptime":             time.Since(e.metrics.startTime).String(),
			"last_event_time":    e.metrics.lastEventTime.Format(time.RFC3339),
		},
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
