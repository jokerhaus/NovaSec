// filename: internal/correlator/service.go
// NovaSec Correlator Service

package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/correlator/dsl"
	"novasec/internal/models"
)

// Service represents the correlator service
type Service struct {
	config   *config.Config
	logger   *logging.Logger
	nats     *nats.Client
	compiler *dsl.Compiler
	rules    map[string]*dsl.CompiledRule
	stopChan chan struct{}
}

// NewService creates a new correlator service
func NewService(cfg *config.Config, logger *logging.Logger, natsClient *nats.Client) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		nats:     natsClient,
		compiler: dsl.NewCompiler(),
		rules:    make(map[string]*dsl.CompiledRule),
		stopChan: make(chan struct{}),
	}
}

// Start starts the correlator service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting correlator service")

	// Subscribe to normalized events
	_ = s.nats.SubscribeToEvents("events.normalized", func(data []byte) {
		if err := s.handleNormalizedEvent(data); err != nil {
			s.logger.Logger.Error("Failed to handle normalized event", err)
		}
	})

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		s.logger.Logger.Info("Context cancelled, stopping service")
	case <-s.stopChan:
		s.logger.Logger.Info("Stop signal received, stopping service")
	}

	return nil
}

// createAlert создает алерт на основе сработавшего правила // v1.0
func (s *Service) createAlert(compiledRule *dsl.CompiledRule, event *models.Event) (*models.Alert, error) {
	// Генерируем ключ дедупликации
	dedupKey := fmt.Sprintf("%s:%s:%s",
		compiledRule.Rule.ID,
		compiledRule.Evaluator.GetGroupKey(event),
		compiledRule.Rule.Severity)

	// Создаем алерт
	alert := &models.Alert{
		RuleID:    compiledRule.Rule.ID,
		Severity:  compiledRule.Rule.Severity,
		DedupKey:  dedupKey,
		Status:    "new",
		Env:       event.Env,
		Host:      event.Host,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Заполняем payload
	alert.Payload = map[string]interface{}{
		"rule_name":        compiledRule.Rule.Name,
		"rule_description": compiledRule.Rule.Description,
		"triggering_event": event,
		"group_key":        compiledRule.Evaluator.GetGroupKey(event),
	}

	return alert, nil
}

// Stop stops the correlator service
func (s *Service) Stop() {
	close(s.stopChan)
}

// handleNormalizedEvent processes normalized events from NATS
func (s *Service) handleNormalizedEvent(data []byte) error {
	var event models.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	s.logger.Logger.WithField("host", event.Host).WithField("category", event.Category).Debug("Processing normalized event")

	// Обрабатываем событие через все активные правила
	for ruleID, compiledRule := range s.rules {
		if !compiledRule.Rule.Enabled {
			continue
		}

		// Проверяем, соответствует ли событие правилу
		if !compiledRule.Matcher.Match(&event) {
			continue
		}

		s.logger.Logger.WithField("rule_id", ruleID).WithField("host", event.Host).Debug("Event matched rule")

		// Добавляем событие в окно оценки
		if triggered := compiledRule.Evaluator.AddEvent(&event); triggered {
			s.logger.Logger.WithField("rule_id", ruleID).WithField("host", event.Host).Info("Rule threshold triggered")

			// Создаем алерт
			alert, err := s.createAlert(compiledRule, &event)
			if err != nil {
				s.logger.Logger.WithField("rule_id", ruleID).WithField("error", err).Error("Failed to create alert")
				continue
			}

			// Публикуем алерт
			if err := s.nats.PublishEvent("alerts.created", alert); err != nil {
				s.logger.Logger.WithField("rule_id", ruleID).WithField("error", err).Error("Failed to publish alert")
				continue
			}

			s.logger.Logger.WithField("rule_id", ruleID).WithField("alert_id", alert.ID).Info("Alert created and published")
		}
	}

	return nil
}
