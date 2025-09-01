// filename: internal/alerting/service.go
// NovaSec Alerting Service

package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/models"
)

// Service represents the alerting service
type Service struct {
	config *config.Config
	logger *logging.Logger
	nats   *nats.Client
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new alerting service
func NewService(cfg *config.Config, logger *logging.Logger, natsClient *nats.Client) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		nats:     natsClient,
		stopChan: make(chan struct{}),
	}
}

// Start starts the alerting service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting alerting service")

	// Subscribe to created alerts
	_ = s.nats.SubscribeToEvents("alerts.created", func(data []byte) {
		if err := s.handleCreatedAlert(data); err != nil {
			s.logger.Logger.Error("Failed to handle created alert", err)
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

// Stop stops the alerting service
func (s *Service) Stop() {
	close(s.stopChan)
}

// handleCreatedAlert processes created alerts from NATS
func (s *Service) handleCreatedAlert(data []byte) error {
	var alert models.Alert
	if err := json.Unmarshal(data, &alert); err != nil {
		return fmt.Errorf("failed to unmarshal alert: %w", err)
	}

	s.logger.Logger.WithField("alert_id", alert.ID).WithField("severity", alert.Severity).Debug("Processing created alert")

	// Реализуем логику маршрутизации алертов
	if err := s.routeAlert(&alert); err != nil {
		return fmt.Errorf("failed to route alert %s: %w", alert.ID, err)
	}

	return nil
}

// routeAlert определяет каналы для алерта и отправляет уведомления
func (s *Service) routeAlert(alert *models.Alert) error {
	// Определяем каналы на основе severity и env
	channels := s.determineChannels(alert)

	if len(channels) == 0 {
		s.logger.Logger.WithField("alert_id", alert.ID).Warn("No channels configured for alert")
		return nil
	}

	// Отправляем уведомления в каждый канал
	for _, channel := range channels {
		if err := s.sendToChannel(alert, channel); err != nil {
			s.logger.Logger.WithField("alert_id", alert.ID).WithField("channel", channel).Error("Failed to send to channel", err)
			// Продолжаем с другими каналами
			continue
		}
		s.logger.Logger.WithField("alert_id", alert.ID).WithField("channel", channel).Info("Alert sent to channel")
	}

	return nil
}

// determineChannels определяет каналы для алерта на основе конфигурации
func (s *Service) determineChannels(alert *models.Alert) []string {
	var channels []string

	// Базовые каналы по severity
	switch strings.ToLower(alert.Severity) {
	case "critical":
		channels = append(channels, "email", "telegram", "webhook")
	case "high":
		channels = append(channels, "email", "telegram")
	case "medium":
		channels = append(channels, "email")
	case "low":
		channels = append(channels, "email")
	default:
		channels = append(channels, "email")
	}

	// Дополнительные каналы по env
	if alert.Env == "production" {
		channels = append(channels, "webhook")
	}

	// Убираем дубликаты
	seen := make(map[string]bool)
	var uniqueChannels []string
	for _, ch := range channels {
		if !seen[ch] {
			seen[ch] = true
			uniqueChannels = append(uniqueChannels, ch)
		}
	}

	return uniqueChannels
}

// sendToChannel отправляет алерт в указанный канал
func (s *Service) sendToChannel(alert *models.Alert, channel string) error {
	switch channel {
	case "email":
		return s.sendEmail(alert)
	case "telegram":
		return s.sendTelegram(alert)
	case "webhook":
		return s.sendWebhook(alert)
	default:
		return fmt.Errorf("unknown channel: %s", channel)
	}
}

// sendEmail отправляет алерт по email
func (s *Service) sendEmail(alert *models.Alert) error {
	// Получаем конфигурацию SMTP из config
	// В реальной реализации здесь будет доступ к конфигурации SMTP
	// Пока используем базовую логику
	// TODO: Добавить доступ к конфигурации SMTP

	// Здесь будет реализация отправки email
	// Пока логируем
	s.logger.Logger.WithField("alert_id", alert.ID).Info("Email notification would be sent")
	return nil
}

// sendTelegram отправляет алерт в Telegram
func (s *Service) sendTelegram(alert *models.Alert) error {
	// Получаем конфигурацию Telegram из config
	// В реальной реализации здесь будет доступ к конфигурации Telegram
	// Пока используем базовую логику
	// TODO: Добавить доступ к конфигурации Telegram

	// Здесь будет реализация отправки в Telegram
	// Пока логируем
	s.logger.Logger.WithField("alert_id", alert.ID).Info("Telegram notification would be sent")
	return nil
}

// sendWebhook отправляет алерт по webhook
func (s *Service) sendWebhook(alert *models.Alert) error {
	// Получаем конфигурацию webhook из config
	// В реальной реализации здесь будет доступ к конфигурации webhook
	// Пока используем базовую логику
	// TODO: Добавить доступ к конфигурации webhook

	// Здесь будет реализация отправки webhook
	// Пока логируем
	s.logger.Logger.WithField("alert_id", alert.ID).Info("Webhook notification would be sent")
	return nil
}
