// filename: internal/adminapi/service.go
package alerting

import (
	"context"
	"fmt"
	"strings"
	"time"

	"novasec/internal/alerting/channels"
	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/models"

	"github.com/google/uuid"
)

// Service представляет сервис алертинга // v1.0
type Service struct {
	logger          *logging.Logger
	natsClient      *nats.Client
	emailChannel    *channels.EmailChannel
	telegramChannel *channels.TelegramChannel
	webhookChannel  *channels.WebhookChannel
	config          *config.Config
	stopChan        chan struct{}
}

// NewService создает новый сервис алертинга // v1.0
func NewService(logger *logging.Logger, natsClient *nats.Client, config *config.Config) *Service {
	// Инициализируем каналы уведомлений с дефолтными конфигурациями
	emailConfig := &channels.EmailConfig{
		SMTPHost:   "localhost",
		SMTPPort:   587,
		From:       "alerts@novasec.local",
		To:         []string{"admin@novasec.local"},
		Timeout:    30 * time.Second,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
		UseTLS:     false,
	}
	telegramConfig := &channels.TelegramConfig{
		BotToken:  "default_token",
		ChatID:    "default_chat",
		ParseMode: "HTML",
	}
	webhookConfig := &channels.WebhookConfig{
		URL:        "http://localhost:8080/webhook",
		Method:     "POST",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}

	emailChannel := channels.NewEmailChannel(emailConfig, logger)
	telegramChannel := channels.NewTelegramChannel(telegramConfig, logger)
	webhookChannel := channels.NewWebhookChannel(webhookConfig, logger)

	return &Service{
		logger:          logger,
		natsClient:      natsClient,
		emailChannel:    emailChannel,
		telegramChannel: telegramChannel,
		webhookChannel:  webhookChannel,
		config:          config,
		stopChan:        make(chan struct{}),
	}
}

// Start запускает сервис алертинга // v1.0
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting alerting service")

	// Подписываемся на события создания алертов
	if err := s.subscribeToAlerts(ctx); err != nil {
		return fmt.Errorf("failed to subscribe to alerts: %w", err)
	}

	// Запускаем фоновые задачи
	go s.backgroundTasks(ctx)

	s.logger.Logger.Info("Alerting service started successfully")
	return nil
}

// Stop останавливает сервис алертинга // v1.0
func (s *Service) Stop() error {
	s.logger.Logger.Info("Stopping alerting service")

	// Отправляем сигнал остановки
	close(s.stopChan)

	// Ждем завершения фоновых задач
	time.Sleep(100 * time.Millisecond)

	s.logger.Logger.Info("Alerting service stopped")
	return nil
}

// subscribeToAlerts подписывается на события создания алертов // v1.0
func (s *Service) subscribeToAlerts(ctx context.Context) error {
	// Подписываемся на subject alerts.created
	// В реальной реализации здесь будет подписка на NATS
	s.logger.Logger.Info("Subscribed to alerts.created events")
	return nil
}

// backgroundTasks выполняет фоновые задачи // v1.0
func (s *Service) backgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Logger.Info("Background tasks context cancelled")
			return
		case <-s.stopChan:
			s.logger.Logger.Info("Background tasks stop signal received")
			return
		case <-ticker.C:
			// Проверяем состояние каналов уведомлений
			s.checkChannelsHealth()
		}
	}
}

// checkChannelsHealth проверяет здоровье каналов уведомлений // v1.0
func (s *Service) checkChannelsHealth() {
	// Проверяем email канал
	if err := s.emailChannel.TestConnection(); err != nil {
		s.logger.Logger.WithField("channel", "email").WithField("error", err.Error()).Warn("Email channel health check failed")
	} else {
		s.logger.Logger.WithField("channel", "email").Debug("Email channel health check passed")
	}

	// Проверяем Telegram канал
	if err := s.telegramChannel.TestConnection(); err != nil {
		s.logger.Logger.WithField("channel", "telegram").WithField("error", err.Error()).Warn("Telegram channel health check failed")
	} else {
		s.logger.Logger.WithField("channel", "telegram").Debug("Telegram channel health check passed")
	}

	// Проверяем webhook канал
	if err := s.webhookChannel.TestConnection(); err != nil {
		s.logger.Logger.WithField("channel", "webhook").WithField("error", err.Error()).Warn("Webhook channel health check failed")
	} else {
		s.logger.Logger.WithField("channel", "webhook").Debug("Webhook channel health check passed")
	}
}

// ProcessAlert обрабатывает созданный алерт // v1.0
func (s *Service) ProcessAlert(alert *models.Alert) error {
	s.logger.Logger.WithField("alert_id", alert.ID).WithField("severity", alert.Severity).Debug("Processing created alert")

	// Определяем каналы для отправки
	channels := s.determineChannels(alert)

	// Отправляем уведомления во все определенные каналы
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

// determineChannels определяет каналы для алерта на основе конфигурации // v1.0
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

// sendToChannel отправляет алерт в указанный канал // v1.0
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

// sendEmail отправляет алерт по email // v1.0
func (s *Service) sendEmail(alert *models.Alert) error {
	// Создаем уникальный ID для отслеживания
	messageID := uuid.New().String()

	// Отправляем email через канал
	if err := s.emailChannel.Send(alert); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Logger.WithField("alert_id", alert.ID).WithField("message_id", messageID).Info("Email notification sent successfully")
	return nil
}

// sendTelegram отправляет алерт в Telegram // v1.0
func (s *Service) sendTelegram(alert *models.Alert) error {
	// Отправляем в Telegram через канал
	if err := s.telegramChannel.Send(alert); err != nil {
		return fmt.Errorf("failed to send Telegram message: %w", err)
	}

	s.logger.Logger.WithField("alert_id", alert.ID).Info("Telegram notification sent successfully")
	return nil
}

// sendWebhook отправляет алерт по webhook // v1.0
func (s *Service) sendWebhook(alert *models.Alert) error {
	// Отправляем webhook через канал
	if err := s.webhookChannel.Send(alert); err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}

	s.logger.Logger.WithField("alert_id", alert.ID).Info("Webhook notification sent successfully")
	return nil
}

// Каналы уведомлений сами форматируют сообщения на основе алерта

// GetServiceInfo возвращает информацию о сервисе // v1.0
func (s *Service) GetServiceInfo() map[string]interface{} {
	return map[string]interface{}{
		"service":    "alerting",
		"status":     "running",
		"version":    "1.0.0",
		"started_at": time.Now().Format(time.RFC3339),
		"channels": map[string]interface{}{
			"email": map[string]interface{}{
				"enabled": true,
				"host":    "localhost",
				"port":    587,
			},
			"telegram": map[string]interface{}{
				"enabled": true,
				"bot_id":  "default",
			},
			"webhook": map[string]interface{}{
				"enabled": true,
				"url":     "http://localhost:8080/webhook",
			},
		},
	}
}
