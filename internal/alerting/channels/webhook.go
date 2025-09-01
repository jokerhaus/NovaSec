// filename: internal/alerting/channels/webhook.go
package channels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/models"
)

// WebhookChannel представляет канал отправки webhook уведомлений // v1.0
type WebhookChannel struct {
	config *WebhookConfig
	logger *logging.Logger
	client *http.Client
}

// WebhookConfig конфигурация webhook канала // v1.0
type WebhookConfig struct {
	URL           string            `yaml:"url"`
	Method        string            `yaml:"method"` // POST, PUT, PATCH
	Headers       map[string]string `yaml:"headers"`
	Timeout       time.Duration     `yaml:"timeout"`
	MaxRetries    int               `yaml:"max_retries"`
	RetryDelay    time.Duration     `yaml:"retry_delay"`
	RetryStatuses []int             `yaml:"retry_statuses"` // HTTP статусы для ретрая
	Auth          *WebhookAuth      `yaml:"auth"`
}

// WebhookAuth аутентификация для webhook // v1.0
type WebhookAuth struct {
	Type     string `yaml:"type"` // basic, bearer, custom
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
	Header   string `yaml:"header,omitempty"` // для custom auth
}

// WebhookPayload представляет payload для webhook // v1.0
type WebhookPayload struct {
	Alert       *models.Alert `json:"alert"`
	Timestamp   time.Time     `json:"timestamp"`
	Source      string        `json:"source"`
	Version     string        `json:"version"`
	Environment string        `json:"environment"`
}

// NewWebhookChannel создает новый webhook канал // v1.0
func NewWebhookChannel(config *WebhookConfig, logger *logging.Logger) *WebhookChannel {
	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &WebhookChannel{
		config: config,
		logger: logger,
		client: client,
	}
}

// Send отправляет webhook уведомление // v1.0
func (w *WebhookChannel) Send(alert *models.Alert) error {
	// Формируем payload
	payload := WebhookPayload{
		Alert:       alert,
		Timestamp:   time.Now(),
		Source:      "novasec",
		Version:     "1.0.0",
		Environment: alert.Env,
	}

	// Сериализуем в JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Отправляем с ретраями
	var lastErr error
	for attempt := 0; attempt <= w.config.MaxRetries; attempt++ {
		if attempt > 0 {
			w.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt,
				"delay":    w.config.RetryDelay,
			}).Info("Retrying webhook send")

			time.Sleep(w.config.RetryDelay)
		}

		if err := w.sendWebhook(jsonData); err != nil {
			lastErr = err
			w.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt + 1,
				"error":    err.Error(),
			}).Warn("Webhook send attempt failed")
			continue
		}

		// Успешная отправка
		w.logger.Logger.WithFields(map[string]interface{}{
			"alert_id": alert.ID,
			"attempt":  attempt + 1,
			"url":      w.config.URL,
		}).Info("Webhook sent successfully")

		return nil
	}

	return fmt.Errorf("failed to send webhook after %d attempts: %w", w.config.MaxRetries+1, lastErr)
}

// sendWebhook отправляет webhook запрос // v1.0
func (w *WebhookChannel) sendWebhook(jsonData []byte) error {
	// Создаем HTTP запрос
	req, err := http.NewRequest(w.config.Method, w.config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Устанавливаем заголовки
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NovaSec/1.0.0")
	req.Header.Set("X-NovaSec-Version", "1.0.0")
	req.Header.Set("X-NovaSec-Timestamp", time.Now().Format(time.RFC3339))

	// Добавляем кастомные заголовки
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	// Добавляем аутентификацию
	if err := w.addAuth(req); err != nil {
		return fmt.Errorf("failed to add authentication: %w", err)
	}

	// Отправляем запрос
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if !w.shouldRetry(resp.StatusCode) {
		if resp.StatusCode >= 400 {
			return fmt.Errorf("webhook returned status %d", resp.StatusCode)
		}
	} else {
		return fmt.Errorf("webhook returned retryable status %d", resp.StatusCode)
	}

	return nil
}

// addAuth добавляет аутентификацию к запросу // v1.0
func (w *WebhookChannel) addAuth(req *http.Request) error {
	if w.config.Auth == nil {
		return nil
	}

	switch w.config.Auth.Type {
	case "basic":
		if w.config.Auth.Username != "" && w.config.Auth.Password != "" {
			req.SetBasicAuth(w.config.Auth.Username, w.config.Auth.Password)
		}
	case "bearer":
		if w.config.Auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+w.config.Auth.Token)
		}
	case "custom":
		if w.config.Auth.Header != "" && w.config.Auth.Token != "" {
			req.Header.Set(w.config.Auth.Header, w.config.Auth.Token)
		}
	}

	return nil
}

// shouldRetry определяет, нужно ли повторить запрос // v1.0
func (w *WebhookChannel) shouldRetry(statusCode int) bool {
	// Если указаны конкретные статусы для ретрая
	if len(w.config.RetryStatuses) > 0 {
		for _, status := range w.config.RetryStatuses {
			if status == statusCode {
				return true
			}
		}
		return false
	}

	// По умолчанию повторяем для 5xx и некоторых 4xx статусов
	if statusCode >= 500 {
		return true
	}

	// Повторяем для некоторых 4xx статусов
	retryable4xx := []int{408, 429, 502, 503, 504}
	for _, status := range retryable4xx {
		if status == statusCode {
			return true
		}
	}

	return false
}

// TestConnection тестирует соединение с webhook // v1.0
func (w *WebhookChannel) TestConnection() error {
	// Создаем тестовый алерт
	testAlert := &models.Alert{
		ID:       "test_webhook",
		Severity: "info",
		Host:     "test-host",
		RuleID:   "test_rule",
		TS:       time.Now(),
		Payload: map[string]interface{}{
			"message": "This is a test webhook from NovaSec",
		},
		CreatedAt: time.Now(),
	}

	// Отправляем тестовый webhook
	return w.Send(testAlert)
}

// GetConfig возвращает конфигурацию канала // v1.0
func (w *WebhookChannel) GetConfig() *WebhookConfig {
	return w.config
}

// GetType возвращает тип канала // v1.0
func (w *WebhookChannel) GetType() string {
	return "webhook"
}

// ValidateConfig валидирует конфигурацию webhook // v1.0
func (w *WebhookChannel) ValidateConfig() error {
	if w.config.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	if w.config.Method == "" {
		w.config.Method = "POST"
	}

	// Валидируем метод
	validMethods := []string{"POST", "PUT", "PATCH"}
	isValidMethod := false
	for _, method := range validMethods {
		if method == w.config.Method {
			isValidMethod = true
			break
		}
	}

	if !isValidMethod {
		return fmt.Errorf("invalid HTTP method: %s. Must be one of: %v", w.config.Method, validMethods)
	}

	// Устанавливаем дефолтные значения
	if w.config.Timeout == 0 {
		w.config.Timeout = 30 * time.Second
	}

	if w.config.MaxRetries == 0 {
		w.config.MaxRetries = 3
	}

	if w.config.RetryDelay == 0 {
		w.config.RetryDelay = 5 * time.Second
	}

	return nil
}

// GetWebhookStats возвращает статистику webhook канала // v1.0
func (w *WebhookChannel) GetWebhookStats() map[string]interface{} {
	return map[string]interface{}{
		"type":        "webhook",
		"url":         w.config.URL,
		"method":      w.config.Method,
		"timeout":     w.config.Timeout.String(),
		"max_retries": w.config.MaxRetries,
		"retry_delay": w.config.RetryDelay.String(),
		"auth_type":   w.getAuthType(),
		"headers":     len(w.config.Headers),
	}
}

// getAuthType возвращает тип аутентификации // v1.0
func (w *WebhookChannel) getAuthType() string {
	if w.config.Auth == nil {
		return "none"
	}
	return w.config.Auth.Type
}
