// filename: internal/alerting/channels/telegram.go
package channels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/models"
)

// TelegramChannel представляет канал отправки Telegram уведомлений // v1.0
type TelegramChannel struct {
	config *TelegramConfig
	logger *logging.Logger
	client *http.Client
}

// TelegramConfig конфигурация Telegram канала // v1.0
type TelegramConfig struct {
	BotToken              string        `yaml:"bot_token"`
	ChatID                string        `yaml:"chat_id"`
	ParseMode             string        `yaml:"parse_mode"` // HTML, Markdown, MarkdownV2
	DisableWebPagePreview bool          `yaml:"disable_web_page_preview"`
	Timeout               time.Duration `yaml:"timeout"`
	MaxRetries            int           `yaml:"max_retries"`
	RetryDelay            time.Duration `yaml:"retry_delay"`
}

// TelegramMessage представляет сообщение для Telegram // v1.0
type TelegramMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
}

// TelegramResponse представляет ответ от Telegram API // v1.0
type TelegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
	ErrorCode   int    `json:"error_code,omitempty"`
}

// NewTelegramChannel создает новый Telegram канал // v1.0
func NewTelegramChannel(config *TelegramConfig, logger *logging.Logger) *TelegramChannel {
	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &TelegramChannel{
		config: config,
		logger: logger,
		client: client,
	}
}

// Send отправляет Telegram уведомление // v1.0
func (t *TelegramChannel) Send(alert *models.Alert) error {
	// Формируем сообщение
	text, err := t.formatMessage(alert)
	if err != nil {
		return fmt.Errorf("failed to format Telegram message: %w", err)
	}

	// Отправляем с ретраями
	var lastErr error
	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			t.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt,
				"delay":    t.config.RetryDelay,
			}).Info("Retrying Telegram send")

			time.Sleep(t.config.RetryDelay)
		}

		if err := t.sendMessage(text); err != nil {
			lastErr = err
			t.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt + 1,
				"error":    err.Error(),
			}).Warn("Telegram send attempt failed")
			continue
		}

		// Успешная отправка
		t.logger.Logger.WithFields(map[string]interface{}{
			"alert_id": alert.ID,
			"attempt":  attempt + 1,
			"chat_id":  t.config.ChatID,
		}).Info("Telegram message sent successfully")

		return nil
	}

	return fmt.Errorf("failed to send Telegram message after %d attempts: %w", t.config.MaxRetries+1, lastErr)
}

// formatMessage форматирует сообщение для Telegram // v1.0
func (t *TelegramChannel) formatMessage(alert *models.Alert) (string, error) {
	// Формируем сообщение в зависимости от parse_mode
	var message string

	switch t.config.ParseMode {
	case "HTML":
		message = t.formatHTMLMessage(alert)
	case "Markdown", "MarkdownV2":
		message = t.formatMarkdownMessage(alert)
	default:
		message = t.formatPlainMessage(alert)
	}

	return message, nil
}

// formatHTMLMessage форматирует сообщение в HTML // v1.0
func (t *TelegramChannel) formatHTMLMessage(alert *models.Alert) string {
	severityIcon := t.getSeverityIcon(alert.Severity)

	message := fmt.Sprintf(`🚨 <b>Alert: %s</b>

<b>Severity:</b> %s
<b>Host:</b> %s
<b>Rule:</b> %s
<b>Time:</b> %s

<b>Message:</b> %s

<b>Alert ID:</b> <code>%s</code>
<b>Created:</b> %s

---
<i>NovaSec Security Platform</i>`,
		severityIcon,
		alert.Severity,
		alert.Host,
		alert.RuleID,
		alert.TS.Format(time.RFC3339),
		alert.GetPayloadString("message"),
		alert.ID,
		alert.CreatedAt.Format(time.RFC3339))

	return message
}

// formatMarkdownMessage форматирует сообщение в Markdown // v1.0
func (t *TelegramChannel) formatMarkdownMessage(alert *models.Alert) string {
	severityIcon := t.getSeverityIcon(alert.Severity)

	message := fmt.Sprintf(`🚨 *Alert: %s*

*Severity:* %s
*Host:* %s
*Rule:* %s
*Time:* %s

*Message:* %s

*Alert ID:* `+"`"+`%s`+"`"+`
*Created:* %s

---
_NovaSec Security Platform_`,
		severityIcon,
		alert.Severity,
		alert.Host,
		alert.RuleID,
		alert.TS.Format(time.RFC3339),
		alert.GetPayloadString("message"),
		alert.ID,
		alert.CreatedAt.Format(time.RFC3339))

	return message
}

// formatPlainMessage форматирует сообщение в обычном тексте // v1.0
func (t *TelegramChannel) formatPlainMessage(alert *models.Alert) string {
	severityIcon := t.getSeverityIcon(alert.Severity)

	message := fmt.Sprintf(`🚨 Alert: %s

Severity: %s
Host: %s
Rule: %s
Time: %s

Message: %s

Alert ID: %s
Created: %s

---
NovaSec Security Platform`,
		severityIcon,
		alert.Severity,
		alert.Host,
		alert.RuleID,
		alert.TS.Format(time.RFC3339),
		alert.GetPayloadString("message"),
		alert.ID,
		alert.CreatedAt.Format(time.RFC3339))

	return message
}

// getSeverityIcon возвращает иконку для severity // v1.0
func (t *TelegramChannel) getSeverityIcon(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// sendMessage отправляет сообщение через Telegram Bot API // v1.0
func (t *TelegramChannel) sendMessage(text string) error {
	// Формируем сообщение
	message := TelegramMessage{
		ChatID:                t.config.ChatID,
		Text:                  text,
		ParseMode:             t.config.ParseMode,
		DisableWebPagePreview: t.config.DisableWebPagePreview,
	}

	// Сериализуем в JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Формируем URL для API
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.config.BotToken)

	// Создаем HTTP запрос
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Отправляем запрос
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	// Парсим ответ
	var telegramResp TelegramResponse
	if err := json.NewDecoder(resp.Body).Decode(&telegramResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Проверяем успешность
	if !telegramResp.OK {
		return fmt.Errorf("telegram API error: %s (code: %d)", telegramResp.Description, telegramResp.ErrorCode)
	}

	return nil
}

// TestConnection тестирует соединение с Telegram Bot API // v1.0
func (t *TelegramChannel) TestConnection() error {
	// Отправляем тестовое сообщение
	testAlert := &models.Alert{
		ID:       "test_alert",
		Severity: "info",
		Host:     "test-host",
		RuleID:   "test_rule",
		TS:       time.Now(),
		Payload: map[string]interface{}{
			"message": "This is a test message from NovaSec",
		},
		CreatedAt: time.Now(),
	}

	return t.Send(testAlert)
}

// GetConfig возвращает конфигурацию канала // v1.0
func (t *TelegramChannel) GetConfig() *TelegramConfig {
	return t.config
}

// GetType возвращает тип канала // v1.0
func (t *TelegramChannel) GetType() string {
	return "telegram"
}

// GetBotInfo получает информацию о боте // v1.0
func (t *TelegramChannel) GetBotInfo() (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", t.config.BotToken)

	resp, err := t.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get bot info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	var botInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&botInfo); err != nil {
		return nil, fmt.Errorf("failed to decode bot info: %w", err)
	}

	return botInfo, nil
}
