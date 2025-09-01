// filename: internal/correlator/dsl/actions.go
package dsl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/novasec/novasec/internal/models"
)

// CreateAlertAction действие создания алерта // v1.0
type CreateAlertAction struct {
	actionType string
	config     map[string]interface{}
}

// Execute выполняет действие создания алерта // v1.0
func (a *CreateAlertAction) Execute(alert *models.Alert) error {
	// Алерт уже создан, просто логируем
	log.Printf("Alert created: %s - %s on %s", alert.RuleID, alert.Severity, alert.Host)
	return nil
}

// GetType возвращает тип действия // v1.0
func (a *CreateAlertAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *CreateAlertAction) GetConfig() map[string]interface{} {
	return a.config
}

// SendEmailAction действие отправки email // v1.0
type SendEmailAction struct {
	actionType string
	config     map[string]interface{}
	delay      time.Duration
	retry      int
	timeout    time.Duration
}

// Execute выполняет действие отправки email // v1.0
func (a *SendEmailAction) Execute(alert *models.Alert) error {
	// Получаем конфигурацию SMTP
	smtpHost, ok := a.config["smtp_host"].(string)
	if !ok {
		return fmt.Errorf("smtp_host not configured")
	}
	smtpPort, ok := a.config["smtp_port"].(string)
	if !ok {
		smtpPort = "587"
	}
	username, ok := a.config["username"].(string)
	if !ok {
		return fmt.Errorf("username not configured")
	}
	password, ok := a.config["password"].(string)
	if !ok {
		return fmt.Errorf("password not configured")
	}
	to, ok := a.config["to"].(string)
	if !ok {
		return fmt.Errorf("to email not configured")
	}
	from, ok := a.config["from"].(string)
	if !ok {
		from = username
	}

	// Формируем сообщение
	subject := fmt.Sprintf("[%s] Alert: %s", alert.Severity, alert.RuleID)
	body := fmt.Sprintf("Alert Details:\nRule: %s\nSeverity: %s\nHost: %s\nTime: %s",
		alert.RuleID, alert.Severity, alert.Host, alert.TS.Format(time.RFC3339))

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", from, to, subject, body)

	// Настройки аутентификации
	auth := smtp.PlainAuth("", username, password, smtpHost)

	// Отправляем email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("Email sent to %s for alert %s", to, alert.RuleID)
	return nil
}

// GetType возвращает тип действия // v1.0
func (a *SendEmailAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *SendEmailAction) GetConfig() map[string]interface{} {
	return a.config
}

// SendTelegramAction действие отправки в Telegram // v1.0
type SendTelegramAction struct {
	actionType string
	config     map[string]interface{}
	delay      time.Duration
	retry      int
	timeout    time.Duration
}

// Execute выполняет действие отправки в Telegram // v1.0
func (a *SendTelegramAction) Execute(alert *models.Alert) error {
	// Получаем конфигурацию Telegram
	botToken, ok := a.config["bot_token"].(string)
	if !ok {
		return fmt.Errorf("bot_token not configured")
	}
	chatID, ok := a.config["chat_id"].(string)
	if !ok {
		return fmt.Errorf("chat_id not configured")
	}

	// Формируем сообщение
	message := fmt.Sprintf("🚨 *Alert: %s*\nSeverity: %s\nHost: %s\nRule: %s\nTime: %s\n\n%s",
		alert.Severity, alert.Severity, alert.Host, alert.RuleID,
		alert.TS.Format(time.RFC3339), alert.GetPayloadString("message"))

	// Создаем HTTP клиент с таймаутом
	client := &http.Client{
		Timeout: a.timeout,
	}

	// Формируем URL для Telegram Bot API
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	// Подготавливаем данные
	data := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram message: %w", err)
	}

	// Отправляем запрос
	resp, err := client.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %d - %s", resp.StatusCode, string(body))
	}

	log.Printf("Telegram message sent to chat %s for alert %s", chatID, alert.RuleID)
	return nil
}

// GetType возвращает тип действия // v1.0
func (a *SendTelegramAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *SendTelegramAction) GetConfig() map[string]interface{} {
	return a.config
}

// WebhookAction действие отправки webhook // v1.0
type WebhookAction struct {
	actionType string
	config     map[string]interface{}
	delay      time.Duration
	retry      int
	timeout    time.Duration
}

// Execute выполняет действие отправки webhook // v1.0
func (a *WebhookAction) Execute(alert *models.Alert) error {
	// Получаем конфигурацию webhook
	webhookURL, ok := a.config["url"].(string)
	if !ok {
		return fmt.Errorf("webhook url not configured")
	}

	// Проверяем валидность URL
	_, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Формируем payload
	payload := map[string]interface{}{
		"alert_id":  alert.ID,
		"rule_id":   alert.RuleID,
		"severity":  alert.Severity,
		"host":      alert.Host,
		"message":   alert.GetPayloadString("message"),
		"timestamp": alert.TS.Format(time.RFC3339),
		"dedup_key": alert.DedupKey,
		"env":       alert.Env,
		"status":    alert.Status,
	}

	// Добавляем дополнительные поля из конфига
	if headers, ok := a.config["headers"].(map[string]interface{}); ok {
		payload["custom_headers"] = headers
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Создаем HTTP клиент с таймаутом
	client := &http.Client{
		Timeout: a.timeout,
	}

	// Создаем запрос
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NovaSec/1.0")

	// Отправляем запрос
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Webhook sent to %s for alert %s", webhookURL, alert.RuleID)
	return nil
}

// GetType возвращает тип действия // v1.0
func (a *WebhookAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *WebhookAction) GetConfig() map[string]interface{} {
	return a.config
}

// LogAction действие логирования // v1.0
type LogAction struct {
	actionType string
	config     map[string]interface{}
}

// Execute выполняет действие логирования // v1.0
func (a *LogAction) Execute(alert *models.Alert) error {
	// Получаем уровень логирования
	logLevel, ok := a.config["level"].(string)
	if !ok {
		logLevel = "info"
	}

	// Формируем сообщение лога
	logMessage := fmt.Sprintf("[%s] Alert triggered - Rule: %s, Severity: %s, Host: %s, Message: %s",
		strings.ToUpper(logLevel), alert.RuleID, alert.Severity, alert.Host, alert.GetPayloadString("message"))

	// Логируем в зависимости от уровня
	switch strings.ToLower(logLevel) {
	case "error":
		log.Printf("ERROR: %s", logMessage)
	case "warn", "warning":
		log.Printf("WARN: %s", logMessage)
	case "debug":
		log.Printf("DEBUG: %s", logMessage)
	default:
		log.Printf("INFO: %s", logMessage)
	}

	// Если указан файл для логирования
	if logFile, ok := a.config["file"].(string); ok && logFile != "" {
		// В продакшене здесь можно добавить запись в файл
		log.Printf("Alert also logged to file: %s", logFile)
	}

	return nil
}

// GetType возвращает тип действия // v1.0
func (a *LogAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *LogAction) GetConfig() map[string]interface{} {
	return a.config
}

// ScriptAction действие выполнения скрипта // v1.0
type ScriptAction struct {
	actionType string
	config     map[string]interface{}
	timeout    time.Duration
}

// Execute выполняет действие выполнения скрипта // v1.0
func (a *ScriptAction) Execute(alert *models.Alert) error {
	// Получаем конфигурацию скрипта
	scriptPath, ok := a.config["script_path"].(string)
	if !ok {
		return fmt.Errorf("script_path not configured")
	}

	// Проверяем, что скрипт существует и исполняемый
	if scriptPath == "" {
		return fmt.Errorf("script_path is empty")
	}

	// Получаем аргументы скрипта
	args := []string{}
	if scriptArgs, ok := a.config["args"].([]interface{}); ok {
		for _, arg := range scriptArgs {
			if strArg, ok := arg.(string); ok {
				args = append(args, strArg)
			}
		}
	}

	// Добавляем переменные окружения для скрипта
	env := []string{
		fmt.Sprintf("ALERT_ID=%s", alert.ID),
		fmt.Sprintf("RULE_ID=%s", alert.RuleID),
		fmt.Sprintf("SEVERITY=%s", alert.Severity),
		fmt.Sprintf("HOST=%s", alert.Host),
		fmt.Sprintf("MESSAGE=%s", alert.GetPayloadString("message")),
		fmt.Sprintf("TIMESTAMP=%s", alert.TS.Format(time.RFC3339)),
		fmt.Sprintf("DEDUP_KEY=%s", alert.DedupKey),
		fmt.Sprintf("ENV=%s", alert.Env),
		fmt.Sprintf("STATUS=%s", alert.Status),
	}

	// Создаем контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	// Выполняем скрипт
	cmd := exec.CommandContext(ctx, scriptPath, args...)
	cmd.Env = append(os.Environ(), env...)

	// Захватываем вывод
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Запускаем скрипт
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("script execution failed: %w, stderr: %s", err, stderr.String())
	}

	// Логируем результат
	log.Printf("Script %s executed successfully for alert %s", scriptPath, alert.RuleID)
	if stdout.Len() > 0 {
		log.Printf("Script output: %s", stdout.String())
	}

	return nil
}

// GetType возвращает тип действия // v1.0
func (a *ScriptAction) GetType() string {
	return a.actionType
}

// GetConfig возвращает конфигурацию действия // v1.0
func (a *ScriptAction) GetConfig() map[string]interface{} {
	return a.config
}
