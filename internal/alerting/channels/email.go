// filename: internal/alerting/channels/email.go
package channels

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"text/template"
	"time"

	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/models"
)

// EmailChannel представляет канал отправки email уведомлений // v1.0
type EmailChannel struct {
	config *EmailConfig
	logger *logging.Logger
}

// EmailConfig конфигурация email канала // v1.0
type EmailConfig struct {
	SMTPHost    string        `yaml:"smtp_host"`
	SMTPPort    int           `yaml:"smtp_port"`
	Username    string        `yaml:"username"`
	Password    string        `yaml:"password"`
	From        string        `yaml:"from"`
	To          []string      `yaml:"to"`
	Subject     string        `yaml:"subject"`
	Template    string        `yaml:"template"`
	Timeout     time.Duration `yaml:"timeout"`
	MaxRetries  int           `yaml:"max_retries"`
	RetryDelay  time.Duration `yaml:"retry_delay"`
	UseTLS      bool          `yaml:"use_tls"`
	UseStartTLS bool          `yaml:"use_starttls"`
}

// NewEmailChannel создает новый email канал // v1.0
func NewEmailChannel(config *EmailConfig, logger *logging.Logger) *EmailChannel {
	return &EmailChannel{
		config: config,
		logger: logger,
	}
}

// Send отправляет email уведомление // v1.0
func (e *EmailChannel) Send(alert *models.Alert) error {
	// Формируем сообщение
	subject, body, err := e.formatMessage(alert)
	if err != nil {
		return fmt.Errorf("failed to format email message: %w", err)
	}

	// Отправляем с ретраями
	var lastErr error
	for attempt := 0; attempt <= e.config.MaxRetries; attempt++ {
		if attempt > 0 {
			e.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt,
				"delay":    e.config.RetryDelay,
			}).Info("Retrying email send")

			time.Sleep(e.config.RetryDelay)
		}

		if err := e.sendEmail(subject, body); err != nil {
			lastErr = err
			e.logger.Logger.WithFields(map[string]interface{}{
				"alert_id": alert.ID,
				"attempt":  attempt + 1,
				"error":    err.Error(),
			}).Warn("Email send attempt failed")
			continue
		}

		// Успешная отправка
		e.logger.Logger.WithFields(map[string]interface{}{
			"alert_id": alert.ID,
			"attempt":  attempt + 1,
			"to":       e.config.To,
		}).Info("Email sent successfully")

		return nil
	}

	return fmt.Errorf("failed to send email after %d attempts: %w", e.config.MaxRetries+1, lastErr)
}

// formatMessage форматирует email сообщение // v1.0
func (e *EmailChannel) formatMessage(alert *models.Alert) (string, string, error) {
	// Формируем subject
	subject := e.config.Subject
	if subject == "" {
		subject = fmt.Sprintf("[%s] Alert: %s", alert.Severity, alert.RuleID)
	}

	// Заменяем плейсхолдеры в subject
	subject = e.replacePlaceholders(subject, alert)

	// Формируем body
	var body string
	if e.config.Template != "" {
		// Используем кастомный шаблон
		tmpl, err := template.New("email").Parse(e.config.Template)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse email template: %w", err)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, alert); err != nil {
			return "", "", fmt.Errorf("failed to execute email template: %w", err)
		}
		body = buf.String()
	} else {
		// Используем дефолтный шаблон
		body = e.defaultTemplate(alert)
	}

	return subject, body, nil
}

// defaultTemplate возвращает дефолтный шаблон email // v1.0
func (e *EmailChannel) defaultTemplate(alert *models.Alert) string {
	return fmt.Sprintf(`Alert Details

Rule ID: %s
Severity: %s
Host: %s
Environment: %s
Status: %s
Timestamp: %s
Dedup Key: %s

Message: %s

Alert ID: %s
Created: %s

---
NovaSec Security Platform
Generated: %s`,
		alert.RuleID,
		alert.Severity,
		alert.Host,
		alert.Env,
		alert.Status,
		alert.TS.Format(time.RFC3339),
		alert.DedupKey,
		alert.GetPayloadString("message"),
		alert.ID,
		alert.CreatedAt.Format(time.RFC3339),
		time.Now().Format(time.RFC3339))
}

// replacePlaceholders заменяет плейсхолдеры в тексте // v1.0
func (e *EmailChannel) replacePlaceholders(text string, alert *models.Alert) string {
	replacements := map[string]string{
		"{{.RuleID}}":    alert.RuleID,
		"{{.Severity}}":  alert.Severity,
		"{{.Host}}":      alert.Host,
		"{{.Env}}":       alert.Env,
		"{{.Status}}":    alert.Status,
		"{{.AlertID}}":   alert.ID,
		"{{.Timestamp}}": alert.TS.Format(time.RFC3339),
		"{{.Message}}":   alert.GetPayloadString("message"),
	}

	for placeholder, value := range replacements {
		text = string(bytes.ReplaceAll([]byte(text), []byte(placeholder), []byte(value)))
	}

	return text
}

// sendEmail отправляет email через SMTP // v1.0
func (e *EmailChannel) sendEmail(subject, body string) error {
	// Формируем заголовки
	headers := make(map[string]string)
	headers["From"] = e.config.From
	headers["To"] = e.joinEmails(e.config.To)
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=UTF-8"
	headers["Date"] = time.Now().Format(time.RFC1123Z)

	// Формируем сообщение
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// Настройки аутентификации
	auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)

	// Адрес SMTP сервера
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)

	// Отправляем email
	if e.config.UseTLS {
		// Используем TLS
		tlsConfig := &tls.Config{
			ServerName: e.config.SMTPHost,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to establish TLS connection: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, e.config.SMTPHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}

		if err := client.Mail(e.config.From); err != nil {
			return fmt.Errorf("failed to set sender: %w", err)
		}

		for _, to := range e.config.To {
			if err := client.Rcpt(to); err != nil {
				return fmt.Errorf("failed to set recipient %s: %w", to, err)
			}
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to start data transfer: %w", err)
		}

		_, err = w.Write([]byte(message))
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("failed to close data transfer: %w", err)
		}
	} else {
		// Используем обычный SMTP
		err := smtp.SendMail(addr, auth, e.config.From, e.config.To, []byte(message))
		if err != nil {
			return fmt.Errorf("failed to send email: %w", err)
		}
	}

	return nil
}

// joinEmails объединяет email адреса в строку // v1.0
func (e *EmailChannel) joinEmails(emails []string) string {
	result := ""
	for i, email := range emails {
		if i > 0 {
			result += ", "
		}
		result += email
	}
	return result
}

// GetConfig возвращает конфигурацию канала // v1.0
func (e *EmailChannel) GetConfig() *EmailConfig {
	return e.config
}

// GetType возвращает тип канала // v1.0
func (e *EmailChannel) GetType() string {
	return "email"
}

// TestConnection тестирует соединение с SMTP сервером // v1.0
func (e *EmailChannel) TestConnection() error {
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)

	// Пробуем подключиться
	conn, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Пробуем аутентифицироваться
	auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
	if err := conn.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate with SMTP server: %w", err)
	}

	return nil
}
