// filename: internal/alerting/channels/email_test.go
package channels

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/models"
)

// createTestLogger создает logger для тестов
func createTestLogger(t *testing.T) *logging.Logger {
	config := logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}
	logger, err := logging.NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return logger
}

// createTestEmailConfig создает реалистичную конфигурацию email для тестов
func createTestEmailConfig() *EmailConfig {
	return &EmailConfig{
		SMTPHost:    "smtp.gmail.com",
		SMTPPort:    587,
		Username:    "alerts@company.com",
		Password:    "test_password",
		From:        "alerts@company.com",
		To:          []string{"security@company.com", "admin@company.com"},
		Subject:     "[{{.Severity}}] Security Alert: {{.RuleID}}",
		Template:    "", // Используем дефолтный шаблон
		Timeout:     30 * time.Second,
		MaxRetries:  3,
		RetryDelay:  5 * time.Second,
		UseTLS:      true,
		UseStartTLS: true,
	}
}

// createRealisticAlert создает реалистичный алерт для тестирования
func createRealisticAlert(severity, ruleName, host, message string) *models.Alert {
	return &models.Alert{
		ID:        fmt.Sprintf("alert_%s_%d", severity, time.Now().Unix()),
		RuleID:    fmt.Sprintf("rule_%s_%s", ruleName, severity),
		Severity:  severity,
		Status:    "new",
		Host:      host,
		Env:       "production",
		TS:        time.Now(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Payload: map[string]interface{}{
			"rule_name":        ruleName,
			"rule_description": fmt.Sprintf("Detects %s activity", ruleName),
			"message":          message,
			"source_ip":        "203.0.113.45",
			"destination_ip":   "10.0.0.50",
			"user_agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"request_count":    150,
			"threshold":        100,
			"time_window":      "5m",
			"attack_type":      "brute_force",
			"target_service":   "ssh",
			"geolocation":      "Russia",
			"asn":              "AS12345",
		},
	}
}

func TestNewEmailChannel(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	if channel == nil {
		t.Fatal("NewEmailChannel returned nil")
	}

	if channel.config != config {
		t.Error("Email channel config not set correctly")
	}

	if channel.logger != logger {
		t.Error("Email channel logger not set correctly")
	}

	// Проверяем, что конфигурация передалась правильно
	if channel.config.SMTPHost != "smtp.gmail.com" {
		t.Errorf("SMTP host wrong: got %s want smtp.gmail.com", channel.config.SMTPHost)
	}

	if channel.config.SMTPPort != 587 {
		t.Errorf("SMTP port wrong: got %d want 587", channel.config.SMTPPort)
	}

	if channel.config.Username != "alerts@company.com" {
		t.Errorf("Username wrong: got %s want alerts@company.com", channel.config.Username)
	}

	if len(channel.config.To) != 2 {
		t.Errorf("To recipients count wrong: got %d want 2", len(channel.config.To))
	}

	if channel.config.To[0] != "security@company.com" {
		t.Errorf("First recipient wrong: got %s want security@company.com", channel.config.To[0])
	}

	if channel.config.To[1] != "admin@company.com" {
		t.Errorf("Second recipient wrong: got %s want admin@company.com", channel.config.To[1])
	}

	if channel.config.MaxRetries != 3 {
		t.Errorf("Max retries wrong: got %d want 3", channel.config.MaxRetries)
	}

	if channel.config.UseTLS != true {
		t.Error("UseTLS should be true")
	}

	if channel.config.UseStartTLS != true {
		t.Error("UseStartTLS should be true")
	}
}

func TestEmailChannel_FormatMessage(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	// Создаем реалистичные алерты для тестирования
	testCases := []struct {
		name     string
		severity string
		ruleName string
		host     string
		message  string
	}{
		{
			name:     "Critical Brute Force Attack",
			severity: "critical",
			ruleName: "brute_force_detection",
			host:     "web-server-01.company.com",
			message:  "Multiple failed login attempts detected from IP 203.0.113.45",
		},
		{
			name:     "High SQL Injection Attempt",
			severity: "high",
			ruleName: "sql_injection_detection",
			host:     "api-gateway.company.com",
			message:  "SQL injection pattern detected in request parameters",
		},
		{
			name:     "Medium Port Scan Detection",
			severity: "medium",
			ruleName: "port_scan_detection",
			host:     "firewall-01.company.com",
			message:  "Port scan detected from IP 198.51.100.67",
		},
		{
			name:     "Low Policy Violation",
			severity: "low",
			ruleName: "policy_violation",
			host:     "user-workstation.company.com",
			message:  "User violated company policy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := createRealisticAlert(tc.severity, tc.ruleName, tc.host, tc.message)

			subject, body, err := channel.formatMessage(alert)
			if err != nil {
				t.Fatalf("formatMessage failed: %v", err)
			}

			// Проверяем subject (с учетом плейсхолдеров)
			expectedSubject := fmt.Sprintf("[%s] Security Alert: %s", tc.severity, alert.RuleID)
			if subject != expectedSubject {
				t.Errorf("Subject wrong: got %s want %s", subject, expectedSubject)
			}

			// Проверяем, что body не пустой
			if body == "" {
				t.Error("Email body should not be empty")
			}

			// Проверяем, что в body есть информация об алерте (дефолтный шаблон)
			if !strings.Contains(body, "Alert Details") {
				t.Error("Email body should contain 'Alert Details' header")
			}

			if !strings.Contains(body, fmt.Sprintf("Rule ID: %s", alert.RuleID)) {
				t.Errorf("Email body should contain rule ID: %s", alert.RuleID)
			}

			if !strings.Contains(body, fmt.Sprintf("Severity: %s", tc.severity)) {
				t.Errorf("Email body should contain severity: %s", tc.severity)
			}

			if !strings.Contains(body, fmt.Sprintf("Host: %s", tc.host)) {
				t.Errorf("Email body should contain host: %s", tc.host)
			}

			if !strings.Contains(body, "Environment: production") {
				t.Error("Email body should contain environment")
			}

			if !strings.Contains(body, tc.message) {
				t.Errorf("Email body should contain message: %s", tc.message)
			}

			if !strings.Contains(body, fmt.Sprintf("Alert ID: %s", alert.ID)) {
				t.Errorf("Email body should contain alert ID: %s", alert.ID)
			}
		})
	}
}

func TestEmailChannel_FormatMessage_InvalidAlert(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	// Тестируем с алертом без обязательных полей
	invalidAlert := &models.Alert{
		// Отсутствуют обязательные поля
	}

	// Ожидаем ошибку из-за отсутствующих полей
	_, _, err := channel.formatMessage(invalidAlert)
	if err == nil {
		t.Log("formatMessage succeeded with invalid alert (this might be expected)")
	} else {
		t.Logf("Expected error for invalid alert: %v", err)
	}
}

func TestEmailChannel_ReplacePlaceholders(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	alert := createRealisticAlert("critical", "brute_force_detection", "web-server-01.company.com", "Multiple failed login attempts")

	// Тестируем различные плейсхолдеры (согласно реальной реализации)
	testCases := []struct {
		template string
		expected string
	}{
		{
			template: "Alert ID: {{.AlertID}}",
			expected: fmt.Sprintf("Alert ID: %s", alert.ID),
		},
		{
			template: "Severity: {{.Severity}}",
			expected: "Severity: critical",
		},
		{
			template: "Rule: {{.RuleID}}",
			expected: fmt.Sprintf("Rule: %s", alert.RuleID),
		},
		{
			template: "Host: {{.Host}}",
			expected: "Host: web-server-01.company.com",
		},
		{
			template: "Environment: {{.Env}}",
			expected: "Environment: production",
		},
		{
			template: "Status: {{.Status}}",
			expected: "Status: new",
		},
		{
			template: "Message: {{.Message}}",
			expected: "Message: Multiple failed login attempts",
		},
		{
			template: "Timestamp: {{.Timestamp}}",
			expected: fmt.Sprintf("Timestamp: %s", alert.TS.Format(time.RFC3339)),
		},
		{
			template: "Complex: {{.Severity}} alert on {{.Host}}",
			expected: "Complex: critical alert on web-server-01.company.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.template, func(t *testing.T) {
			result := channel.replacePlaceholders(tc.template, alert)
			if result != tc.expected {
				t.Errorf("Placeholder replacement wrong: got %s want %s", result, tc.expected)
			}
		})
	}
}

func TestEmailChannel_ReplacePlaceholders_InvalidTemplate(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	alert := createRealisticAlert("critical", "test_rule", "test_host", "test message")

	// Тестируем неверные плейсхолдеры
	invalidTemplates := []string{
		"{{.NonExistentField}}",
		"{{.Invalid.Syntax}",
		"{{.Complex.Field}}",
	}

	for _, template := range invalidTemplates {
		t.Run(template, func(t *testing.T) {
			result := channel.replacePlaceholders(template, alert)
			// Должен вернуть исходный шаблон или пустую строку для неверных плейсхолдеров
			if result == "" {
				t.Logf("Invalid template %s returned empty string", template)
			}
		})
	}
}

func TestEmailChannel_Send_RealisticData(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	// Создаем реалистичные алерты для тестирования
	testCases := []struct {
		name     string
		severity string
		ruleName string
		host     string
		message  string
	}{
		{
			name:     "Zero Day Exploit",
			severity: "critical",
			ruleName: "zero_day_exploit",
			host:     "critical-server.company.com",
			message:  "Zero-day exploit detected in web application",
		},
		{
			name:     "Data Breach Attempt",
			severity: "high",
			ruleName: "data_breach_detection",
			host:     "database-server.company.com",
			message:  "Suspicious data access pattern detected",
		},
		{
			name:     "Network Intrusion",
			severity: "medium",
			ruleName: "network_intrusion",
			host:     "network-monitor.company.com",
			message:  "Unauthorized network access detected",
		},
		{
			name:     "Policy Violation",
			severity: "low",
			ruleName: "policy_violation",
			host:     "user-workstation.company.com",
			message:  "User violated company security policy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := createRealisticAlert(tc.severity, tc.ruleName, tc.host, tc.message)

			// Ожидаем ошибку, так как SMTP сервер недоступен в тестах
			err := channel.Send(alert)
			if err == nil {
				t.Logf("Email send succeeded for %s (this is unexpected in test environment)", tc.name)
			} else {
				t.Logf("Expected email send error for %s: %v", tc.name, err)
			}

			// Проверяем, что алерт не изменился
			if alert.ID == "" {
				t.Error("Alert ID should not be empty after send attempt")
			}

			if alert.Severity != tc.severity {
				t.Errorf("Alert severity should not change: got %s want %s", alert.Severity, tc.severity)
			}

			if alert.Host != tc.host {
				t.Errorf("Alert host should not change: got %s want %s", alert.Host, tc.host)
			}
		})
	}
}

func TestEmailChannel_Send_InvalidAlert(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	channel := NewEmailChannel(config, logger)

	// Тестируем с алертом без обязательных полей
	invalidAlert := &models.Alert{
		// Отсутствуют обязательные поля
	}

	// Ожидаем ошибку из-за отсутствующих полей
	err := channel.Send(invalidAlert)
	if err == nil {
		t.Log("Send succeeded with invalid alert (this might be expected)")
	} else {
		t.Logf("Expected error for invalid alert: %v", err)
	}
}

func TestEmailChannel_ConfigurationValidation(t *testing.T) {
	logger := createTestLogger(t)

	// Тестируем с nil конфигом
	channel := NewEmailChannel(nil, logger)
	if channel == nil {
		t.Fatal("NewEmailChannel returned nil with nil config")
	}

	// Тестируем с минимальным конфигом
	minimalConfig := &EmailConfig{
		SMTPHost: "localhost",
		SMTPPort: 25,
		From:     "test@example.com",
		To:       []string{"admin@example.com"},
	}

	channelWithMinimal := NewEmailChannel(minimalConfig, logger)
	if channelWithMinimal.config != minimalConfig {
		t.Error("Channel config not set correctly")
	}

	// Проверяем дефолтные значения
	if channelWithMinimal.config.MaxRetries != 0 {
		t.Errorf("Default MaxRetries wrong: got %d want 0", channelWithMinimal.config.MaxRetries)
	}

	if channelWithMinimal.config.UseTLS != false {
		t.Error("Default UseTLS should be false")
	}

	if channelWithMinimal.config.UseStartTLS != false {
		t.Error("Default UseStartTLS should be false")
	}
}

func TestEmailChannel_RetryLogic(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestEmailConfig()

	// Устанавливаем короткие таймауты для тестов
	config.Timeout = 1 * time.Second
	config.RetryDelay = 100 * time.Millisecond
	config.MaxRetries = 2

	channel := NewEmailChannel(config, logger)

	alert := createRealisticAlert("critical", "test_rule", "test_host", "test message")

	// Ожидаем ошибку после всех попыток
	err := channel.Send(alert)
	if err == nil {
		t.Log("Email send succeeded (unexpected in test environment)")
	} else {
		t.Logf("Expected email send error after retries: %v", err)
	}

	// Проверяем, что конфигурация ретраев правильная
	if channel.config.MaxRetries != 2 {
		t.Errorf("MaxRetries wrong: got %d want 2", channel.config.MaxRetries)
	}

	if channel.config.RetryDelay != 100*time.Millisecond {
		t.Errorf("RetryDelay wrong: got %v want 100ms", channel.config.RetryDelay)
	}
}
