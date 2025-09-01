// filename: internal/alerting/service_test.go
package alerting

import (
	"context"
	"fmt"
	"testing"
	"time"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
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

// createTestConfig создает реалистичный конфиг для тестов
func createTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		NATS: config.NATSConfig{
			URLs:      []string{"nats://localhost:4222"},
			ClusterID: "test-cluster",
			ClientID:  "test-client",
		},
		ClickHouse: config.ClickHouseConfig{
			Hosts:    []string{"localhost"},
			Database: "test_db",
			Port:     9000,
		},
		PostgreSQL: config.PostgreSQLConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "test_db",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
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
			"source_ip":        "192.168.1.100",
			"destination_ip":   "10.0.0.50",
			"user_agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"request_count":    150,
			"threshold":        100,
			"time_window":      "5m",
		},
	}
}

func TestNewService(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	// Создаем реальный NATS клиент для тестирования
	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	if service == nil {
		t.Fatal("NewService returned nil")
	}

	if service.logger != logger {
		t.Error("Service logger not set correctly")
	}

	if service.natsClient != natsClient {
		t.Error("Service NATS client not set correctly")
	}

	if service.config != config {
		t.Error("Service config not set correctly")
	}

	if service.stopChan == nil {
		t.Error("Service stopChan not initialized")
	}

	// Проверяем, что каналы уведомлений инициализированы с реальными конфигами
	if service.emailChannel == nil {
		t.Error("Email channel not initialized")
	}

	if service.telegramChannel == nil {
		t.Error("Telegram channel not initialized")
	}

	if service.webhookChannel == nil {
		t.Error("Webhook channel not initialized")
	}

	// Проверяем, что конфигурация передалась правильно
	if service.config.NATS.URLs[0] != "nats://localhost:4222" {
		t.Errorf("NATS URL wrong: got %s want nats://localhost:4222", service.config.NATS.URLs[0])
	}

	if service.config.NATS.ClusterID != "test-cluster" {
		t.Errorf("NATS ClusterID wrong: got %s want test-cluster", service.config.NATS.ClusterID)
	}

	if service.config.NATS.ClientID != "test-client" {
		t.Errorf("NATS ClientID wrong: got %s want test-client", service.config.NATS.ClientID)
	}
}

func TestService_StartAndStop(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Создаем контекст с отменой
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запускаем сервис в горутине
	errChan := make(chan error, 1)
	go func() {
		errChan <- service.Start(ctx)
	}()

	// Даем время на запуск
	time.Sleep(100 * time.Millisecond)

	// Проверяем, что сервис запущен
	select {
	case <-service.stopChan:
		t.Error("stopChan should not be closed while running")
	default:
		// OK
	}

	// Отменяем контекст
	cancel()

	// Ждем завершения
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Service.Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Service.Start did not return within timeout")
	}
}

func TestService_Stop(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Проверяем, что stopChan не закрыт
	select {
	case <-service.stopChan:
		t.Error("stopChan should not be closed initially")
	default:
		// OK
	}

	// Останавливаем сервис
	err = service.Stop()
	if err != nil {
		t.Errorf("Service.Stop returned error: %v", err)
	}

	// Проверяем, что stopChan закрыт
	select {
	case <-service.stopChan:
		// OK
	default:
		t.Error("stopChan should be closed after Stop()")
	}
}

func TestService_ProcessAlert_RealisticData(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Создаем реалистичные алерты для тестирования
	testCases := []struct {
		name     string
		severity string
		ruleName string
		host     string
		message  string
	}{
		{
			name:     "Brute Force Attack",
			severity: "critical",
			ruleName: "brute_force_detection",
			host:     "web-server-01.company.com",
			message:  "Multiple failed login attempts detected from IP 203.0.113.45",
		},
		{
			name:     "SQL Injection Attempt",
			severity: "high",
			ruleName: "sql_injection_detection",
			host:     "api-gateway.company.com",
			message:  "SQL injection pattern detected in request parameters",
		},
		{
			name:     "Port Scan Detection",
			severity: "medium",
			ruleName: "port_scan_detection",
			host:     "firewall-01.company.com",
			message:  "Port scan detected from IP 198.51.100.67",
		},
		{
			name:     "Suspicious File Upload",
			severity: "low",
			ruleName: "file_upload_detection",
			host:     "file-server.company.com",
			message:  "Suspicious file type uploaded: .exe from untrusted source",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alert := createRealisticAlert(tc.severity, tc.ruleName, tc.host, tc.message)

			// Проверяем, что алерт создан корректно
			if alert.ID == "" {
				t.Error("Alert ID should not be empty")
			}

			if alert.RuleID == "" {
				t.Error("Alert RuleID should not be empty")
			}

			if alert.Severity != tc.severity {
				t.Errorf("Alert severity wrong: got %s want %s", alert.Severity, tc.severity)
			}

			if alert.Host != tc.host {
				t.Errorf("Alert host wrong: got %s want %s", alert.Host, tc.host)
			}

			if alert.Payload["message"] != tc.message {
				t.Errorf("Alert message wrong: got %s want %s", alert.Payload["message"], tc.message)
			}

			// Обрабатываем алерт
			err := service.ProcessAlert(alert)
			if err != nil {
				t.Errorf("ProcessAlert failed for %s: %v", tc.name, err)
			}

			// Проверяем, что алерт обработан (статус может измениться)
			if alert.Status == "" {
				t.Error("Alert status should be set after processing")
			}
		})
	}
}

func TestService_ProcessAlert_InvalidData(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Тестируем с nil алертом
	err = service.ProcessAlert(nil)
	if err == nil {
		t.Error("ProcessAlert should return error for nil alert")
	}

	// Тестируем с алертом без обязательных полей
	invalidAlert := &models.Alert{
		// Отсутствуют обязательные поля
	}

	err = service.ProcessAlert(invalidAlert)
	if err == nil {
		t.Error("ProcessAlert should return error for invalid alert")
	}

	// Тестируем с алертом с неверным уровнем важности
	invalidSeverityAlert := createRealisticAlert("invalid_severity", "test_rule", "test_host", "test message")
	invalidSeverityAlert.Severity = "super_critical" // Несуществующий уровень

	err = service.ProcessAlert(invalidSeverityAlert)
	if err == nil {
		t.Error("ProcessAlert should return error for invalid severity")
	}
}

func TestService_ProcessAlert_ConcurrentRealistic(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Создаем реалистичные алерты для конкурентной обработки
	alerts := []*models.Alert{
		createRealisticAlert("critical", "ddos_detection", "load-balancer-01.company.com", "DDoS attack detected from multiple sources"),
		createRealisticAlert("high", "malware_detection", "endpoint-01.company.com", "Malware signature detected in file upload"),
		createRealisticAlert("medium", "unauthorized_access", "database-01.company.com", "Unauthorized access attempt to database"),
		createRealisticAlert("low", "policy_violation", "user-01.company.com", "User attempted to access restricted resource"),
		createRealisticAlert("critical", "data_exfiltration", "file-server.company.com", "Large amount of data being transferred to external IP"),
		createRealisticAlert("high", "privilege_escalation", "admin-server.company.com", "Privilege escalation attempt detected"),
		createRealisticAlert("medium", "network_anomaly", "network-monitor.company.com", "Unusual network traffic pattern detected"),
		createRealisticAlert("low", "failed_authentication", "auth-service.company.com", "Multiple failed authentication attempts"),
		createRealisticAlert("critical", "ransomware_detection", "backup-server.company.com", "Ransomware activity detected"),
		createRealisticAlert("high", "insider_threat", "hr-system.company.com", "Suspicious access pattern by internal user"),
	}

	// Запускаем конкурентную обработку
	done := make(chan bool, len(alerts))
	errors := make(chan error, len(alerts))

	for i, alert := range alerts {
		go func(alert *models.Alert, id int) {
			err := service.ProcessAlert(alert)
			if err != nil {
				errors <- fmt.Errorf("ProcessAlert failed for alert %d: %v", id, err)
			}
			done <- true
		}(alert, i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < len(alerts); i++ {
		<-done
	}

	// Проверяем ошибки
	close(errors)
	for err := range errors {
		t.Errorf("Concurrent processing error: %v", err)
	}

	// Проверяем, что все алерты обработаны
	for i, alert := range alerts {
		if alert.Status == "" {
			t.Errorf("Alert %d status not set after processing", i)
		}
	}
}

func TestService_AlertSeverityHandling(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Тестируем различные уровни важности с реалистичными данными
	testCases := []struct {
		severity string
		ruleName string
		host     string
		message  string
		expected bool
	}{
		{
			severity: "critical",
			ruleName: "zero_day_exploit",
			host:     "critical-server.company.com",
			message:  "Zero-day exploit detected in web application",
			expected: true,
		},
		{
			severity: "high",
			ruleName: "data_breach",
			host:     "database-server.company.com",
			message:  "Suspicious data access pattern detected",
			expected: true,
		},
		{
			severity: "medium",
			ruleName: "network_scan",
			host:     "network-monitor.company.com",
			message:  "Network scan detected from external IP",
			expected: true,
		},
		{
			severity: "low",
			ruleName: "policy_violation",
			host:     "user-workstation.company.com",
			message:  "User violated company policy",
			expected: true,
		},
		{
			severity: "invalid_level",
			ruleName: "test_rule",
			host:     "test-host.company.com",
			message:  "Test message",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Severity_%s", tc.severity), func(t *testing.T) {
			alert := createRealisticAlert(tc.severity, tc.ruleName, tc.host, tc.message)

			err := service.ProcessAlert(alert)
			if tc.expected && err != nil {
				t.Errorf("Expected success for severity %s, got error: %v", tc.severity, err)
			}

			// Проверяем, что алерт обработан корректно
			if tc.expected && alert.Status == "" {
				t.Errorf("Alert status should be set for valid severity %s", tc.severity)
			}
		})
	}
}

func TestService_BackgroundTasks(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	natsConfig := nats.Config{
		URLs:      []string{"nats://localhost:4222"},
		ClusterID: "test-cluster",
		ClientID:  "test-client",
	}

	natsClient, err := nats.NewClient(natsConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to NATS: %v", err)
	}
	defer natsClient.Close()

	service := NewService(logger, natsClient, config)

	// Создаем контекст с отменой
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запускаем фоновые задачи
	go service.backgroundTasks(ctx)

	// Даем время на запуск
	time.Sleep(100 * time.Millisecond)

	// Отменяем контекст
	cancel()

	// Даем время на завершение
	time.Sleep(100 * time.Millisecond)
}

func TestService_ConfigurationValidation(t *testing.T) {
	logger := createTestLogger(t)

	// Тестируем с nil конфигом
	service := NewService(logger, nil, nil)
	if service == nil {
		t.Fatal("NewService returned nil with nil config")
	}

	// Проверяем, что используются дефолтные значения
	if service.emailChannel == nil {
		t.Error("Email channel should be initialized with default config")
	}

	if service.telegramChannel == nil {
		t.Error("Telegram channel should be initialized with default config")
	}

	if service.webhookChannel == nil {
		t.Error("Webhook channel should be initialized with default config")
	}

	// Тестируем с реальным конфигом
	realConfig := createTestConfig()
	serviceWithConfig := NewService(logger, nil, realConfig)

	if serviceWithConfig.config != realConfig {
		t.Error("Service config not set correctly")
	}

	// Проверяем, что реальные значения передались
	if serviceWithConfig.config.NATS.URLs[0] != "nats://localhost:4222" {
		t.Errorf("Real config not applied: got %s want nats://localhost:4222", serviceWithConfig.config.NATS.URLs[0])
	}
}
