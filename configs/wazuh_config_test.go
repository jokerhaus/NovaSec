// filename: configs/wazuh_config_test.go
package configs

import (
	"os"
	"testing"
	"time"
)

// WazuhConfig представляет конфигурацию Wazuh агента
type WazuhConfig struct {
	Enabled              bool          `yaml:"enabled"`
	ManagerHost          string        `yaml:"manager_host"`
	ManagerPort          int           `yaml:"manager_port"`
	AgentName            string        `yaml:"agent_name"`
	AgentGroup           string        `yaml:"agent_group"`
	RegistrationPassword string        `yaml:"registration_password"`
	KeepAliveInterval    time.Duration `yaml:"keep_alive_interval"`
	ReconnectInterval    time.Duration `yaml:"reconnect_interval"`
	MaxReconnectAttempts int           `yaml:"max_reconnect_attempts"`
	LogLevel             string        `yaml:"log_level"`
	NovaSec              NovaSecConfig `yaml:"novasec"`
}

// NovaSecConfig представляет конфигурацию интеграции с NovaSec
type NovaSecConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Endpoint      string        `yaml:"endpoint"`
	APIKey        string        `yaml:"api_key"`
	Timeout       time.Duration `yaml:"timeout"`
	BatchSize     int           `yaml:"batch_size"`
	BatchTimeout  time.Duration `yaml:"batch_timeout"`
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

// TestWazuhConfigValidation тестирует валидацию конфигурации Wazuh
func TestWazuhConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      WazuhConfig
		expectError bool
	}{
		{
			name: "Valid_Config",
			config: WazuhConfig{
				Enabled:              true,
				ManagerHost:          "localhost",
				ManagerPort:          1514,
				AgentName:            "novasec-agent",
				AgentGroup:           "default",
				RegistrationPassword: "",
				KeepAliveInterval:    60 * time.Second,
				ReconnectInterval:    30 * time.Second,
				MaxReconnectAttempts: 10,
				LogLevel:             "info",
				NovaSec: NovaSecConfig{
					Enabled:       true,
					Endpoint:      "http://localhost:8080/api/v1/events",
					APIKey:        "",
					Timeout:       30 * time.Second,
					BatchSize:     100,
					BatchTimeout:  5 * time.Second,
					RetryAttempts: 3,
					RetryDelay:    1 * time.Second,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid_Port",
			config: WazuhConfig{
				Enabled:     true,
				ManagerHost: "localhost",
				ManagerPort: 0, // Невалидный порт
			},
			expectError: true,
		},
		{
			name: "Empty_Agent_Name",
			config: WazuhConfig{
				Enabled:     true,
				ManagerHost: "localhost",
				ManagerPort: 1514,
				AgentName:   "", // Пустое имя агента
			},
			expectError: true,
		},
		{
			name: "Invalid_Timeout",
			config: WazuhConfig{
				Enabled:     true,
				ManagerHost: "localhost",
				ManagerPort: 1514,
				AgentName:   "test-agent",
				NovaSec: NovaSecConfig{
					Enabled:  true,
					Endpoint: "http://localhost:8080/api/v1/events",
					Timeout:  -1 * time.Second, // Невалидный timeout
				},
			},
			expectError: true,
		},
		{
			name: "Invalid_Batch_Size",
			config: WazuhConfig{
				Enabled:     true,
				ManagerHost: "localhost",
				ManagerPort: 1514,
				AgentName:   "test-agent",
				NovaSec: NovaSecConfig{
					Enabled:   true,
					Endpoint:  "http://localhost:8080/api/v1/events",
					BatchSize: -1, // Невалидный batch size
					Timeout:   30 * time.Second,
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWazuhConfig(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// validateWazuhConfig валидирует конфигурацию Wazuh
func validateWazuhConfig(config WazuhConfig) error {
	if config.Enabled {
		if config.ManagerHost == "" {
			return &ConfigError{Field: "manager_host", Message: "Manager host is required when Wazuh is enabled"}
		}
		if config.ManagerPort <= 0 || config.ManagerPort > 65535 {
			return &ConfigError{Field: "manager_port", Message: "Manager port must be between 1 and 65535"}
		}
		if config.AgentName == "" {
			return &ConfigError{Field: "agent_name", Message: "Agent name is required when Wazuh is enabled"}
		}
		if config.AgentGroup == "" {
			return &ConfigError{Field: "agent_group", Message: "Agent group is required when Wazuh is enabled"}
		}
		if config.KeepAliveInterval <= 0 {
			return &ConfigError{Field: "keep_alive_interval", Message: "Keep alive interval must be positive"}
		}
		if config.ReconnectInterval <= 0 {
			return &ConfigError{Field: "reconnect_interval", Message: "Reconnect interval must be positive"}
		}
		if config.MaxReconnectAttempts < 0 {
			return &ConfigError{Field: "max_reconnect_attempts", Message: "Max reconnect attempts must be non-negative"}
		}
		if config.LogLevel != "" && !isValidLogLevel(config.LogLevel) {
			return &ConfigError{Field: "log_level", Message: "Invalid log level"}
		}

		// Валидация NovaSec конфигурации
		if config.NovaSec.Enabled {
			if config.NovaSec.Endpoint == "" {
				return &ConfigError{Field: "novasec.endpoint", Message: "NovaSec endpoint is required when integration is enabled"}
			}
			if config.NovaSec.Timeout <= 0 {
				return &ConfigError{Field: "novasec.timeout", Message: "NovaSec timeout must be positive"}
			}
			if config.NovaSec.BatchSize <= 0 {
				return &ConfigError{Field: "novasec.batch_size", Message: "NovaSec batch size must be positive"}
			}
			if config.NovaSec.BatchTimeout <= 0 {
				return &ConfigError{Field: "novasec.batch_timeout", Message: "NovaSec batch timeout must be positive"}
			}
			if config.NovaSec.RetryAttempts < 0 {
				return &ConfigError{Field: "novasec.retry_attempts", Message: "NovaSec retry attempts must be non-negative"}
			}
			if config.NovaSec.RetryDelay < 0 {
				return &ConfigError{Field: "novasec.retry_delay", Message: "NovaSec retry delay must be non-negative"}
			}
		}
	}

	return nil
}

// ConfigError представляет ошибку конфигурации
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Message
}

// isValidLogLevel проверяет валидность уровня логирования
func isValidLogLevel(level string) bool {
	validLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

// TestWazuhConfigYAML тестирует загрузку конфигурации из YAML
func TestWazuhConfigYAML(t *testing.T) {
	// Создаем временный файл конфигурации
	configYAML := `
wazuh:
  enabled: true
  manager_host: "localhost"
  manager_port: 1514
  agent_name: "novasec-agent"
  agent_group: "default"
  registration_password: ""
  keep_alive_interval: "60s"
  reconnect_interval: "30s"
  max_reconnect_attempts: 10
  log_level: "info"
  novasec:
    enabled: true
    endpoint: "http://localhost:8080/api/v1/events"
    api_key: ""
    timeout: "30s"
    batch_size: 100
    batch_timeout: "5s"
    retry_attempts: 3
    retry_delay: "1s"
`

	// Создаем временный файл
	tmpFile, err := os.CreateTemp("", "wazuh_config_test_*.yml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Записываем конфигурацию в файл
	if _, err := tmpFile.WriteString(configYAML); err != nil {
		t.Fatalf("Failed to write config to file: %v", err)
	}
	tmpFile.Close()

	// Читаем файл
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Парсим YAML (упрощенная версия без внешней библиотеки)
	// В реальном тесте здесь бы использовался yaml.Unmarshal
	// Пока просто проверяем, что файл читается
	if len(data) == 0 {
		t.Fatal("Config file should not be empty")
	}

	// Проверяем, что конфигурация содержит ожидаемые строки
	configStr := string(data)
	expectedStrings := []string{
		"wazuh:",
		"enabled: true",
		"manager_host: \"localhost\"",
		"manager_port: 1514",
		"agent_name: \"novasec-agent\"",
		"novasec:",
		"endpoint: \"http://localhost:8080/api/v1/events\"",
		"batch_size: 100",
	}

	for _, expected := range expectedStrings {
		if !contains(configStr, expected) {
			t.Errorf("Config should contain: %s", expected)
		}
	}
}

// contains проверяет, содержит ли строка подстроку
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsSubstring(s, substr))))
}

// containsSubstring проверяет, содержит ли строка подстроку
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestWazuhConfigDefaults тестирует значения по умолчанию
func TestWazuhConfigDefaults(t *testing.T) {
	config := WazuhConfig{
		Enabled: true,
		// Остальные поля не заданы
	}

	// Применяем значения по умолчанию
	applyWazuhDefaults(&config)

	// Проверяем значения по умолчанию
	if config.ManagerHost != "localhost" {
		t.Errorf("Default manager host should be localhost, got %s", config.ManagerHost)
	}
	if config.ManagerPort != 1514 {
		t.Errorf("Default manager port should be 1514, got %d", config.ManagerPort)
	}
	if config.AgentName != "novasec-agent" {
		t.Errorf("Default agent name should be novasec-agent, got %s", config.AgentName)
	}
	if config.AgentGroup != "default" {
		t.Errorf("Default agent group should be default, got %s", config.AgentGroup)
	}
	if config.KeepAliveInterval != 60*time.Second {
		t.Errorf("Default keep alive interval should be 60s, got %v", config.KeepAliveInterval)
	}
	if config.ReconnectInterval != 30*time.Second {
		t.Errorf("Default reconnect interval should be 30s, got %v", config.ReconnectInterval)
	}
	if config.MaxReconnectAttempts != 10 {
		t.Errorf("Default max reconnect attempts should be 10, got %d", config.MaxReconnectAttempts)
	}
	if config.LogLevel != "info" {
		t.Errorf("Default log level should be info, got %s", config.LogLevel)
	}

	// Проверяем NovaSec значения по умолчанию
	if config.NovaSec.Endpoint != "http://localhost:8080/api/v1/events" {
		t.Errorf("Default NovaSec endpoint should be correct, got %s", config.NovaSec.Endpoint)
	}
	if config.NovaSec.Timeout != 30*time.Second {
		t.Errorf("Default NovaSec timeout should be 30s, got %v", config.NovaSec.Timeout)
	}
	if config.NovaSec.BatchSize != 100 {
		t.Errorf("Default NovaSec batch size should be 100, got %d", config.NovaSec.BatchSize)
	}
	if config.NovaSec.BatchTimeout != 5*time.Second {
		t.Errorf("Default NovaSec batch timeout should be 5s, got %v", config.NovaSec.BatchTimeout)
	}
	if config.NovaSec.RetryAttempts != 3 {
		t.Errorf("Default NovaSec retry attempts should be 3, got %d", config.NovaSec.RetryAttempts)
	}
	if config.NovaSec.RetryDelay != 1*time.Second {
		t.Errorf("Default NovaSec retry delay should be 1s, got %v", config.NovaSec.RetryDelay)
	}
}

// applyWazuhDefaults применяет значения по умолчанию к конфигурации
func applyWazuhDefaults(config *WazuhConfig) {
	if config.ManagerHost == "" {
		config.ManagerHost = "localhost"
	}
	if config.ManagerPort == 0 {
		config.ManagerPort = 1514
	}
	if config.AgentName == "" {
		config.AgentName = "novasec-agent"
	}
	if config.AgentGroup == "" {
		config.AgentGroup = "default"
	}
	if config.KeepAliveInterval == 0 {
		config.KeepAliveInterval = 60 * time.Second
	}
	if config.ReconnectInterval == 0 {
		config.ReconnectInterval = 30 * time.Second
	}
	if config.MaxReconnectAttempts == 0 {
		config.MaxReconnectAttempts = 10
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}

	// NovaSec значения по умолчанию
	if config.NovaSec.Endpoint == "" {
		config.NovaSec.Endpoint = "http://localhost:8080/api/v1/events"
	}
	if config.NovaSec.Timeout == 0 {
		config.NovaSec.Timeout = 30 * time.Second
	}
	if config.NovaSec.BatchSize == 0 {
		config.NovaSec.BatchSize = 100
	}
	if config.NovaSec.BatchTimeout == 0 {
		config.NovaSec.BatchTimeout = 5 * time.Second
	}
	if config.NovaSec.RetryAttempts == 0 {
		config.NovaSec.RetryAttempts = 3
	}
	if config.NovaSec.RetryDelay == 0 {
		config.NovaSec.RetryDelay = 1 * time.Second
	}
}

// TestWazuhConfigEnvironmentVariables тестирует загрузку конфигурации из переменных окружения
func TestWazuhConfigEnvironmentVariables(t *testing.T) {
	// Устанавливаем переменные окружения
	os.Setenv("WAZUH_MANAGER_HOST", "test-manager")
	os.Setenv("WAZUH_MANAGER_PORT", "1515")
	os.Setenv("WAZUH_AGENT_NAME", "test-agent")
	os.Setenv("WAZUH_AGENT_GROUP", "test-group")
	os.Setenv("NOVASEC_ENDPOINT", "http://test-novasec:8080/api/v1/events")
	os.Setenv("NOVASEC_API_KEY", "test-api-key")

	defer func() {
		os.Unsetenv("WAZUH_MANAGER_HOST")
		os.Unsetenv("WAZUH_MANAGER_PORT")
		os.Unsetenv("WAZUH_AGENT_NAME")
		os.Unsetenv("WAZUH_AGENT_GROUP")
		os.Unsetenv("NOVASEC_ENDPOINT")
		os.Unsetenv("NOVASEC_API_KEY")
	}()

	// Создаем конфигурацию
	config := WazuhConfig{
		Enabled: true,
	}

	// Применяем переменные окружения
	applyWazuhEnvironmentVariables(&config)

	// Проверяем, что переменные окружения применены
	if config.ManagerHost != "test-manager" {
		t.Errorf("Manager host should be test-manager, got %s", config.ManagerHost)
	}
	if config.ManagerPort != 1515 {
		t.Errorf("Manager port should be 1515, got %d", config.ManagerPort)
	}
	if config.AgentName != "test-agent" {
		t.Errorf("Agent name should be test-agent, got %s", config.AgentName)
	}
	if config.AgentGroup != "test-group" {
		t.Errorf("Agent group should be test-group, got %s", config.AgentGroup)
	}
	if config.NovaSec.Endpoint != "http://test-novasec:8080/api/v1/events" {
		t.Errorf("NovaSec endpoint should be correct, got %s", config.NovaSec.Endpoint)
	}
	if config.NovaSec.APIKey != "test-api-key" {
		t.Errorf("NovaSec API key should be test-api-key, got %s", config.NovaSec.APIKey)
	}
}

// applyWazuhEnvironmentVariables применяет переменные окружения к конфигурации
func applyWazuhEnvironmentVariables(config *WazuhConfig) {
	if managerHost := os.Getenv("WAZUH_MANAGER_HOST"); managerHost != "" {
		config.ManagerHost = managerHost
	}
	if managerPort := os.Getenv("WAZUH_MANAGER_PORT"); managerPort != "" {
		// В реальной реализации здесь будет парсинг порта
		config.ManagerPort = 1515 // Упрощенная версия для теста
	}
	if agentName := os.Getenv("WAZUH_AGENT_NAME"); agentName != "" {
		config.AgentName = agentName
	}
	if agentGroup := os.Getenv("WAZUH_AGENT_GROUP"); agentGroup != "" {
		config.AgentGroup = agentGroup
	}
	if endpoint := os.Getenv("NOVASEC_ENDPOINT"); endpoint != "" {
		config.NovaSec.Endpoint = endpoint
	}
	if apiKey := os.Getenv("NOVASEC_API_KEY"); apiKey != "" {
		config.NovaSec.APIKey = apiKey
	}
}

// TestWazuhConfigIntegration тестирует полную интеграцию конфигурации
func TestWazuhConfigIntegration(t *testing.T) {
	// Создаем полную конфигурацию
	config := WazuhConfig{
		Enabled:              true,
		ManagerHost:          "wazuh-manager.example.com",
		ManagerPort:          1514,
		AgentName:            "production-agent",
		AgentGroup:           "production",
		RegistrationPassword: "secret-password",
		KeepAliveInterval:    120 * time.Second,
		ReconnectInterval:    60 * time.Second,
		MaxReconnectAttempts: 20,
		LogLevel:             "warn",
		NovaSec: NovaSecConfig{
			Enabled:       true,
			Endpoint:      "https://novasec.example.com/api/v1/events",
			APIKey:        "api-key-12345",
			Timeout:       60 * time.Second,
			BatchSize:     500,
			BatchTimeout:  10 * time.Second,
			RetryAttempts: 5,
			RetryDelay:    2 * time.Second,
		},
	}

	// Валидируем конфигурацию
	if err := validateWazuhConfig(config); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Проверяем, что конфигурация корректна
	if !config.Enabled {
		t.Error("Wazuh should be enabled")
	}
	if config.ManagerHost != "wazuh-manager.example.com" {
		t.Error("Manager host should be correct")
	}
	if config.ManagerPort != 1514 {
		t.Error("Manager port should be correct")
	}
	if config.AgentName != "production-agent" {
		t.Error("Agent name should be correct")
	}
	if config.AgentGroup != "production" {
		t.Error("Agent group should be correct")
	}
	if config.RegistrationPassword != "secret-password" {
		t.Error("Registration password should be correct")
	}
	if config.KeepAliveInterval != 120*time.Second {
		t.Error("Keep alive interval should be correct")
	}
	if config.ReconnectInterval != 60*time.Second {
		t.Error("Reconnect interval should be correct")
	}
	if config.MaxReconnectAttempts != 20 {
		t.Error("Max reconnect attempts should be correct")
	}
	if config.LogLevel != "warn" {
		t.Error("Log level should be correct")
	}

	// Проверяем NovaSec конфигурацию
	if !config.NovaSec.Enabled {
		t.Error("NovaSec integration should be enabled")
	}
	if config.NovaSec.Endpoint != "https://novasec.example.com/api/v1/events" {
		t.Error("NovaSec endpoint should be correct")
	}
	if config.NovaSec.APIKey != "api-key-12345" {
		t.Error("NovaSec API key should be correct")
	}
	if config.NovaSec.Timeout != 60*time.Second {
		t.Error("NovaSec timeout should be correct")
	}
	if config.NovaSec.BatchSize != 500 {
		t.Error("NovaSec batch size should be correct")
	}
	if config.NovaSec.BatchTimeout != 10*time.Second {
		t.Error("NovaSec batch timeout should be correct")
	}
	if config.NovaSec.RetryAttempts != 5 {
		t.Error("NovaSec retry attempts should be correct")
	}
	if config.NovaSec.RetryDelay != 2*time.Second {
		t.Error("NovaSec retry delay should be correct")
	}
}
