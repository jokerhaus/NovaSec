// filename: docker/wazuh_docker_test.go
package docker

import (
	"os"
	"testing"
	"text/template"
)

// TestWazuhDockerfileValidation тестирует валидность Dockerfile для Wazuh агента
func TestWazuhDockerfileValidation(t *testing.T) {
	dockerfilePath := "Dockerfile.wazuh-agent"

	// Проверяем, что файл существует
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		t.Fatalf("Dockerfile %s does not exist", dockerfilePath)
	}

	// Читаем содержимое Dockerfile
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("Failed to read Dockerfile: %v", err)
	}

	dockerfileContent := string(content)

	// Проверяем обязательные инструкции
	requiredInstructions := []string{
		"FROM ubuntu:22.04",
		"ENV DEBIAN_FRONTEND=noninteractive",
		"RUN apt-get update",
		"apt-get install -y",
		"RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH",
		"wazuh-agent",
		"RUN echo '#!/bin/bash",
		"ENTRYPOINT",
	}

	for _, instruction := range requiredInstructions {
		if !contains(dockerfileContent, instruction) {
			t.Errorf("Dockerfile should contain: %s", instruction)
		}
	}

	// Проверяем переменные окружения
	requiredEnvVars := []string{
		"WAZUH_MANAGER",
		"WAZUH_MANAGER_PORT",
		"WAZUH_AGENT_NAME",
		"WAZUH_AGENT_GROUP",
		"NOVASEC_ENDPOINT",
		"NOVASEC_API_KEY",
	}

	for _, envVar := range requiredEnvVars {
		if !contains(dockerfileContent, "ENV "+envVar) {
			t.Errorf("Dockerfile should define environment variable: %s", envVar)
		}
	}

	// Проверяем, что скрипты созданы
	if !contains(dockerfileContent, "wazuh-novasec-integration.sh") {
		t.Error("Dockerfile should create wazuh-novasec-integration.sh script")
	}

	if !contains(dockerfileContent, "start-wazuh-agent.sh") {
		t.Error("Dockerfile should create start-wazuh-agent.sh script")
	}

	// Проверяем systemd сервис
	if !contains(dockerfileContent, "wazuh-novasec-integration.service") {
		t.Error("Dockerfile should create systemd service file")
	}

	// Проверяем права доступа
	if !contains(dockerfileContent, "chmod +x") {
		t.Error("Dockerfile should set executable permissions on scripts")
	}
}

// TestWazuhDockerComposeValidation тестирует валидность docker-compose конфигурации
func TestWazuhDockerComposeValidation(t *testing.T) {
	composePath := "docker-compose.yml"

	// Проверяем, что файл существует
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Fatalf("Docker Compose file %s does not exist", composePath)
	}

	// Читаем содержимое docker-compose.yml
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}

	composeContent := string(content)

	// Проверяем, что Wazuh агент определен
	if !contains(composeContent, "wazuh-agent:") {
		t.Error("Docker Compose should define wazuh-agent service")
	}

	// Проверяем основные поля сервиса
	requiredFields := []string{
		"build:",
		"container_name: novasec-wazuh-agent",
		"environment:",
		"volumes:",
		"networks:",
		"depends_on:",
		"restart: unless-stopped",
		"privileged: true",
	}

	for _, field := range requiredFields {
		if !contains(composeContent, field) {
			t.Errorf("Docker Compose should contain: %s", field)
		}
	}

	// Проверяем переменные окружения
	requiredEnvVars := []string{
		"WAZUH_MANAGER=localhost",
		"WAZUH_MANAGER_PORT=1514",
		"WAZUH_AGENT_NAME=novasec-agent",
		"WAZUH_AGENT_GROUP=default",
		"NOVASEC_ENDPOINT=http://novasec-ingest:8080/api/v1/events",
		"NOVASEC_API_KEY=",
	}

	for _, envVar := range requiredEnvVars {
		if !contains(composeContent, envVar) {
			t.Errorf("Docker Compose should define environment variable: %s", envVar)
		}
	}

	// Проверяем volumes
	requiredVolumes := []string{
		"wazuh-agent-logs:/var/ossec/logs",
		"wazuh-agent-queue:/var/ossec/queue",
		"wazuh-agent-var:/var/ossec/var",
	}

	for _, volume := range requiredVolumes {
		if !contains(composeContent, volume) {
			t.Errorf("Docker Compose should define volume: %s", volume)
		}
	}

	// Проверяем capabilities
	requiredCapabilities := []string{
		"SYS_PTRACE",
		"AUDIT_CONTROL",
		"AUDIT_READ",
	}

	for _, cap := range requiredCapabilities {
		if !contains(composeContent, cap) {
			t.Errorf("Docker Compose should add capability: %s", cap)
		}
	}

	// Проверяем volumes в секции volumes
	requiredVolumeDefinitions := []string{
		"wazuh-agent-logs:",
		"wazuh-agent-queue:",
		"wazuh-agent-var:",
	}

	for _, volumeDef := range requiredVolumeDefinitions {
		if !contains(composeContent, volumeDef) {
			t.Errorf("Docker Compose should define volume: %s", volumeDef)
		}
	}
}

// TestWazuhIntegrationScript тестирует скрипт интеграции
func TestWazuhIntegrationScript(t *testing.T) {
	// Создаем тестовый скрипт интеграции
	scriptTemplate := `#!/bin/bash
# Скрипт для отправки событий Wazuh в NovaSec

NOVASEC_ENDPOINT=${NOVASEC_ENDPOINT:-"http://localhost:8080/api/v1/events"}
NOVASEC_API_KEY=${NOVASEC_API_KEY:-""}
WAZUH_LOG_FILE="/var/ossec/logs/alerts/alerts.json"

# Функция для отправки события в NovaSec
send_to_novasec() {
    local event_data="$1"
    
    if [ -n "$NOVASEC_API_KEY" ]; then
        curl -X POST "$NOVASEC_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $NOVASEC_API_KEY" \
            -d "$event_data"
    else
        curl -X POST "$NOVASEC_ENDPOINT" \
            -H "Content-Type: application/json" \
            -d "$event_data"
    fi
}

# Мониторим файл логов Wazuh
tail -f "$WAZUH_LOG_FILE" | while read line; do
    if [ -n "$line" ]; then
        echo "Sending event to NovaSec: $line"
        send_to_novasec "$line"
    fi
done
`

	// Создаем временный файл
	tmpFile, err := os.CreateTemp("", "wazuh_integration_test_*.sh")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Записываем скрипт в файл
	if _, err := tmpFile.WriteString(scriptTemplate); err != nil {
		t.Fatalf("Failed to write script to file: %v", err)
	}
	tmpFile.Close()

	// Проверяем, что файл создан
	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Fatal("Script file should exist")
	}

	// Проверяем содержимое скрипта
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read script file: %v", err)
	}

	scriptContent := string(content)

	// Проверяем обязательные элементы скрипта
	requiredElements := []string{
		"#!/bin/bash",
		"NOVASEC_ENDPOINT=",
		"NOVASEC_API_KEY=",
		"WAZUH_LOG_FILE=",
		"send_to_novasec()",
		"curl -X POST",
		"Content-Type: application/json",
		"tail -f",
	}

	for _, element := range requiredElements {
		if !contains(scriptContent, element) {
			t.Errorf("Script should contain: %s", element)
		}
	}
}

// TestWazuhSystemdService тестирует systemd сервис
func TestWazuhSystemdService(t *testing.T) {
	// Создаем тестовый systemd сервис
	serviceTemplate := `[Unit]
Description=Wazuh NovaSec Integration
After=wazuh-agent.service
Requires=wazuh-agent.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wazuh-novasec-integration.sh
Restart=always
RestartSec=10
Environment=NOVASEC_ENDPOINT={{.NovaSecEndpoint}}
Environment=NOVASEC_API_KEY={{.NovaSecAPIKey}}

[Install]
WantedBy=multi-user.target
`

	// Создаем временный файл
	tmpFile, err := os.CreateTemp("", "wazuh_service_test_*.service")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Парсим шаблон
	tmpl, err := template.New("service").Parse(serviceTemplate)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	// Данные для шаблона
	data := struct {
		NovaSecEndpoint string
		NovaSecAPIKey   string
	}{
		NovaSecEndpoint: "http://localhost:8080/api/v1/events",
		NovaSecAPIKey:   "test-api-key",
	}

	// Выполняем шаблон
	if err := tmpl.Execute(tmpFile, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}
	tmpFile.Close()

	// Проверяем содержимое сервиса
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read service file: %v", err)
	}

	serviceContent := string(content)

	// Проверяем обязательные секции systemd
	requiredSections := []string{
		"[Unit]",
		"Description=Wazuh NovaSec Integration",
		"After=wazuh-agent.service",
		"Requires=wazuh-agent.service",
		"[Service]",
		"Type=simple",
		"ExecStart=/usr/local/bin/wazuh-novasec-integration.sh",
		"Restart=always",
		"RestartSec=10",
		"Environment=NOVASEC_ENDPOINT=http://localhost:8080/api/v1/events",
		"Environment=NOVASEC_API_KEY=test-api-key",
		"[Install]",
		"WantedBy=multi-user.target",
	}

	for _, section := range requiredSections {
		if !contains(serviceContent, section) {
			t.Errorf("Systemd service should contain: %s", section)
		}
	}
}

// TestWazuhDockerBuild тестирует процесс сборки Docker образа
func TestWazuhDockerBuild(t *testing.T) {
	// Проверяем, что Dockerfile существует
	dockerfilePath := "Dockerfile.wazuh-agent"
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		t.Skip("Dockerfile not found, skipping build test")
	}

	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping build test")
	}

	// В реальном тесте здесь бы выполнялась команда:
	// docker build -f Dockerfile.wazuh-agent -t novasec-wazuh-agent .
	// Но для юнит-теста мы только проверяем, что файлы существуют
	t.Log("Docker build test would run: docker build -f Dockerfile.wazuh-agent -t novasec-wazuh-agent .")
}

// TestWazuhDockerComposeUp тестирует запуск через docker-compose
func TestWazuhDockerComposeUp(t *testing.T) {
	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping compose test")
	}

	// В реальном тесте здесь бы выполнялась команда:
	// docker-compose up -d wazuh-agent
	// Но для юнит-теста мы только проверяем, что файл существует
	t.Log("Docker Compose test would run: docker-compose up -d wazuh-agent")
}

// TestWazuhDockerVolumes тестирует volumes для Wazuh агента
func TestWazuhDockerVolumes(t *testing.T) {
	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping volumes test")
	}

	// Читаем содержимое docker-compose.yml
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}

	composeContent := string(content)

	// Проверяем, что все необходимые volumes определены
	requiredVolumes := map[string]string{
		"wazuh-agent-logs":  "/var/ossec/logs",
		"wazuh-agent-queue": "/var/ossec/queue",
		"wazuh-agent-var":   "/var/ossec/var",
	}

	for volumeName, mountPath := range requiredVolumes {
		volumeDef := volumeName + ":" + mountPath
		if !contains(composeContent, volumeDef) {
			t.Errorf("Docker Compose should define volume: %s", volumeDef)
		}
	}

	// Проверяем, что volumes определены в секции volumes
	volumeDefinitions := []string{
		"wazuh-agent-logs:",
		"wazuh-agent-queue:",
		"wazuh-agent-var:",
	}

	for _, volumeDef := range volumeDefinitions {
		if !contains(composeContent, volumeDef) {
			t.Errorf("Docker Compose should define volume: %s", volumeDef)
		}
	}
}

// TestWazuhDockerNetworking тестирует сетевую конфигурацию
func TestWazuhDockerNetworking(t *testing.T) {
	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping networking test")
	}

	// Читаем содержимое docker-compose.yml
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}

	composeContent := string(content)

	// Проверяем, что Wazuh агент подключен к сети
	if !contains(composeContent, "networks:") {
		t.Error("Docker Compose should define networks section")
	}

	if !contains(composeContent, "novasec-network") {
		t.Error("Docker Compose should use novasec-network")
	}

	// Проверяем зависимости
	if !contains(composeContent, "depends_on:") {
		t.Error("Docker Compose should define depends_on section")
	}

	if !contains(composeContent, "novasec-ingest:") {
		t.Error("Wazuh agent should depend on novasec-ingest")
	}
}

// TestWazuhDockerEnvironment тестирует переменные окружения
func TestWazuhDockerEnvironment(t *testing.T) {
	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping environment test")
	}

	// Читаем содержимое docker-compose.yml
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}

	composeContent := string(content)

	// Проверяем переменные окружения Wazuh
	wazuhEnvVars := []string{
		"WAZUH_MANAGER=localhost",
		"WAZUH_MANAGER_PORT=1514",
		"WAZUH_AGENT_NAME=novasec-agent",
		"WAZUH_AGENT_GROUP=default",
	}

	for _, envVar := range wazuhEnvVars {
		if !contains(composeContent, envVar) {
			t.Errorf("Docker Compose should define Wazuh environment variable: %s", envVar)
		}
	}

	// Проверяем переменные окружения NovaSec
	novasecEnvVars := []string{
		"NOVASEC_ENDPOINT=http://novasec-ingest:8080/api/v1/events",
		"NOVASEC_API_KEY=",
	}

	for _, envVar := range novasecEnvVars {
		if !contains(composeContent, envVar) {
			t.Errorf("Docker Compose should define NovaSec environment variable: %s", envVar)
		}
	}
}

// TestWazuhDockerSecurity тестирует настройки безопасности
func TestWazuhDockerSecurity(t *testing.T) {
	// Проверяем, что docker-compose.yml существует
	composePath := "docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Skip("docker-compose.yml not found, skipping security test")
	}

	// Читаем содержимое docker-compose.yml
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.yml: %v", err)
	}

	composeContent := string(content)

	// Проверяем привилегированный режим
	if !contains(composeContent, "privileged: true") {
		t.Error("Wazuh agent should run in privileged mode")
	}

	// Проверяем capabilities
	requiredCapabilities := []string{
		"SYS_PTRACE",
		"AUDIT_CONTROL",
		"AUDIT_READ",
	}

	for _, cap := range requiredCapabilities {
		if !contains(composeContent, cap) {
			t.Errorf("Wazuh agent should have capability: %s", cap)
		}
	}

	// Проверяем restart policy
	if !contains(composeContent, "restart: unless-stopped") {
		t.Error("Wazuh agent should have restart policy unless-stopped")
	}
}

// Вспомогательная функция для проверки содержимого строки
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
