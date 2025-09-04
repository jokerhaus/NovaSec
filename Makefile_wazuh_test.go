// filename: Makefile_wazuh_test.go
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWazuhMakefileCommands тестирует команды Makefile для Wazuh
func TestWazuhMakefileCommands(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем команды Wazuh
	wazuhCommands := []string{
		"wazuh-build:",
		"wazuh-start:",
		"wazuh-stop:",
		"wazuh-restart:",
		"wazuh-status:",
		"wazuh-test:",
		"wazuh-send-test:",
		"logs-wazuh:",
	}

	for _, command := range wazuhCommands {
		if !strings.Contains(makefileContent, command) {
			t.Errorf("Makefile should contain command: %s", command)
		}
	}

	// Проверяем описания команд
	commandDescriptions := []string{
		"## Собрать Docker образ Wazuh агента",
		"## Запустить Wazuh агент",
		"## Остановить Wazuh агент",
		"## Перезапустить Wazuh агент",
		"## Показать статус Wazuh агента",
		"## Тестировать парсер Wazuh",
		"## Отправить тестовое событие Wazuh",
		"## Показать логи Wazuh агента",
	}

	for _, description := range commandDescriptions {
		if !strings.Contains(makefileContent, description) {
			t.Errorf("Makefile should contain description: %s", description)
		}
	}
}

// TestWazuhMakefileHelp тестирует справку Makefile
func TestWazuhMakefileHelp(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем, что команды Wazuh включены в справку
	helpSection := "Доступные цели:"
	if !strings.Contains(makefileContent, helpSection) {
		t.Error("Makefile should contain help section")
	}

	// Проверяем, что команды Wazuh упоминаются в справке
	wazuhHelpCommands := []string{
		"wazuh-build",
		"wazuh-start",
		"wazuh-stop",
		"wazuh-restart",
		"wazuh-status",
		"wazuh-test",
		"wazuh-send-test",
		"logs-wazuh",
	}

	for _, command := range wazuhHelpCommands {
		if !strings.Contains(makefileContent, command) {
			t.Errorf("Makefile help should mention command: %s", command)
		}
	}
}

// TestWazuhMakefileDockerCommands тестирует Docker команды в Makefile
func TestWazuhMakefileDockerCommands(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем Docker команды для Wazuh
	dockerCommands := []string{
		"docker build -f docker/Dockerfile.wazuh-agent -t novasec-wazuh-agent .",
		"docker-compose -f $(DOCKER_COMPOSE) up -d wazuh-agent",
		"docker-compose -f $(DOCKER_COMPOSE) stop wazuh-agent",
		"docker-compose -f $(DOCKER_COMPOSE) restart wazuh-agent",
		"docker-compose -f $(DOCKER_COMPOSE) ps wazuh-agent",
		"docker-compose -f $(DOCKER_COMPOSE) logs -f wazuh-agent",
	}

	for _, command := range dockerCommands {
		if !strings.Contains(makefileContent, command) {
			t.Errorf("Makefile should contain Docker command: %s", command)
		}
	}
}

// TestWazuhMakefileTestCommands тестирует тестовые команды в Makefile
func TestWazuhMakefileTestCommands(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем тестовые команды
	testCommands := []string{
		"go test -v ./internal/normalizer/parsers/ -run TestWazuhParser",
		"curl -X POST http://localhost:8080/api/v1/events",
		"-H \"Content-Type: application/json\"",
		"-d @internal/fixtures/wazuh_sample_events.jsonl",
	}

	for _, command := range testCommands {
		if !strings.Contains(makefileContent, command) {
			t.Errorf("Makefile should contain test command: %s", command)
		}
	}
}

// TestWazuhMakefileVariables тестирует переменные в Makefile
func TestWazuhMakefileVariables(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем переменные
	requiredVariables := []string{
		"DOCKER_COMPOSE = docker/docker-compose.yml",
		"BINARY_DIR = bin",
		"VERSION = 1.0.0",
	}

	for _, variable := range requiredVariables {
		if !strings.Contains(makefileContent, variable) {
			t.Errorf("Makefile should define variable: %s", variable)
		}
	}
}

// TestWazuhMakefileLogging тестирует логирование в Makefile
func TestWazuhMakefileLogging(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем функции логирования
	loggingFunctions := []string{
		"log_info",
		"log_success",
		"log_warning",
		"log_error",
	}

	for _, function := range loggingFunctions {
		if !strings.Contains(makefileContent, function) {
			t.Errorf("Makefile should define logging function: %s", function)
		}
	}

	// Проверяем использование логирования в командах Wazuh
	wazuhLoggingUsage := []string{
		"$(call log_info,\"Собираем Docker образ Wazuh агента...\")",
		"$(call log_success,\"Docker образ Wazuh агента собран\")",
		"$(call log_info,\"Запускаем Wazuh агент...\")",
		"$(call log_success,\"Wazuh агент запущен\")",
	}

	for _, usage := range wazuhLoggingUsage {
		if !strings.Contains(makefileContent, usage) {
			t.Errorf("Makefile should use logging in Wazuh commands: %s", usage)
		}
	}
}

// TestWazuhMakefileIntegration тестирует интеграцию команд Wazuh с основными командами
func TestWazuhMakefileIntegration(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем, что команды Wazuh интегрированы с основными командами
	integrationChecks := []string{
		"logs-wazuh:",  // Должна быть в списке команд логирования
		"wazuh-build:", // Должна быть в списке команд сборки
		"wazuh-test:",  // Должна быть в списке тестовых команд
	}

	for _, check := range integrationChecks {
		if !strings.Contains(makefileContent, check) {
			t.Errorf("Makefile should integrate Wazuh command: %s", check)
		}
	}
}

// TestWazuhMakefileDependencies тестирует зависимости команд Wazuh
func TestWazuhMakefileDependencies(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем зависимости команд
	dependencyChecks := []string{
		"wazuh-build: ## Собрать Docker образ Wazuh агента",
		"wazuh-start: ## Запустить Wazuh агент",
		"wazuh-stop: ## Остановить Wazuh агент",
		"wazuh-restart: ## Перезапустить Wazuh агент",
		"wazuh-status: ## Показать статус Wazuh агента",
		"wazuh-test: ## Тестировать парсер Wazuh",
		"wazuh-send-test: ## Отправить тестовое событие Wazuh",
		"logs-wazuh: ## Показать логи Wazuh агента",
	}

	for _, check := range dependencyChecks {
		if !strings.Contains(makefileContent, check) {
			t.Errorf("Makefile should have proper command definition: %s", check)
		}
	}
}

// TestWazuhMakefileExecution тестирует выполнение команд Makefile (симуляция)
func TestWazuhMakefileExecution(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Проверяем, что make может прочитать Makefile
	cmd := exec.Command("make", "help")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to execute make help: %v", err)
	}

	outputStr := string(output)

	// Проверяем, что команды Wazuh присутствуют в выводе справки
	wazuhCommands := []string{
		"wazuh-build",
		"wazuh-start",
		"wazuh-stop",
		"wazuh-restart",
		"wazuh-status",
		"wazuh-test",
		"wazuh-send-test",
		"logs-wazuh",
	}

	for _, command := range wazuhCommands {
		if !strings.Contains(outputStr, command) {
			t.Errorf("Make help should show Wazuh command: %s", command)
		}
	}
}

// TestWazuhMakefileSyntax тестирует синтаксис Makefile
func TestWazuhMakefileSyntax(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Проверяем синтаксис Makefile
	cmd := exec.Command("make", "-n", "wazuh-build")
	err := cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-build: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-start")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-start: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-stop")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-stop: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-restart")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-restart: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-status")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-status: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-test")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-test: %v", err)
	}

	cmd = exec.Command("make", "-n", "wazuh-send-test")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in wazuh-send-test: %v", err)
	}

	cmd = exec.Command("make", "-n", "logs-wazuh")
	err = cmd.Run()
	if err != nil {
		t.Errorf("Makefile syntax error in logs-wazuh: %v", err)
	}
}

// TestWazuhMakefileCompleteness тестирует полноту команд Wazuh
func TestWazuhMakefileCompleteness(t *testing.T) {
	// Проверяем, что Makefile существует
	if _, err := os.Stat("Makefile"); os.IsNotExist(err) {
		t.Fatal("Makefile not found")
	}

	// Читаем содержимое Makefile
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("Failed to read Makefile: %v", err)
	}

	makefileContent := string(content)

	// Проверяем, что все необходимые команды присутствуют
	requiredCommands := map[string]string{
		"wazuh-build":     "Собрать Docker образ Wazuh агента",
		"wazuh-start":     "Запустить Wazuh агент",
		"wazuh-stop":      "Остановить Wazuh агент",
		"wazuh-restart":   "Перезапустить Wazuh агент",
		"wazuh-status":    "Показать статус Wazuh агента",
		"wazuh-test":      "Тестировать парсер Wazuh",
		"wazuh-send-test": "Отправить тестовое событие Wazuh",
		"logs-wazuh":      "Показать логи Wazuh агента",
	}

	for command, description := range requiredCommands {
		// Проверяем, что команда определена
		if !strings.Contains(makefileContent, command+":") {
			t.Errorf("Makefile should define command: %s", command)
		}

		// Проверяем, что команда имеет описание
		if !strings.Contains(makefileContent, "## "+description) {
			t.Errorf("Makefile should have description for command %s: %s", command, description)
		}
	}
}
