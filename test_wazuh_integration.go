// filename: test_wazuh_integration.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestWazuhIntegrationAll запускает все тесты интеграции Wazuh
func TestWazuhIntegrationAll(t *testing.T) {
	// Получаем текущую директорию
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Тестируем парсер Wazuh
	t.Run("Parser_Tests", func(t *testing.T) {
		cmd := exec.Command("go", "test", "-v", "./internal/normalizer/parsers/", "-run", "TestWazuh")
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Parser tests failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Parser tests passed\nOutput: %s", string(output))
		}
	})

	// Тестируем конфигурацию
	t.Run("Config_Tests", func(t *testing.T) {
		cmd := exec.Command("go", "test", "-v", "./configs/", "-run", "TestWazuh")
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Config tests failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Config tests passed\nOutput: %s", string(output))
		}
	})

	// Тестируем Docker конфигурацию
	t.Run("Docker_Tests", func(t *testing.T) {
		cmd := exec.Command("go", "test", "-v", "./docker/", "-run", "TestWazuh")
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Docker tests failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Docker tests passed\nOutput: %s", string(output))
		}
	})

	// Тестируем Makefile
	t.Run("Makefile_Tests", func(t *testing.T) {
		cmd := exec.Command("go", "test", "-v", ".", "-run", "TestWazuhMakefile")
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Makefile tests failed: %v\nOutput: %s", err, string(output))
		} else {
			t.Logf("Makefile tests passed\nOutput: %s", string(output))
		}
	})
}

// TestWazuhIntegrationFiles проверяет наличие всех необходимых файлов
func TestWazuhIntegrationFiles(t *testing.T) {
	requiredFiles := []string{
		"internal/normalizer/parsers/wazuh.go",
		"internal/normalizer/parsers/wazuh_test.go",
		"internal/normalizer/parsers/wazuh_integration_test.go",
		"internal/normalizer/parsers/wazuh_complete_integration_test.go",
		"configs/wazuh_config_test.go",
		"docker/wazuh_docker_test.go",
		"docker/Dockerfile.wazuh-agent",
		"docker/docker-compose.yml",
		"internal/fixtures/wazuh_sample_events.jsonl",
		"docs/WAZUH_INTEGRATION.md",
		"Makefile",
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Errorf("Required file not found: %s", file)
		} else {
			t.Logf("✓ Found: %s", file)
		}
	}
}

// TestWazuhIntegrationCommands проверяет команды Makefile
func TestWazuhIntegrationCommands(t *testing.T) {
	// Получаем текущую директорию
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Проверяем команды Makefile
	commands := []string{
		"wazuh-build",
		"wazuh-start",
		"wazuh-stop",
		"wazuh-restart",
		"wazuh-status",
		"wazuh-test",
		"wazuh-send-test",
		"logs-wazuh",
	}

	for _, cmd := range commands {
		t.Run(fmt.Sprintf("Makefile_Command_%s", cmd), func(t *testing.T) {
			// Проверяем, что команда существует в Makefile
			makeCmd := exec.Command("make", "-n", cmd)
			makeCmd.Dir = dir
			err := makeCmd.Run()
			if err != nil {
				t.Errorf("Makefile command '%s' failed: %v", cmd, err)
			} else {
				t.Logf("✓ Makefile command '%s' is valid", cmd)
			}
		})
	}
}

// TestWazuhIntegrationDocker проверяет Docker конфигурацию
func TestWazuhIntegrationDocker(t *testing.T) {
	// Проверяем Dockerfile
	dockerfilePath := "docker/Dockerfile.wazuh-agent"
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		t.Errorf("Dockerfile not found: %s", dockerfilePath)
	} else {
		t.Logf("✓ Dockerfile found: %s", dockerfilePath)
	}

	// Проверяем docker-compose.yml
	composePath := "docker/docker-compose.yml"
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		t.Errorf("Docker Compose file not found: %s", composePath)
	} else {
		t.Logf("✓ Docker Compose file found: %s", composePath)
	}

	// Проверяем, что docker-compose.yml содержит wazuh-agent
	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Errorf("Failed to read docker-compose.yml: %v", err)
	} else {
		composeContent := string(content)
		if !contains(composeContent, "wazuh-agent:") {
			t.Error("docker-compose.yml should contain wazuh-agent service")
		} else {
			t.Logf("✓ docker-compose.yml contains wazuh-agent service")
		}
	}
}

// TestWazuhIntegrationDocumentation проверяет документацию
func TestWazuhIntegrationDocumentation(t *testing.T) {
	docPath := "docs/WAZUH_INTEGRATION.md"
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Documentation not found: %s", docPath)
	} else {
		t.Logf("✓ Documentation found: %s", docPath)
	}

	// Проверяем содержимое документации
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Errorf("Failed to read documentation: %v", err)
	} else {
		docContent := string(content)
		expectedSections := []string{
			"# Интеграция Wazuh агента с NovaSec",
			"## Обзор",
			"## Архитектура интеграции",
			"## Поддерживаемые типы событий",
			"## Установка и настройка",
			"## Мониторинг и отладка",
		}

		for _, section := range expectedSections {
			if !contains(docContent, section) {
				t.Errorf("Documentation should contain section: %s", section)
			} else {
				t.Logf("✓ Documentation contains section: %s", section)
			}
		}
	}
}

// TestWazuhIntegrationSampleData проверяет тестовые данные
func TestWazuhIntegrationSampleData(t *testing.T) {
	samplePath := "internal/fixtures/wazuh_sample_events.jsonl"
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		t.Errorf("Sample data not found: %s", samplePath)
	} else {
		t.Logf("✓ Sample data found: %s", samplePath)
	}

	// Проверяем содержимое тестовых данных
	content, err := os.ReadFile(samplePath)
	if err != nil {
		t.Errorf("Failed to read sample data: %v", err)
	} else {
		sampleContent := string(content)
		expectedEvents := []string{
			"SSH login failed",
			"File added to the system",
			"High number of failed login attempts",
		}

		for _, event := range expectedEvents {
			if !contains(sampleContent, event) {
				t.Errorf("Sample data should contain event: %s", event)
			} else {
				t.Logf("✓ Sample data contains event: %s", event)
			}
		}
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
