// filename: internal/normalizer/parsers/wazuh_integration_test.go
package parsers

import (
	"encoding/json"
	"testing"
	"time"

	"novasec/internal/models"
)

// TestWazuhParserIntegration тестирует полную интеграцию парсера Wazuh
func TestWazuhParserIntegration(t *testing.T) {
	parser := NewWazuhParser()

	// Тест 1: SSH неудачная попытка входа
	t.Run("SSH_Failed_Login", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:30:45.123Z",
				"rule": {
					"level": 7,
					"description": "SSH login failed",
					"id": "5716",
					"firedtimes": 1,
					"mail": false,
					"groups": ["authentication", "pci_dss_10.6.1", "gdpr_IV_35.7.d"]
				},
				"agent": {
					"id": "001",
					"name": "test-server",
					"type": "wazuh",
					"version": "4.7.0",
					"ip": "192.168.1.100"
				},
				"manager": {"name": "wazuh-manager"},
				"id": "1733047845.123456",
				"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
				"location": "/var/log/auth.log",
				"decoders": [{"name": "sshd"}],
				"decoder": {"name": "sshd"},
				"data": {
					"srcip": "192.168.1.200",
					"srcport": "22",
					"srcuser": "admin",
					"system_name": "test-server",
					"program_name": "sshd"
				},
				"predecoder": {
					"program_name": "sshd",
					"timestamp": "Dec  1 10:30:45",
					"hostname": "test-server"
				},
				"input": {"type": "log"},
				"geoLocation": {"location": "Unknown"},
				"cluster": {"node": "wazuh-manager"}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Проверяем основные поля
		assertEqual(t, result.Host, "test-server", "Host")
		assertEqual(t, result.AgentID, "001", "AgentID")
		assertEqual(t, result.Source, "wazuh", "Source")
		assertEqual(t, result.Category, "authentication", "Category")
		assertEqual(t, result.Subtype, "ssh_login_failed", "Subtype")
		assertEqual(t, result.Severity, "medium", "Severity")
		assertEqual(t, result.Message, "SSH login failed", "Message")
		assertEqual(t, result.SrcIP, "192.168.1.200", "SrcIP")
		assertEqual(t, result.UserName, "admin", "UserName")

		// Проверяем метки
		assertLabelExists(t, result.Labels, "wazuh_rule_id", "5716")
		assertLabelExists(t, result.Labels, "wazuh_rule_level", "7")
		assertLabelExists(t, result.Labels, "wazuh_agent_id", "001")
		assertLabelExists(t, result.Labels, "wazuh_agent_name", "test-server")
		assertLabelExists(t, result.Labels, "wazuh_manager", "wazuh-manager")
		assertLabelExists(t, result.Labels, "wazuh_decoder", "sshd")
		assertLabelExists(t, result.Labels, "wazuh_location", "/var/log/auth.log")

		// Проверяем группы правил
		assertLabelExists(t, result.Labels, "wazuh_group_0", "authentication")
		assertLabelExists(t, result.Labels, "wazuh_group_1", "pci_dss_10.6.1")
		assertLabelExists(t, result.Labels, "wazuh_group_2", "gdpr_IV_35.7.d")

		// Проверяем дополнительные данные
		assertLabelExists(t, result.Labels, "wazuh_data_srcip", "192.168.1.200")
		assertLabelExists(t, result.Labels, "wazuh_data_srcport", "22")
		assertLabelExists(t, result.Labels, "wazuh_data_srcuser", "admin")
	})

	// Тест 2: Файловая целостность - создание файла
	t.Run("File_Integrity_Created", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:31:15.456Z",
				"rule": {
					"level": 3,
					"description": "File added to the system",
					"id": "554",
					"firedtimes": 1,
					"mail": false,
					"groups": ["ossec", "syscheck", "pci_dss_11.5", "gdpr_II_5.1.f"]
				},
				"agent": {
					"id": "001",
					"name": "test-server",
					"type": "wazuh",
					"version": "4.7.0",
					"ip": "192.168.1.100"
				},
				"manager": {"name": "wazuh-manager"},
				"id": "1733047875.456789",
				"full_log": "ossec-syscheckd: File '/etc/passwd' added to the system.",
				"location": "/var/ossec/logs/alerts/alerts.log",
				"decoders": [{"name": "ossec"}],
				"decoder": {"name": "ossec"},
				"data": {
					"file": "/etc/passwd",
					"path": "/etc/passwd",
					"mode": "regular",
					"size": "1234",
					"uid": "0",
					"gid": "0",
					"md5": "d41d8cd98f00b204e9800998ecf8427e",
					"sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"perm": "rw-r--r--",
					"inode": "123456",
					"mtime": "2023-12-01T10:31:15Z",
					"ctime": "2023-12-01T10:31:15Z"
				},
				"predecoder": {
					"program_name": "ossec-syscheckd",
					"timestamp": "Dec  1 10:31:15",
					"hostname": "test-server"
				},
				"input": {"type": "log"},
				"geoLocation": {"location": "Unknown"},
				"cluster": {"node": "wazuh-manager"}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Проверяем основные поля
		assertEqual(t, result.Category, "file_integrity", "Category")
		assertEqual(t, result.Subtype, "file_created", "Subtype")
		assertEqual(t, result.Severity, "low", "Severity")
		assertEqual(t, result.FilePath, "/etc/passwd", "FilePath")

		// Проверяем хеши
		assertEqual(t, result.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256")

		// Проверяем метки файла
		assertLabelExists(t, result.Labels, "wazuh_data_file", "/etc/passwd")
		assertLabelExists(t, result.Labels, "wazuh_data_path", "/etc/passwd")
		assertLabelExists(t, result.Labels, "wazuh_data_size", "1234")
		assertLabelExists(t, result.Labels, "wazuh_data_perm", "rw-r--r--")
	})

	// Тест 3: Высокий уровень серьезности - Brute Force
	t.Run("High_Severity_Brute_Force", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:32:30.789Z",
				"rule": {
					"level": 12,
					"description": "High number of failed login attempts",
					"id": "5717",
					"firedtimes": 5,
					"mail": true,
					"groups": ["authentication", "pci_dss_10.6.1", "gdpr_IV_35.7.d"]
				},
				"agent": {
					"id": "001",
					"name": "test-server",
					"type": "wazuh",
					"version": "4.7.0",
					"ip": "192.168.1.100"
				},
				"manager": {"name": "wazuh-manager"},
				"id": "1733047950.789012",
				"full_log": "ossec: Alert: High number of failed login attempts (5) from 192.168.1.200",
				"location": "/var/ossec/logs/alerts/alerts.log",
				"decoders": [{"name": "ossec"}],
				"decoder": {"name": "ossec"},
				"data": {
					"srcip": "192.168.1.200",
					"count": "5",
					"system_name": "test-server",
					"program_name": "ossec"
				},
				"predecoder": {
					"program_name": "ossec",
					"timestamp": "Dec  1 10:32:30",
					"hostname": "test-server"
				},
				"input": {"type": "log"},
				"geoLocation": {"location": "Unknown"},
				"cluster": {"node": "wazuh-manager"}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Проверяем основные поля
		assertEqual(t, result.Category, "authentication", "Category")
		assertEqual(t, result.Subtype, "wazuh_event", "Subtype")
		assertEqual(t, result.Severity, "critical", "Severity")
		assertEqual(t, result.SrcIP, "192.168.1.200", "SrcIP")

		// Проверяем метки
		assertLabelExists(t, result.Labels, "wazuh_rule_level", "12")
		assertLabelExists(t, result.Labels, "wazuh_data_srcip", "192.168.1.200")
		assertLabelExists(t, result.Labels, "wazuh_data_count", "5")
	})

	// Тест 4: Malware обнаружение
	t.Run("Malware_Detection", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:33:45.123Z",
				"rule": {
					"level": 10,
					"description": "Malware detected",
					"id": "100001",
					"firedtimes": 1,
					"mail": true,
					"groups": ["malware", "virus", "pci_dss_5.1.1"]
				},
				"agent": {
					"id": "001",
					"name": "test-server",
					"type": "wazuh",
					"version": "4.7.0",
					"ip": "192.168.1.100"
				},
				"manager": {"name": "wazuh-manager"},
				"id": "1733048025.123456",
				"full_log": "ossec: Alert: Malware detected in file /tmp/suspicious.exe",
				"location": "/var/ossec/logs/alerts/alerts.log",
				"decoders": [{"name": "ossec"}],
				"decoder": {"name": "ossec"},
				"data": {
					"file": "/tmp/suspicious.exe",
					"path": "/tmp/suspicious.exe",
					"sha256": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
					"malware_name": "Trojan.Generic",
					"system_name": "test-server",
					"program_name": "ossec"
				},
				"predecoder": {
					"program_name": "ossec",
					"timestamp": "Dec  1 10:33:45",
					"hostname": "test-server"
				},
				"input": {"type": "log"},
				"geoLocation": {"location": "Unknown"},
				"cluster": {"node": "wazuh-manager"}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Проверяем основные поля
		assertEqual(t, result.Category, "malware", "Category")
		assertEqual(t, result.Subtype, "malware_detected", "Subtype")
		assertEqual(t, result.Severity, "high", "Severity")
		assertEqual(t, result.FilePath, "/tmp/suspicious.exe", "FilePath")
		assertEqual(t, result.SHA256, "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", "SHA256")

		// Проверяем метки
		assertLabelExists(t, result.Labels, "wazuh_data_malware_name", "Trojan.Generic")
		assertLabelExists(t, result.Labels, "wazuh_group_0", "malware")
		assertLabelExists(t, result.Labels, "wazuh_group_1", "virus")
	})

	// Тест 5: Сетевые события
	t.Run("Network_Firewall_Block", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:34:15.456Z",
				"rule": {
					"level": 6,
					"description": "Firewall blocked connection",
					"id": "100002",
					"firedtimes": 1,
					"mail": false,
					"groups": ["network", "firewall", "pci_dss_1.1.4"]
				},
				"agent": {
					"id": "001",
					"name": "test-server",
					"type": "wazuh",
					"version": "4.7.0",
					"ip": "192.168.1.100"
				},
				"manager": {"name": "wazuh-manager"},
				"id": "1733048055.456789",
				"full_log": "iptables: Blocked connection from 192.168.1.250:12345 to 192.168.1.100:22",
				"location": "/var/log/iptables.log",
				"decoders": [{"name": "iptables"}],
				"decoder": {"name": "iptables"},
				"data": {
					"srcip": "192.168.1.250",
					"srcport": "12345",
					"dstip": "192.168.1.100",
					"dstport": "22",
					"protocol": "tcp",
					"action": "blocked",
					"system_name": "test-server",
					"program_name": "iptables"
				},
				"predecoder": {
					"program_name": "iptables",
					"timestamp": "Dec  1 10:34:15",
					"hostname": "test-server"
				},
				"input": {"type": "log"},
				"geoLocation": {"location": "Unknown"},
				"cluster": {"node": "wazuh-manager"}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Проверяем основные поля
		assertEqual(t, result.Category, "network", "Category")
		assertEqual(t, result.Subtype, "firewall_block", "Subtype")
		assertEqual(t, result.Severity, "medium", "Severity")
		assertEqual(t, result.SrcIP, "192.168.1.250", "SrcIP")
		assertEqual(t, result.DstIP, "192.168.1.100", "DstIP")

		// Проверяем сетевую информацию
		if result.Network == nil {
			t.Error("Network information should not be nil")
		} else {
			assertEqual(t, result.Network.SrcIP, "192.168.1.250", "Network.SrcIP")
			assertEqual(t, result.Network.DstIP, "192.168.1.100", "Network.DstIP")
			assertEqual(t, result.Network.Proto, "tcp", "Network.Proto")
		}

		// Проверяем метки
		assertLabelExists(t, result.Labels, "wazuh_data_action", "blocked")
		assertLabelExists(t, result.Labels, "wazuh_data_protocol", "tcp")
	})
}

// TestWazuhParserEdgeCasesIntegration тестирует граничные случаи
func TestWazuhParserEdgeCasesIntegration(t *testing.T) {
	parser := NewWazuhParser()

	// Тест 1: Пустое событие
	t.Run("Empty_Event", func(t *testing.T) {
		_, err := parser.ParseEvent(nil)
		if err == nil {
			t.Error("Expected error for nil event")
		}

		emptyEvent := &models.Event{}
		_, err = parser.ParseEvent(emptyEvent)
		if err == nil {
			t.Error("Expected error for empty event")
		}
	})

	// Тест 2: Невалидный JSON
	t.Run("Invalid_JSON", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw:  `{"invalid": json}`,
		}

		_, err := parser.ParseEvent(rawEvent)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	// Тест 3: Событие без обязательных полей
	t.Run("Missing_Required_Fields", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "2023-12-01T10:30:45.123Z",
				"rule": {
					"level": 3,
					"description": "Test event"
				},
				"agent": {
					"id": "001",
					"name": "test-server"
				}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Должно работать с дефолтными значениями
		assertEqual(t, result.Host, "test-server", "Host")
		assertEqual(t, result.Source, "wazuh", "Source")
		assertEqual(t, result.Category, "system", "Category") // Дефолтная категория
	})

	// Тест 4: Событие с нестандартным timestamp
	t.Run("Non_Standard_Timestamp", func(t *testing.T) {
		rawEvent := &models.Event{
			TS:   time.Now(),
			Host: "test-server",
			Raw: `{
				"timestamp": "invalid-timestamp",
				"rule": {
					"level": 3,
					"description": "Test event"
				},
				"agent": {
					"id": "001",
					"name": "test-server"
				}
			}`,
		}

		result, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}

		// Должно использовать текущее время
		if result.TS.IsZero() {
			t.Error("Timestamp should not be zero")
		}
	})
}

// TestWazuhParserPerformanceIntegration тестирует производительность парсера
func TestWazuhParserPerformanceIntegration(t *testing.T) {
	parser := NewWazuhParser()

	// Создаем тестовое событие
	rawEvent := &models.Event{
		TS:   time.Now(),
		Host: "test-server",
		Raw: `{
			"timestamp": "2023-12-01T10:30:45.123Z",
			"rule": {
				"level": 7,
				"description": "SSH login failed",
				"id": "5716",
				"firedtimes": 1,
				"mail": false,
				"groups": ["authentication", "pci_dss_10.6.1", "gdpr_IV_35.7.d"]
			},
			"agent": {
				"id": "001",
				"name": "test-server",
				"type": "wazuh",
				"version": "4.7.0",
				"ip": "192.168.1.100"
			},
			"manager": {"name": "wazuh-manager"},
			"id": "1733047845.123456",
			"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
			"location": "/var/log/auth.log",
			"decoders": [{"name": "sshd"}],
			"decoder": {"name": "sshd"},
			"data": {
				"srcip": "192.168.1.200",
				"srcport": "22",
				"srcuser": "admin"
			},
			"predecoder": {
				"program_name": "sshd",
				"timestamp": "Dec  1 10:30:45",
				"hostname": "test-server"
			},
			"input": {"type": "log"},
			"geoLocation": {"location": "Unknown"},
			"cluster": {"node": "wazuh-manager"}
		}`,
	}

	// Тестируем производительность
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := parser.ParseEvent(rawEvent)
		if err != nil {
			t.Fatalf("ParseEvent() error = %v", err)
		}
	}
	duration := time.Since(start)

	t.Logf("Parsed 1000 events in %v (avg: %v per event)", duration, duration/1000)

	// Проверяем, что парсинг достаточно быстрый
	if duration > 1*time.Second {
		t.Errorf("Parsing too slow: %v for 1000 events", duration)
	}
}

// TestWazuhParserConcurrencyIntegration тестирует конкурентность парсера
func TestWazuhParserConcurrencyIntegration(t *testing.T) {
	parser := NewWazuhParser()

	// Создаем тестовое событие
	rawEvent := &models.Event{
		TS:   time.Now(),
		Host: "test-server",
		Raw: `{
			"timestamp": "2023-12-01T10:30:45.123Z",
			"rule": {
				"level": 7,
				"description": "SSH login failed",
				"id": "5716",
				"firedtimes": 1,
				"mail": false,
				"groups": ["authentication"]
			},
			"agent": {
				"id": "001",
				"name": "test-server",
				"type": "wazuh",
				"version": "4.7.0",
				"ip": "192.168.1.100"
			},
			"manager": {"name": "wazuh-manager"},
			"id": "1733047845.123456",
			"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
			"location": "/var/log/auth.log",
			"decoders": [{"name": "sshd"}],
			"decoder": {"name": "sshd"},
			"data": {
				"srcip": "192.168.1.200",
				"srcport": "22",
				"srcuser": "admin"
			},
			"predecoder": {
				"program_name": "sshd",
				"timestamp": "Dec  1 10:30:45",
				"hostname": "test-server"
			},
			"input": {"type": "log"},
			"geoLocation": {"location": "Unknown"},
			"cluster": {"node": "wazuh-manager"}
		}`,
	}

	// Запускаем горутины
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, err := parser.ParseEvent(rawEvent)
				if err != nil {
					errors <- err
					return
				}
			}
			done <- true
		}()
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Горутина завершилась успешно
		case err := <-errors:
			t.Fatalf("ParseEvent() error in goroutine: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for goroutines to complete")
		}
	}
}

// Вспомогательные функции для тестирования

func assertEqual(t *testing.T, got, want, field string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}

func assertLabelExists(t *testing.T, labels map[string]string, key, expectedValue string) {
	t.Helper()
	if labels == nil {
		t.Errorf("Labels should not be nil")
		return
	}
	value, exists := labels[key]
	if !exists {
		t.Errorf("Label %s should exist", key)
		return
	}
	if value != expectedValue {
		t.Errorf("Label %s = %v, want %v", key, value, expectedValue)
	}
}

// TestWazuhParserRegistryIntegrationTest тестирует интеграцию с реестром парсеров
func TestWazuhParserRegistryIntegrationTest(t *testing.T) {
	registry := NewParserRegistry()

	// Проверяем, что Wazuh парсер зарегистрирован
	parser, exists := registry.GetParser("wazuh")
	if !exists {
		t.Fatal("Wazuh parser should be registered")
	}

	// Проверяем, что это правильный парсер
	if parser.GetSupportedSources()[0] != "wazuh" {
		t.Error("Wrong parser returned")
	}

	// Проверяем поиск по источнику
	foundParser := registry.GetParserForSource("wazuh")
	if foundParser == nil {
		t.Error("Parser should be found by source 'wazuh'")
	}

	// Проверяем поиск по категории
	foundParser = registry.GetParserForCategory("authentication")
	if foundParser == nil {
		t.Error("Parser should be found by category 'authentication'")
	}

	// Тестируем парсинг через реестр
	rawEvent := &models.Event{
		TS:     time.Now(),
		Host:   "test-server",
		Source: "wazuh",
		Raw: `{
			"timestamp": "2023-12-01T10:30:45.123Z",
			"rule": {
				"level": 7,
				"description": "SSH login failed",
				"id": "5716",
				"firedtimes": 1,
				"mail": false,
				"groups": ["authentication"]
			},
			"agent": {
				"id": "001",
				"name": "test-server",
				"type": "wazuh",
				"version": "4.7.0",
				"ip": "192.168.1.100"
			},
			"manager": {"name": "wazuh-manager"},
			"id": "1733047845.123456",
			"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
			"location": "/var/log/auth.log",
			"decoders": [{"name": "sshd"}],
			"decoder": {"name": "sshd"},
			"data": {
				"srcip": "192.168.1.200",
				"srcport": "22",
				"srcuser": "admin"
			},
			"predecoder": {
				"program_name": "sshd",
				"timestamp": "Dec  1 10:30:45",
				"hostname": "test-server"
			},
			"input": {"type": "log"},
			"geoLocation": {"location": "Unknown"},
			"cluster": {"node": "wazuh-manager"}
		}`,
	}

	result, err := registry.ParseEvent(rawEvent)
	if err != nil {
		t.Fatalf("Registry ParseEvent() error = %v", err)
	}

	// Проверяем результат
	assertEqual(t, result.Source, "wazuh", "Source")
	assertEqual(t, result.Category, "authentication", "Category")
	assertEqual(t, result.Subtype, "ssh_login_failed", "Subtype")
}

// TestWazuhParserJSONValidationIntegration тестирует валидацию JSON структуры
func TestWazuhParserJSONValidationIntegration(t *testing.T) {
	parser := NewWazuhParser()

	// Тест с полной JSON структурой Wazuh
	fullWazuhEvent := `{
		"timestamp": "2023-12-01T10:30:45.123Z",
		"rule": {
			"level": 7,
			"description": "SSH login failed",
			"id": "5716",
			"firedtimes": 1,
			"mail": false,
			"groups": ["authentication", "pci_dss_10.6.1", "gdpr_IV_35.7.d"],
			"pci_dss": ["10.6.1"],
			"gdpr": ["IV_35.7.d"],
			"hipaa": ["164.312.b"],
			"nist_800_53": ["AU.14"],
			"tsc": ["CC6.1", "CC6.8"],
			"mitre": ["T1021.004"]
		},
		"agent": {
			"id": "001",
			"name": "test-server",
			"type": "wazuh",
			"version": "4.7.0",
			"build": "1",
			"ip": "192.168.1.100",
			"manager": "wazuh-manager",
			"os": {
				"name": "Ubuntu",
				"version": "22.04",
				"arch": "x86_64",
				"platform": "ubuntu",
				"major": "22",
				"minor": "04",
				"build": "",
				"uname": "Linux test-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"
			},
			"dateAdd": "2023-12-01T10:00:00Z",
			"lastKeepAlive": "2023-12-01T10:30:45Z",
			"status": "active",
			"group": ["default"],
			"sum": "",
			"sum2": "",
			"lastScan": {
				"time": "2023-12-01T10:00:00Z"
			}
		},
		"manager": {
			"name": "wazuh-manager"
		},
		"id": "1733047845.123456",
		"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
		"location": "/var/log/auth.log",
		"decoders": [{"name": "sshd"}],
		"decoder": {"name": "sshd"},
		"data": {
			"srcip": "192.168.1.200",
			"srcport": "22",
			"srcuser": "admin",
			"srcuid": "-1",
			"dstuser": "admin",
			"dstuid": "-1",
			"system_name": "test-server",
			"program_name": "sshd",
			"logfile": "/var/log/auth.log",
			"full_log": "Dec  1 10:30:45 test-server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2",
			"timestamp": "Dec  1 10:30:45",
			"hostname": "test-server",
			"program_name": "sshd"
		},
		"predecoder": {
			"program_name": "sshd",
			"timestamp": "Dec  1 10:30:45",
			"hostname": "test-server"
		},
		"input": {
			"type": "log"
		},
		"geoLocation": {
			"location": "Unknown"
		},
		"cluster": {
			"node": "wazuh-manager"
		}
	}`

	// Проверяем, что JSON валиден
	var wazuhEvent WazuhEvent
	err := json.Unmarshal([]byte(fullWazuhEvent), &wazuhEvent)
	if err != nil {
		t.Fatalf("JSON unmarshal error = %v", err)
	}

	// Проверяем, что все поля заполнены
	assertEqual(t, wazuhEvent.Timestamp, "2023-12-01T10:30:45.123Z", "Timestamp")
	if wazuhEvent.Rule.Level != 7 {
		t.Errorf("Rule.Level = %v, want 7", wazuhEvent.Rule.Level)
	}
	assertEqual(t, wazuhEvent.Rule.Description, "SSH login failed", "Rule.Description")
	assertEqual(t, wazuhEvent.Agent.ID, "001", "Agent.ID")
	assertEqual(t, wazuhEvent.Agent.Name, "test-server", "Agent.Name")
	assertEqual(t, wazuhEvent.Manager.Name, "wazuh-manager", "Manager.Name")

	// Тестируем парсинг полного события
	rawEvent := &models.Event{
		TS:   time.Now(),
		Host: "test-server",
		Raw:  fullWazuhEvent,
	}

	result, err := parser.ParseEvent(rawEvent)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	// Проверяем, что все поля правильно извлечены
	assertEqual(t, result.Host, "test-server", "Host")
	assertEqual(t, result.AgentID, "001", "AgentID")
	assertEqual(t, result.Source, "wazuh", "Source")
	assertEqual(t, result.Category, "authentication", "Category")
	assertEqual(t, result.Subtype, "ssh_login_failed", "Subtype")
	assertEqual(t, result.Severity, "medium", "Severity")
	assertEqual(t, result.Message, "SSH login failed", "Message")
	assertEqual(t, result.SrcIP, "192.168.1.200", "SrcIP")
	assertEqual(t, result.UserName, "admin", "UserName")

	// Проверяем, что все метки созданы
	expectedLabels := []string{
		"wazuh_rule_id", "wazuh_rule_level", "wazuh_agent_id", "wazuh_agent_name",
		"wazuh_manager", "wazuh_decoder", "wazuh_location", "wazuh_group_0",
		"wazuh_group_1", "wazuh_group_2", "wazuh_data_srcip", "wazuh_data_srcport",
		"wazuh_data_srcuser", "wazuh_data_srcuid", "wazuh_data_dstuser",
		"wazuh_data_dstuid", "wazuh_data_system_name", "wazuh_data_program_name",
		"wazuh_data_logfile", "wazuh_data_timestamp", "wazuh_data_hostname",
	}

	for _, label := range expectedLabels {
		if _, exists := result.Labels[label]; !exists {
			t.Errorf("Expected label %s not found", label)
		}
	}
}
