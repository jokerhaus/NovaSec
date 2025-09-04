// filename: internal/normalizer/parsers/wazuh_complete_integration_test.go
package parsers

import (
	"encoding/json"
	"testing"
	"time"

	"novasec/internal/models"
)

// TestWazuhCompleteIntegration тестирует полную интеграцию Wazuh с NovaSec
func TestWazuhCompleteIntegration(t *testing.T) {
	t.Run("End_to_End_Integration", func(t *testing.T) {
		// 1. Создаем реестр парсеров
		registry := NewParserRegistry()

		// 2. Проверяем, что парсер зарегистрирован
		registeredParser, exists := registry.GetParser("wazuh")
		if !exists {
			t.Fatal("Wazuh parser should be registered")
		}

		// 3. Проверяем, что парсер работает
		if registeredParser == nil {
			t.Error("Registered parser should not be nil")
		}

		// 4. Тестируем различные типы событий
		testCases := []struct {
			name        string
			eventData   string
			expectedCat string
			expectedSub string
			expectedSev string
		}{
			{
				name: "SSH_Failed_Login",
				eventData: `{
					"timestamp": "2023-12-01T10:30:45.123Z",
					"rule": {
						"level": 7,
						"description": "SSH login failed",
						"id": "5716",
						"firedtimes": 1,
						"mail": false,
						"groups": ["authentication", "pci_dss_10.6.1"]
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
				expectedCat: "authentication",
				expectedSub: "ssh_login_failed",
				expectedSev: "medium",
			},
			{
				name: "File_Integrity_Modified",
				eventData: `{
					"timestamp": "2023-12-01T10:31:15.456Z",
					"rule": {
						"level": 5,
						"description": "File modified",
						"id": "555",
						"firedtimes": 1,
						"mail": false,
						"groups": ["ossec", "syscheck", "pci_dss_11.5"]
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
					"full_log": "ossec-syscheckd: File '/etc/passwd' was modified.",
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
				expectedCat: "file_integrity",
				expectedSub: "file_modified",
				expectedSev: "medium",
			},
			{
				name: "High_Severity_Brute_Force",
				eventData: `{
					"timestamp": "2023-12-01T10:32:30.789Z",
					"rule": {
						"level": 12,
						"description": "High number of failed login attempts",
						"id": "5717",
						"firedtimes": 5,
						"mail": true,
						"groups": ["authentication", "pci_dss_10.6.1"]
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
						"count": "5"
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
				expectedCat: "authentication",
				expectedSub: "wazuh_event",
				expectedSev: "critical",
			},
		}

		// 5. Тестируем каждое событие
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Создаем сырое событие
				rawEvent := &models.Event{
					TS:     time.Now(),
					Host:   "test-server",
					Source: "wazuh",
					Raw:    tc.eventData,
				}

				// Парсим через реестр
				result, err := registry.ParseEvent(rawEvent)
				if err != nil {
					t.Fatalf("ParseEvent() error = %v", err)
				}

				// Проверяем результат
				if result.Category != tc.expectedCat {
					t.Errorf("Category = %v, want %v", result.Category, tc.expectedCat)
				}
				if result.Subtype != tc.expectedSub {
					t.Errorf("Subtype = %v, want %v", result.Subtype, tc.expectedSub)
				}
				if result.Severity != tc.expectedSev {
					t.Errorf("Severity = %v, want %v", result.Severity, tc.expectedSev)
				}

				// Проверяем, что событие нормализовано
				if result.Source != "wazuh" {
					t.Errorf("Source = %v, want wazuh", result.Source)
				}
				if result.Host != "test-server" {
					t.Errorf("Host = %v, want test-server", result.Host)
				}

				// Проверяем метки
				if result.Labels == nil {
					t.Error("Labels should not be nil")
				}
				if _, exists := result.Labels["wazuh_rule_id"]; !exists {
					t.Error("Should have wazuh_rule_id label")
				}
				if _, exists := result.Labels["wazuh_agent_id"]; !exists {
					t.Error("Should have wazuh_agent_id label")
				}
			})
		}
	})
}

// TestWazuhParserRegistryIntegrationComplete тестирует интеграцию с реестром парсеров
func TestWazuhParserRegistryIntegrationComplete(t *testing.T) {
	registry := NewParserRegistry()

	// Проверяем, что Wazuh парсер зарегистрирован
	parser, exists := registry.GetParser("wazuh")
	if !exists {
		t.Fatal("Wazuh parser should be registered")
	}

	// Проверяем поддерживаемые источники
	sources := parser.GetSupportedSources()
	expectedSources := []string{"wazuh", "wazuh-agent", "ossec"}
	for _, expected := range expectedSources {
		found := false
		for _, source := range sources {
			if source == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected source %s not found in supported sources", expected)
		}
	}

	// Проверяем поддерживаемые категории
	categories := parser.GetSupportedCategories()
	expectedCategories := []string{
		"authentication", "file_integrity", "network", "malware",
		"system", "web", "database", "windows", "linux",
	}
	for _, expected := range expectedCategories {
		found := false
		for _, category := range categories {
			if category == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected category %s not found in supported categories", expected)
		}
	}

	// Проверяем поддерживаемые подтипы
	subtypes := parser.GetSupportedSubtypes()
	expectedSubtypes := []string{
		"ssh_login_failed", "ssh_login_success", "ssh_event",
		"sudo_command", "su_command", "file_modified", "file_created",
		"file_deleted", "file_integrity", "firewall_block",
		"network_connection", "malware_detected", "windows_event",
		"wazuh_event",
	}
	for _, expected := range expectedSubtypes {
		found := false
		for _, subtype := range subtypes {
			if subtype == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subtype %s not found in supported subtypes", expected)
		}
	}
}

// TestWazuhParserPerformanceComplete тестирует производительность парсера
func TestWazuhParserPerformanceComplete(t *testing.T) {
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

// TestWazuhParserConcurrencyComplete тестирует конкурентность парсера
func TestWazuhParserConcurrencyComplete(t *testing.T) {
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

// TestWazuhParserEdgeCasesComplete тестирует граничные случаи
func TestWazuhParserEdgeCasesComplete(t *testing.T) {
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
		if result.Host != "test-server" {
			t.Errorf("Host = %v, want test-server", result.Host)
		}
		if result.Source != "wazuh" {
			t.Errorf("Source = %v, want wazuh", result.Source)
		}
		if result.Category != "system" {
			t.Errorf("Category = %v, want system", result.Category)
		}
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

// TestWazuhParserJSONValidationComplete тестирует валидацию JSON структуры
func TestWazuhParserJSONValidationComplete(t *testing.T) {
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
	if wazuhEvent.Timestamp != "2023-12-01T10:30:45.123Z" {
		t.Errorf("Timestamp = %v, want 2023-12-01T10:30:45.123Z", wazuhEvent.Timestamp)
	}
	if wazuhEvent.Rule.Level != 7 {
		t.Errorf("Rule.Level = %v, want 7", wazuhEvent.Rule.Level)
	}
	if wazuhEvent.Rule.Description != "SSH login failed" {
		t.Errorf("Rule.Description = %v, want SSH login failed", wazuhEvent.Rule.Description)
	}
	if wazuhEvent.Agent.ID != "001" {
		t.Errorf("Agent.ID = %v, want 001", wazuhEvent.Agent.ID)
	}
	if wazuhEvent.Agent.Name != "test-server" {
		t.Errorf("Agent.Name = %v, want test-server", wazuhEvent.Agent.Name)
	}
	if wazuhEvent.Manager.Name != "wazuh-manager" {
		t.Errorf("Manager.Name = %v, want wazuh-manager", wazuhEvent.Manager.Name)
	}

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
	if result.Host != "test-server" {
		t.Errorf("Host = %v, want test-server", result.Host)
	}
	if result.AgentID != "001" {
		t.Errorf("AgentID = %v, want 001", result.AgentID)
	}
	if result.Source != "wazuh" {
		t.Errorf("Source = %v, want wazuh", result.Source)
	}
	if result.Category != "authentication" {
		t.Errorf("Category = %v, want authentication", result.Category)
	}
	if result.Subtype != "ssh_login_failed" {
		t.Errorf("Subtype = %v, want ssh_login_failed", result.Subtype)
	}
	if result.Severity != "medium" {
		t.Errorf("Severity = %v, want medium", result.Severity)
	}
	if result.Message != "SSH login failed" {
		t.Errorf("Message = %v, want SSH login failed", result.Message)
	}
	if result.SrcIP != "192.168.1.200" {
		t.Errorf("SrcIP = %v, want 192.168.1.200", result.SrcIP)
	}
	if result.UserName != "admin" {
		t.Errorf("UserName = %v, want admin", result.UserName)
	}

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
