// filename: internal/normalizer/parsers/wazuh_test.go
package parsers

import (
	"testing"
	"time"

	"novasec/internal/models"
)

func TestWazuhParser_ParseEvent(t *testing.T) {
	parser := NewWazuhParser()

	tests := []struct {
		name     string
		rawEvent string
		expected *models.Event
	}{
		{
			name:     "SSH login failed event",
			rawEvent: `{"timestamp":"2023-12-01T10:30:45.123Z","rule":{"level":7,"description":"SSH login failed","id":"5716","firedtimes":1,"mail":false,"groups":["authentication","pci_dss_10.6.1","gdpr_IV_35.7.d"]},"agent":{"id":"001","name":"test-agent","type":"wazuh","version":"4.7.0","build":"1","ip":"192.168.1.100","manager":"wazuh-manager","os":{"name":"Ubuntu","version":"22.04","arch":"x86_64","platform":"ubuntu","major":"22","minor":"04","build":"","uname":"Linux test-agent 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"},"dateAdd":"2023-12-01T10:00:00Z","lastKeepAlive":"2023-12-01T10:30:45Z","status":"active","group":["default"],"sum":"","sum2":"","lastScan":{"time":"2023-12-01T10:00:00Z"}},"manager":{"name":"wazuh-manager"},"id":"1733047845.123456","full_log":"Dec  1 10:30:45 test-agent sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2","location":"/var/log/auth.log","decoders":[{"name":"sshd"}],"decoder":{"name":"sshd"},"data":{"srcip":"192.168.1.200","srcport":"22","srcuser":"admin","srcuid":"-1","dstuser":"admin","dstuid":"-1","system_name":"test-agent","program_name":"sshd","logfile":"/var/log/auth.log","full_log":"Dec  1 10:30:45 test-agent sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2","timestamp":"Dec  1 10:30:45","hostname":"test-agent","program_name":"sshd"},"predecoder":{"program_name":"sshd","timestamp":"Dec  1 10:30:45","hostname":"test-agent"},"input":{"type":"log"},"geoLocation":{"location":"Unknown"},"cluster":{"node":"wazuh-manager"}}`,
			expected: &models.Event{
				Host:     "test-agent",
				AgentID:  "001",
				Source:   "wazuh",
				Category: "authentication",
				Subtype:  "ssh_login_failed",
				Severity: "medium",
				Message:  "SSH login failed",
				SrcIP:    "192.168.1.200",
				UserName: "admin",
			},
		},
		{
			name:     "File integrity event",
			rawEvent: `{"timestamp":"2023-12-01T10:31:15.456Z","rule":{"level":3,"description":"File added to the system","id":"554","firedtimes":1,"mail":false,"groups":["ossec","syscheck","pci_dss_11.5","gdpr_II_5.1.f"]},"agent":{"id":"001","name":"test-agent","type":"wazuh","version":"4.7.0","build":"1","ip":"192.168.1.100","manager":"wazuh-manager","os":{"name":"Ubuntu","version":"22.04","arch":"x86_64","platform":"ubuntu","major":"22","minor":"04","build":"","uname":"Linux test-agent 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"},"dateAdd":"2023-12-01T10:00:00Z","lastKeepAlive":"2023-12-01T10:31:15Z","status":"active","group":["default"],"sum":"","sum2":"","lastScan":{"time":"2023-12-01T10:00:00Z"}},"manager":{"name":"wazuh-manager"},"id":"1733047875.456789","full_log":"ossec-syscheckd: File '/etc/passwd' added to the system.","location":"/var/ossec/logs/alerts/alerts.log","decoders":[{"name":"ossec"}],"decoder":{"name":"ossec"},"data":{"file":"/etc/passwd","path":"/etc/passwd","mode":"regular","size":"1234","uid":"0","gid":"0","md5":"d41d8cd98f00b204e9800998ecf8427e","sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","perm":"rw-r--r--","inode":"123456","mtime":"2023-12-01T10:31:15Z","ctime":"2023-12-01T10:31:15Z","system_name":"test-agent","program_name":"ossec-syscheckd","logfile":"/var/ossec/logs/alerts/alerts.log","full_log":"ossec-syscheckd: File '/etc/passwd' added to the system.","timestamp":"Dec  1 10:31:15","hostname":"test-agent","program_name":"ossec-syscheckd"},"predecoder":{"program_name":"ossec-syscheckd","timestamp":"Dec  1 10:31:15","hostname":"test-agent"},"input":{"type":"log"},"geoLocation":{"location":"Unknown"},"cluster":{"node":"wazuh-manager"}}`,
			expected: &models.Event{
				Host:     "test-agent",
				AgentID:  "001",
				Source:   "wazuh",
				Category: "file_integrity",
				Subtype:  "file_created",
				Severity: "low",
				Message:  "File added to the system",
				FilePath: "/etc/passwd",
			},
		},
		{
			name:     "High severity brute force event",
			rawEvent: `{"timestamp":"2023-12-01T10:32:30.789Z","rule":{"level":12,"description":"High number of failed login attempts","id":"5717","firedtimes":5,"mail":true,"groups":["authentication","pci_dss_10.6.1","gdpr_IV_35.7.d"]},"agent":{"id":"001","name":"test-agent","type":"wazuh","version":"4.7.0","build":"1","ip":"192.168.1.100","manager":"wazuh-manager","os":{"name":"Ubuntu","version":"22.04","arch":"x86_64","platform":"ubuntu","major":"22","minor":"04","build":"","uname":"Linux test-agent 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"},"dateAdd":"2023-12-01T10:00:00Z","lastKeepAlive":"2023-12-01T10:32:30Z","status":"active","group":["default"],"sum":"","sum2":"","lastScan":{"time":"2023-12-01T10:00:00Z"}},"manager":{"name":"wazuh-manager"},"id":"1733047950.789012","full_log":"ossec: Alert: High number of failed login attempts (5) from 192.168.1.200","location":"/var/ossec/logs/alerts/alerts.log","decoders":[{"name":"ossec"}],"decoder":{"name":"ossec"},"data":{"srcip":"192.168.1.200","count":"5","system_name":"test-agent","program_name":"ossec","logfile":"/var/ossec/logs/alerts/alerts.log","full_log":"ossec: Alert: High number of failed login attempts (5) from 192.168.1.200","timestamp":"Dec  1 10:32:30","hostname":"test-agent","program_name":"ossec"},"predecoder":{"program_name":"ossec","timestamp":"Dec  1 10:32:30","hostname":"test-agent"},"input":{"type":"log"},"geoLocation":{"location":"Unknown"},"cluster":{"node":"wazuh-manager"}}`,
			expected: &models.Event{
				Host:     "test-agent",
				AgentID:  "001",
				Source:   "wazuh",
				Category: "authentication",
				Subtype:  "wazuh_event",
				Severity: "critical",
				Message:  "High number of failed login attempts",
				SrcIP:    "192.168.1.200",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawEvent := &models.Event{
				TS:   time.Now(),
				Host: "test-agent",
				Raw:  tt.rawEvent,
			}

			result, err := parser.ParseEvent(rawEvent)
			if err != nil {
				t.Fatalf("ParseEvent() error = %v", err)
			}

			if result.Host != tt.expected.Host {
				t.Errorf("Host = %v, want %v", result.Host, tt.expected.Host)
			}

			if result.AgentID != tt.expected.AgentID {
				t.Errorf("AgentID = %v, want %v", result.AgentID, tt.expected.AgentID)
			}

			if result.Source != tt.expected.Source {
				t.Errorf("Source = %v, want %v", result.Source, tt.expected.Source)
			}

			if result.Category != tt.expected.Category {
				t.Errorf("Category = %v, want %v", result.Category, tt.expected.Category)
			}

			if result.Subtype != tt.expected.Subtype {
				t.Errorf("Subtype = %v, want %v", result.Subtype, tt.expected.Subtype)
			}

			if result.Severity != tt.expected.Severity {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.expected.Severity)
			}

			if result.Message != tt.expected.Message {
				t.Errorf("Message = %v, want %v", result.Message, tt.expected.Message)
			}

			if result.SrcIP != tt.expected.SrcIP {
				t.Errorf("SrcIP = %v, want %v", result.SrcIP, tt.expected.SrcIP)
			}

			if result.UserName != tt.expected.UserName {
				t.Errorf("UserName = %v, want %v", result.UserName, tt.expected.UserName)
			}

			if result.FilePath != tt.expected.FilePath {
				t.Errorf("FilePath = %v, want %v", result.FilePath, tt.expected.FilePath)
			}

			// Проверяем наличие меток
			if result.Labels == nil {
				t.Error("Labels should not be nil")
			}

			// Проверяем обязательные метки Wazuh
			expectedLabels := []string{"wazuh_rule_id", "wazuh_rule_level", "wazuh_agent_id", "wazuh_agent_name"}
			for _, label := range expectedLabels {
				if _, exists := result.Labels[label]; !exists {
					t.Errorf("Expected label %s not found", label)
				}
			}
		})
	}
}

func TestWazuhParser_GetSupportedSources(t *testing.T) {
	parser := NewWazuhParser()
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
}

func TestWazuhParser_GetSupportedCategories(t *testing.T) {
	parser := NewWazuhParser()
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
}

func TestWazuhParser_GetSupportedSubtypes(t *testing.T) {
	parser := NewWazuhParser()
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

func TestWazuhParser_DetermineSeverity(t *testing.T) {
	parser := &WazuhParser{}

	tests := []struct {
		level    int
		expected string
	}{
		{1, "info"},
		{3, "low"},
		{5, "medium"},
		{8, "high"},
		{12, "critical"},
		{15, "critical"},
	}

	for _, tt := range tests {
		result := parser.determineSeverity(tt.level)
		if result != tt.expected {
			t.Errorf("determineSeverity(%d) = %v, want %v", tt.level, result, tt.expected)
		}
	}
}

func TestWazuhParser_DetermineCategory(t *testing.T) {
	parser := &WazuhParser{}

	tests := []struct {
		name     string
		groups   []string
		expected string
	}{
		{
			name:     "authentication group",
			groups:   []string{"authentication"},
			expected: "authentication",
		},
		{
			name:     "file_integrity group",
			groups:   []string{"file_integrity"},
			expected: "file_integrity",
		},
		{
			name:     "network group",
			groups:   []string{"network"},
			expected: "network",
		},
		{
			name:     "malware group",
			groups:   []string{"malware"},
			expected: "malware",
		},
		{
			name:     "unknown group",
			groups:   []string{"unknown"},
			expected: "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wazuhEvent := WazuhEvent{
				Rule: WazuhRule{
					Groups: tt.groups,
				},
			}

			result := parser.determineCategory(wazuhEvent)
			if result != tt.expected {
				t.Errorf("determineCategory() = %v, want %v", result, tt.expected)
			}
		})
	}
}
