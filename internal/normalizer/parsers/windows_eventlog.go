// filename: internal/normalizer/parsers/windows_eventlog.go
package parsers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/novasec/novasec/internal/models"
)

// WindowsEventLogParser парсит Windows Event Log события // v1.0
type WindowsEventLogParser struct {
	// Регулярные выражения для различных типов событий
	loginSuccessRegex        *regexp.Regexp
	loginFailureRegex        *regexp.Regexp
	logoutRegex              *regexp.Regexp
	privilegeUseRegex        *regexp.Regexp
	privilegeEscalationRegex *regexp.Regexp
	processCreationRegex     *regexp.Regexp
	fileAccessRegex          *regexp.Regexp
	registryAccessRegex      *regexp.Regexp
	networkConnectionRegex   *regexp.Regexp
}

// NewWindowsEventLogParser создает новый парсер Windows Event Log // v1.0
func NewWindowsEventLogParser() *WindowsEventLogParser {
	return &WindowsEventLogParser{
		// Успешные входы в систему (Event ID 4624)
		loginSuccessRegex: regexp.MustCompile(`(?i)Event ID:\s*4624.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Logon ID:\s*(\S+).*?Source Network Address:\s*(\S+).*?Source Port:\s*(\S+)`),

		// Неудачные попытки входа (Event ID 4625)
		loginFailureRegex: regexp.MustCompile(`(?i)Event ID:\s*4625.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Source Network Address:\s*(\S+).*?Source Port:\s*(\S+).*?Failure Reason:\s*(\S+)`),

		// Выходы из системы (Event ID 4634)
		logoutRegex: regexp.MustCompile(`(?i)Event ID:\s*4634.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Logon ID:\s*(\S+)`),

		// Использование привилегий (Event ID 4673)
		privilegeUseRegex: regexp.MustCompile(`(?i)Event ID:\s*4673.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Privilege:\s*(\S+)`),

		// Повышение привилегий (Event ID 4674)
		privilegeEscalationRegex: regexp.MustCompile(`(?i)Event ID:\s*4674.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Privilege:\s*(\S+)`),

		// Создание процессов (Event ID 4688)
		processCreationRegex: regexp.MustCompile(`(?i)Event ID:\s*4688.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?New Process Name:\s*(\S+).*?Process ID:\s*(\S+)`),

		// Доступ к файлам (Event ID 4663)
		fileAccessRegex: regexp.MustCompile(`(?i)Event ID:\s*4663.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Object Name:\s*(\S+).*?Access Mask:\s*(\S+)`),

		// Доступ к реестру (Event ID 4663)
		registryAccessRegex: regexp.MustCompile(`(?i)Event ID:\s*4663.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Object Name:\s*(\S+).*?Access Mask:\s*(\S+)`),

		// Сетевые подключения (Event ID 5156)
		networkConnectionRegex: regexp.MustCompile(`(?i)Event ID:\s*5156.*?Account Name:\s*(\S+).*?Account Domain:\s*(\S+).*?Source Address:\s*(\S+).*?Source Port:\s*(\S+).*?Destination Address:\s*(\S+).*?Destination Port:\s*(\S+)`),
	}
}

// ParseEvent парсит событие Windows Event Log // v1.0
func (p *WindowsEventLogParser) ParseEvent(rawEvent *models.Event) (*models.Event, error) {
	if rawEvent == nil || rawEvent.Raw == "" {
		return nil, fmt.Errorf("empty event or raw data")
	}

	raw := rawEvent.Raw
	normalized := *rawEvent

	// Пытаемся распарсить различные типы событий
	if event := p.parseLoginEvent(raw); event != nil {
		normalized = *event
		normalized.Raw = raw
		return &normalized, nil
	}

	if event := p.parsePrivilegeEvent(raw); event != nil {
		normalized = *event
		normalized.Raw = raw
		return &normalized, nil
	}

	if event := p.parseProcessEvent(raw); event != nil {
		normalized = *event
		normalized.Raw = raw
		return &normalized, nil
	}

	if event := p.parseFileEvent(raw); event != nil {
		normalized = *event
		normalized.Raw = raw
		return &normalized, nil
	}

	if event := p.parseNetworkEvent(raw); event != nil {
		normalized = *event
		normalized.Raw = raw
		return &normalized, nil
	}

	// Если ничего не распарсилось, возвращаем исходное событие
	return &normalized, nil
}

// parseLoginEvent парсит события входа/выхода // v1.0
func (p *WindowsEventLogParser) parseLoginEvent(raw string) *models.Event {
	// Проверяем успешные входы
	if matches := p.loginSuccessRegex.FindStringSubmatch(raw); len(matches) >= 6 {
		port, _ := strconv.Atoi(matches[5])
		srcIP := p.parseIP(matches[4])

		return &models.Event{
			Category: "auth",
			Subtype:  "login_success",
			Source:   "windows_eventlog",
			Severity: "info",
			Message:  fmt.Sprintf("Successful Windows login for user %s\\%s from %s", matches[2], matches[1], matches[4]),
			User: &models.User{
				Name: matches[1],
			},
			Network: &models.Network{
				SrcIP:   srcIP,
				SrcPort: &port,
				Proto:   "tcp",
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"logon_id":    matches[3],
				"event_id":    "4624",
			},
		}
	}

	// Проверяем неудачные попытки входа
	if matches := p.loginFailureRegex.FindStringSubmatch(raw); len(matches) >= 6 {
		port, _ := strconv.Atoi(matches[4])
		srcIP := p.parseIP(matches[3])

		return &models.Event{
			Category: "auth",
			Subtype:  "login_failed",
			Source:   "windows_eventlog",
			Severity: "high",
			Message:  fmt.Sprintf("Failed Windows login attempt for user %s\\%s from %s: %s", matches[2], matches[1], matches[3], matches[5]),
			User: &models.User{
				Name: matches[1],
			},
			Network: &models.Network{
				SrcIP:   srcIP,
				SrcPort: &port,
				Proto:   "tcp",
			},
			Labels: map[string]string{
				"auth_method":    "windows_auth",
				"service":        "windows_eventlog",
				"domain":         matches[2],
				"failure_reason": matches[5],
				"event_id":       "4625",
			},
		}
	}

	// Проверяем выходы из системы
	if matches := p.logoutRegex.FindStringSubmatch(raw); len(matches) >= 4 {
		return &models.Event{
			Category: "auth",
			Subtype:  "logout",
			Source:   "windows_eventlog",
			Severity: "info",
			Message:  fmt.Sprintf("Windows logout for user %s\\%s", matches[2], matches[1]),
			User: &models.User{
				Name: matches[1],
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"logon_id":    matches[3],
				"event_id":    "4634",
			},
		}
	}

	return nil
}

// parsePrivilegeEvent парсит события привилегий // v1.0
func (p *WindowsEventLogParser) parsePrivilegeEvent(raw string) *models.Event {
	// Проверяем использование привилегий
	if matches := p.privilegeUseRegex.FindStringSubmatch(raw); len(matches) >= 4 {
		return &models.Event{
			Category: "auth",
			Subtype:  "privilege_use",
			Source:   "windows_eventlog",
			Severity: "medium",
			Message:  fmt.Sprintf("Privilege use by user %s\\%s: %s", matches[2], matches[1], matches[3]),
			User: &models.User{
				Name: matches[1],
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"privilege":   matches[3],
				"event_id":    "4673",
			},
		}
	}

	// Проверяем повышение привилегий
	if matches := p.privilegeEscalationRegex.FindStringSubmatch(raw); len(matches) >= 4 {
		return &models.Event{
			Category: "auth",
			Subtype:  "privilege_escalation_success",
			Source:   "windows_eventlog",
			Severity: "high",
			Message:  fmt.Sprintf("Privilege escalation by user %s\\%s: %s", matches[2], matches[1], matches[3]),
			User: &models.User{
				Name: matches[1],
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"privilege":   matches[3],
				"event_id":    "4674",
			},
		}
	}

	return nil
}

// parseProcessEvent парсит события создания процессов // v1.0
func (p *WindowsEventLogParser) parseProcessEvent(raw string) *models.Event {
	if matches := p.processCreationRegex.FindStringSubmatch(raw); len(matches) >= 5 {
		pid, _ := strconv.Atoi(matches[4])

		return &models.Event{
			Category: "process",
			Subtype:  "creation",
			Source:   "windows_eventlog",
			Severity: "info",
			Message:  fmt.Sprintf("Process created by user %s\\%s: %s (PID: %d)", matches[2], matches[1], matches[3], pid),
			User: &models.User{
				Name: matches[1],
			},
			Process: &models.Process{
				Name: matches[3],
				PID:  &pid,
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"event_id":    "4688",
			},
		}
	}

	return nil
}

// parseFileEvent парсит события доступа к файлам // v1.0
func (p *WindowsEventLogParser) parseFileEvent(raw string) *models.Event {
	if matches := p.fileAccessRegex.FindStringSubmatch(raw); len(matches) >= 5 {
		// Проверяем, является ли это файлом (не реестром)
		if !strings.Contains(strings.ToLower(matches[3]), "\\registry\\") {
			return &models.Event{
				Category: "file",
				Subtype:  "access",
				Source:   "windows_eventlog",
				Severity: "medium",
				Message:  fmt.Sprintf("File access by user %s\\%s: %s", matches[2], matches[1], matches[3]),
				User: &models.User{
					Name: matches[1],
				},
				File: &models.File{
					Path: matches[3],
				},
				Labels: map[string]string{
					"auth_method": "windows_auth",
					"service":     "windows_eventlog",
					"domain":      matches[2],
					"access_mask": matches[4],
					"event_id":    "4663",
				},
			}
		}
	}

	return nil
}

// parseNetworkEvent парсит сетевые события // v1.0
func (p *WindowsEventLogParser) parseNetworkEvent(raw string) *models.Event {
	if matches := p.networkConnectionRegex.FindStringSubmatch(raw); len(matches) >= 7 {
		srcPort, _ := strconv.Atoi(matches[4])
		dstPort, _ := strconv.Atoi(matches[6])
		srcIP := p.parseIP(matches[3])
		dstIP := p.parseIP(matches[5])

		return &models.Event{
			Category: "network",
			Subtype:  "connection",
			Source:   "windows_eventlog",
			Severity: "info",
			Message:  fmt.Sprintf("Network connection by user %s\\%s: %s:%d -> %s:%d", matches[2], matches[1], matches[3], srcPort, matches[5], dstPort),
			User: &models.User{
				Name: matches[1],
			},
			Network: &models.Network{
				SrcIP:   srcIP,
				SrcPort: &srcPort,
				DstIP:   dstIP,
				DstPort: &dstPort,
				Proto:   "tcp",
			},
			Labels: map[string]string{
				"auth_method": "windows_auth",
				"service":     "windows_eventlog",
				"domain":      matches[2],
				"event_id":    "5156",
			},
		}
	}

	return nil
}

// parseIP парсит IP адрес в числовой формат // v1.0
func (p *WindowsEventLogParser) parseIP(ipStr string) *int {
	// Простая реализация для IPv4
	// В продакшене лучше использовать net.ParseIP
	if ipStr == "::1" || ipStr == "localhost" || ipStr == "-" {
		ip := 2130706433 // 127.0.0.1
		return &ip
	}

	// Для простоты возвращаем 0 для нераспознанных IP
	ip := 0
	return &ip
}

// GetSupportedSources возвращает список поддерживаемых источников // v1.0
func (p *WindowsEventLogParser) GetSupportedSources() []string {
	return []string{"windows_eventlog"}
}

// GetSupportedCategories возвращает список поддерживаемых категорий // v1.0
func (p *WindowsEventLogParser) GetSupportedCategories() []string {
	return []string{"auth", "process", "file", "network"}
}

// GetSupportedSubtypes возвращает список поддерживаемых подтипов // v1.0
func (p *WindowsEventLogParser) GetSupportedSubtypes() []string {
	return []string{
		"login_success", "login_failed", "logout",
		"privilege_use", "privilege_escalation_success",
		"creation", "access", "connection",
	}
}
