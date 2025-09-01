// filename: internal/normalizer/parsers/linux_auth.go
package parsers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/novasec/novasec/internal/models"
)

// LinuxAuthParser парсер для логов аутентификации Linux (SSH, sudo, su) // v1.0
type LinuxAuthParser struct {
	name     string
	patterns map[string]*regexp.Regexp
}

// NewLinuxAuthParser создает новый парсер аутентификации Linux // v1.0
func NewLinuxAuthParser() Parser {
	patterns := map[string]*regexp.Regexp{
		// SSH неудачные попытки входа
		"ssh_failed": regexp.MustCompile(`sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2`),
		// SSH успешные входы
		"ssh_success": regexp.MustCompile(`sshd\[\d+\]:\s+Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2`),
		// SSH отключения
		"ssh_disconnect": regexp.MustCompile(`sshd\[\d+\]:\s+Disconnected from (?:invalid user )?(\w+) (\d+\.\d+\.\d+\.\d+) port (\d+)`),
		// Sudo команды
		"sudo_command": regexp.MustCompile(`sudo:\s+(\w+) : TTY=(.+) ; PWD=(.+) ; USER=(\w+) ; COMMAND=(.+)`),
		// Sudo ошибки
		"sudo_error": regexp.MustCompile(`sudo:\s+(\w+) : (\d+ incorrect password attempts) ; TTY=(.+) ; PWD=(.+) ; USER=(\w+) ; COMMAND=(.+)`),
		// Su команды
		"su_command": regexp.MustCompile(`su\[\d+\]:\s+\(to (\w+)\) (\w+) on (\w+)`),
		// PAM аутентификация
		"pam_auth": regexp.MustCompile(`(\w+)\[\d+\]:\s+pam_unix\((.+)\):\s+(authentication failure|session opened|session closed) for user (\w+)`),
	}

	return &LinuxAuthParser{
		name:     "linux_auth",
		patterns: patterns,
	}
}

// GetName возвращает имя парсера // v1.0
func (p *LinuxAuthParser) GetName() string {
	return p.name
}

// GetPriority возвращает приоритет парсера // v1.0
func (p *LinuxAuthParser) GetPriority() int {
	return 80 // Высокий приоритет для системных логов
}

// CanParse определяет, может ли парсер обработать данное сырое событие // v1.0
func (p *LinuxAuthParser) CanParse(raw string) bool {
	// Проверяем наличие ключевых слов аутентификации
	keywords := []string{"sshd", "sudo", "su[", "pam_unix", "authentication", "password", "session"}

	for _, keyword := range keywords {
		if strings.Contains(raw, keyword) {
			return true
		}
	}

	return false
}

// Parse парсит сырое событие в структурированную модель // v1.0
func (p *LinuxAuthParser) Parse(raw string, baseEvent *models.Event) (*models.Event, error) {
	if baseEvent == nil {
		baseEvent = &models.Event{
			TS:       time.Now(),
			Category: "authentication",
			Raw:      raw,
		}
	}

	// Устанавливаем базовые поля
	baseEvent.Source = "linux_auth"
	baseEvent.Category = "authentication"
	baseEvent.Raw = raw

	// Пытаемся найти совпадение с паттернами
	for patternName, pattern := range p.patterns {
		if matches := pattern.FindStringSubmatch(raw); matches != nil {
			return p.parseByPattern(patternName, matches, baseEvent)
		}
	}

	// Если конкретный паттерн не найден, создаем общее событие
	return p.parseGenericAuth(raw, baseEvent)
}

// parseByPattern парсит событие по конкретному паттерну // v1.0
func (p *LinuxAuthParser) parseByPattern(patternName string, matches []string, event *models.Event) (*models.Event, error) {
	switch patternName {
	case "ssh_failed":
		return p.parseSSHFailed(matches, event)
	case "ssh_success":
		return p.parseSSHSuccess(matches, event)
	case "ssh_disconnect":
		return p.parseSSHDisconnect(matches, event)
	case "sudo_command":
		return p.parseSudoCommand(matches, event)
	case "sudo_error":
		return p.parseSudoError(matches, event)
	case "su_command":
		return p.parseSuCommand(matches, event)
	case "pam_auth":
		return p.parsePAMAuth(matches, event)
	default:
		return p.parseGenericAuth(event.Raw, event)
	}
}

// parseSSHFailed парсит неудачную SSH попытку // v1.0
func (p *LinuxAuthParser) parseSSHFailed(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 4 {
		return nil, fmt.Errorf("insufficient SSH failed matches")
	}

	username := matches[1]
	srcIP := matches[2]
	port := matches[3]

	event.Subtype = "ssh_login_failed"
	event.Severity = "medium"
	event.Message = fmt.Sprintf("SSH login failed for user %s from %s", username, srcIP)

	// Устанавливаем пользователя
	event.User = &models.User{Name: username}
	event.UserName = username

	// Устанавливаем сетевую информацию
	if portNum, err := strconv.Atoi(port); err == nil {
		event.Network = &models.Network{
			SrcIP:   srcIP,
			SrcPort: &portNum,
			Proto:   "tcp",
		}
		event.SrcIP = srcIP
		event.SrcPort = &portNum
		event.Proto = "tcp"
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_result"] = "failed"
	event.Labels["auth_method"] = "ssh"
	event.Labels["protocol"] = "ssh"

	return event, nil
}

// parseSSHSuccess парсит успешную SSH попытку // v1.0
func (p *LinuxAuthParser) parseSSHSuccess(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 4 {
		return nil, fmt.Errorf("insufficient SSH success matches")
	}

	username := matches[1]
	srcIP := matches[2]
	port := matches[3]

	event.Subtype = "ssh_login_success"
	event.Severity = "info"
	event.Message = fmt.Sprintf("SSH login successful for user %s from %s", username, srcIP)

	// Устанавливаем пользователя
	event.User = &models.User{Name: username}
	event.UserName = username

	// Устанавливаем сетевую информацию
	if portNum, err := strconv.Atoi(port); err == nil {
		event.Network = &models.Network{
			SrcIP:   srcIP,
			SrcPort: &portNum,
			Proto:   "tcp",
		}
		event.SrcIP = srcIP
		event.SrcPort = &portNum
		event.Proto = "tcp"
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_result"] = "success"
	event.Labels["auth_method"] = "ssh"
	event.Labels["protocol"] = "ssh"

	return event, nil
}

// parseSSHDisconnect парсит отключение SSH // v1.0
func (p *LinuxAuthParser) parseSSHDisconnect(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 4 {
		return nil, fmt.Errorf("insufficient SSH disconnect matches")
	}

	username := matches[1]
	srcIP := matches[2]
	port := matches[3]

	event.Subtype = "ssh_disconnect"
	event.Severity = "low"
	event.Message = fmt.Sprintf("SSH disconnection for user %s from %s", username, srcIP)

	// Устанавливаем пользователя
	event.User = &models.User{Name: username}
	event.UserName = username

	// Устанавливаем сетевую информацию
	if portNum, err := strconv.Atoi(port); err == nil {
		event.Network = &models.Network{
			SrcIP:   srcIP,
			SrcPort: &portNum,
			Proto:   "tcp",
		}
		event.SrcIP = srcIP
		event.SrcPort = &portNum
		event.Proto = "tcp"
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_result"] = "disconnect"
	event.Labels["auth_method"] = "ssh"
	event.Labels["protocol"] = "ssh"

	return event, nil
}

// parseSudoCommand парсит команду sudo // v1.0
func (p *LinuxAuthParser) parseSudoCommand(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 6 {
		return nil, fmt.Errorf("insufficient sudo command matches")
	}

	user := matches[1]
	tty := matches[2]
	pwd := matches[3]
	targetUser := matches[4]
	command := matches[5]

	event.Subtype = "sudo_command"
	event.Severity = "info"
	event.Message = fmt.Sprintf("Sudo command executed: %s by %s as %s", command, user, targetUser)

	// Устанавливаем пользователя
	event.User = &models.User{Name: user}
	event.UserName = user

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_method"] = "sudo"
	event.Labels["target_user"] = targetUser
	event.Labels["tty"] = tty
	event.Labels["pwd"] = pwd
	event.Labels["command"] = command

	return event, nil
}

// parseSudoError парсит ошибку sudo // v1.0
func (p *LinuxAuthParser) parseSudoError(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 7 {
		return nil, fmt.Errorf("insufficient sudo error matches")
	}

	user := matches[1]
	error := matches[2]
	tty := matches[3]
	pwd := matches[4]
	targetUser := matches[5]
	command := matches[6]

	event.Subtype = "sudo_error"
	event.Severity = "medium"
	event.Message = fmt.Sprintf("Sudo error: %s for %s trying to run %s as %s", error, user, command, targetUser)

	// Устанавливаем пользователя
	event.User = &models.User{Name: user}
	event.UserName = user

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_method"] = "sudo"
	event.Labels["auth_result"] = "failed"
	event.Labels["target_user"] = targetUser
	event.Labels["tty"] = tty
	event.Labels["pwd"] = pwd
	event.Labels["command"] = command
	event.Labels["error"] = error

	return event, nil
}

// parseSuCommand парсит команду su // v1.0
func (p *LinuxAuthParser) parseSuCommand(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 4 {
		return nil, fmt.Errorf("insufficient su command matches")
	}

	targetUser := matches[1]
	sourceUser := matches[2]
	tty := matches[3]

	event.Subtype = "su_command"
	event.Severity = "info"
	event.Message = fmt.Sprintf("Su command: %s switched to %s on %s", sourceUser, targetUser, tty)

	// Устанавливаем пользователя
	event.User = &models.User{Name: sourceUser}
	event.UserName = sourceUser

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_method"] = "su"
	event.Labels["target_user"] = targetUser
	event.Labels["tty"] = tty

	return event, nil
}

// parsePAMAuth парсит PAM аутентификацию // v1.0
func (p *LinuxAuthParser) parsePAMAuth(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 5 {
		return nil, fmt.Errorf("insufficient PAM auth matches")
	}

	service := matches[1]
	module := matches[2]
	result := matches[3]
	user := matches[4]

	event.Subtype = "pam_authentication"

	switch result {
	case "authentication failure":
		event.Severity = "medium"
	case "session opened":
		event.Severity = "info"
	case "session closed":
		event.Severity = "low"
	default:
		event.Severity = "low"
	}

	event.Message = fmt.Sprintf("PAM %s for user %s via %s: %s", result, user, service, module)

	// Устанавливаем пользователя
	event.User = &models.User{Name: user}
	event.UserName = user

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["auth_method"] = "pam"
	event.Labels["service"] = service
	event.Labels["module"] = module
	event.Labels["result"] = result

	return event, nil
}

// parseGenericAuth парсит общее событие аутентификации // v1.0
func (p *LinuxAuthParser) parseGenericAuth(raw string, event *models.Event) (*models.Event, error) {
	event.Subtype = "authentication_event"
	event.Severity = "low"
	event.Message = "Generic authentication event"

	// Пытаемся извлечь базовую информацию
	if strings.Contains(raw, "failed") || strings.Contains(raw, "error") {
		event.Severity = "medium"
		event.Subtype = "auth_failure"
	}

	if strings.Contains(raw, "success") || strings.Contains(raw, "accepted") {
		event.Severity = "info"
		event.Subtype = "auth_success"
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["parser"] = "linux_auth"
	event.Labels["parsed"] = "generic"

	return event, nil
}

// GetSupportedCategories возвращает список поддерживаемых категорий // v1.0
func (p *LinuxAuthParser) GetSupportedCategories() []string {
	return []string{"authentication"}
}

// GetSupportedSources возвращает список поддерживаемых источников // v1.0
func (p *LinuxAuthParser) GetSupportedSources() []string {
	return []string{"linux_auth", "sshd", "sudo", "su", "pam_unix"}
}

// GetSupportedSubtypes возвращает список поддерживаемых подтипов // v1.0
func (p *LinuxAuthParser) GetSupportedSubtypes() []string {
	return []string{
		"ssh_login_failed", "ssh_login_success", "ssh_disconnect",
		"sudo_command", "sudo_error", "su_command", "pam_authentication",
		"authentication_event", "auth_failure", "auth_success",
	}
}

// ParseEvent парсит событие (для совместимости с интерфейсом) // v1.0
func (p *LinuxAuthParser) ParseEvent(event *models.Event) (*models.Event, error) {
	if event == nil || event.Raw == "" {
		return nil, fmt.Errorf("empty event or raw data")
	}

	return p.Parse(event.Raw, event)
}
