// filename: internal/normalizer/parsers/nginx_access.go
package parsers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"novasec/internal/models"
)

// NginxAccessParser парсер для nginx access логов // v1.0
type NginxAccessParser struct {
	name     string
	patterns map[string]*regexp.Regexp
}

// NewNginxAccessParser создает новый парсер nginx access логов // v1.0
func NewNginxAccessParser() Parser {
	patterns := map[string]*regexp.Regexp{
		// Стандартный combined формат
		"combined": regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[^"]*" (\d+) (\d+|-) "([^"]*)" "([^"]*)"(?: "([^"]*)")?`),
		// Общий формат (common)
		"common": regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[^"]*" (\d+) (\d+|-)`),
		// JSON формат
		"json": regexp.MustCompile(`^\s*\{.*\}\s*$`),
	}

	return &NginxAccessParser{
		name:     "nginx_access",
		patterns: patterns,
	}
}

// GetName возвращает имя парсера // v1.0
func (p *NginxAccessParser) GetName() string {
	return p.name
}

// GetPriority возвращает приоритет парсера // v1.0
func (p *NginxAccessParser) GetPriority() int {
	return 60 // Средний приоритет
}

// CanParse определяет, может ли парсер обработать данное сырое событие // v1.0
func (p *NginxAccessParser) CanParse(raw string) bool {
	// Проверяем наличие типичных элементов nginx access лога
	indicators := []string{
		`"GET `,
		`"POST `,
		`"PUT `,
		`"DELETE `,
		`"HEAD `,
		`"OPTIONS `,
		` HTTP/`,
		`Mozilla/`,
		`curl/`,
		`nginx`,
	}

	for _, indicator := range indicators {
		if strings.Contains(raw, indicator) {
			return true
		}
	}

	// Проверяем паттерны
	for _, pattern := range p.patterns {
		if pattern.MatchString(raw) {
			return true
		}
	}

	return false
}

// Parse парсит сырое событие в структурированную модель // v1.0
func (p *NginxAccessParser) Parse(raw string, baseEvent *models.Event) (*models.Event, error) {
	if baseEvent == nil {
		baseEvent = &models.Event{
			TS:       time.Now(),
			Category: "web",
			Raw:      raw,
		}
	}

	// Устанавливаем базовые поля
	baseEvent.Source = "nginx"
	baseEvent.Category = "web"
	baseEvent.Raw = raw

	// Пытаемся найти совпадение с паттернами
	for patternName, pattern := range p.patterns {
		if matches := pattern.FindStringSubmatch(raw); matches != nil {
			return p.parseByPattern(patternName, matches, baseEvent)
		}
	}

	// Если конкретный паттерн не найден, создаем общее событие
	return p.parseGenericAccess(raw, baseEvent)
}

// parseByPattern парсит событие по конкретному паттерну // v1.0
func (p *NginxAccessParser) parseByPattern(patternName string, matches []string, event *models.Event) (*models.Event, error) {
	switch patternName {
	case "combined":
		return p.parseCombinedFormat(matches, event)
	case "common":
		return p.parseCommonFormat(matches, event)
	case "json":
		return p.parseJSONFormat(matches[0], event)
	default:
		return p.parseGenericAccess(event.Raw, event)
	}
}

// parseCombinedFormat парсит combined формат // v1.0
func (p *NginxAccessParser) parseCombinedFormat(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 10 {
		return nil, fmt.Errorf("insufficient matches for combined format")
	}

	clientIP := matches[1]
	user := matches[2]
	timestamp := matches[3]
	method := matches[4]
	uri := matches[5]
	statusCode := matches[6]
	responseSize := matches[7]
	referer := matches[8]
	userAgent := matches[9]

	// Парсим timestamp
	if parsedTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestamp); err == nil {
		event.TS = parsedTime
	}

	// Определяем подтип и важность
	event.Subtype = "http_request"
	event.Severity = p.determineSeverity(method, statusCode, uri)
	event.Message = fmt.Sprintf("%s %s %s - %s", method, uri, statusCode, clientIP)

	// Устанавливаем сетевую информацию
	event.Network = &models.Network{
		SrcIP: clientIP,
		Proto: "tcp",
	}
	event.SrcIP = clientIP
	event.Proto = "tcp"

	// Устанавливаем пользователя (если есть)
	if user != "-" {
		event.User = &models.User{Name: user}
		event.UserName = user
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["http_method"] = method
	event.Labels["http_uri"] = uri
	event.Labels["http_status"] = statusCode
	event.Labels["http_size"] = responseSize
	event.Labels["http_referer"] = referer
	event.Labels["http_user_agent"] = userAgent
	event.Labels["access_type"] = "combined"

	// Определяем потенциальные угрозы
	p.detectThreats(event, method, uri, statusCode, userAgent)

	return event, nil
}

// parseCommonFormat парсит common формат // v1.0
func (p *NginxAccessParser) parseCommonFormat(matches []string, event *models.Event) (*models.Event, error) {
	if len(matches) < 8 {
		return nil, fmt.Errorf("insufficient matches for common format")
	}

	clientIP := matches[1]
	user := matches[2]
	timestamp := matches[3]
	method := matches[4]
	uri := matches[5]
	statusCode := matches[6]
	responseSize := matches[7]

	// Парсим timestamp
	if parsedTime, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestamp); err == nil {
		event.TS = parsedTime
	}

	// Определяем подтип и важность
	event.Subtype = "http_request"
	event.Severity = p.determineSeverity(method, statusCode, uri)
	event.Message = fmt.Sprintf("%s %s %s - %s", method, uri, statusCode, clientIP)

	// Устанавливаем сетевую информацию
	event.Network = &models.Network{
		SrcIP: clientIP,
		Proto: "tcp",
	}
	event.SrcIP = clientIP
	event.Proto = "tcp"

	// Устанавливаем пользователя (если есть)
	if user != "-" {
		event.User = &models.User{Name: user}
		event.UserName = user
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["http_method"] = method
	event.Labels["http_uri"] = uri
	event.Labels["http_status"] = statusCode
	event.Labels["http_size"] = responseSize
	event.Labels["access_type"] = "common"

	// Определяем потенциальные угрозы
	p.detectThreats(event, method, uri, statusCode, "")

	return event, nil
}

// parseJSONFormat парсит JSON формат // v1.0
func (p *NginxAccessParser) parseJSONFormat(raw string, event *models.Event) (*models.Event, error) {
	// Парсим JSON лог
	var logEntry struct {
		Time      string  `json:"time"`
		Method    string  `json:"method"`
		URI       string  `json:"uri"`
		Status    int     `json:"status"`
		UserAgent string  `json:"user_agent"`
		IP        string  `json:"ip"`
		Referer   string  `json:"referer"`
		Bytes     int64   `json:"bytes"`
		Duration  float64 `json:"duration"`
	}

	if err := json.Unmarshal([]byte(raw), &logEntry); err != nil {
		return nil, fmt.Errorf("failed to parse JSON log: %w", err)
	}

	// Заполняем событие
	event.Subtype = "http_request_json"
	event.Severity = p.determineSeverity(logEntry.Method, strconv.Itoa(logEntry.Status), logEntry.URI)
	event.Message = fmt.Sprintf("HTTP %s %s - %d", logEntry.Method, logEntry.URI, logEntry.Status)

	// Добавляем сетевую информацию
	if logEntry.IP != "" {
		event.Network = &models.Network{
			SrcIP: logEntry.IP,
			Proto: "http",
		}
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["access_type"] = "json"
	event.Labels["parser"] = "nginx_access"
	event.Labels["method"] = logEntry.Method
	event.Labels["status"] = strconv.Itoa(logEntry.Status)
	event.Labels["user_agent"] = logEntry.UserAgent
	event.Labels["referer"] = logEntry.Referer
	event.Labels["bytes"] = strconv.FormatInt(logEntry.Bytes, 10)
	event.Labels["duration"] = strconv.FormatFloat(logEntry.Duration, 'f', 3, 64)

	// Определяем угрозы
	p.detectThreats(event, logEntry.Method, logEntry.URI, strconv.Itoa(logEntry.Status), logEntry.UserAgent)

	return event, nil
}

// determineSeverity определяет важность события // v1.0
func (p *NginxAccessParser) determineSeverity(method, statusCode, uri string) string {
	status, _ := strconv.Atoi(statusCode)

	// Критические ошибки сервера
	if status >= 500 {
		return "high"
	}

	// Ошибки клиента
	if status >= 400 {
		// Особо важные коды ошибок
		if status == 401 || status == 403 || status == 404 {
			return "medium"
		}
		return "low"
	}

	// Подозрительные URI
	suspiciousPatterns := []string{
		"../", "..\\", "..", "passwd", "shadow", "etc/", "proc/",
		"admin", "wp-admin", "phpMyAdmin", "login", "shell",
		"cmd", "exec", "eval", "system", "script", "sql",
	}

	uriLower := strings.ToLower(uri)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(uriLower, pattern) {
			return "medium"
		}
	}

	// Подозрительные методы
	if method == "PUT" || method == "DELETE" || method == "PATCH" {
		return "medium"
	}

	// Успешные запросы
	if status >= 200 && status < 300 {
		return "info"
	}

	return "low"
}

// detectThreats определяет потенциальные угрозы // v1.0
func (p *NginxAccessParser) detectThreats(event *models.Event, method, uri, statusCode, userAgent string) {
	threats := []string{}

	// SQL Injection
	sqlPatterns := []string{"'", "union", "select", "insert", "update", "delete", "drop", "exec"}
	uriLower := strings.ToLower(uri)
	for _, pattern := range sqlPatterns {
		if strings.Contains(uriLower, pattern) {
			threats = append(threats, "sql_injection")
			break
		}
	}

	// XSS
	xssPatterns := []string{"<script", "javascript:", "onload=", "onerror=", "alert("}
	for _, pattern := range xssPatterns {
		if strings.Contains(uriLower, pattern) {
			threats = append(threats, "xss")
			break
		}
	}

	// Directory Traversal
	if strings.Contains(uri, "../") || strings.Contains(uri, "..\\") {
		threats = append(threats, "directory_traversal")
	}

	// Command Injection
	cmdPatterns := []string{"|", "&", ";", "`", "$", "cmd", "exec", "system"}
	for _, pattern := range cmdPatterns {
		if strings.Contains(uriLower, pattern) {
			threats = append(threats, "command_injection")
			break
		}
	}

	// Brute Force (множественные 401/403)
	status, _ := strconv.Atoi(statusCode)
	if status == 401 || status == 403 {
		threats = append(threats, "auth_bruteforce")
	}

	// Bot Detection
	if userAgent != "" {
		botPatterns := []string{"bot", "crawler", "spider", "scraper", "scanner"}
		uaLower := strings.ToLower(userAgent)
		for _, pattern := range botPatterns {
			if strings.Contains(uaLower, pattern) {
				threats = append(threats, "bot_activity")
				break
			}
		}
	}

	// Добавляем угрозы в метки
	if len(threats) > 0 {
		event.Labels["threats"] = strings.Join(threats, ",")
		// Повышаем важность если обнаружены угрозы
		if event.Severity == "info" || event.Severity == "low" {
			event.Severity = "medium"
		}
	}
}

// parseGenericAccess парсит общий access лог // v1.0
func (p *NginxAccessParser) parseGenericAccess(raw string, event *models.Event) (*models.Event, error) {
	event.Subtype = "web_access"
	event.Severity = "info"
	event.Message = "Generic web access event"

	// Пытаемся извлечь базовую информацию
	if strings.Contains(raw, " 4") || strings.Contains(raw, " 5") {
		event.Severity = "medium"
		event.Subtype = "web_error"
	}

	// Добавляем метки
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["parser"] = "nginx_access"
	event.Labels["parsed"] = "generic"

	return event, nil
}

// GetSupportedCategories возвращает список поддерживаемых категорий // v1.0
func (p *NginxAccessParser) GetSupportedCategories() []string {
	return []string{"web"}
}

// GetSupportedSources возвращает список поддерживаемых источников // v1.0
func (p *NginxAccessParser) GetSupportedSources() []string {
	return []string{"nginx", "nginx_access", "httpd", "apache"}
}

// GetSupportedSubtypes возвращает список поддерживаемых подтипов // v1.0
func (p *NginxAccessParser) GetSupportedSubtypes() []string {
	return []string{
		"http_request", "http_request_json", "web_access", "web_error",
	}
}

// ParseEvent парсит событие (для совместимости с интерфейсом) // v1.0
func (p *NginxAccessParser) ParseEvent(event *models.Event) (*models.Event, error) {
	if event == nil || event.Raw == "" {
		return nil, fmt.Errorf("empty event or raw data")
	}

	return p.Parse(event.Raw, event)
}
