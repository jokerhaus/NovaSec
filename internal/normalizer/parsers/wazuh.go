// filename: internal/normalizer/parsers/wazuh.go
package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"novasec/internal/models"
)

// WazuhParser парсер для событий Wazuh агента // v1.0
type WazuhParser struct {
	name string
}

// WazuhEvent представляет структуру события Wazuh // v1.0
type WazuhEvent struct {
	Timestamp   string                 `json:"timestamp"`
	Rule        WazuhRule              `json:"rule"`
	Agent       WazuhAgent             `json:"agent"`
	Manager     WazuhManager           `json:"manager"`
	ID          string                 `json:"id"`
	FullLog     string                 `json:"full_log"`
	Location    string                 `json:"location"`
	Decoders    []WazuhDecoder         `json:"decoders"`
	Decoder     WazuhDecoderInfo       `json:"decoder"`
	Data        map[string]interface{} `json:"data"`
	Predecoder  WazuhPredecoder        `json:"predecoder"`
	Input       WazuhInput             `json:"input"`
	GeoLocation WazuhGeoLocation       `json:"geoLocation"`
	Cluster     WazuhCluster           `json:"cluster"`
}

// WazuhRule представляет правило Wazuh // v1.0
type WazuhRule struct {
	Level       int      `json:"level"`
	Description string   `json:"description"`
	ID          string   `json:"id"`
	Firedtimes  int      `json:"firedtimes"`
	Mail        bool     `json:"mail"`
	Groups      []string `json:"groups"`
	PciDss      []string `json:"pci_dss"`
	Gpg13       []string `json:"gpg13"`
	Gdpr        []string `json:"gdpr"`
	Hipaa       []string `json:"hipaa"`
	Nist800     []string `json:"nist_800_53"`
	Tsc         []string `json:"tsc"`
	Mitre       []string `json:"mitre"`
}

// WazuhAgent представляет информацию об агенте // v1.0
type WazuhAgent struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	Version       string        `json:"version"`
	Build         string        `json:"build"`
	IP            string        `json:"ip"`
	Manager       string        `json:"manager"`
	OS            WazuhOS       `json:"os"`
	DateAdd       string        `json:"dateAdd"`
	LastKeepAlive string        `json:"lastKeepAlive"`
	Status        string        `json:"status"`
	Group         []string      `json:"group"`
	Sum           string        `json:"sum"`
	Sum2          string        `json:"sum2"`
	LastScan      WazuhLastScan `json:"lastScan"`
}

// WazuhOS представляет информацию об операционной системе // v1.0
type WazuhOS struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Platform string `json:"platform"`
	Major    string `json:"major"`
	Minor    string `json:"minor"`
	Build    string `json:"build"`
	Uname    string `json:"uname"`
}

// WazuhLastScan представляет информацию о последнем сканировании // v1.0
type WazuhLastScan struct {
	Time string `json:"time"`
}

// WazuhManager представляет информацию о менеджере // v1.0
type WazuhManager struct {
	Name string `json:"name"`
}

// WazuhDecoder представляет информацию о декодере // v1.0
type WazuhDecoder struct {
	Name string `json:"name"`
}

// WazuhDecoderInfo представляет информацию о декодере // v1.0
type WazuhDecoderInfo struct {
	Name string `json:"name"`
}

// WazuhPredecoder представляет информацию о преддекодере // v1.0
type WazuhPredecoder struct {
	ProgramName string `json:"program_name"`
	Timestamp   string `json:"timestamp"`
	Hostname    string `json:"hostname"`
}

// WazuhInput представляет информацию о входе // v1.0
type WazuhInput struct {
	Type string `json:"type"`
}

// WazuhGeoLocation представляет географическую информацию // v1.0
type WazuhGeoLocation struct {
	Location string `json:"location"`
}

// WazuhCluster представляет информацию о кластере // v1.0
type WazuhCluster struct {
	Node string `json:"node"`
}

// NewWazuhParser создает новый парсер Wazuh // v1.0
func NewWazuhParser() Parser {
	return &WazuhParser{
		name: "wazuh",
	}
}

// ParseEvent парсит событие Wazuh // v1.0
func (p *WazuhParser) ParseEvent(rawEvent *models.Event) (*models.Event, error) {
	if rawEvent == nil || rawEvent.Raw == "" {
		return nil, fmt.Errorf("empty event or raw data")
	}

	// Парсим JSON событие Wazuh
	var wazuhEvent WazuhEvent
	if err := json.Unmarshal([]byte(rawEvent.Raw), &wazuhEvent); err != nil {
		return nil, fmt.Errorf("failed to parse Wazuh JSON: %w", err)
	}

	// Создаем нормализованное событие
	normalizedEvent := &models.Event{
		TS:       p.parseTimestamp(wazuhEvent.Timestamp),
		Host:     wazuhEvent.Agent.Name,
		AgentID:  wazuhEvent.Agent.ID,
		Env:      rawEvent.Env,
		Source:   "wazuh",
		Category: p.determineCategory(wazuhEvent),
		Subtype:  p.determineSubtype(wazuhEvent),
		Severity: p.determineSeverity(wazuhEvent.Rule.Level),
		Message:  wazuhEvent.Rule.Description,
		Raw:      rawEvent.Raw,
		Labels:   make(map[string]string),
	}

	// Заполняем дополнительные поля
	p.fillAdditionalFields(normalizedEvent, wazuhEvent)

	// Заполняем плоские поля
	normalizedEvent.FillFlatFields()

	return normalizedEvent, nil
}

// parseTimestamp парсит timestamp Wazuh // v1.0
func (p *WazuhParser) parseTimestamp(timestamp string) time.Time {
	// Wazuh использует формат: "2023-12-01T10:30:45.123Z"
	if timestamp == "" {
		return time.Now()
	}

	// Пробуем разные форматы
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timestamp); err == nil {
			return t
		}
	}

	// Если не удалось распарсить, возвращаем текущее время
	return time.Now()
}

// determineCategory определяет категорию события // v1.0
func (p *WazuhParser) determineCategory(wazuhEvent WazuhEvent) string {
	// Анализируем группы правил для определения категории
	for _, group := range wazuhEvent.Rule.Groups {
		switch strings.ToLower(group) {
		case "authentication", "auth":
			return "authentication"
		case "network", "firewall":
			return "network"
		case "file_integrity", "fim":
			return "file_integrity"
		case "malware", "virus":
			return "malware"
		case "system", "syslog":
			return "system"
		case "web", "apache", "nginx":
			return "web"
		case "database", "mysql", "postgresql":
			return "database"
		case "windows", "windows_event":
			return "windows"
		case "linux", "unix":
			return "linux"
		}
	}

	// Анализируем описание правила
	description := strings.ToLower(wazuhEvent.Rule.Description)
	if strings.Contains(description, "login") || strings.Contains(description, "auth") {
		return "authentication"
	}
	if strings.Contains(description, "file") || strings.Contains(description, "integrity") {
		return "file_integrity"
	}
	if strings.Contains(description, "network") || strings.Contains(description, "firewall") {
		return "network"
	}
	if strings.Contains(description, "malware") || strings.Contains(description, "virus") {
		return "malware"
	}

	return "system"
}

// determineSubtype определяет подтип события // v1.0
func (p *WazuhParser) determineSubtype(wazuhEvent WazuhEvent) string {
	// Анализируем описание правила для определения подтипа
	description := strings.ToLower(wazuhEvent.Rule.Description)

	// Аутентификация
	if strings.Contains(description, "ssh") {
		if strings.Contains(description, "failed") || strings.Contains(description, "invalid") {
			return "ssh_login_failed"
		}
		if strings.Contains(description, "success") || strings.Contains(description, "accepted") {
			return "ssh_login_success"
		}
		return "ssh_event"
	}

	if strings.Contains(description, "sudo") {
		return "sudo_command"
	}

	if strings.Contains(description, "su ") {
		return "su_command"
	}

	// Файловая целостность
	if strings.Contains(description, "file") {
		if strings.Contains(description, "modified") || strings.Contains(description, "changed") {
			return "file_modified"
		}
		if strings.Contains(description, "created") || strings.Contains(description, "added") {
			return "file_created"
		}
		if strings.Contains(description, "deleted") {
			return "file_deleted"
		}
		return "file_integrity"
	}

	// Сеть
	if strings.Contains(description, "firewall") || strings.Contains(description, "blocked") {
		return "firewall_block"
	}

	if strings.Contains(description, "port") || strings.Contains(description, "connection") {
		return "network_connection"
	}

	// Malware
	if strings.Contains(description, "malware") || strings.Contains(description, "virus") {
		return "malware_detected"
	}

	// Windows события
	if strings.Contains(description, "windows") || strings.Contains(description, "event log") {
		return "windows_event"
	}

	return "wazuh_event"
}

// determineSeverity определяет серьезность события // v1.0
func (p *WazuhParser) determineSeverity(level int) string {
	switch {
	case level >= 12:
		return "critical"
	case level >= 8:
		return "high"
	case level >= 5:
		return "medium"
	case level >= 3:
		return "low"
	default:
		return "info"
	}
}

// fillAdditionalFields заполняет дополнительные поля события // v1.0
func (p *WazuhParser) fillAdditionalFields(event *models.Event, wazuhEvent WazuhEvent) {
	// Заполняем метки
	event.Labels["wazuh_rule_id"] = wazuhEvent.Rule.ID
	event.Labels["wazuh_rule_level"] = strconv.Itoa(wazuhEvent.Rule.Level)
	event.Labels["wazuh_agent_id"] = wazuhEvent.Agent.ID
	event.Labels["wazuh_agent_name"] = wazuhEvent.Agent.Name
	event.Labels["wazuh_agent_version"] = wazuhEvent.Agent.Version
	event.Labels["wazuh_manager"] = wazuhEvent.Manager.Name
	event.Labels["wazuh_decoder"] = wazuhEvent.Decoder.Name
	event.Labels["wazuh_location"] = wazuhEvent.Location

	// Добавляем группы правил как метки
	for i, group := range wazuhEvent.Rule.Groups {
		event.Labels[fmt.Sprintf("wazuh_group_%d", i)] = group
	}

	// Заполняем информацию о пользователе, если есть
	if user, ok := wazuhEvent.Data["user"]; ok {
		if userName, ok := user.(string); ok {
			event.User = &models.User{Name: userName}
			event.UserName = userName
		}
	} else if srcUser, ok := wazuhEvent.Data["srcuser"]; ok {
		if userName, ok := srcUser.(string); ok {
			event.User = &models.User{Name: userName}
			event.UserName = userName
		}
	}

	// Заполняем сетевую информацию, если есть
	if srcIP, ok := wazuhEvent.Data["srcip"]; ok {
		if srcIPStr, ok := srcIP.(string); ok {
			event.SrcIP = srcIPStr
			if event.Network == nil {
				event.Network = &models.Network{}
			}
			event.Network.SrcIP = srcIPStr
		}
	}

	if dstIP, ok := wazuhEvent.Data["dstip"]; ok {
		if dstIPStr, ok := dstIP.(string); ok {
			event.DstIP = dstIPStr
			if event.Network == nil {
				event.Network = &models.Network{}
			}
			event.Network.DstIP = dstIPStr
		}
	}

	// Заполняем протокол, если есть
	if protocol, ok := wazuhEvent.Data["protocol"]; ok {
		if protocolStr, ok := protocol.(string); ok {
			event.Proto = protocolStr
			if event.Network == nil {
				event.Network = &models.Network{}
			}
			event.Network.Proto = protocolStr
		}
	}

	// Заполняем информацию о файле, если есть
	if filePath, ok := wazuhEvent.Data["file"]; ok {
		if filePathStr, ok := filePath.(string); ok {
			event.File = &models.File{Path: filePathStr}
			event.FilePath = filePathStr
		}
	}

	// Заполняем информацию о процессе, если есть
	if processName, ok := wazuhEvent.Data["process"]; ok {
		if processNameStr, ok := processName.(string); ok {
			event.Process = &models.Process{Name: processNameStr}
			event.ProcessName = processNameStr
		}
	}

	if processPID, ok := wazuhEvent.Data["pid"]; ok {
		if pidStr, ok := processPID.(string); ok {
			if pid, err := strconv.Atoi(pidStr); err == nil {
				if event.Process == nil {
					event.Process = &models.Process{}
				}
				event.Process.PID = &pid
				event.ProcessPID = &pid
			}
		}
	}

	// Заполняем хеши, если есть
	if sha256, ok := wazuhEvent.Data["sha256"]; ok {
		if sha256Str, ok := sha256.(string); ok {
			event.Hashes = &models.Hashes{SHA256: sha256Str}
			event.SHA256 = sha256Str
		}
	}

	// Заполняем географическую информацию, если есть
	if geoLocation := wazuhEvent.GeoLocation.Location; geoLocation != "" {
		event.Enrich = &models.Enrichment{Geo: geoLocation}
		event.Geo = geoLocation
	}

	// Добавляем все дополнительные данные как метки
	for key, value := range wazuhEvent.Data {
		if valueStr, ok := value.(string); ok {
			event.Labels[fmt.Sprintf("wazuh_data_%s", key)] = valueStr
		}
	}
}

// GetSupportedSources возвращает список поддерживаемых источников // v1.0
func (p *WazuhParser) GetSupportedSources() []string {
	return []string{"wazuh", "wazuh-agent", "ossec"}
}

// GetSupportedCategories возвращает список поддерживаемых категорий // v1.0
func (p *WazuhParser) GetSupportedCategories() []string {
	return []string{
		"authentication", "file_integrity", "network", "malware",
		"system", "web", "database", "windows", "linux",
	}
}

// GetSupportedSubtypes возвращает список поддерживаемых подтипов // v1.0
func (p *WazuhParser) GetSupportedSubtypes() []string {
	return []string{
		"ssh_login_failed", "ssh_login_success", "ssh_event",
		"sudo_command", "su_command", "file_modified", "file_created",
		"file_deleted", "file_integrity", "firewall_block",
		"network_connection", "malware_detected", "windows_event",
		"wazuh_event",
	}
}
