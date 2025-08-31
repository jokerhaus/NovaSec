// internal/models/event.go
package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Event представляет единую модель события для SIEM/HIDS платформы
type Event struct {
	TS        time.Time            `json:"ts" validate:"required"`
	Host      string               `json:"host" validate:"required"`
	AgentID   string               `json:"agent_id"`
	Env       string               `json:"env"`
	Source    string               `json:"source"`
	Severity  string               `json:"severity"`
	Category  string               `json:"category" validate:"required"`
	Subtype   string               `json:"subtype" validate:"required"`
	Message   string               `json:"message" validate:"required"`
	User      *User                `json:"user,omitempty"`
	Network   *Network             `json:"network,omitempty"`
	File      *File                `json:"file,omitempty"`
	Process   *Process             `json:"process,omitempty"`
	Hashes    *Hashes              `json:"hashes,omitempty"`
	Labels    map[string]string    `json:"labels,omitempty"`
	Enrich    *Enrichment          `json:"enrich,omitempty"`
	Raw       string               `json:"raw,omitempty"`
}

// User представляет информацию о пользователе
type User struct {
	Name string `json:"name"`
	UID  *int   `json:"uid,omitempty"`
}

// Network представляет сетевую информацию
type Network struct {
	SrcIP   *int   `json:"src_ip,omitempty"`
	SrcPort *int   `json:"src_port,omitempty"`
	DstIP   *int   `json:"dst_ip,omitempty"`
	DstPort *int   `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`
}

// File представляет информацию о файле
type File struct {
	Path string `json:"path"`
}

// Process представляет информацию о процессе
type Process struct {
	PID  *int   `json:"pid,omitempty"`
	Name string `json:"name"`
}

// Hashes представляет хеши файла
type Hashes struct {
	SHA256 string `json:"sha256"`
}

// Enrichment представляет обогащенные данные
type Enrichment struct {
	Geo string `json:"geo,omitempty"`
	ASN *int   `json:"asn,omitempty"`
	IOC string `json:"ioc,omitempty"`
}

// NewEventFromNDJSON создает новое событие из NDJSON строки // v1.0
func NewEventFromNDJSON(ndjsonLine string) (*Event, error) {
	ndjsonLine = strings.TrimSpace(ndjsonLine)
	if ndjsonLine == "" {
		return nil, fmt.Errorf("empty NDJSON line")
	}

	var event Event
	if err := json.Unmarshal([]byte(ndjsonLine), &event); err != nil {
		return nil, fmt.Errorf("failed to parse NDJSON: %w", err)
	}

	// Валидация обязательных полей
	if event.TS.IsZero() {
		return nil, fmt.Errorf("timestamp is required")
	}
	if event.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if event.Category == "" {
		return nil, fmt.Errorf("category is required")
	}
	if event.Subtype == "" {
		return nil, fmt.Errorf("subtype is required")
	}
	if event.Message == "" {
		return nil, fmt.Errorf("message is required")
	}

	// Установка значений по умолчанию
	if event.Env == "" {
		event.Env = "production"
	}
	if event.Severity == "" {
		event.Severity = "info"
	}
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}

	return &event, nil
}

// ToJSON возвращает событие в JSON формате // v1.0
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// GetDedupKey возвращает ключ для дедупликации // v1.0
func (e *Event) GetDedupKey() string {
	return fmt.Sprintf("%s:%s:%s:%s", e.Host, e.Category, e.Subtype, e.Source)
}

// IsHighSeverity проверяет, является ли событие высокоприоритетным // v1.0
func (e *Event) IsHighSeverity() bool {
	return e.Severity == "high" || e.Severity == "critical"
}

// GetNetworkIPAsString возвращает IP адрес как строку // v1.0
func (e *Event) GetNetworkIPAsString() string {
	if e.Network == nil {
		return ""
	}
	if e.Network.SrcIP != nil {
		return fmt.Sprintf("%d", *e.Network.SrcIP)
	}
	if e.Network.DstIP != nil {
		return fmt.Sprintf("%d", *e.Network.DstIP)
	}
	return ""
}

// AddLabel добавляет метку к событию // v1.0
func (e *Event) AddLabel(key, value string) {
	if e.Labels == nil {
		e.Labels = make(map[string]string)
	}
	e.Labels[key] = value
}

// GetLabel возвращает значение метки // v1.0
func (e *Event) GetLabel(key string) string {
	if e.Labels == nil {
		return ""
	}
	return e.Labels[key]
}

// SetTimestampFromUnix устанавливает timestamp из Unix timestamp // v1.0
func (e *Event) SetTimestampFromUnix(unix int64) {
	e.TS = time.Unix(unix, 0)
}

// SetTimestampFromUnixMilli устанавливает timestamp из Unix timestamp в миллисекундах // v1.0
func (e *Event) SetTimestampFromUnixMilli(unixMilli int64) {
	e.TS = time.UnixMilli(unixMilli)
}

// ParseIPPort парсит IP:port строку // v1.0
func ParseIPPort(ipPort string) (string, int, error) {
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid IP:port format: %s", ipPort)
	}
	
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", parts[1])
	}
	
	return parts[0], port, nil
}
