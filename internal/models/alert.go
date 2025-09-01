// filename: internal/models/alert.go
package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Alert представляет алерт, сгенерированный коррелятором
type Alert struct {
	ID        string                 `json:"id" db:"id"`
	TS        time.Time              `json:"ts" db:"ts"`
	RuleID    string                 `json:"rule_id" db:"rule_id"`
	Severity  string                 `json:"severity" db:"severity"`
	DedupKey  string                 `json:"dedup_key" db:"dedup_key"`
	Payload   map[string]interface{} `json:"payload" db:"payload"`
	Status    string                 `json:"status" db:"status"`
	Env       string                 `json:"env" db:"env"`
	Host      string                 `json:"host" db:"host"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// AlertStatus представляет статус алерта
type AlertStatus string

const (
	AlertStatusNew          AlertStatus = "new"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusClosed       AlertStatus = "closed"
)

// NewAlert создает новый алерт // v1.0
func NewAlert(ruleID, severity, dedupKey, env, host string, payload map[string]interface{}) *Alert {
	now := time.Now()
	return &Alert{
		ID:        uuid.New().String(),
		TS:        now,
		RuleID:    ruleID,
		Severity:  severity,
		DedupKey:  dedupKey,
		Payload:   payload,
		Status:    string(AlertStatusNew),
		Env:       env,
		Host:      host,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ToJSON возвращает алерт в JSON формате // v1.0
func (a *Alert) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}

// UpdateStatus обновляет статус алерта // v1.0
func (a *Alert) UpdateStatus(status AlertStatus) {
	a.Status = string(status)
	a.UpdatedAt = time.Now()
}

// IsHighPriority проверяет, является ли алерт высокоприоритетным // v1.0
func (a *Alert) IsHighPriority() bool {
	return a.Severity == "high" || a.Severity == "critical"
}

// GetPayloadValue возвращает значение из payload по ключу // v1.0
func (a *Alert) GetPayloadValue(key string) interface{} {
	if a.Payload == nil {
		return nil
	}
	return a.Payload[key]
}

// GetPayloadString возвращает строковое значение из payload // v1.0
func (a *Alert) GetPayloadString(key string) string {
	if val := a.GetPayloadValue(key); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// GetPayloadInt возвращает целочисленное значение из payload // v1.0
func (a *Alert) GetPayloadInt(key string) int {
	if val := a.GetPayloadValue(key); val != nil {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := fmt.Sscanf(v, "%d", new(int)); err == nil {
				return i
			}
		}
	}
	return 0
}

// AddPayloadValue добавляет значение в payload // v1.0
func (a *Alert) AddPayloadValue(key string, value interface{}) {
	if a.Payload == nil {
		a.Payload = make(map[string]interface{})
	}
	a.Payload[key] = value
}

// GetAge возвращает возраст алерта // v1.0
func (a *Alert) GetAge() time.Duration {
	return time.Since(a.CreatedAt)
}

// IsStale проверяет, является ли алерт устаревшим // v1.0
func (a *Alert) IsStale(threshold time.Duration) bool {
	return a.GetAge() > threshold
}

// Clone создает копию алерта // v1.0
func (a *Alert) Clone() *Alert {
	clone := *a
	if a.Payload != nil {
		clone.Payload = make(map[string]interface{})
		for k, v := range a.Payload {
			clone.Payload[k] = v
		}
	}
	return &clone
}
