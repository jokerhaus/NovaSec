// filename: internal/models/rule.go
package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// Rule представляет правило корреляции
type Rule struct {
	ID        string        `json:"id" db:"id"`
	Name      string        `json:"name" db:"name"`
	Version   int           `json:"version" db:"version"`
	YAML      string        `json:"yaml" db:"yaml"`
	Enabled   bool          `json:"enabled" db:"enabled"`
	CreatedAt time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt time.Time     `json:"updated_at" db:"updated_at"`
	Compiled  *CompiledRule `json:"compiled,omitempty"`
}

// CompiledRule представляет скомпилированное правило
type CompiledRule struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
	Window      time.Duration       `json:"window"`
	GroupBy     []string            `json:"group_by"`
	Threshold   int                 `json:"threshold"`
	Suppress    time.Duration       `json:"suppress"`
	Actions     []string            `json:"actions"`
	Conditions  []CompiledCondition `json:"conditions"`
}

// CompiledCondition представляет скомпилированное условие
type CompiledCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// RuleAction представляет действие правила
type RuleAction string

const (
	ActionAlert  RuleAction = "alert"
	ActionBlock  RuleAction = "block"
	ActionLog    RuleAction = "log"
	ActionNotify RuleAction = "notify"
)

// NewRule создает новое правило // v1.0
func NewRule(id, name, yaml string) *Rule {
	now := time.Now()
	return &Rule{
		ID:        id,
		Name:      name,
		Version:   1,
		YAML:      yaml,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ToJSON возвращает правило в JSON формате // v1.0
func (r *Rule) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// UpdateVersion увеличивает версию правила // v1.0
func (r *Rule) UpdateVersion() {
	r.Version++
	r.UpdatedAt = time.Now()
}

// Enable включает правило // v1.0
func (r *Rule) Enable() {
	r.Enabled = true
	r.UpdatedAt = time.Now()
}

// Disable отключает правило // v1.0
func (r *Rule) Disable() {
	r.Enabled = false
	r.UpdatedAt = time.Now()
}

// IsActive проверяет, активно ли правило // v1.0
func (r *Rule) IsActive() bool {
	return r.Enabled && r.Compiled != nil
}

// GetCompiledRule возвращает скомпилированное правило // v1.0
func (r *Rule) GetCompiledRule() *CompiledRule {
	return r.Compiled
}

// SetCompiledRule устанавливает скомпилированное правило // v1.0
func (r *Rule) SetCompiledRule(compiled *CompiledRule) {
	r.Compiled = compiled
	r.UpdatedAt = time.Now()
}

// Validate проверяет корректность правила // v1.0
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.YAML == "" {
		return fmt.Errorf("rule YAML is required")
	}
	if r.Version <= 0 {
		return fmt.Errorf("rule version must be positive")
	}
	return nil
}

// Clone создает копию правила // v1.0
func (r *Rule) Clone() *Rule {
	clone := *r
	if r.Compiled != nil {
		clone.Compiled = &CompiledRule{}
		*clone.Compiled = *r.Compiled
	}
	return &clone
}

// GetAge возвращает возраст правила // v1.0
func (r *Rule) GetAge() time.Duration {
	return time.Since(r.CreatedAt)
}

// IsStale проверяет, является ли правило устаревшим // v1.0
func (r *Rule) IsStale(threshold time.Duration) bool {
	return r.GetAge() > threshold
}
