// filename: internal/correlator/dsl/types.go
package dsl

import (
	"fmt"
	"time"

	"novasec/internal/models"
)

// Rule представляет правило корреляции // v1.0
type Rule struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Severity    string                 `yaml:"severity" json:"severity"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Window      WindowConfig           `yaml:"window" json:"window"`
	GroupBy     []string               `yaml:"group_by" json:"group_by"`
	Threshold   ThresholdConfig        `yaml:"threshold" json:"threshold"`
	Suppress    SuppressConfig         `yaml:"suppress" json:"suppress"`
	Actions     []Action               `yaml:"actions" json:"actions"`
	Conditions  []Condition            `yaml:"conditions" json:"conditions"`
	Metadata    map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// WindowConfig конфигурация временного окна // v1.0
type WindowConfig struct {
	Duration time.Duration `yaml:"duration" json:"duration"`
	Sliding  bool          `yaml:"sliding" json:"sliding"`
}

// ThresholdConfig конфигурация порога срабатывания // v1.0
type ThresholdConfig struct {
	Count int    `yaml:"count" json:"count"`
	Type  string `yaml:"type" json:"type"`   // "count" или "unique"
	Field string `yaml:"field" json:"field"` // поле для unique подсчета
}

// SuppressConfig конфигурация подавления // v1.0
type SuppressConfig struct {
	Duration time.Duration `yaml:"duration" json:"duration"`
	Key      string        `yaml:"key" json:"key"` // ключ подавления
}

// Action действие при срабатывании правила // v1.0
type Action struct {
	Type    string                 `yaml:"type" json:"type"`
	Config  map[string]interface{} `yaml:"config" json:"config"`
	Delay   time.Duration          `yaml:"delay" json:"delay"`
	Retry   int                    `yaml:"retry" json:"retry"`
	Timeout time.Duration          `yaml:"timeout" json:"timeout"`
}

// Condition условие для срабатывания правила // v1.0
type Condition struct {
	Field    string `yaml:"field" json:"field"`
	Operator string `yaml:"operator" json:"operator"`
	Value    string `yaml:"value" json:"value"`
	Invert   bool   `yaml:"invert" json:"invert"`
}

// CompiledRule скомпилированное правило // v1.0
type CompiledRule struct {
	Rule      *Rule
	Matcher   EventMatcher
	Evaluator WindowEvaluator
	Actions   []ActionExecutor
}

// EventMatcher интерфейс для сопоставления событий // v1.0
type EventMatcher interface {
	Match(event *models.Event) bool
	GetPriority() int
}

// WindowEvaluator интерфейс для оценки временных окон // v1.0
type WindowEvaluator interface {
	AddEvent(event *models.Event) bool
	IsTriggered() bool
	GetGroupKey(event *models.Event) string
	GetWindowStart() time.Time
	GetWindowEnd() time.Time
	Reset()
}

// ActionExecutor интерфейс для выполнения действий // v1.0
type ActionExecutor interface {
	Execute(alert *models.Alert) error
	GetType() string
	GetConfig() map[string]interface{}
}

// WindowState состояние временного окна // v1.0
type WindowState struct {
	RuleID      string
	GroupKey    string
	StartTime   time.Time
	EndTime     time.Time
	EventCount  int
	UniqueCount map[string]int
	LastEvent   time.Time
}

// AlertContext контекст для создания алерта // v1.0
type AlertContext struct {
	Rule      *Rule
	Events    []*models.Event
	GroupKey  string
	Count     int
	Unique    map[string]int
	Window    WindowState
	Timestamp time.Time
}

// MatchResult результат сопоставления события // v1.0
type MatchResult struct {
	Matched  bool
	RuleID   string
	GroupKey string
	Priority int
}

// EvaluationResult результат оценки правила // v1.0
type EvaluationResult struct {
	Triggered bool
	Alert     *models.Alert
	Error     error
}

// RuleStats статистика по правилу // v1.0
type RuleStats struct {
	RuleID           string
	EventCount       int64
	MatchCount       int64
	TriggerCount     int64
	LastTrigger      time.Time
	AverageWindow    time.Duration
	SuppressionCount int64
}

// SupportedOperators поддерживаемые операторы сравнения // v1.0
var SupportedOperators = map[string]string{
	"eq":         "equals",
	"ne":         "not equals",
	"gt":         "greater than",
	"gte":        "greater than or equal",
	"lt":         "less than",
	"lte":        "less than or equal",
	"in":         "in list",
	"nin":        "not in list",
	"regex":      "regular expression",
	"contains":   "contains",
	"startswith": "starts with",
	"endswith":   "ends with",
}

// SupportedSeverities поддерживаемые уровни важности // v1.0
var SupportedSeverities = []string{
	"low", "medium", "high", "critical",
}

// SupportedActionTypes поддерживаемые типы действий // v1.0
var SupportedActionTypes = []string{
	"create_alert", "send_email", "send_telegram", "webhook", "log", "script",
}

// ValidateRule валидирует правило корреляции // v1.0
func ValidateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Severity == "" {
		return fmt.Errorf("rule severity is required")
	}
	if !isValidSeverity(rule.Severity) {
		return fmt.Errorf("invalid severity: %s", rule.Severity)
	}
	if rule.Window.Duration <= 0 {
		return fmt.Errorf("window duration must be positive")
	}
	if rule.Threshold.Count <= 0 {
		return fmt.Errorf("threshold count must be positive")
	}
	if !isValidThresholdType(rule.Threshold.Type) {
		return fmt.Errorf("invalid threshold type: %s", rule.Threshold.Type)
	}
	if rule.Suppress.Duration <= 0 {
		return fmt.Errorf("suppress duration must be positive")
	}
	return nil
}

// isValidSeverity проверяет валидность уровня важности // v1.0
func isValidSeverity(severity string) bool {
	for _, s := range SupportedSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

// isValidThresholdType проверяет валидность типа порога // v1.0
func isValidThresholdType(thresholdType string) bool {
	return thresholdType == "count" || thresholdType == "unique"
}
