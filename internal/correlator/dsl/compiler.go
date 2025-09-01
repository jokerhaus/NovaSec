// filename: internal/correlator/dsl/compiler.go
package dsl

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"novasec/internal/models"
)

// Compiler компилирует YAML правила в исполняемые структуры // v1.0
type Compiler struct {
	// Кэш скомпилированных правил
	compiledRules map[string]*CompiledRule
}

// NewCompiler создает новый компилятор DSL // v1.0
func NewCompiler() *Compiler {
	return &Compiler{
		compiledRules: make(map[string]*CompiledRule),
	}
}

// CompileRule компилирует правило в исполняемую структуру // v1.0
func (c *Compiler) CompileRule(rule *Rule) (*CompiledRule, error) {
	// Проверяем кэш
	if cached, exists := c.compiledRules[rule.ID]; exists {
		// Проверяем, изменилось ли правило
		if c.isRuleChanged(rule, cached.Rule) {
			// Правило изменилось, перекомпилируем
		} else {
			// Правило не изменилось, возвращаем кэшированное
			return cached, nil
		}
	}

	// Валидируем правило
	if err := ValidateRule(rule); err != nil {
		return nil, fmt.Errorf("rule validation failed: %w", err)
	}

	// Создаем матчер событий
	matcher, err := c.createEventMatcher(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to create event matcher: %w", err)
	}

	// Создаем оценщик временных окон
	evaluator, err := c.createWindowEvaluator(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to create window evaluator: %w", err)
	}

	// Создаем исполнители действий
	actions, err := c.createActionExecutors(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to create action executors: %w", err)
	}

	compiledRule := &CompiledRule{
		Rule:      rule,
		Matcher:   matcher,
		Evaluator: evaluator,
		Actions:   actions,
	}

	// Кэшируем скомпилированное правило
	c.compiledRules[rule.ID] = compiledRule

	return compiledRule, nil
}

// createEventMatcher создает матчер событий для правила // v1.0
func (c *Compiler) createEventMatcher(rule *Rule) (EventMatcher, error) {
	matcher := &CompositeEventMatcher{
		conditions: rule.Conditions,
		priority:   c.calculatePriority(rule),
	}

	return matcher, nil
}

// createWindowEvaluator создает оценщик временных окон // v1.0
func (c *Compiler) createWindowEvaluator(rule *Rule) (WindowEvaluator, error) {
	evaluator := NewSlidingWindowEvaluator(
		rule.ID,
		rule.Window.Duration,
		rule.Threshold,
		rule.GroupBy,
		rule.Window.Sliding,
	)
	return evaluator, nil
}

// createActionExecutors создает исполнители действий // v1.0
func (c *Compiler) createActionExecutors(rule *Rule) ([]ActionExecutor, error) {
	var executors []ActionExecutor

	for _, action := range rule.Actions {
		executor, err := c.createActionExecutor(action)
		if err != nil {
			return nil, fmt.Errorf("failed to create action executor for %s: %w", action.Type, err)
		}
		executors = append(executors, executor)
	}

	return executors, nil
}

// createActionExecutor создает исполнитель для конкретного действия // v1.0
func (c *Compiler) createActionExecutor(action Action) (ActionExecutor, error) {
	switch action.Type {
	case "create_alert":
		return &CreateAlertAction{
			actionType: action.Type,
			config:     action.Config,
		}, nil
	case "send_email":
		return &SendEmailAction{
			actionType: action.Type,
			config:     action.Config,
			delay:      action.Delay,
			retry:      action.Retry,
			timeout:    action.Timeout,
		}, nil
	case "send_telegram":
		return &SendTelegramAction{
			actionType: action.Type,
			config:     action.Config,
			delay:      action.Delay,
			retry:      action.Retry,
			timeout:    action.Timeout,
		}, nil
	case "webhook":
		return &WebhookAction{
			actionType: action.Type,
			config:     action.Config,
			delay:      action.Delay,
			retry:      action.Retry,
			timeout:    action.Timeout,
		}, nil
	case "log":
		return &LogAction{
			actionType: action.Type,
			config:     action.Config,
		}, nil
	case "script":
		return &ScriptAction{
			actionType: action.Type,
			config:     action.Config,
			timeout:    action.Timeout,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

// calculatePriority вычисляет приоритет правила // v1.0
func (c *Compiler) calculatePriority(rule *Rule) int {
	priority := 0

	// Базовый приоритет по важности
	switch rule.Severity {
	case "critical":
		priority += 100
	case "high":
		priority += 80
	case "medium":
		priority += 60
	case "low":
		priority += 40
	}

	// Дополнительный приоритет по сложности условий
	priority += len(rule.Conditions) * 5

	// Приоритет по типу порога
	if rule.Threshold.Type == "unique" {
		priority += 10
	}

	// Приоритет по размеру окна (меньше окно = выше приоритет)
	if rule.Window.Duration < time.Minute {
		priority += 20
	} else if rule.Window.Duration < time.Hour {
		priority += 10
	}

	return priority
}

// GetCompiledRule возвращает скомпилированное правило из кэша // v1.0
func (c *Compiler) GetCompiledRule(ruleID string) (*CompiledRule, bool) {
	rule, exists := c.compiledRules[ruleID]
	return rule, exists
}

// ClearCache очищает кэш скомпилированных правил // v1.0
func (c *Compiler) ClearCache() {
	c.compiledRules = make(map[string]*CompiledRule)
}

// GetCacheStats возвращает статистику кэша // v1.0
func (c *Compiler) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"total_rules": len(c.compiledRules),
		"cache_size":  len(c.compiledRules),
	}
}

// CompositeEventMatcher составной матчер событий // v1.0
type CompositeEventMatcher struct {
	conditions []Condition
	priority   int
}

// Match проверяет, соответствует ли событие условиям правила // v1.0
func (m *CompositeEventMatcher) Match(event *models.Event) bool {
	for _, condition := range m.conditions {
		if !m.evaluateCondition(event, condition) {
			return false
		}
	}
	return true
}

// GetPriority возвращает приоритет матчера // v1.0
func (m *CompositeEventMatcher) GetPriority() int {
	return m.priority
}

// evaluateCondition оценивает одно условие // v1.0
func (m *CompositeEventMatcher) evaluateCondition(event *models.Event, condition Condition) bool {
	value := m.extractFieldValue(event, condition.Field)
	result := m.compareValues(value, condition.Operator, condition.Value)

	if condition.Invert {
		return !result
	}
	return result
}

// extractFieldValue извлекает значение поля из события // v1.0
func (m *CompositeEventMatcher) extractFieldValue(event *models.Event, field string) string {
	switch field {
	case "host":
		return event.Host
	case "agent_id":
		return event.AgentID
	case "env":
		return event.Env
	case "source":
		return event.Source
	case "severity":
		return event.Severity
	case "category":
		return event.Category
	case "subtype":
		return event.Subtype
	case "message":
		return event.Message
	case "user.name":
		if event.User != nil {
			return event.User.Name
		}
		return ""
	case "network.src_ip":
		if event.Network != nil && event.Network.SrcIP != "" {
			return event.Network.SrcIP
		}
		return ""
	case "network.src_port":
		if event.Network != nil && event.Network.SrcPort != nil {
			return strconv.Itoa(*event.Network.SrcPort)
		}
		return ""
	case "network.proto":
		if event.Network != nil {
			return event.Network.Proto
		}
		return ""
	case "file.path":
		if event.File != nil {
			return event.File.Path
		}
		return ""
	case "process.name":
		if event.Process != nil {
			return event.Process.Name
		}
		return ""
	case "process.pid":
		if event.Process != nil && event.Process.PID != nil {
			return strconv.Itoa(*event.Process.PID)
		}
		return ""
	default:
		// Проверяем метки
		if event.Labels != nil {
			if value, exists := event.Labels[field]; exists {
				return value
			}
		}
		return ""
	}
}

// compareValues сравнивает значения согласно оператору // v1.0
func (m *CompositeEventMatcher) compareValues(actual, operator, expected string) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "ne":
		return actual != expected
	case "contains":
		return strings.Contains(actual, expected)
	case "startswith":
		return strings.HasPrefix(actual, expected)
	case "endswith":
		return strings.HasSuffix(actual, expected)
	case "regex":
		if matched, err := regexp.MatchString(expected, actual); err == nil {
			return matched
		}
		return false
	case "in":
		values := strings.Split(expected, ",")
		for _, value := range values {
			if strings.TrimSpace(value) == actual {
				return true
			}
		}
		return false
	case "nin":
		values := strings.Split(expected, ",")
		for _, value := range values {
			if strings.TrimSpace(value) == actual {
				return false
			}
		}
		return true
	case "gt", "gte", "lt", "lte":
		return m.compareNumeric(actual, operator, expected)
	default:
		return false
	}
}

// compareNumeric сравнивает числовые значения // v1.0
func (m *CompositeEventMatcher) compareNumeric(actual, operator, expected string) bool {
	actualNum, err1 := strconv.ParseFloat(actual, 64)
	expectedNum, err2 := strconv.ParseFloat(expected, 64)

	if err1 != nil || err2 != nil {
		return false
	}

	switch operator {
	case "gt":
		return actualNum > expectedNum
	case "gte":
		return actualNum >= expectedNum
	case "lt":
		return actualNum < expectedNum
	case "lte":
		return actualNum <= expectedNum
	default:
		return false
	}
}

// Дублирующиеся определения SlidingWindowEvaluator удалены. Используется реализация из evaluator.go

// isRuleChanged проверяет, изменилось ли правило // v1.0
func (c *Compiler) isRuleChanged(newRule, oldRule *Rule) bool {
	// Простая проверка по имени и описанию
	if newRule.Name != oldRule.Name {
		return true
	}
	if newRule.Description != oldRule.Description {
		return true
	}
	if newRule.Severity != oldRule.Severity {
		return true
	}
	if newRule.Enabled != oldRule.Enabled {
		return true
	}

	// Проверяем Window конфигурацию
	if newRule.Window.Duration != oldRule.Window.Duration {
		return true
	}
	if newRule.Window.Sliding != oldRule.Window.Sliding {
		return true
	}

	// Проверяем Threshold конфигурацию
	if newRule.Threshold.Count != oldRule.Threshold.Count {
		return true
	}
	if newRule.Threshold.Type != oldRule.Threshold.Type {
		return true
	}
	if newRule.Threshold.Field != oldRule.Threshold.Field {
		return true
	}

	// Проверяем Suppress конфигурацию
	if newRule.Suppress.Duration != oldRule.Suppress.Duration {
		return true
	}
	if newRule.Suppress.Key != oldRule.Suppress.Key {
		return true
	}

	// Проверяем количество условий и действий
	if len(newRule.Conditions) != len(oldRule.Conditions) {
		return true
	}
	if len(newRule.Actions) != len(oldRule.Actions) {
		return true
	}

	// TODO: Добавить более детальную проверку условий и действий
	// Пока считаем, что если количество изменилось, то правило изменилось

	return false
}
