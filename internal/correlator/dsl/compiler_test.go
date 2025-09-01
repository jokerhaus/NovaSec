// filename: internal/correlator/dsl/compiler_test.go
package dsl

import (
	"testing"
	"time"
)

func TestNewCompiler(t *testing.T) {
	compiler := NewCompiler()
	if compiler == nil {
		t.Fatal("NewCompiler() returned nil")
	}
	if compiler.compiledRules == nil {
		t.Error("compiledRules map not initialized")
	}
}

func TestCompileRule_ValidRule(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:          "test_rule",
		Name:        "Test Rule",
		Description: "A test rule for testing",
		Severity:    "high",
		Enabled:     true,
		Window: WindowConfig{
			Duration: 5 * time.Minute,
			Sliding:  true,
		},
		Threshold: ThresholdConfig{
			Count: 3,
			Type:  "count",
			Field: "user",
		},
		Suppress: SuppressConfig{
			Duration: 1 * time.Hour,
			Key:      "user:host",
		},
		Conditions: []Condition{
			{
				Field:    "user",
				Operator: "eq",
				Value:    "testuser",
			},
		},
		Actions: []Action{
			{
				Type: "create_alert",
				Config: map[string]interface{}{
					"severity": "high",
					"message":  "Test alert triggered",
				},
			},
		},
	}

	compiledRule, err := compiler.CompileRule(rule)
	if err != nil {
		t.Fatalf("CompileRule failed: %v", err)
	}

	if compiledRule == nil {
		t.Fatal("CompileRule returned nil")
	}

	if compiledRule.Rule != rule {
		t.Error("CompiledRule.Rule does not match original rule")
	}

	if compiledRule.Matcher == nil {
		t.Error("CompiledRule.Matcher is nil")
	}

	if compiledRule.Evaluator == nil {
		t.Error("CompiledRule.Evaluator is nil")
	}

	if len(compiledRule.Actions) != 1 {
		t.Errorf("Expected 1 action, got %d", len(compiledRule.Actions))
	}

	// Проверяем кэширование
	if len(compiler.compiledRules) != 1 {
		t.Errorf("Expected 1 cached rule, got %d", len(compiler.compiledRules))
	}

	if compiler.compiledRules["test_rule"] != compiledRule {
		t.Error("Cached rule does not match compiled rule")
	}
}

func TestCompileRule_InvalidRule(t *testing.T) {
	compiler := NewCompiler()

	// Правило без ID
	invalidRule := &Rule{
		Name:        "Invalid Rule",
		Description: "Rule without ID",
		Severity:    "high",
	}

	_, err := compiler.CompileRule(invalidRule)
	if err == nil {
		t.Error("Expected error for rule without ID")
	}

	// Правило без действий
	invalidRule2 := &Rule{
		ID:          "invalid_rule_2",
		Name:        "Invalid Rule 2",
		Description: "Rule without actions",
		Severity:    "high",
		Actions:     []Action{},
	}

	_, err = compiler.CompileRule(invalidRule2)
	if err == nil {
		t.Error("Expected error for rule without actions")
	}
}

func TestCompileRule_DuplicateID(t *testing.T) {
	compiler := NewCompiler()

	rule1 := &Rule{
		ID:          "duplicate_id",
		Name:        "First Rule",
		Description: "First rule with duplicate ID",
		Severity:    "high",
		Window: WindowConfig{
			Duration: 5 * time.Minute,
			Sliding:  true,
		},
		Threshold: ThresholdConfig{
			Count: 3,
			Type:  "count",
			Field: "user",
		},
		Suppress: SuppressConfig{
			Duration: 1 * time.Hour,
			Key:      "user:host",
		},
		Actions: []Action{
			{Type: "create_alert", Config: map[string]interface{}{"message": "First"}},
		},
	}

	rule2 := &Rule{
		ID:          "duplicate_id",
		Name:        "Second Rule",
		Description: "Second rule with duplicate ID",
		Severity:    "medium",
		Window: WindowConfig{
			Duration: 5 * time.Minute,
			Sliding:  true,
		},
		Threshold: ThresholdConfig{
			Count: 3,
			Type:  "count",
			Field: "user",
		},
		Suppress: SuppressConfig{
			Duration: 1 * time.Hour,
			Key:      "user:host",
		},
		Actions: []Action{
			{Type: "create_alert", Config: map[string]interface{}{"message": "Second"}},
		},
	}

	// Компилируем первое правило
	compiled1, err := compiler.CompileRule(rule1)
	if err != nil {
		t.Fatalf("Failed to compile first rule: %v", err)
	}

	// Компилируем второе правило (должно перезаписать первое)
	compiled2, err := compiler.CompileRule(rule2)
	if err != nil {
		t.Fatalf("Failed to compile second rule: %v", err)
	}

	// Проверяем, что в кэше только одно правило
	if len(compiler.compiledRules) != 1 {
		t.Errorf("Expected 1 cached rule, got %d", len(compiler.compiledRules))
	}

	// Проверяем, что кэшировано второе правило
	cachedRule := compiler.compiledRules["duplicate_id"]
	if cachedRule != compiled2 {
		t.Error("Cached rule is not the second compiled rule")
	}

	if cachedRule.Rule.Name != "Second Rule" {
		t.Errorf("Expected cached rule name 'Second Rule', got '%s'", cachedRule.Rule.Name)
	}

	// Проверяем, что первое правило больше не в кэше
	if compiler.compiledRules["duplicate_id"] == compiled1 {
		t.Error("First rule should not be cached anymore")
	}
}

func TestCreateEventMatcher(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:       "test_rule",
		Name:     "Test Rule",
		Severity: "high",
		Conditions: []Condition{
			{
				Field:    "user",
				Operator: "eq",
				Value:    "testuser",
			},
			{
				Field:    "category",
				Operator: "eq",
				Value:    "auth",
			},
		},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	matcher, err := compiler.createEventMatcher(rule)
	if err != nil {
		t.Fatalf("createEventMatcher failed: %v", err)
	}

	if matcher == nil {
		t.Fatal("createEventMatcher returned nil")
	}

	// Проверяем, что матчер реализует интерфейс EventMatcher
	if _, ok := matcher.(EventMatcher); !ok {
		t.Error("Returned matcher does not implement EventMatcher interface")
	}
}

func TestCreateWindowEvaluator(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:       "test_rule",
		Name:     "Test Rule",
		Severity: "high",
		Window: WindowConfig{
			Duration: 10 * time.Minute,
			Sliding:  true,
		},
		Threshold: ThresholdConfig{
			Count: 5,
			Type:  "unique",
			Field: "user",
		},
		GroupBy: []string{"host", "user"},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	evaluator, err := compiler.createWindowEvaluator(rule)
	if err != nil {
		t.Fatalf("createWindowEvaluator failed: %v", err)
	}

	if evaluator == nil {
		t.Fatal("createWindowEvaluator returned nil")
	}

	// Проверяем, что оценщик реализует интерфейс WindowEvaluator
	if _, ok := evaluator.(WindowEvaluator); !ok {
		t.Error("Returned evaluator does not implement WindowEvaluator interface")
	}
}

func TestCreateActionExecutors(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:       "test_rule",
		Name:     "Test Rule",
		Severity: "high",
		Actions: []Action{
			{
				Type: "create_alert",
				Config: map[string]interface{}{
					"severity": "high",
					"message":  "Test alert",
				},
			},
			{
				Type: "send_email",
				Config: map[string]interface{}{
					"to":      "admin@example.com",
					"subject": "Test notification",
				},
			},
		},
	}

	executors, err := compiler.createActionExecutors(rule)
	if err != nil {
		t.Fatalf("createActionExecutors failed: %v", err)
	}

	if len(executors) != 2 {
		t.Errorf("Expected 2 action executors, got %d", len(executors))
	}

	// Проверяем, что каждый исполнитель реализует интерфейс ActionExecutor
	for i, executor := range executors {
		if _, ok := executor.(ActionExecutor); !ok {
			t.Errorf("Executor %d does not implement ActionExecutor interface", i)
		}
	}
}

func TestCreateActionExecutor_UnsupportedType(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:       "test_rule",
		Name:     "Test Rule",
		Severity: "high",
		Actions: []Action{
			{
				Type: "unsupported_action_type",
				Config: map[string]interface{}{
					"param": "value",
				},
			},
		},
	}

	_, err := compiler.createActionExecutors(rule)
	if err == nil {
		t.Error("Expected error for unsupported action type")
	}
}

func TestCompilerCache(t *testing.T) {
	compiler := NewCompiler()

	rule := &Rule{
		ID:       "cached_rule",
		Name:     "Cached Rule",
		Severity: "high",
		Window: WindowConfig{
			Duration: 5 * time.Minute,
			Sliding:  true,
		},
		Threshold: ThresholdConfig{
			Count: 3,
			Type:  "count",
			Field: "user",
		},
		Suppress: SuppressConfig{
			Duration: 1 * time.Hour,
			Key:      "user:host",
		},
		Actions: []Action{
			{Type: "create_alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	// Компилируем правило первый раз
	compiled1, err := compiler.CompileRule(rule)
	if err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}

	// Компилируем то же правило второй раз (должно вернуть кэшированное)
	compiled2, err := compiler.CompileRule(rule)
	if err != nil {
		t.Fatalf("Failed to compile rule second time: %v", err)
	}

	// Проверяем, что возвращается тот же объект
	if compiled1 != compiled2 {
		t.Error("Second compilation did not return cached rule")
	}

	// Проверяем размер кэша
	if len(compiler.compiledRules) != 1 {
		t.Errorf("Expected 1 cached rule, got %d", len(compiler.compiledRules))
	}
}

func TestCompilerConcurrency(t *testing.T) {
	compiler := NewCompiler()

	// Создаем несколько правил для конкурентной компиляции
	rules := []*Rule{
		{
			ID:       "rule_1",
			Name:     "Rule 1",
			Severity: "high",
			Window: WindowConfig{
				Duration: 5 * time.Minute,
				Sliding:  true,
			},
			Threshold: ThresholdConfig{
				Count: 3,
				Type:  "count",
				Field: "user",
			},
			Suppress: SuppressConfig{
				Duration: 1 * time.Hour,
				Key:      "user:host",
			},
			Actions: []Action{{Type: "create_alert", Config: map[string]interface{}{"message": "Rule 1"}}},
		},
		{
			ID:       "rule_2",
			Name:     "Rule 2",
			Severity: "medium",
			Window: WindowConfig{
				Duration: 5 * time.Minute,
				Sliding:  true,
			},
			Threshold: ThresholdConfig{
				Count: 3,
				Type:  "count",
				Field: "user",
			},
			Suppress: SuppressConfig{
				Duration: 1 * time.Hour,
				Key:      "user:host",
			},
			Actions: []Action{{Type: "create_alert", Config: map[string]interface{}{"message": "Rule 2"}}},
		},
		{
			ID:       "rule_3",
			Name:     "Rule 3",
			Severity: "low",
			Window: WindowConfig{
				Duration: 5 * time.Minute,
				Sliding:  true,
			},
			Threshold: ThresholdConfig{
				Count: 3,
				Type:  "count",
				Field: "user",
			},
			Suppress: SuppressConfig{
				Duration: 1 * time.Hour,
				Key:      "user:host",
			},
			Actions: []Action{{Type: "create_alert", Config: map[string]interface{}{"message": "Rule 3"}}},
		},
	}

	// Запускаем конкурентную компиляцию
	done := make(chan bool, len(rules))

	for _, rule := range rules {
		go func(r *Rule) {
			_, err := compiler.CompileRule(r)
			if err != nil {
				t.Errorf("Failed to compile rule %s: %v", r.ID, err)
			}
			done <- true
		}(rule)
	}

	// Ждем завершения всех горутин
	for i := 0; i < len(rules); i++ {
		<-done
	}

	// Проверяем, что все правила скомпилированы
	if len(compiler.compiledRules) != len(rules) {
		t.Errorf("Expected %d compiled rules, got %d", len(rules), len(compiler.compiledRules))
	}

	// Проверяем каждое правило
	for _, rule := range rules {
		if _, exists := compiler.compiledRules[rule.ID]; !exists {
			t.Errorf("Rule %s not found in cache", rule.ID)
		}
	}
}
