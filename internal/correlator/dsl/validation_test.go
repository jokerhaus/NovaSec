// filename: internal/correlator/dsl/validation_test.go
package dsl

import (
	"testing"
	"time"
)

func TestValidateRule_ValidRule(t *testing.T) {
	rule := &Rule{
		ID:          "valid_rule",
		Name:        "Valid Rule",
		Description: "A valid rule for testing",
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
					"message":  "Test alert",
				},
			},
		},
	}

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for valid rule: %v", err)
	}
}

func TestValidateRule_MissingID(t *testing.T) {
	rule := &Rule{
		Name:        "Rule without ID",
		Description: "Rule missing ID field",
		Severity:    "high",
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule without ID")
	}
}

func TestValidateRule_EmptyID(t *testing.T) {
	rule := &Rule{
		ID:          "",
		Name:        "Rule with empty ID",
		Description: "Rule with empty ID field",
		Severity:    "high",
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with empty ID")
	}
}

func TestValidateRule_InvalidSeverity(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_severity_rule",
		Name:        "Rule with invalid severity",
		Description: "Rule with unsupported severity level",
		Severity:    "invalid_severity",
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with invalid severity")
	}
}

func TestValidateRule_ValidSeverities(t *testing.T) {
	validSeverities := []string{"low", "medium", "high", "critical"}

	for _, severity := range validSeverities {
		rule := &Rule{
			ID:          "severity_" + severity,
			Name:        "Rule with " + severity + " severity",
			Description: "Rule testing " + severity + " severity",
			Severity:    severity,
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

		err := ValidateRule(rule)
		if err != nil {
			t.Errorf("ValidateRule failed for severity '%s': %v", severity, err)
		}
	}
}

func TestValidateRule_NoActions(t *testing.T) {
	rule := &Rule{
		ID:          "no_actions_rule",
		Name:        "Rule without actions",
		Description: "Rule with empty actions slice",
		Severity:    "high",
		Actions:     []Action{},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule without actions")
	}
}

func TestValidateRule_NilActions(t *testing.T) {
	rule := &Rule{
		ID:          "nil_actions_rule",
		Name:        "Rule with nil actions",
		Description: "Rule with nil actions slice",
		Severity:    "high",
		Actions:     nil,
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with nil actions")
	}
}

func TestValidateRule_InvalidActionType(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_action_rule",
		Name:        "Rule with invalid action type",
		Description: "Rule with unsupported action type",
		Severity:    "high",
		Actions: []Action{
			{
				Type: "unsupported_action",
				Config: map[string]interface{}{
					"param": "value",
				},
			},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with invalid action type")
	}
}

func TestValidateRule_ValidActionTypes(t *testing.T) {
	validActionTypes := []string{"alert", "email", "webhook", "telegram"}

	for _, actionType := range validActionTypes {
		rule := &Rule{
			ID:          "action_" + actionType,
			Name:        "Rule with " + actionType + " action",
			Description: "Rule testing " + actionType + " action",
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
				{
					Type: actionType,
					Config: map[string]interface{}{
						"message": "Test " + actionType,
					},
				},
			},
		}

		err := ValidateRule(rule)
		if err != nil {
			t.Errorf("ValidateRule failed for action type '%s': %v", actionType, err)
		}
	}
}

func TestValidateRule_InvalidWindowDuration(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_window_rule",
		Name:        "Rule with invalid window duration",
		Description: "Rule with zero window duration",
		Severity:    "high",
		Window: WindowConfig{
			Duration: 0,
			Sliding:  true,
		},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with zero window duration")
	}
}

func TestValidateRule_InvalidThreshold(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_threshold_rule",
		Name:        "Rule with invalid threshold",
		Description: "Rule with zero threshold count",
		Severity:    "high",
		Threshold: ThresholdConfig{
			Count: 0,
			Type:  "count",
			Field: "user",
		},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with zero threshold count")
	}
}

func TestValidateRule_InvalidThresholdType(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_threshold_type_rule",
		Name:        "Rule with invalid threshold type",
		Description: "Rule with unsupported threshold type",
		Severity:    "high",
		Threshold: ThresholdConfig{
			Count: 5,
			Type:  "invalid_type",
			Field: "user",
		},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with invalid threshold type")
	}
}

func TestValidateRule_ValidThresholdTypes(t *testing.T) {
	validThresholdTypes := []string{"count", "unique"}

	for _, thresholdType := range validThresholdTypes {
		rule := &Rule{
			ID:          "threshold_" + thresholdType,
			Name:        "Rule with " + thresholdType + " threshold",
			Description: "Rule testing " + thresholdType + " threshold",
			Severity:    "high",
			Window: WindowConfig{
				Duration: 5 * time.Minute,
				Sliding:  true,
			},
			Threshold: ThresholdConfig{
				Count: 5,
				Type:  thresholdType,
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

		err := ValidateRule(rule)
		if err != nil {
			t.Errorf("ValidateRule failed for threshold type '%s': %v", thresholdType, err)
		}
	}
}

func TestValidateRule_InvalidConditionOperator(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_operator_rule",
		Name:        "Rule with invalid condition operator",
		Description: "Rule with unsupported condition operator",
		Severity:    "high",
		Conditions: []Condition{
			{
				Field:    "user",
				Operator: "invalid_operator",
				Value:    "testuser",
			},
		},
		Actions: []Action{
			{Type: "alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with invalid condition operator")
	}
}

func TestValidateRule_ValidConditionOperators(t *testing.T) {
	validOperators := []string{"eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "regex", "contains", "startswith", "endswith"}

	for _, operator := range validOperators {
		rule := &Rule{
			ID:          "operator_" + operator,
			Name:        "Rule with " + operator + " operator",
			Description: "Rule testing " + operator + " operator",
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
			Conditions: []Condition{
				{
					Field:    "user",
					Operator: operator,
					Value:    "testuser",
				},
			},
			Actions: []Action{
				{Type: "create_alert", Config: map[string]interface{}{"message": "Test"}},
			},
		}

		err := ValidateRule(rule)
		if err != nil {
			t.Errorf("ValidateRule failed for operator '%s': %v", operator, err)
		}
	}
}

func TestValidateRule_ComplexRule(t *testing.T) {
	rule := &Rule{
		ID:          "complex_rule",
		Name:        "Complex Rule",
		Description: "A complex rule with multiple conditions and actions",
		Severity:    "critical",
		Enabled:     true,
		Window: WindowConfig{
			Duration: 10 * time.Minute,
			Sliding:  false,
		},
		Threshold: ThresholdConfig{
			Count: 10,
			Type:  "unique",
			Field: "ip",
		},
		GroupBy: []string{"host", "user"},
		Suppress: SuppressConfig{
			Duration: 1 * time.Hour,
			Key:      "user:host",
		},
		Conditions: []Condition{
			{
				Field:    "category",
				Operator: "eq",
				Value:    "auth",
			},
			{
				Field:    "subtype",
				Operator: "eq",
				Value:    "login_failed",
			},
			{
				Field:    "severity",
				Operator: "gte",
				Value:    "medium",
			},
		},
		Actions: []Action{
			{
				Type: "create_alert",
				Config: map[string]interface{}{
					"severity": "critical",
					"message":  "Multiple failed login attempts detected",
				},
			},
			{
				Type: "send_email",
				Config: map[string]interface{}{
					"to":      "security@example.com",
					"subject": "Security Alert: Failed Login Attempts",
				},
			},
		},
	}

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for complex rule: %v", err)
	}
}

func TestValidateRule_SuppressionConfig(t *testing.T) {
	rule := &Rule{
		ID:          "suppression_rule",
		Name:        "Rule with Suppression",
		Description: "Rule testing suppression configuration",
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
			{Type: "create_alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err != nil {
		t.Errorf("ValidateRule failed for rule with suppression: %v", err)
	}
}

func TestValidateRule_InvalidSuppressionDuration(t *testing.T) {
	rule := &Rule{
		ID:          "invalid_suppression_rule",
		Name:        "Rule with Invalid Suppression",
		Description: "Rule testing invalid suppression duration",
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
			Duration: 0,
			Key:      "user:host",
		},
		Actions: []Action{
			{Type: "create_alert", Config: map[string]interface{}{"message": "Test"}},
		},
	}

	err := ValidateRule(rule)
	if err == nil {
		t.Error("Expected error for rule with zero suppression duration")
	}
}
