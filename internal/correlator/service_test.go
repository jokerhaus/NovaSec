// filename: internal/correlator/service_test.go
package correlator

import (
	"testing"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/correlator/dsl"
	"novasec/internal/models"
)

// createTestLogger создает logger для тестов
func createTestLogger(t *testing.T) *logging.Logger {
	config := logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}
	logger, err := logging.NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return logger
}

func TestService_CreateAlert(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем тестовое правило
	rule := &dsl.Rule{
		ID:          "test_rule",
		Name:        "Test Rule",
		Description: "Test rule description",
		Severity:    "high",
		Enabled:     true,
	}

	// Создаем скомпилированное правило
	compiledRule := &dsl.CompiledRule{
		Rule: rule,
		Evaluator: &MockEvaluator{
			groupKey: "test_host",
		},
	}

	// Создаем тестовое событие
	event := &models.Event{
		Host:     "test_host",
		Env:      "test",
		Category: "security",
		Subtype:  "test",
		TS:       time.Now(),
		Message:  "Test event message",
	}

	// Создаем сервис для тестирования
	service := &Service{
		logger: logger,
	}

	// Создаем алерт
	alert, err := service.createAlert(compiledRule, event)
	if err != nil {
		t.Fatalf("createAlert failed: %v", err)
	}

	if alert == nil {
		t.Fatal("createAlert returned nil alert")
	}

	// Проверяем поля алерта
	if alert.RuleID != rule.ID {
		t.Errorf("Alert RuleID wrong: got %s want %s", alert.RuleID, rule.ID)
	}

	if alert.Severity != rule.Severity {
		t.Errorf("Alert Severity wrong: got %s want %s", alert.Severity, rule.Severity)
	}

	if alert.Status != "new" {
		t.Errorf("Alert Status wrong: got %s want %s", alert.Status, "new")
	}

	if alert.Host != event.Host {
		t.Errorf("Alert Host wrong: got %s want %s", alert.Host, event.Host)
	}

	if alert.Env != event.Env {
		t.Errorf("Alert Env wrong: got %s want %s", alert.Env, event.Env)
	}

	// Проверяем DedupKey
	expectedDedupKey := "test_rule:test_host:high"
	if alert.DedupKey != expectedDedupKey {
		t.Errorf("Alert DedupKey wrong: got %s want %s", alert.DedupKey, expectedDedupKey)
	}

	// Проверяем Payload
	if alert.Payload == nil {
		t.Fatal("Alert Payload is nil")
	}

	if payload, ok := alert.Payload["rule_name"]; !ok || payload != rule.Name {
		t.Error("Alert Payload missing or wrong rule_name")
	}

	if payload, ok := alert.Payload["rule_description"]; !ok || payload != rule.Description {
		t.Error("Alert Payload missing or wrong rule_description")
	}

	if payload, ok := alert.Payload["triggering_event"]; !ok || payload != event {
		t.Error("Alert Payload missing or wrong triggering_event")
	}

	if payload, ok := alert.Payload["group_key"]; !ok || payload != "test_host" {
		t.Error("Alert Payload missing or wrong group_key")
	}
}

// MockEvaluator мок для Evaluator
type MockEvaluator struct {
	groupKey      string
	shouldTrigger bool
}

func (m *MockEvaluator) AddEvent(event *models.Event) bool {
	return m.shouldTrigger
}

func (m *MockEvaluator) IsTriggered() bool {
	return m.shouldTrigger
}

func (m *MockEvaluator) GetGroupKey(event *models.Event) string {
	return m.groupKey
}

func (m *MockEvaluator) GetWindowStart() time.Time {
	return time.Now().Add(-5 * time.Minute)
}

func (m *MockEvaluator) GetWindowEnd() time.Time {
	return time.Now().Add(5 * time.Minute)
}

func (m *MockEvaluator) Reset() {
	// Ничего не делаем в моке
}
