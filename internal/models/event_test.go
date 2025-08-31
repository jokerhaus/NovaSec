// internal/models/event_test.go
// NovaSec Event Model Tests

package models

import (
	"testing"
	"time"
)

func TestNewEventFromNDJSON(t *testing.T) {
	validJSON := `{"ts":"2024-01-01T12:00:00Z","host":"test-host","category":"test","subtype":"test","message":"test message"}`
	
	event, err := NewEventFromNDJSON(validJSON)
	if err != nil {
		t.Fatalf("Failed to parse valid JSON: %v", err)
	}
	
	if event.Host != "test-host" {
		t.Errorf("Expected host 'test-host', got '%s'", event.Host)
	}
	
	if event.Category != "test" {
		t.Errorf("Expected category 'test', got '%s'", event.Category)
	}
}

func TestEventValidation(t *testing.T) {
	event := &Event{
		TS:       time.Now(),
		Host:     "test-host",
		Category: "test",
		Subtype:  "test",
		Message:  "test message",
	}
	
	if event.Host == "" || event.Category == "" || event.Subtype == "" || event.Message == "" {
		t.Error("Event should have all required fields")
	}
}

func TestEventDefaultValues(t *testing.T) {
	event := &Event{
		TS:       time.Now(),
		Host:     "server-01",
		Category: "auth",
		Subtype:  "login",
		Message:  "Test message",
	}

	if event.Env == "" {
		event.Env = "production"
	}

	if event.Severity == "" {
		event.Severity = "info"
	}

	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}

	if event.Env != "production" {
		t.Errorf("Expected Env to be 'production', got %s", event.Env)
	}

	if event.Severity != "info" {
		t.Errorf("Expected Severity to be 'info', got %s", event.Severity)
	}

	if event.Labels == nil {
		t.Error("Expected Labels to be initialized")
	}
}

func TestEventMethods(t *testing.T) {
	event := &Event{
		TS:       time.Now(),
		Host:     "server-01",
		Category: "auth",
		Subtype:  "login",
		Message:  "Test message",
		Source:   "test",
		Labels:   make(map[string]string),
	}

	// Test GetDedupKey
	dedupKey := event.GetDedupKey()
	expectedKey := "server-01:auth:login:test"
	if dedupKey != expectedKey {
		t.Errorf("GetDedupKey() = %v, want %v", dedupKey, expectedKey)
	}

	// Test AddLabel
	event.AddLabel("test_key", "test_value")
	if event.Labels["test_key"] != "test_value" {
		t.Error("AddLabel() failed to add label")
	}

	// Test GetLabel
	labelValue := event.GetLabel("test_key")
	if labelValue != "test_value" {
		t.Errorf("GetLabel() = %v, want %v", labelValue, "test_value")
	}

	// Test IsHighSeverity
	event.Severity = "high"
	if !event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return true for high severity")
	}

	event.Severity = "info"
	if event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return false for info severity")
	}
}
