// filename: internal/normalizer/parsers/interface_test.go
package parsers

import (
	"errors"
	"testing"
	"time"

	"novasec/internal/models"
)

// MockParser реализует интерфейс Parser для тестирования
type MockParser struct {
	name            string
	supportedSource string
	priority        int
	canParse        bool
	parseResult     *models.Event
	parseError      error
}

func (m *MockParser) GetName() string {
	return m.name
}

func (m *MockParser) GetSupportedSources() []string {
	return []string{m.supportedSource}
}

func (m *MockParser) GetPriority() int {
	return m.priority
}

func (m *MockParser) CanParse(source string) bool {
	return m.canParse
}

func (m *MockParser) ParseEvent(rawEvent interface{}) (*models.Event, error) {
	if m.parseError != nil {
		return nil, m.parseError
	}
	return m.parseResult, nil
}

func TestParserInterface_GetName(t *testing.T) {
	parser := &MockParser{
		name: "test_parser",
	}

	if parser.GetName() != "test_parser" {
		t.Errorf("Expected name 'test_parser', got %s", parser.GetName())
	}
}

func TestParserInterface_GetSupportedSources(t *testing.T) {
	parser := &MockParser{
		supportedSource: "nginx",
	}

	sources := parser.GetSupportedSources()
	if len(sources) != 1 {
		t.Errorf("Expected 1 supported source, got %d", len(sources))
	}
	if sources[0] != "nginx" {
		t.Errorf("Expected supported source 'nginx', got %s", sources[0])
	}
}

func TestParserInterface_GetPriority(t *testing.T) {
	parser := &MockParser{
		priority: 10,
	}

	if parser.GetPriority() != 10 {
		t.Errorf("Expected priority 10, got %d", parser.GetPriority())
	}
}

func TestParserInterface_CanParse(t *testing.T) {
	parser := &MockParser{
		canParse: true,
	}

	if !parser.CanParse("nginx") {
		t.Error("Expected CanParse to return true")
	}

	parser.canParse = false
	if parser.CanParse("nginx") {
		t.Error("Expected CanParse to return false")
	}
}

func TestParserInterface_ParseEvent_Success(t *testing.T) {
	expectedEvent := &models.Event{
		TS:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Host:     "testhost",
		Source:   "nginx",
		Category: "web",
		Subtype:  "access",
		Severity: "info",
		Message:  "GET / 200",
	}

	parser := &MockParser{
		parseResult: expectedEvent,
		parseError:  nil,
	}

	event, err := parser.ParseEvent("raw_event_data")
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	if event == nil {
		t.Fatal("ParseEvent returned nil event")
	}

	if event.Source != expectedEvent.Source {
		t.Errorf("Expected Source %s, got %s", expectedEvent.Source, event.Source)
	}
	if event.Category != expectedEvent.Category {
		t.Errorf("Expected Category %s, got %s", expectedEvent.Category, event.Category)
	}
	if event.Subtype != expectedEvent.Subtype {
		t.Errorf("Expected Subtype %s, got %s", expectedEvent.Subtype, event.Subtype)
	}
	if event.Severity != expectedEvent.Severity {
		t.Errorf("Expected Severity %s, got %s", expectedEvent.Severity, event.Severity)
	}
}

func TestParserInterface_ParseEvent_Error(t *testing.T) {
	expectedError := errors.New("parsing failed")
	parser := &MockParser{
		parseResult: nil,
		parseError:  expectedError,
	}

	event, err := parser.ParseEvent("raw_event_data")
	if err == nil {
		t.Error("Expected ParseEvent to return error")
	}
	if err.Error() != expectedError.Error() {
		t.Errorf("Expected error '%s', got '%v'", expectedError.Error(), err.Error())
	}
	if event != nil {
		t.Error("Expected ParseEvent to return nil event on error")
	}
}

func TestParserInterface_MultipleSupportedSources(t *testing.T) {
	parser := &MockParser{
		supportedSource: "nginx,apache,iis",
	}

	sources := parser.GetSupportedSources()
	if len(sources) != 1 {
		t.Errorf("Expected 1 supported source, got %d", len(sources))
	}
	if sources[0] != "nginx,apache,iis" {
		t.Errorf("Expected supported source 'nginx,apache,iis', got %s", sources[0])
	}
}

func TestParserInterface_ZeroPriority(t *testing.T) {
	parser := &MockParser{
		priority: 0,
	}

	if parser.GetPriority() != 0 {
		t.Errorf("Expected priority 0, got %d", parser.GetPriority())
	}
}

func TestParserInterface_NegativePriority(t *testing.T) {
	parser := &MockParser{
		priority: -5,
	}

	if parser.GetPriority() != -5 {
		t.Errorf("Expected priority -5, got %d", parser.GetPriority())
	}
}

func TestParserInterface_EmptyName(t *testing.T) {
	parser := &MockParser{
		name: "",
	}

	if parser.GetName() != "" {
		t.Errorf("Expected empty name, got %s", parser.GetName())
	}
}

func TestParserInterface_EmptySupportedSource(t *testing.T) {
	parser := &MockParser{
		supportedSource: "",
	}

	sources := parser.GetSupportedSources()
	if len(sources) != 1 {
		t.Errorf("Expected 1 supported source, got %d", len(sources))
	}
	if sources[0] != "" {
		t.Errorf("Expected empty supported source, got %s", sources[0])
	}
}

func TestParserInterface_CanParseWithEmptySource(t *testing.T) {
	parser := &MockParser{
		canParse: true,
	}

	if !parser.CanParse("") {
		t.Error("Expected CanParse to return true for empty source")
	}
}

func TestParserInterface_ParseEventWithNilInput(t *testing.T) {
	expectedEvent := &models.Event{
		Source:   "test",
		Category: "test",
	}

	parser := &MockParser{
		parseResult: expectedEvent,
		parseError:  nil,
	}

	event, err := parser.ParseEvent(nil)
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	if event == nil {
		t.Fatal("ParseEvent returned nil event")
	}
}

func TestParserInterface_ParseEventWithEmptyInput(t *testing.T) {
	expectedEvent := &models.Event{
		Source:   "test",
		Category: "test",
	}

	parser := &MockParser{
		parseResult: expectedEvent,
		parseError:  nil,
	}

	event, err := parser.ParseEvent("")
	if err != nil {
		t.Fatalf("ParseEvent failed: %v", err)
	}

	if event == nil {
		t.Fatal("ParseEvent returned nil event")
	}
}

func TestParserInterface_ConsistentBehavior(t *testing.T) {
	parser := &MockParser{
		name:            "consistent_parser",
		supportedSource: "consistent_source",
		priority:        5,
		canParse:        true,
	}

	// Проверяем, что методы возвращают консистентные значения
	name1 := parser.GetName()
	name2 := parser.GetName()
	if name1 != name2 {
		t.Error("GetName should return consistent values")
	}

	sources1 := parser.GetSupportedSources()
	sources2 := parser.GetSupportedSources()
	if len(sources1) != len(sources2) {
		t.Error("GetSupportedSources should return consistent values")
	}

	priority1 := parser.GetPriority()
	priority2 := parser.GetPriority()
	if priority1 != priority2 {
		t.Error("GetPriority should return consistent values")
	}

	canParse1 := parser.CanParse("test")
	canParse2 := parser.CanParse("test")
	if canParse1 != canParse2 {
		t.Error("CanParse should return consistent values")
	}
}

func TestParserInterface_MethodChaining(t *testing.T) {
	parser := &MockParser{
		name:            "chained_parser",
		supportedSource: "chained_source",
		priority:        3,
		canParse:        true,
	}

	// Проверяем, что можно вызывать методы в цепочке
	// (хотя в реальности это не очень полезно для интерфейса)
	name := parser.GetName()
	sources := parser.GetSupportedSources()
	priority := parser.GetPriority()
	canParse := parser.CanParse("test")

	// Проверяем, что все методы работают корректно
	if name != "chained_parser" {
		t.Errorf("Expected name 'chained_parser', got %s", name)
	}
	if len(sources) != 1 || sources[0] != "chained_source" {
		t.Errorf("Expected sources ['chained_source'], got %v", sources)
	}
	if priority != 3 {
		t.Errorf("Expected priority 3, got %d", priority)
	}
	if !canParse {
		t.Error("Expected CanParse to return true")
	}
}
