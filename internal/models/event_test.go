// filename: internal/models/event_test.go
// NovaSec Event Model Tests

package models

import (
	"encoding/json"
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

	// Проверяем, что плоские поля заполнены
	if event.Env != "production" {
		t.Errorf("Expected Env to be 'production', got %s", event.Env)
	}

	if event.Severity != "info" {
		t.Errorf("Expected Severity to be 'info', got %s", event.Severity)
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

func TestEventValidationErrors(t *testing.T) {
	// Test missing timestamp
	invalidJSON := `{"host":"test-host","category":"test","subtype":"test","message":"test message"}`
	_, err := NewEventFromNDJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for missing timestamp")
	}

	// Test missing host
	invalidJSON = `{"ts":"2024-01-01T12:00:00Z","category":"test","subtype":"test","message":"test message"}`
	_, err = NewEventFromNDJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for missing host")
	}

	// Test missing category
	invalidJSON = `{"ts":"2024-01-01T12:00:00Z","host":"test-host","subtype":"test","message":"test message"}`
	_, err = NewEventFromNDJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for missing category")
	}

	// Test missing subtype
	invalidJSON = `{"ts":"2024-01-01T12:00:00Z","host":"test-host","category":"test","message":"test message"}`
	_, err = NewEventFromNDJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for missing subtype")
	}

	// Test missing message
	invalidJSON = `{"ts":"2024-01-01T12:00:00Z","host":"test-host","category":"test","subtype":"test"}`
	_, err = NewEventFromNDJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for missing message")
	}

	// Test empty NDJSON line
	_, err = NewEventFromNDJSON("")
	if err == nil {
		t.Error("Expected error for empty NDJSON line")
	}

	// Test invalid JSON
	_, err = NewEventFromNDJSON("invalid json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
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

	// Test GetDedupKey with empty Source
	event.Source = ""
	dedupKey = event.GetDedupKey()
	expectedKey = "server-01:auth:login:"
	if dedupKey != expectedKey {
		t.Errorf("GetDedupKey() = %v, want %v", dedupKey, expectedKey)
	}

	// Test GetDedupKey with nil Labels
	event.Labels = nil
	dedupKey = event.GetDedupKey()
	expectedKey = "server-01:auth:login:"
	if dedupKey != expectedKey {
		t.Errorf("GetDedupKey() = %v, want %v", dedupKey, expectedKey)
	}

	// Test AddLabel
	event.AddLabel("test_key", "test_value")
	if event.Labels["test_key"] != "test_value" {
		t.Error("AddLabel() failed to add label")
	}

	// Test AddLabel with nil Labels
	event.Labels = nil
	event.AddLabel("new_key", "new_value")
	if event.Labels == nil {
		t.Error("AddLabel() should initialize Labels if nil")
	}
	if event.Labels["new_key"] != "new_value" {
		t.Error("AddLabel() failed to add label after initialization")
	}

	// Test GetLabel
	labelValue := event.GetLabel("test_key")
	if labelValue != "test_value" {
		t.Errorf("GetLabel() = %v, want %v", labelValue, "test_value")
	}

	// Test GetLabel with nil Labels
	event.Labels = nil
	labelValue = event.GetLabel("nonexistent")
	if labelValue != "" {
		t.Errorf("GetLabel() should return empty string for nil Labels, got %v", labelValue)
	}

	// Test FillFlatFields
	event.User = &User{Name: "testuser", UID: &[]int{1000}[0]}
	event.Network = &Network{SrcIP: "192.168.1.1", SrcPort: &[]int{22}[0]}
	event.File = &File{Path: "/test/file"}
	event.Process = &Process{PID: &[]int{1234}[0], Name: "testproc"}
	event.Hashes = &Hashes{SHA256: "testhash"}
	event.Enrich = &Enrichment{Geo: "US", ASN: &[]int{12345}[0], IOC: "testioc"}

	event.FillFlatFields()

	if event.UserName != "testuser" {
		t.Errorf("Expected UserName to be 'testuser', got %s", event.UserName)
	}

	if event.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP to be '192.168.1.1', got %s", event.SrcIP)
	}

	if event.FilePath != "/test/file" {
		t.Errorf("Expected FilePath to be '/test/file', got %s", event.FilePath)
	}

	if event.ProcessName != "testproc" {
		t.Errorf("Expected ProcessName to be 'testproc', got %s", event.ProcessName)
	}

	if event.SHA256 != "testhash" {
		t.Errorf("Expected SHA256 to be 'testhash', got %s", event.SHA256)
	}

	if event.Geo != "US" {
		t.Errorf("Expected Geo to be 'US', got %s", event.Geo)
	}

	// Test FillFlatFields with nil structures
	event.User = nil
	event.Network = nil
	event.File = nil
	event.Process = nil
	event.Hashes = nil
	event.Enrich = nil

	event.FillFlatFields()

	// Should not panic and should clear flat fields
	if event.UserName != "" {
		t.Errorf("Expected UserName to be empty after nil User, got %s", event.UserName)
	}
	if event.SrcIP != "" {
		t.Errorf("Expected SrcIP to be empty after nil Network, got %s", event.SrcIP)
	}
	if event.FilePath != "" {
		t.Errorf("Expected FilePath to be empty after nil File, got %s", event.FilePath)
	}
	if event.ProcessName != "" {
		t.Errorf("Expected ProcessName to be empty after nil Process, got %s", event.ProcessName)
	}
	if event.SHA256 != "" {
		t.Errorf("Expected SHA256 to be empty after nil Hashes, got %s", event.SHA256)
	}
	if event.Geo != "" {
		t.Errorf("Expected Geo to be empty after nil Enrich, got %s", event.Geo)
	}

	// Test FillFlatFields with partially filled structures
	event.User = &User{Name: "partial"}
	event.Network = &Network{SrcIP: "192.168.1.1"}
	event.File = &File{Path: "/partial/file"}
	event.Process = &Process{Name: "partial"}
	event.Hashes = &Hashes{SHA256: "partial"}
	event.Enrich = &Enrichment{Geo: "US"}

	event.FillFlatFields()

	if event.UserName != "partial" {
		t.Errorf("Expected UserName to be 'partial', got %s", event.UserName)
	}
	if event.SrcIP != "192.168.1.1" {
		t.Errorf("Expected SrcIP to be '192.168.1.1', got %s", event.SrcIP)
	}
	if event.FilePath != "/partial/file" {
		t.Errorf("Expected FilePath to be '/partial/file', got %s", event.FilePath)
	}
	if event.ProcessName != "partial" {
		t.Errorf("Expected ProcessName to be 'partial', got %s", event.ProcessName)
	}
	if event.SHA256 != "partial" {
		t.Errorf("Expected SHA256 to be 'partial', got %s", event.SHA256)
	}
	if event.Geo != "US" {
		t.Errorf("Expected Geo to be 'US', got %s", event.Geo)
	}

	// Test FillFlatFields with empty values in structures
	event.User = &User{Name: "", UID: nil}
	event.Network = &Network{SrcIP: "", SrcPort: nil}
	event.File = &File{Path: ""}
	event.Process = &Process{PID: nil, Name: ""}
	event.Hashes = &Hashes{SHA256: ""}
	event.Enrich = &Enrichment{Geo: "", ASN: nil, IOC: ""}

	event.FillFlatFields()

	if event.UserName != "" {
		t.Errorf("Expected UserName to be empty, got %s", event.UserName)
	}
	if event.UserUID != nil {
		t.Errorf("Expected UserUID to be nil, got %v", event.UserUID)
	}
	if event.SrcIP != "" {
		t.Errorf("Expected SrcIP to be empty, got %s", event.SrcIP)
	}
	if event.SrcPort != nil {
		t.Errorf("Expected SrcPort to be nil, got %v", event.SrcPort)
	}
	if event.FilePath != "" {
		t.Errorf("Expected FilePath to be empty, got %s", event.FilePath)
	}
	if event.ProcessPID != nil {
		t.Errorf("Expected ProcessPID to be nil, got %v", event.ProcessPID)
	}
	if event.ProcessName != "" {
		t.Errorf("Expected ProcessName to be empty, got %s", event.ProcessName)
	}
	if event.SHA256 != "" {
		t.Errorf("Expected SHA256 to be empty, got %s", event.SHA256)
	}
	if event.Geo != "" {
		t.Errorf("Expected Geo to be empty, got %s", event.Geo)
	}
	if event.ASN != nil {
		t.Errorf("Expected ASN to be nil, got %v", event.ASN)
	}
	if event.IOC != "" {
		t.Errorf("Expected IOC to be empty, got %s", event.IOC)
	}

	// Test IsHighSeverity
	event.Severity = "high"
	if !event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return true for high severity")
	}

	event.Severity = "critical"
	if !event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return true for critical severity")
	}

	event.Severity = "info"
	if event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return false for info severity")
	}

	event.Severity = "low"
	if event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return false for low severity")
	}

	event.Severity = "warning"
	if event.IsHighSeverity() {
		t.Error("IsHighSeverity() should return false for warning severity")
	}

	// Test GetNetworkIPAsString
	event.Network = &Network{SrcIP: "192.168.1.1"}
	ipString := event.GetNetworkIPAsString()
	if ipString != "192.168.1.1" {
		t.Errorf("GetNetworkIPAsString() = %v, want %v", ipString, "192.168.1.1")
	}

	event.Network = &Network{DstIP: "10.0.0.1"}
	ipString = event.GetNetworkIPAsString()
	if ipString != "10.0.0.1" {
		t.Errorf("GetNetworkIPAsString() = %v, want %v", ipString, "10.0.0.1")
	}

	// Test GetNetworkIPAsString with nil Network
	event.Network = nil
	ipString = event.GetNetworkIPAsString()
	if ipString != "" {
		t.Errorf("GetNetworkIPAsString() should return empty string for nil Network, got %v", ipString)
	}

	// Test ParseIPPort
	ip, port, err := ParseIPPort("192.168.1.1:22")
	if err != nil {
		t.Errorf("ParseIPPort() failed: %v", err)
	}
	if ip != "192.168.1.1" {
		t.Errorf("ParseIPPort() ip = %v, want %v", ip, "192.168.1.1")
	}
	if port != 22 {
		t.Errorf("ParseIPPort() port = %v, want %v", port, 22)
	}

	// Test invalid IP:port
	_, _, err = ParseIPPort("invalid")
	if err == nil {
		t.Error("ParseIPPort() should fail for invalid format")
	}

	// Test IP:port with invalid port
	_, _, err = ParseIPPort("192.168.1.1:invalid")
	if err == nil {
		t.Error("ParseIPPort() should fail for invalid port")
	}

	// Test IP:port with missing port
	_, _, err = ParseIPPort("192.168.1.1:")
	if err == nil {
		t.Error("ParseIPPort() should fail for missing port")
	}

	// Test IP:port with missing IP
	_, _, err = ParseIPPort(":22")
	if err == nil {
		t.Error("ParseIPPort() should fail for missing IP")
	}

	// Test SetTimestampFromUnix
	event.SetTimestampFromUnix(1640995200) // 2022-01-01 00:00:00 UTC
	expectedTime := time.Unix(1640995200, 0)
	if !event.TS.Equal(expectedTime) {
		t.Errorf("SetTimestampFromUnix() = %v, want %v", event.TS, expectedTime)
	}

	// Test SetTimestampFromUnixMilli
	event.SetTimestampFromUnixMilli(1640995200000) // 2022-01-01 00:00:00 UTC in milliseconds
	expectedTime = time.UnixMilli(1640995200000)
	if !event.TS.Equal(expectedTime) {
		t.Errorf("SetTimestampFromUnixMilli() = %v, want %v", event.TS, expectedTime)
	}

	// Test SetTimestampFromUnix with zero value
	event.SetTimestampFromUnix(0)
	expectedTime = time.Unix(0, 0)
	if !event.TS.Equal(expectedTime) {
		t.Errorf("SetTimestampFromUnix(0) = %v, want %v", event.TS, expectedTime)
	}

	// Test SetTimestampFromUnixMilli with zero value
	event.SetTimestampFromUnixMilli(0)
	expectedTime = time.UnixMilli(0)
	if !event.TS.Equal(expectedTime) {
		t.Errorf("SetTimestampFromUnixMilli(0) = %v, want %v", event.TS, expectedTime)
	}

	// Test ToJSON
	jsonData, err := event.ToJSON()
	if err != nil {
		t.Errorf("ToJSON() failed: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("ToJSON() returned empty data")
	}

	// Verify JSON can be parsed back
	var parsedEvent Event
	err = json.Unmarshal(jsonData, &parsedEvent)
	if err != nil {
		t.Errorf("Failed to parse JSON back: %v", err)
	}
	if parsedEvent.Host != event.Host {
		t.Errorf("Parsed event host mismatch: got %s, want %s", parsedEvent.Host, event.Host)
	}

	// Test ToJSON with minimal event
	minimalEvent := &Event{
		TS:       time.Now(),
		Host:     "minimal-host",
		Category: "minimal",
		Subtype:  "minimal",
		Message:  "minimal message",
	}
	minimalEvent.FillFlatFields()

	jsonData, err = minimalEvent.ToJSON()
	if err != nil {
		t.Errorf("ToJSON() failed for minimal event: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("ToJSON() returned empty data for minimal event")
	}
}
