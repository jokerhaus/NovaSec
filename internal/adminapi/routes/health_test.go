// filename: internal/adminapi/routes/health_test.go
package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"novasec/internal/common/logging"

	"github.com/gin-gonic/gin"
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

// createTestContext создает gin контекст для тестов
func createTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}

// contains проверяет, содержит ли строка подстроку
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || contains(s[1:], substr)))
}

func TestNewHealthHandler(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	if handler == nil {
		t.Fatal("NewHealthHandler returned nil")
	}

	if handler.logger != logger {
		t.Error("Handler logger not set correctly")
	}
}

func TestHealthHandler_HealthCheck(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.HealthCheck(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Проверяем заголовки (Gin добавляет charset=utf-8)
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}

	// Проверяем тело ответа
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Проверяем обязательные поля
	if status, exists := response["status"]; !exists || status != "healthy" {
		t.Errorf("Response missing or invalid status field: got %v", status)
	}

	if timestamp, exists := response["timestamp"]; !exists {
		t.Errorf("Response missing timestamp field: got %v", timestamp)
	}
}

func TestHealthHandler_DetailedHealthCheck(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.DetailedHealthCheck(c)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Проверяем детальные поля
	if status, exists := response["status"]; !exists || status != "healthy" {
		t.Errorf("Response missing or invalid status field: got %v", status)
	}

	if timestamp, exists := response["timestamp"]; !exists {
		t.Errorf("Response missing timestamp field: got %v", timestamp)
	}

	if components, exists := response["components"]; !exists {
		t.Errorf("Response missing components field: got %v", components)
	}

	if system, exists := response["system"]; !exists {
		t.Errorf("Response missing system field: got %v", system)
	}
}

func TestHealthHandler_ReadinessCheck(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.ReadinessCheck(c)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if ready, exists := response["ready"]; !exists {
		t.Errorf("Response missing ready field: got %v", ready)
	}

	if timestamp, exists := response["timestamp"]; !exists {
		t.Errorf("Response missing timestamp field: got %v", timestamp)
	}
}

func TestHealthHandler_LivenessCheck(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.LivenessCheck(c)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if alive, exists := response["alive"]; !exists {
		t.Errorf("Response missing alive field: got %v", alive)
	}

	if timestamp, exists := response["timestamp"]; !exists {
		t.Errorf("Response missing timestamp field: got %v", timestamp)
	}
}

func TestHealthHandler_Status(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.Status(c)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if status, exists := response["status"]; !exists {
		t.Errorf("Response missing status field: got %v", status)
	}

	if timestamp, exists := response["timestamp"]; !exists {
		t.Errorf("Response missing timestamp field: got %v", timestamp)
	}

	if service, exists := response["service"]; !exists {
		t.Errorf("Response missing service field: got %v", service)
	}

	if performance, exists := response["performance"]; !exists {
		t.Errorf("Response missing performance field: got %v", performance)
	}
}

func TestHealthHandler_Metrics(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.Metrics(c)

	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "text/plain; version=0.0.4; charset=utf-8")
	}

	// Metrics возвращает plain text в формате Prometheus
	body := w.Body.String()
	if body == "" {
		t.Error("Metrics response is empty")
	}

	// Проверяем наличие базовых метрик в тексте
	if !contains(body, "novasec_adminapi_uptime_seconds") {
		t.Error("Metrics missing uptime metric")
	}

	if !contains(body, "novasec_adminapi_requests_total") {
		t.Error("Metrics missing requests_total metric")
	}

	if !contains(body, "novasec_adminapi_request_duration_seconds") {
		t.Error("Metrics missing request_duration metric")
	}
}

func TestHealthHandler_ResponseStructure(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	// Тестируем все эндпоинты для проверки структуры ответов
	endpoints := []struct {
		name     string
		handler  func(*gin.Context)
		expected map[string]interface{}
	}{
		{
			name:    "HealthCheck",
			handler: handler.HealthCheck,
			expected: map[string]interface{}{
				"status": "healthy",
			},
		},
		{
			name:    "DetailedHealthCheck",
			handler: handler.DetailedHealthCheck,
			expected: map[string]interface{}{
				"status": "healthy",
			},
		},
		{
			name:    "ReadinessCheck",
			handler: handler.ReadinessCheck,
			expected: map[string]interface{}{
				"ready": true,
			},
		},
		{
			name:    "LivenessCheck",
			handler: handler.LivenessCheck,
			expected: map[string]interface{}{
				"alive": true,
			},
		},
		{
			name:    "Status",
			handler: handler.Status,
			expected: map[string]interface{}{
				"timestamp": true, // Проверяем только существование поля
			},
		},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			c, w := createTestContext(t)
			endpoint.handler(c)

			if status := w.Code; status != http.StatusOK {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			// Проверяем ожидаемые поля
			for key, expectedValue := range endpoint.expected {
				if value, exists := response[key]; !exists {
					t.Errorf("Response missing field: %s", key)
				} else if expectedValue == true {
					// Если expectedValue == true, проверяем только существование поля
					// (поле существует, значение не важно)
				} else if value != expectedValue {
					t.Errorf("Field %s has wrong value: got %v want %v", key, value, expectedValue)
				}
			}

			// Проверяем наличие timestamp во всех ответах
			if _, exists := response["timestamp"]; !exists {
				t.Error("Response missing timestamp field")
			}
		})
	}
}

func TestHealthHandler_ConcurrentAccess(t *testing.T) {
	logger := createTestLogger(t)
	handler := NewHealthHandler(logger)

	// Тестируем конкурентный доступ к health handler
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			c, w := createTestContext(t)
			handler.HealthCheck(c)

			if status := w.Code; status != http.StatusOK {
				t.Errorf("Handler returned wrong status in goroutine %d: got %v", id, status)
			}

			done <- true
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestHealthHandler_LoggerIntegration(t *testing.T) {
	// Создаем logger с debug уровнем для проверки интеграции
	config := logging.Config{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	}
	logger, err := logging.NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	handler := NewHealthHandler(logger)

	c, w := createTestContext(t)
	handler.HealthCheck(c)

	// Проверяем, что handler использует logger корректно
	// (в реальности мы могли бы проверить логи, но для тестов достаточно проверить ответ)
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler with debug logger returned wrong status: got %v", status)
	}

	// Проверяем, что ответ содержит корректные данные
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if status, exists := response["status"]; !exists || status != "healthy" {
		t.Errorf("Response missing or invalid status field: got %v", status)
	}
}
