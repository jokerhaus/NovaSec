// filename: internal/adminapi/routes/alerts_test.go
package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/common/pg"

	"github.com/gin-gonic/gin"
)

// createAlertsTestLogger создает logger для тестов alerts
func createAlertsTestLogger(t *testing.T) *logging.Logger {
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

// createAlertsTestContext создает gin контекст для тестов alerts
func createAlertsTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}

func TestNewAlertsHandler(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	if handler == nil {
		t.Fatal("NewAlertsHandler returned nil")
	}

	if handler.logger != logger {
		t.Error("Handler logger not set correctly")
	}

	if handler.pgClient != pgClient {
		t.Error("Handler pgClient not set correctly")
	}

	if handler.alertCache == nil {
		t.Error("Handler alertCache not initialized")
	}

	if handler.cacheTTL != 10*time.Minute {
		t.Errorf("Handler cacheTTL wrong: got %v want %v", handler.cacheTTL, 10*time.Minute)
	}
}

func TestAlertsHandler_GetAlerts_DefaultParams(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса
	c.Request = httptest.NewRequest("GET", "/alerts", nil)

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Проверяем заголовки
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json; charset=utf-8")
	}
}

func TestAlertsHandler_GetAlerts_WithFilters(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с фильтрами
	req := httptest.NewRequest("GET", "/alerts?severity=high&rule_id=rule_1&limit=50", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_WithDateRange(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с датами
	from := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	to := time.Now().Format(time.RFC3339)
	req := httptest.NewRequest("GET", "/alerts?from="+from+"&to="+to, nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_InvalidLimit(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с неверным лимитом
	req := httptest.NewRequest("GET", "/alerts?limit=invalid", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_InvalidDate(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с неверной датой
	req := httptest.NewRequest("GET", "/alerts?from=invalid-date", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_ExceedMaxLimit(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с превышением максимального лимита
	req := httptest.NewRequest("GET", "/alerts?limit=2000", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_WithCursor(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с курсором
	req := httptest.NewRequest("GET", "/alerts?cursor=alert_123", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_WithEnvironment(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса с окружением
	req := httptest.NewRequest("GET", "/alerts?env=production", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_WithStatus(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса со статусом
	req := httptest.NewRequest("GET", "/alerts?status=active", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_ComplexFilters(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса со всеми фильтрами
	from := time.Now().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	to := time.Now().Format(time.RFC3339)
	req := httptest.NewRequest("GET", "/alerts?from="+from+"&to="+to+"&severity=critical&rule_id=rule_1&status=active&env=production&limit=200", nil)
	c.Request = req

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestAlertsHandler_GetAlerts_EmptyResponse(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса
	c.Request = httptest.NewRequest("GET", "/alerts", nil)

	handler.GetAlerts(c)

	// Проверяем статус код
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Проверяем, что ответ содержит пустой массив
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if alerts, exists := response["alerts"]; !exists {
		t.Error("Response missing alerts field")
	} else if alerts == nil {
		t.Error("Alerts field is nil")
	}
}

func TestAlertsHandler_GetAlerts_ResponseStructure(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)

	// Устанавливаем параметры запроса
	c.Request = httptest.NewRequest("GET", "/alerts", nil)

	handler.GetAlerts(c)

	// Проверяем структуру ответа
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Проверяем обязательные поля
	requiredFields := []string{"alerts", "pagination"}
	for _, field := range requiredFields {
		if _, exists := response[field]; !exists {
			t.Errorf("Response missing required field: %s", field)
		}
	}

	// Проверяем, что alerts является массивом
	if alerts, exists := response["alerts"]; !exists {
		t.Error("Response missing alerts field")
	} else if alerts == nil {
		t.Error("Alerts field is nil")
	}

	// Проверяем, что pagination является объектом
	if pagination, exists := response["pagination"]; !exists {
		t.Error("Response missing pagination field")
	} else if pagination == nil {
		t.Error("Pagination field is nil")
	}
}

func TestAlertsHandler_GetAlerts_ConcurrentAccess(t *testing.T) {
	logger := createTestLogger(t)

	// Создаем реальный pg.Client для тестирования
	config := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(config)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	// Запускаем несколько горутин для конкурентного доступа
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			c, w := createTestContext(t)
			c.Request = httptest.NewRequest("GET", "/alerts", nil)

			handler.GetAlerts(c)

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

func TestAlertsHandler_GetAlerts_LoggerIntegration(t *testing.T) {
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

	// Создаем реальный pg.Client для тестирования
	pgConfig := pg.Config{
		Host:     "localhost",
		Port:     5432,
		Database: "test",
		Username: "test",
		Password: "test",
		SSLMode:  "disable",
	}

	pgClient, err := pg.NewClient(pgConfig)
	if err != nil {
		t.Skipf("Skipping test - cannot connect to PostgreSQL: %v", err)
	}
	defer pgClient.Close()

	handler := NewAlertsHandler(logger, pgClient)

	c, w := createTestContext(t)
	c.Request = httptest.NewRequest("GET", "/alerts", nil)

	handler.GetAlerts(c)

	// Проверяем, что handler использует logger корректно
	if status := w.Code; status != http.StatusOK {
		t.Errorf("Handler with debug logger returned wrong status: got %v", status)
	}
}
