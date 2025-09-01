// filename: internal/normalizer/pipeline_test.go
package normalizer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"novasec/internal/common/logging"
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

// createTestConfig создает конфиг для тестов
func createTestConfig() *Config {
	return &Config{
		MaxWorkers:   2,
		BatchSize:    10,
		BatchTimeout: 100 * time.Millisecond,
		QueueSize:    100,
		ProcessDelay: 10 * time.Millisecond,
	}
}

func TestNewPipeline(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	if pipeline == nil {
		t.Fatal("NewPipeline returned nil")
	}

	if pipeline.config != config {
		t.Error("Pipeline config not set correctly")
	}

	if pipeline.logger != logger {
		t.Error("Pipeline logger not set correctly")
	}

	if pipeline.parsers == nil {
		t.Error("Pipeline parsers not initialized")
	}

	if len(pipeline.parsers) == 0 {
		t.Error("Pipeline parsers list is empty")
	}

	if pipeline.stopChan == nil {
		t.Error("Pipeline stopChan not initialized")
	}

	if pipeline.eventQueue == nil {
		t.Error("Pipeline eventQueue not initialized")
	}

	if pipeline.stats == nil {
		t.Error("Pipeline stats not initialized")
	}

	if pipeline.stats.startTime.IsZero() {
		t.Error("Pipeline stats startTime not set")
	}

	// Проверяем, что парсеры инициализированы правильно
	expectedParsers := 3 // LinuxAuthParser, NginxAccessParser, WindowsEventLogParser
	if len(pipeline.parsers) != expectedParsers {
		t.Errorf("Expected %d parsers, got %d", expectedParsers, len(pipeline.parsers))
	}
}

func TestPipeline_StartAndStop(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	// Создаем контекст с отменой
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запускаем pipeline в горутине
	errChan := make(chan error, 1)
	go func() {
		errChan <- pipeline.Start(ctx)
	}()

	// Даем время на запуск
	time.Sleep(100 * time.Millisecond)

	// Проверяем, что pipeline запущен
	select {
	case <-pipeline.stopChan:
		t.Error("stopChan should not be closed while running")
	default:
		// OK
	}

	// Отменяем контекст
	cancel()

	// Ждем завершения
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Pipeline.Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Pipeline.Start did not return within timeout")
	}
}

func TestPipeline_Stop(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	// Проверяем, что stopChan не закрыт
	select {
	case <-pipeline.stopChan:
		t.Error("stopChan should not be closed initially")
	default:
		// OK
	}

	// Останавливаем pipeline
	pipeline.Stop()

	// Проверяем, что stopChan закрыт
	select {
	case <-pipeline.stopChan:
		// OK
	default:
		t.Error("stopChan should be closed after Stop()")
	}
}

func TestPipeline_StatsManagement(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	// Проверяем начальную статистику
	initialStats := pipeline.GetStats()
	if initialStats == nil {
		t.Fatal("GetStats returned nil")
	}

	// Проверяем базовые поля
	if metrics, ok := initialStats["metrics"].(map[string]interface{}); ok {
		if eventsReceived, ok := metrics["events_received"].(int64); !ok || eventsReceived != 0 {
			t.Errorf("Initial events received count wrong: got %v want %d", eventsReceived, 0)
		}

		if eventsProcessed, ok := metrics["events_processed"].(int64); !ok || eventsProcessed != 0 {
			t.Errorf("Initial events processed count wrong: got %v want %d", eventsProcessed, 0)
		}

		if eventsNormalized, ok := metrics["events_normalized"].(int64); !ok || eventsNormalized != 0 {
			t.Errorf("Initial events normalized count wrong: got %v want %d", eventsNormalized, 0)
		}

		if eventsSaved, ok := metrics["events_saved"].(int64); !ok || eventsSaved != 0 {
			t.Errorf("Initial events saved count wrong: got %v want %d", eventsSaved, 0)
		}

		if errors, ok := metrics["errors"].(int64); !ok || errors != 0 {
			t.Errorf("Initial errors count wrong: got %v want %d", errors, 0)
		}
	} else {
		t.Error("Metrics field not found in stats")
	}

	if queueSize, ok := initialStats["queue_size"].(int); !ok || queueSize != 0 {
		t.Errorf("Initial QueueSize wrong: got %v want %d", queueSize, 0)
	}

	// Обновляем статистику
	pipeline.updateStats("events_received", nil)
	pipeline.updateStats("events_processed", nil)
	pipeline.updateStats("events_normalized", nil)
	pipeline.updateStats("events_saved", nil)
	pipeline.updateStats("errors", nil)

	// Проверяем обновленную статистику
	if pipeline.stats.eventsReceived != 1 {
		t.Errorf("Events received count wrong: got %d want %d", pipeline.stats.eventsReceived, 1)
	}

	if pipeline.stats.eventsProcessed != 1 {
		t.Errorf("Events processed count wrong: got %d want %d", pipeline.stats.eventsProcessed, 1)
	}

	if pipeline.stats.eventsNormalized != 1 {
		t.Errorf("Events normalized count wrong: got %d want %d", pipeline.stats.eventsNormalized, 1)
	}

	if pipeline.stats.eventsSaved != 1 {
		t.Errorf("Events saved count wrong: got %d want %d", pipeline.stats.eventsSaved, 1)
	}

	if pipeline.stats.errors != 1 {
		t.Errorf("Errors count wrong: got %d want %d", pipeline.stats.errors, 1)
	}

	// Проверяем, что lastEventTime обновился
	if pipeline.stats.lastEventTime.IsZero() {
		t.Error("lastEventTime should be updated after stats update")
	}
}

func TestPipeline_ConcurrentStatsUpdate(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	// Запускаем несколько горутин для конкурентного обновления статистики
	done := make(chan bool, 10)
	expectedCount := int64(10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			// Обновляем статистику
			pipeline.updateStats("events_received", nil)
			done <- true
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		<-done
	}

	// Проверяем, что все события были обработаны
	if pipeline.stats.eventsReceived != expectedCount {
		t.Errorf("Events received count wrong: got %d want %d", pipeline.stats.eventsReceived, expectedCount)
	}
}

func TestPipeline_ConfigValidation(t *testing.T) {
	logger := createTestLogger(t)

	// Тестируем с нулевыми значениями
	zeroConfig := &Config{
		MaxWorkers:   0,
		BatchSize:    0,
		BatchTimeout: 0,
		QueueSize:    0,
		ProcessDelay: 0,
	}

	pipeline := NewPipeline(zeroConfig, logger, nil, nil)

	if pipeline == nil {
		t.Fatal("NewPipeline returned nil with zero config")
	}

	// Проверяем, что используются переданные значения
	if pipeline.config.MaxWorkers != 0 {
		t.Errorf("MaxWorkers changed: got %d want %d", pipeline.config.MaxWorkers, 0)
	}

	if pipeline.config.BatchSize != 0 {
		t.Errorf("BatchSize changed: got %d want %d", pipeline.config.BatchSize, 0)
	}

	if pipeline.config.QueueSize != 0 {
		t.Errorf("QueueSize changed: got %d want %d", pipeline.config.QueueSize, 0)
	}

	// Тестируем с большими значениями
	largeConfig := &Config{
		MaxWorkers:   100,
		BatchSize:    1000,
		BatchTimeout: 10 * time.Second,
		QueueSize:    10000,
		ProcessDelay: 1 * time.Second,
	}

	pipeline2 := NewPipeline(largeConfig, logger, nil, nil)

	if pipeline2 == nil {
		t.Fatal("NewPipeline returned nil with large config")
	}

	if pipeline2.config.MaxWorkers != 100 {
		t.Errorf("MaxWorkers wrong: got %d want %d", pipeline2.config.MaxWorkers, 100)
	}

	if pipeline2.config.BatchSize != 1000 {
		t.Errorf("BatchSize wrong: got %d want %d", pipeline2.config.BatchSize, 1000)
	}

	if pipeline2.config.QueueSize != 10000 {
		t.Errorf("QueueSize wrong: got %d want %d", pipeline2.config.QueueSize, 10000)
	}
}

func TestPipeline_StatsStructure(t *testing.T) {
	logger := createTestLogger(t)
	config := createTestConfig()

	pipeline := NewPipeline(config, logger, nil, nil)

	stats := pipeline.GetStats()

	// Проверяем структуру статистики
	requiredFields := []string{"status", "workers", "batch_size", "batch_timeout", "queue_size", "metrics"}
	for _, field := range requiredFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Required field missing: %s", field)
		}
	}

	// Проверяем поле metrics
	metrics, ok := stats["metrics"].(map[string]interface{})
	if !ok {
		t.Fatal("Metrics field is not a map")
	}

	requiredMetrics := []string{
		"events_received", "events_processed", "events_normalized",
		"events_saved", "worker_utilization", "errors", "uptime", "last_event_time",
	}

	for _, metric := range requiredMetrics {
		if _, exists := metrics[metric]; !exists {
			t.Errorf("Required metric missing: %s", metric)
		}
	}

	// Проверяем типы полей
	if status, ok := stats["status"].(string); !ok || status != "running" {
		t.Errorf("Status field wrong: got %v want %s", status, "running")
	}

	if workers, ok := stats["workers"].(int); !ok || workers != config.MaxWorkers {
		t.Errorf("Workers field wrong: got %v want %d", workers, config.MaxWorkers)
	}

	if batchSize, ok := stats["batch_size"].(int); !ok || batchSize != config.BatchSize {
		t.Errorf("BatchSize field wrong: got %v want %d", batchSize, config.BatchSize)
	}

	if queueSize, ok := stats["queue_size"].(int); !ok || queueSize != 0 {
		t.Errorf("QueueSize field wrong: got %v want %d", queueSize, 0)
	}
}

func TestPipeline_WorkerConfiguration(t *testing.T) {
	logger := createTestLogger(t)

	// Тестируем с разным количеством воркеров
	testCases := []int{1, 2, 5, 10}

	for _, workerCount := range testCases {
		t.Run(fmt.Sprintf("Workers_%d", workerCount), func(t *testing.T) {
			config := &Config{
				MaxWorkers:   workerCount,
				BatchSize:    10,
				BatchTimeout: 100 * time.Millisecond,
				QueueSize:    100,
				ProcessDelay: 10 * time.Millisecond,
			}

			pipeline := NewPipeline(config, logger, nil, nil)

			if pipeline.config.MaxWorkers != workerCount {
				t.Errorf("MaxWorkers wrong: got %d want %d", pipeline.config.MaxWorkers, workerCount)
			}

			// Проверяем, что pipeline создается корректно
			if pipeline == nil {
				t.Fatal("Pipeline is nil")
			}

			if pipeline.stopChan == nil {
				t.Error("stopChan is nil")
			}

			if pipeline.eventQueue == nil {
				t.Error("eventQueue is nil")
			}

			if pipeline.stats == nil {
				t.Error("stats is nil")
			}
		})
	}
}
