// filename: internal/correlator/state/memory_test.go
package state

import (
	"fmt"
	"testing"
	"time"

	"novasec/internal/correlator/dsl"
)

func TestNewMemoryStateManager(t *testing.T) {
	manager := NewMemoryStateManager()
	if manager == nil {
		t.Fatal("NewMemoryStateManager() returned nil")
	}
	if manager.windows == nil {
		t.Error("windows map not initialized")
	}
}

func TestMemoryStateManager_GetWindowState(t *testing.T) {
	manager := NewMemoryStateManager()

	ruleID := "test_rule"
	groupKey := "user:testuser"

	// Получаем состояние окна
	window, err := manager.GetWindowState(ruleID, groupKey)
	if err != nil {
		t.Fatalf("GetWindowState failed: %v", err)
	}

	if window == nil {
		t.Fatal("GetWindowState returned nil")
	}

	// Проверяем, что окно создано с правильными параметрами
	if window.RuleID != ruleID {
		t.Errorf("Expected RuleID %s, got %s", ruleID, window.RuleID)
	}
	if window.GroupKey != groupKey {
		t.Errorf("Expected GroupKey %s, got %s", groupKey, window.GroupKey)
	}
	if window.EventCount != 0 {
		t.Errorf("Expected EventCount 0, got %d", window.EventCount)
	}
	if window.UniqueCount == nil {
		t.Error("UniqueCount map not initialized")
	}
}

func TestMemoryStateManager_UpdateWindowState(t *testing.T) {
	manager := NewMemoryStateManager()

	ruleID := "test_rule"
	groupKey := "user:testuser"

	// Создаем состояние окна
	window := &dsl.WindowState{
		RuleID:      ruleID,
		GroupKey:    groupKey,
		StartTime:   time.Now(),
		EndTime:     time.Now().Add(5 * time.Minute),
		EventCount:  10,
		UniqueCount: map[string]int{"user": 5, "host": 3},
		LastEvent:   time.Now(),
	}

	// Обновляем состояние окна
	err := manager.UpdateWindowState(ruleID, groupKey, window)
	if err != nil {
		t.Fatalf("UpdateWindowState failed: %v", err)
	}

	// Получаем обновленное состояние
	updatedWindow, err := manager.GetWindowState(ruleID, groupKey)
	if err != nil {
		t.Fatalf("GetWindowState failed: %v", err)
	}

	// Проверяем, что состояние обновлено
	if updatedWindow.EventCount != 10 {
		t.Errorf("Expected EventCount 10, got %d", updatedWindow.EventCount)
	}
	if len(updatedWindow.UniqueCount) != 2 {
		t.Errorf("Expected 2 unique counts, got %d", len(updatedWindow.UniqueCount))
	}
}

func TestMemoryStateManager_GetWindowState_NonExistent(t *testing.T) {
	manager := NewMemoryStateManager()

	// Получаем состояние окна для несуществующего правила
	window, err := manager.GetWindowState("non_existent_rule", "non_existent_group")
	if err != nil {
		t.Fatalf("GetWindowState failed: %v", err)
	}

	if window == nil {
		t.Fatal("GetWindowState returned nil for non-existent rule/group")
	}

	// Проверяем, что создано новое окно
	if window.RuleID != "non_existent_rule" {
		t.Errorf("Expected RuleID 'non_existent_rule', got %s", window.RuleID)
	}
	if window.GroupKey != "non_existent_group" {
		t.Errorf("Expected GroupKey 'non_existent_group', got %s", window.GroupKey)
	}
}

func TestMemoryStateManager_CleanupExpiredWindows(t *testing.T) {
	manager := NewMemoryStateManager()

	ruleID := "test_rule"
	groupKey := "user:testuser"

	// Создаем окно с истекшим временем
	expiredWindow := &dsl.WindowState{
		RuleID:      ruleID,
		GroupKey:    groupKey,
		StartTime:   time.Now().Add(-2 * time.Hour),
		EndTime:     time.Now().Add(-1 * time.Hour), // Окно истекло час назад
		EventCount:  5,
		UniqueCount: map[string]int{"user": 3},
		LastEvent:   time.Now().Add(-1 * time.Hour),
	}

	// Обновляем состояние окна
	err := manager.UpdateWindowState(ruleID, groupKey, expiredWindow)
	if err != nil {
		t.Fatalf("UpdateWindowState failed: %v", err)
	}

	// Проверяем, что окно добавлено
	windowCount := manager.GetWindowCount()
	if windowCount != 1 {
		t.Errorf("Expected 1 window before cleanup, got %d", windowCount)
	}

	// Запускаем очистку
	err = manager.CleanupExpiredWindows()
	if err != nil {
		t.Fatalf("CleanupExpiredWindows failed: %v", err)
	}

	// Проверяем, что истекшее окно удалено
	windowCount = manager.GetWindowCount()
	if windowCount != 0 {
		t.Errorf("Expected 0 windows after cleanup, got %d", windowCount)
	}
}

func TestMemoryStateManager_GetStats(t *testing.T) {
	manager := NewMemoryStateManager()

	// Создаем несколько окон
	windows := []struct {
		ruleID   string
		groupKey string
		expired  bool
	}{
		{"rule_1", "group_a", false},
		{"rule_1", "group_b", false},
		{"rule_2", "group_a", true}, // Истекшее окно
	}

	for _, w := range windows {
		endTime := time.Now()
		if w.expired {
			endTime = time.Now().Add(-1 * time.Hour)
		} else {
			endTime = time.Now().Add(1 * time.Hour)
		}

		window := &dsl.WindowState{
			RuleID:      w.ruleID,
			GroupKey:    w.groupKey,
			StartTime:   time.Now(),
			EndTime:     endTime,
			EventCount:  5,
			UniqueCount: map[string]int{"user": 3},
			LastEvent:   time.Now(),
		}

		err := manager.UpdateWindowState(w.ruleID, w.groupKey, window)
		if err != nil {
			t.Fatalf("UpdateWindowState failed: %v", err)
		}
	}

	// Получаем статистику
	stats := manager.GetStats()

	// Проверяем статистику
	if stats["total_windows"] != 3 {
		t.Errorf("Expected total_windows 3, got %v", stats["total_windows"])
	}
	if stats["type"] != "memory" {
		t.Errorf("Expected type 'memory', got %v", stats["type"])
	}
	if stats["active_windows"] != 2 {
		t.Errorf("Expected active_windows 2, got %v", stats["active_windows"])
	}
}

func TestMemoryStateManager_GetWindowInfo(t *testing.T) {
	manager := NewMemoryStateManager()

	ruleID := "test_rule"
	groupKey := "user:testuser"

	// Создаем окно
	window := &dsl.WindowState{
		RuleID:      ruleID,
		GroupKey:    groupKey,
		StartTime:   time.Now(),
		EndTime:     time.Now().Add(5 * time.Minute),
		EventCount:  10,
		UniqueCount: map[string]int{"user": 5, "host": 3},
		LastEvent:   time.Now(),
	}

	// Обновляем состояние окна
	err := manager.UpdateWindowState(ruleID, groupKey, window)
	if err != nil {
		t.Fatalf("UpdateWindowState failed: %v", err)
	}

	// Получаем информацию об окне
	info, err := manager.GetWindowInfo(ruleID, groupKey)
	if err != nil {
		t.Fatalf("GetWindowInfo failed: %v", err)
	}

	// Проверяем информацию
	if info["rule_id"] != ruleID {
		t.Errorf("Expected rule_id %s, got %v", ruleID, info["rule_id"])
	}
	if info["group_key"] != groupKey {
		t.Errorf("Expected group_key %s, got %v", groupKey, info["group_key"])
	}
	if info["event_count"] != 10 {
		t.Errorf("Expected event_count 10, got %v", info["event_count"])
	}
	if info["unique_count"] != 2 {
		t.Errorf("Expected unique_count 2, got %v", info["unique_count"])
	}
	if info["is_expired"] != false {
		t.Errorf("Expected is_expired false, got %v", info["is_expired"])
	}
}

func TestMemoryStateManager_GetWindowInfo_NonExistent(t *testing.T) {
	manager := NewMemoryStateManager()

	// Получаем информацию о несуществующем окне
	_, err := manager.GetWindowInfo("non_existent_rule", "non_existent_group")
	if err == nil {
		t.Error("Expected error for non-existent window")
	}
}

func TestMemoryStateManager_ListWindows(t *testing.T) {
	manager := NewMemoryStateManager()

	// Создаем несколько окон
	windows := []struct {
		ruleID   string
		groupKey string
	}{
		{"rule_1", "group_a"},
		{"rule_1", "group_b"},
		{"rule_2", "group_a"},
	}

	for _, w := range windows {
		window := &dsl.WindowState{
			RuleID:      w.ruleID,
			GroupKey:    w.groupKey,
			StartTime:   time.Now(),
			EndTime:     time.Now().Add(5 * time.Minute),
			EventCount:  5,
			UniqueCount: map[string]int{"user": 3},
			LastEvent:   time.Now(),
		}

		err := manager.UpdateWindowState(w.ruleID, w.groupKey, window)
		if err != nil {
			t.Fatalf("UpdateWindowState failed: %v", err)
		}
	}

	// Получаем список окон
	windowList := manager.ListWindows()

	// Проверяем количество окон
	if len(windowList) != 3 {
		t.Errorf("Expected 3 windows, got %d", len(windowList))
	}

	// Проверяем, что все окна присутствуют
	expectedWindows := map[string]bool{
		"rule_1:group_a": true,
		"rule_1:group_b": true,
		"rule_2:group_a": true,
	}

	for _, windowInfo := range windowList {
		ruleID := windowInfo["rule_id"].(string)
		groupKey := windowInfo["group_key"].(string)
		key := ruleID + ":" + groupKey

		if !expectedWindows[key] {
			t.Errorf("Unexpected window: %s", key)
		}
	}
}

func TestMemoryStateManager_ClearAllWindows(t *testing.T) {
	manager := NewMemoryStateManager()

	// Создаем несколько окон
	windows := []struct {
		ruleID   string
		groupKey string
	}{
		{"rule_1", "group_a"},
		{"rule_1", "group_b"},
		{"rule_2", "group_a"},
	}

	for _, w := range windows {
		window := &dsl.WindowState{
			RuleID:      w.ruleID,
			GroupKey:    w.groupKey,
			StartTime:   time.Now(),
			EndTime:     time.Now().Add(5 * time.Minute),
			EventCount:  5,
			UniqueCount: map[string]int{"user": 3},
			LastEvent:   time.Now(),
		}

		err := manager.UpdateWindowState(w.ruleID, w.groupKey, window)
		if err != nil {
			t.Fatalf("UpdateWindowState failed: %v", err)
		}
	}

	// Проверяем, что окна созданы
	windowCount := manager.GetWindowCount()
	if windowCount != 3 {
		t.Errorf("Expected 3 windows before clear, got %d", windowCount)
	}

	// Очищаем все окна
	manager.ClearAllWindows()

	// Проверяем, что все окна удалены
	windowCount = manager.GetWindowCount()
	if windowCount != 0 {
		t.Errorf("Expected 0 windows after clear, got %d", windowCount)
	}
}

func TestMemoryStateManager_ConcurrentAccess(t *testing.T) {
	manager := NewMemoryStateManager()

	// Запускаем несколько горутин для конкурентного доступа
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			ruleID := fmt.Sprintf("rule_%d", id)
			groupKey := fmt.Sprintf("group_%d", id)

			// Создаем окно
			window := &dsl.WindowState{
				RuleID:      ruleID,
				GroupKey:    groupKey,
				StartTime:   time.Now(),
				EndTime:     time.Now().Add(5 * time.Minute),
				EventCount:  id,
				UniqueCount: map[string]int{"user": id},
				LastEvent:   time.Now(),
			}

			err := manager.UpdateWindowState(ruleID, groupKey, window)
			if err != nil {
				t.Errorf("UpdateWindowState failed in goroutine %d: %v", id, err)
			}

			// Читаем состояние окна
			_, err = manager.GetWindowState(ruleID, groupKey)
			if err != nil {
				t.Errorf("GetWindowState failed in goroutine %d: %v", id, err)
			}

			done <- true
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		<-done
	}

	// Проверяем, что все окна созданы
	windowCount := manager.GetWindowCount()
	if windowCount != 10 {
		t.Errorf("Expected 10 windows after concurrent access, got %d", windowCount)
	}
}

func TestMemoryStateManager_MakeKey(t *testing.T) {
	manager := NewMemoryStateManager()

	ruleID := "test_rule"
	groupKey := "user:testuser"

	// Создаем ключ
	key := manager.makeKey(ruleID, groupKey)
	expectedKey := "test_rule:user:testuser"

	if key != expectedKey {
		t.Errorf("Expected key %s, got %s", expectedKey, key)
	}
}

func TestMemoryStateManager_ParseKey(t *testing.T) {
	manager := NewMemoryStateManager()

	// Тестируем парсинг корректного ключа
	key := "rule_1:group_a"
	parts := manager.parseKey(key)

	if len(parts) != 2 {
		t.Errorf("Expected 2 parts, got %d", len(parts))
	}
	if parts[0] != "rule_1" {
		t.Errorf("Expected first part 'rule_1', got %s", parts[0])
	}
	if parts[1] != "group_a" {
		t.Errorf("Expected second part 'group_a', got %s", parts[1])
	}

	// Тестируем парсинг некорректного ключа
	invalidKey := "invalid_key"
	parts = manager.parseKey(invalidKey)

	if len(parts) != 2 {
		t.Errorf("Expected 2 parts for invalid key, got %d", len(parts))
	}
	if parts[0] != "unknown" {
		t.Errorf("Expected first part 'unknown' for invalid key, got %s", parts[0])
	}
	if parts[1] != "unknown" {
		t.Errorf("Expected second part 'unknown' for invalid key, got %s", parts[1])
	}
}
