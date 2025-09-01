// filename: internal/correlator/state/memory.go
package state

import (
	"fmt"
	"sync"
	"time"

	"github.com/novasec/novasec/internal/correlator/dsl"
)

// MemoryStateManager реализует StateManager в памяти // v1.0
type MemoryStateManager struct {
	windows map[string]*dsl.WindowState
	mu      sync.RWMutex
}

// NewMemoryStateManager создает новый in-memory StateManager // v1.0
func NewMemoryStateManager() *MemoryStateManager {
	return &MemoryStateManager{
		windows: make(map[string]*dsl.WindowState),
	}
}

// GetWindowState возвращает состояние окна для правила и группы // v1.0
func (m *MemoryStateManager) GetWindowState(ruleID, groupKey string) (*dsl.WindowState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(ruleID, groupKey)
	window, exists := m.windows[key]
	
	if !exists {
		// Создаем новое состояние окна
		window = &dsl.WindowState{
			StartTime:   time.Now(),
			EndTime:     time.Now().Add(5 * time.Minute), // Дефолтное окно 5 минут
			EventCount:  0,
			UniqueCount: make(map[string]int),
			LastEvent:   time.Time{},
		}
		m.windows[key] = window
	}

	return window, nil
}

// UpdateWindowState обновляет состояние окна // v1.0
func (m *MemoryStateManager) UpdateWindowState(ruleID, groupKey string, state *dsl.WindowState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.makeKey(ruleID, groupKey)
	m.windows[key] = state

	return nil
}

// CleanupExpiredWindows очищает истекшие окна // v1.0
func (m *MemoryStateManager) CleanupExpiredWindows() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredKeys := []string{}

	for key, window := range m.windows {
		if now.After(window.EndTime.Add(5 * time.Minute)) { // Дополнительный буфер
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(m.windows, key)
	}

	return nil
}

// GetStats возвращает статистику состояния // v1.0
func (m *MemoryStateManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_windows": len(m.windows),
		"type":          "memory",
	}

	// Подсчитываем активные окна
	activeWindows := 0
	now := time.Now()
	for _, window := range m.windows {
		if now.Before(window.EndTime) {
			activeWindows++
		}
	}
	stats["active_windows"] = activeWindows

	return stats
}

// makeKey создает ключ для окна // v1.0
func (m *MemoryStateManager) makeKey(ruleID, groupKey string) string {
	return fmt.Sprintf("%s:%s", ruleID, groupKey)
}

// GetWindowCount возвращает количество окон // v1.0
func (m *MemoryStateManager) GetWindowCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.windows)
}

// ClearAllWindows очищает все окна // v1.0
func (m *MemoryStateManager) ClearAllWindows() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Очищаем map
	for k := range m.windows {
		delete(m.windows, k)
	}
}

// GetWindowInfo возвращает информацию о конкретном окне // v1.0
func (m *MemoryStateManager) GetWindowInfo(ruleID, groupKey string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.makeKey(ruleID, groupKey)
	window, exists := m.windows[key]
	
	if !exists {
		return nil, fmt.Errorf("window not found for rule %s, group %s", ruleID, groupKey)
	}

	info := map[string]interface{}{
		"rule_id":     ruleID,
		"group_key":   groupKey,
		"start_time":  window.StartTime,
		"end_time":    window.EndTime,
		"event_count": window.EventCount,
		"unique_count": len(window.UniqueCount),
		"last_event":  window.LastEvent,
		"is_expired":  time.Now().After(window.EndTime),
	}

	return info, nil
}

// ListWindows возвращает список всех окон // v1.0
func (m *MemoryStateManager) ListWindows() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	windows := make([]map[string]interface{}, 0, len(m.windows))
	
	for key, window := range m.windows {
		// Парсим ключ для извлечения rule_id и group_key
		parts := m.parseKey(key)
		if len(parts) == 2 {
			info := map[string]interface{}{
				"rule_id":     parts[0],
				"group_key":   parts[1],
				"start_time":  window.StartTime,
				"end_time":    window.EndTime,
				"event_count": window.EventCount,
				"unique_count": len(window.UniqueCount),
				"last_event":  window.LastEvent,
				"is_expired":  time.Now().After(window.EndTime),
			}
			windows = append(windows, info)
		}
	}

	return windows
}

// parseKey парсит ключ окна // v1.0
func (m *MemoryStateManager) parseKey(key string) []string {
	// Простой парсинг по двоеточию
	// В реальной реализации может потребоваться более сложная логика
	// если group_key содержит двоеточия
	return []string{key[:len(key)/2], key[len(key)/2+1:]}
}
