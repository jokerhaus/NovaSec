// filename: internal/correlator/dsl/evaluator.go
package dsl

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/novasec/novasec/internal/models"
)

// SlidingWindowEvaluator оценщик скользящих временных окон // v1.0
type SlidingWindowEvaluator struct {
	ruleID     string
	windowSize time.Duration
	threshold  ThresholdConfig
	groupBy    []string
	sliding    bool

	// Состояние окон по группам
	windows map[string]*WindowState
}

// NewSlidingWindowEvaluator создает новый оценщик скользящих окон // v1.0
func NewSlidingWindowEvaluator(ruleID string, windowSize time.Duration, threshold ThresholdConfig, groupBy []string, sliding bool) *SlidingWindowEvaluator {
	return &SlidingWindowEvaluator{
		ruleID:     ruleID,
		windowSize: windowSize,
		threshold:  threshold,
		groupBy:    groupBy,
		sliding:    sliding,
		windows:    make(map[string]*WindowState),
	}
}

// AddEvent добавляет событие в окно и возвращает true если сработал триггер // v1.0
func (e *SlidingWindowEvaluator) AddEvent(event *models.Event) bool {
	groupKey := e.GetGroupKey(event)

	// Получаем или создаем состояние окна для группы
	window, exists := e.windows[groupKey]
	if !exists {
		window = &WindowState{
			RuleID:      e.ruleID,
			GroupKey:    groupKey,
			StartTime:   time.Now(),
			EndTime:     time.Now().Add(e.windowSize),
			EventCount:  0,
			UniqueCount: make(map[string]int),
			LastEvent:   time.Now(),
		}
		e.windows[groupKey] = window
	}

	// Проверяем, нужно ли сбросить окно
	if e.shouldResetWindow(window) {
		e.resetWindow(window)
	}

	// Добавляем событие в окно
	window.EventCount++
	window.LastEvent = time.Now()

	// Обновляем уникальные значения если нужно
	if e.threshold.Type == "unique" && e.threshold.Field != "" {
		value := e.extractFieldValue(event, e.threshold.Field)
		if value != "" {
			window.UniqueCount[value]++
		}
	}

	// Проверяем, сработал ли триггер
	return e.checkThreshold(window)
}

// IsTriggered проверяет, сработал ли триггер для группы // v1.0
func (e *SlidingWindowEvaluator) IsTriggered() bool {
	for _, window := range e.windows {
		if e.checkThreshold(window) {
			return true
		}
	}
	return false
}

// GetGroupKey генерирует ключ группы для события // v1.0
func (e *SlidingWindowEvaluator) GetGroupKey(event *models.Event) string {
	if len(e.groupBy) == 0 {
		return "default"
	}

	var keyParts []string
	for _, field := range e.groupBy {
		value := e.extractFieldValue(event, field)
		if value != "" {
			keyParts = append(keyParts, fmt.Sprintf("%s=%s", field, value))
		}
	}

	if len(keyParts) == 0 {
		return "default"
	}

	// Сортируем для детерминированности
	sort.Strings(keyParts)
	return strings.Join(keyParts, "|")
}

// GetWindowStart возвращает время начала окна для группы // v1.0
func (e *SlidingWindowEvaluator) GetWindowStart() time.Time {
	// Возвращаем самое раннее время начала среди всех окон
	var earliest time.Time
	for _, window := range e.windows {
		if earliest.IsZero() || window.StartTime.Before(earliest) {
			earliest = window.StartTime
		}
	}
	return earliest
}

// GetWindowEnd возвращает время окончания окна для группы // v1.0
func (e *SlidingWindowEvaluator) GetWindowEnd() time.Time {
	// Возвращаем самое позднее время окончания среди всех окон
	var latest time.Time
	for _, window := range e.windows {
		if window.EndTime.After(latest) {
			latest = window.EndTime
		}
	}
	return latest
}

// Reset сбрасывает все окна // v1.0
func (e *SlidingWindowEvaluator) Reset() {
	for _, window := range e.windows {
		e.resetWindow(window)
	}
}

// shouldResetWindow проверяет, нужно ли сбросить окно // v1.0
func (e *SlidingWindowEvaluator) shouldResetWindow(window *WindowState) bool {
	now := time.Now()

	if e.sliding {
		// Для скользящего окна сбрасываем если прошло больше размера окна
		return now.Sub(window.StartTime) > e.windowSize
	} else {
		// Для фиксированного окна сбрасываем если текущее время вышло за пределы окна
		return now.After(window.EndTime)
	}
}

// resetWindow сбрасывает состояние окна // v1.0
func (e *SlidingWindowEvaluator) resetWindow(window *WindowState) {
	now := time.Now()

	if e.sliding {
		// Для скользящего окна сдвигаем начало
		window.StartTime = now
		window.EndTime = now.Add(e.windowSize)
	} else {
		// Для фиксированного окна создаем новое окно
		window.StartTime = now
		window.EndTime = now.Add(e.windowSize)
	}

	window.EventCount = 0
	window.UniqueCount = make(map[string]int)
	window.LastEvent = now
}

// checkThreshold проверяет, достигнут ли порог // v1.0
func (e *SlidingWindowEvaluator) checkThreshold(window *WindowState) bool {
	switch e.threshold.Type {
	case "count":
		return window.EventCount >= e.threshold.Count
	case "unique":
		if e.threshold.Field == "" {
			return false
		}
		uniqueCount := len(window.UniqueCount)
		return uniqueCount >= e.threshold.Count
	default:
		return false
	}
}

// extractFieldValue извлекает значение поля из события // v1.0
func (e *SlidingWindowEvaluator) extractFieldValue(event *models.Event, field string) string {
	switch field {
	case "host":
		return event.Host
	case "agent_id":
		return event.AgentID
	case "env":
		return event.Env
	case "source":
		return event.Source
	case "severity":
		return event.Severity
	case "category":
		return event.Category
	case "subtype":
		return event.Subtype
	case "user.name":
		if event.User != nil {
			return event.User.Name
		}
		return ""
	case "network.src_ip":
		if event.Network != nil && event.Network.SrcIP != nil {
			return fmt.Sprintf("%d", *event.Network.SrcIP)
		}
		return ""
	case "network.src_port":
		if event.Network != nil && event.Network.SrcPort != nil {
			return fmt.Sprintf("%d", *event.Network.SrcPort)
		}
		return ""
	case "network.proto":
		if event.Network != nil {
			return event.Network.Proto
		}
		return ""
	case "file.path":
		if event.File != nil {
			return event.File.Path
		}
		return ""
	case "process.name":
		if event.Process != nil {
			return event.Process.Name
		}
		return ""
	case "process.pid":
		if event.Process != nil && event.Process.PID != nil {
			return fmt.Sprintf("%d", *event.Process.PID)
		}
		return ""
	default:
		// Проверяем метки
		if event.Labels != nil {
			if value, exists := event.Labels[field]; exists {
				return value
			}
		}
		return ""
	}
}

// GetWindowStats возвращает статистику по окнам // v1.0
func (e *SlidingWindowEvaluator) GetWindowStats() map[string]interface{} {
	stats := make(map[string]interface{})

	for groupKey, window := range e.windows {
		stats[groupKey] = map[string]interface{}{
			"event_count":  window.EventCount,
			"unique_count": len(window.UniqueCount),
			"start_time":   window.StartTime,
			"end_time":     window.EndTime,
			"last_event":   window.LastEvent,
			"is_triggered": e.checkThreshold(window),
		}
	}

	return stats
}

// CleanupExpiredWindows очищает истекшие окна // v1.0
func (e *SlidingWindowEvaluator) CleanupExpiredWindows() {
	now := time.Now()
	expiredKeys := []string{}

	for key, window := range e.windows {
		if now.After(window.EndTime.Add(e.windowSize)) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(e.windows, key)
	}
}
