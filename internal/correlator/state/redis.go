// filename: internal/correlator/state/redis.go
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/correlator/dsl"

	"github.com/redis/go-redis/v9"
)

// RedisStateManager реализует StateManager через Redis // v1.0
type RedisStateManager struct {
	config *RedisConfig
	logger *logging.Logger
	client *redis.Client
}

// RedisConfig конфигурация Redis StateManager // v1.0
type RedisConfig struct {
	Host       string        `yaml:"host"`
	Port       int           `yaml:"port"`
	Password   string        `yaml:"password"`
	Database   int           `yaml:"database"`
	Timeout    time.Duration `yaml:"timeout"`
	MaxRetries int           `yaml:"max_retries"`
	RetryDelay time.Duration `yaml:"retry_delay"`
	KeyPrefix  string        `yaml:"key_prefix"`
	TTL        time.Duration `yaml:"ttl"`
}

// NewRedisStateManager создает новый Redis StateManager // v1.0
func NewRedisStateManager(config *RedisConfig, logger *logging.Logger) *RedisStateManager {
	// Создаем Redis клиент
	client := redis.NewClient(&redis.Options{
		Addr:            fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:        config.Password,
		DB:              config.Database,
		DialTimeout:     config.Timeout,
		ReadTimeout:     config.Timeout,
		WriteTimeout:    config.Timeout,
		MaxRetries:      config.MaxRetries,
		MinRetryBackoff: config.RetryDelay,
		MaxRetryBackoff: config.RetryDelay * 2,
	})

	return &RedisStateManager{
		config: config,
		logger: logger,
		client: client,
	}
}

// GetWindowState возвращает состояние окна для правила и группы // v1.0
func (r *RedisStateManager) GetWindowState(ruleID, groupKey string) (*dsl.WindowState, error) {
	key := r.makeKey(ruleID, groupKey)

	// Получаем данные из Redis
	data, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		if err == redis.Nil {
			// Ключ не найден, возвращаем пустое состояние
			return &dsl.WindowState{
				StartTime:   time.Now(),
				EndTime:     time.Now(),
				EventCount:  0,
				UniqueCount: make(map[string]int),
				LastEvent:   time.Time{},
			}, nil
		}
		return nil, fmt.Errorf("failed to get window state from Redis: %w", err)
	}

	// Десериализуем состояние
	var window dsl.WindowState
	if err := json.Unmarshal([]byte(data), &window); err != nil {
		return nil, fmt.Errorf("failed to unmarshal window state: %w", err)
	}

	r.logger.Logger.WithFields(map[string]interface{}{
		"rule_id":   ruleID,
		"group_key": groupKey,
		"redis_key": key,
	}).Debug("Window state retrieved from Redis")

	return &window, nil
}

// UpdateWindowState обновляет состояние окна в Redis // v1.0
func (r *RedisStateManager) UpdateWindowState(ruleID, groupKey string, state *dsl.WindowState) error {
	key := r.makeKey(ruleID, groupKey)

	// Сериализуем состояние
	stateData, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal window state: %w", err)
	}

	// Определяем TTL
	ttl := r.config.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour // Дефолтный TTL
	}

	// Сохраняем в Redis с TTL
	err = r.client.Set(context.Background(), key, stateData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save window state to Redis: %w", err)
	}

	r.logger.Logger.WithFields(map[string]interface{}{
		"rule_id":     ruleID,
		"group_key":   groupKey,
		"redis_key":   key,
		"ttl":         ttl.String(),
		"state_size":  len(stateData),
		"event_count": state.EventCount,
	}).Debug("Window state updated in Redis")

	return nil
}

// CleanupExpiredWindows очищает истекшие окна в Redis // v1.0
func (r *RedisStateManager) CleanupExpiredWindows() error {
	r.logger.Logger.Debug("Cleaning up expired windows in Redis")

	// Используем SCAN для поиска ключей с префиксом
	pattern := r.config.KeyPrefix + ":*"
	if r.config.KeyPrefix == "" {
		pattern = "novasec:windows:*"
	}

	var cursor uint64
	var err error
	var keys []string

	for {
		keys, cursor, err = r.client.Scan(context.Background(), cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan Redis keys: %w", err)
		}

		// Проверяем TTL для каждого ключа
		for _, key := range keys {
			ttl, err := r.client.TTL(context.Background(), key).Result()
			if err != nil {
				r.logger.Logger.WithError(err).WithField("key", key).Warn("Failed to get TTL for key")
				continue
			}

			// Если TTL < 0, ключ истек
			if ttl < 0 {
				if err := r.client.Del(context.Background(), key).Err(); err != nil {
					r.logger.Logger.WithError(err).WithField("key", key).Warn("Failed to delete expired key")
				} else {
					r.logger.Logger.WithField("key", key).Debug("Deleted expired key")
				}
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

// GetStats возвращает статистику Redis StateManager // v1.0
func (r *RedisStateManager) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"type":       "redis",
		"host":       r.config.Host,
		"port":       r.config.Port,
		"database":   r.config.Database,
		"key_prefix": r.config.KeyPrefix,
		"ttl":        r.config.TTL.String(),
	}

	// Проверяем соединение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		stats["connected"] = false
		stats["error"] = err.Error()
		return stats
	}

	stats["connected"] = true

	// Получаем статистику Redis
	info, err := r.client.Info(ctx, "keyspace").Result()
	if err == nil {
		stats["redis_info"] = info
	}

	// Подсчитываем ключи с префиксом
	pattern := r.config.KeyPrefix + ":*"
	if r.config.KeyPrefix == "" {
		pattern = "novasec:windows:*"
	}

	var cursor uint64
	var keys []string
	totalKeys := 0
	expiredKeys := 0

	for {
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			break
		}

		totalKeys += len(keys)

		// Проверяем TTL для каждого ключа
		for _, key := range keys {
			ttl, err := r.client.TTL(ctx, key).Result()
			if err == nil && ttl < 0 {
				expiredKeys++
			}
		}

		if cursor == 0 {
			break
		}
	}

	stats["total_keys"] = totalKeys
	stats["expired_keys"] = expiredKeys
	stats["last_cleanup"] = time.Now().Format(time.RFC3339)

	return stats
}

// Close закрывает соединение с Redis // v1.0
func (r *RedisStateManager) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// makeKey создает ключ для Redis // v1.0
func (r *RedisStateManager) makeKey(ruleID, groupKey string) string {
	prefix := r.config.KeyPrefix
	if prefix == "" {
		prefix = "novasec:windows"
	}
	return fmt.Sprintf("%s:%s:%s", prefix, ruleID, groupKey)
}

// GetWindowCount возвращает количество окон в Redis // v1.0
func (r *RedisStateManager) GetWindowCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pattern := r.config.KeyPrefix + ":*"
	if r.config.KeyPrefix == "" {
		pattern = "novasec:windows:*"
	}

	var cursor uint64
	var keys []string
	var err error
	totalCount := 0

	for {
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			r.logger.Logger.WithError(err).Error("Failed to scan Redis keys")
			break
		}

		totalCount += len(keys)

		if cursor == 0 {
			break
		}
	}

	return totalCount
}

// ClearAllWindows очищает все окна в Redis // v1.0
func (r *RedisStateManager) ClearAllWindows() error {
	r.logger.Logger.Info("Clearing all windows from Redis")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pattern := r.config.KeyPrefix + ":*"
	if r.config.KeyPrefix == "" {
		pattern = "novasec:windows:*"
	}

	var cursor uint64
	var keys []string
	var err error
	deletedCount := 0

	for {
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan Redis keys: %w", err)
		}

		// Удаляем найденные ключи
		if len(keys) > 0 {
			if err := r.client.Del(ctx, keys...).Err(); err != nil {
				r.logger.Logger.WithError(err).WithField("keys_count", len(keys)).Warn("Failed to delete some keys")
			} else {
				deletedCount += len(keys)
			}
		}

		if cursor == 0 {
			break
		}
	}

	r.logger.Logger.WithField("deleted_keys", deletedCount).Info("Cleared all windows from Redis")
	return nil
}

// GetWindowInfo возвращает информацию о конкретном окне // v1.0
func (r *RedisStateManager) GetWindowInfo(ruleID, groupKey string) (map[string]interface{}, error) {
	key := r.makeKey(ruleID, groupKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Проверяем существование ключа
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check key existence: %w", err)
	}

	if exists == 0 {
		return map[string]interface{}{
			"rule_id":   ruleID,
			"group_key": groupKey,
			"redis_key": key,
			"exists":    false,
		}, nil
	}

	// Получаем TTL
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		ttl = -1 // Если не удалось получить TTL
	}

	// Получаем размер данных
	data, err := r.client.Get(ctx, key).Result()
	size := "0B"
	if err == nil {
		size = fmt.Sprintf("%dB", len(data))
	}

	info := map[string]interface{}{
		"rule_id":     ruleID,
		"group_key":   groupKey,
		"redis_key":   key,
		"ttl":         ttl.String(),
		"exists":      true,
		"size":        size,
		"last_access": time.Now().Format(time.RFC3339),
	}

	return info, nil
}

// ListWindows возвращает список всех окон // v1.0
func (r *RedisStateManager) ListWindows() []map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pattern := r.config.KeyPrefix + ":*"
	if r.config.KeyPrefix == "" {
		pattern = "novasec:windows:*"
	}

	var cursor uint64
	var keys []string
	var err error
	windows := make([]map[string]interface{}, 0)

	for {
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			r.logger.Logger.WithError(err).Error("Failed to scan Redis keys")
			break
		}

		// Получаем информацию о каждом ключе
		for _, key := range keys {
			// Парсим ключ для извлечения rule_id и group_key
			parts := strings.Split(key, ":")
			if len(parts) >= 4 {
				ruleID := parts[len(parts)-2]
				groupKey := parts[len(parts)-1]

				// Получаем TTL
				ttl, err := r.client.TTL(ctx, key).Result()
				if err != nil {
					ttl = -1
				}

				// Получаем размер данных
				data, err := r.client.Get(ctx, key).Result()
				size := "0B"
				if err == nil {
					size = fmt.Sprintf("%dB", len(data))
				}

				window := map[string]interface{}{
					"rule_id":     ruleID,
					"group_key":   groupKey,
					"redis_key":   key,
					"ttl":         ttl.String(),
					"size":        size,
					"last_access": time.Now().Format(time.RFC3339),
				}
				windows = append(windows, window)
			}
		}

		if cursor == 0 {
			break
		}
	}

	return windows
}

// Ping проверяет соединение с Redis // v1.0
func (r *RedisStateManager) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis ping failed: %w", err)
	}

	r.logger.Logger.Debug("Redis ping successful")
	return nil
}

// GetRedisInfo возвращает информацию о Redis сервере // v1.0
func (r *RedisStateManager) GetRedisInfo() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Получаем общую информацию о Redis
	info, err := r.client.Info(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get Redis info: %w", err)
	}

	// Парсим INFO ответ
	result := make(map[string]interface{})
	lines := strings.Split(info, "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Преобразуем числовые значения
				if intVal, err := strconv.Atoi(value); err == nil {
					result[key] = intVal
				} else if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
					result[key] = floatVal
				} else {
					result[key] = value
				}
			}
		}
	}

	return result, nil
}

// FlushDatabase очищает всю базу данных Redis // v1.0
func (r *RedisStateManager) FlushDatabase() error {
	r.logger.Logger.Warn("Flushing Redis database")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// В продакшене эта операция должна быть защищена
	// Выполняем FLUSHDB команду
	if err := r.client.FlushDB(ctx).Err(); err != nil {
		return fmt.Errorf("failed to flush Redis database: %w", err)
	}

	r.logger.Logger.Info("Redis database flushed successfully")
	return nil
}
