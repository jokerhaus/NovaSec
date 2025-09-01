// filename: internal/common/ch/client.go
package ch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"novasec/internal/models"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Client представляет клиент ClickHouse
type Client struct {
	conn   clickhouse.Conn
	config Config
}

// Config представляет конфигурацию ClickHouse
type Config struct {
	Hosts    []string      `yaml:"hosts"`
	Database string        `yaml:"database"`
	Username string        `yaml:"username"`
	Password string        `yaml:"password"`
	Port     int           `yaml:"port"`
	Secure   bool          `yaml:"secure"`
	Compress bool          `yaml:"compress"`
	MaxOpen  int           `yaml:"max_open"`
	MaxIdle  int           `yaml:"max_idle"`
	Timeout  time.Duration `yaml:"timeout"`
}

// NewClient создает новый клиент ClickHouse // v1.0
func NewClient(config Config) (*Client, error) {
	// Создаем DSN
	dsn := &clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", config.Hosts[0], config.Port)},
		Auth: clickhouse.Auth{
			Database: config.Database,
			Username: config.Username,
			Password: config.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		Debug: false,
	}

	if config.Secure {
		// ClickHouse v2 использует TLS по умолчанию при подключении к порту 9440
		// Для порта 9000 нужно явно указать TLS
		if config.Port == 9000 {
			// В ClickHouse v2 TLS настраивается через Options
			dsn.Settings["secure"] = true
		}
	}

	if config.Compress {
		dsn.Compression.Method = clickhouse.CompressionLZ4
	}

	// Подключаемся к ClickHouse
	conn, err := clickhouse.Open(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	// Проверяем соединение
	if err := conn.Ping(context.Background()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	return &Client{
		conn:   conn,
		config: config,
	}, nil
}

// Close закрывает соединение с ClickHouse // v1.0
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Ping проверяет соединение с ClickHouse // v1.0
func (c *Client) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// Exec выполняет SQL команду // v1.0
func (c *Client) Exec(ctx context.Context, query string, args ...interface{}) error {
	return c.conn.Exec(ctx, query, args...)
}

// Query выполняет SQL запрос // v1.0
func (c *Client) Query(ctx context.Context, query string, args ...interface{}) (driver.Rows, error) {
	return c.conn.Query(ctx, query, args...)
}

// QueryRow выполняет SQL запрос и возвращает одну строку // v1.0
func (c *Client) QueryRow(ctx context.Context, query string, args ...interface{}) driver.Row {
	return c.conn.QueryRow(ctx, query, args...)
}

// Prepare подготавливает SQL запрос // v1.0
func (c *Client) Prepare(ctx context.Context, query string) (interface{}, error) {
	// ClickHouse v2 не поддерживает Prepare
	return nil, fmt.Errorf("Prepare not supported in ClickHouse v2")
}

// Begin начинает транзакцию // v1.0
func (c *Client) Begin(ctx context.Context) (interface{}, error) {
	// ClickHouse v2 не поддерживает транзакции
	return nil, fmt.Errorf("Transactions not supported in ClickHouse v2")
}

// InsertEvent вставляет событие в таблицу events // v1.0
func (c *Client) InsertEvent(ctx context.Context, event interface{}) error {
	// Приводим event к типу models.Event
	evt, ok := event.(*models.Event)
	if !ok {
		return fmt.Errorf("invalid event type: expected *models.Event, got %T", event)
	}

	query := `
		INSERT INTO events (
			ts, host, agent_id, env, source, severity, category, subtype, message,
			user_name, user_uid, src_ip, src_port, dst_ip, dst_port, proto,
			file_path, process_pid, process_name, sha256, labels, geo, asn, ioc, raw
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?
		)
	`

	// Используем плоские поля из Event для совместимости с ClickHouse
	user_name := evt.UserName
	user_uid := evt.UserUID
	src_ip := evt.SrcIP
	dst_ip := evt.DstIP
	src_port := evt.SrcPort
	dst_port := evt.DstPort
	proto := evt.Proto
	file_path := evt.FilePath
	process_pid := evt.ProcessPID
	process_name := evt.ProcessName
	sha256 := evt.SHA256
	geo := evt.Geo
	asn := evt.ASN
	ioc := evt.IOC
	raw := evt.Raw

	// Если плоские поля пустые, используем вложенные структуры
	if evt.User != nil {
		if user_name == "" {
			user_name = evt.User.Name
		}
		if user_uid == nil {
			user_uid = evt.User.UID
		}
	}

	if evt.Network != nil {
		if src_ip == "" {
			src_ip = evt.Network.SrcIP
		}
		if dst_ip == "" {
			dst_ip = evt.Network.DstIP
		}
		if src_port == nil {
			src_port = evt.Network.SrcPort
		}
		if dst_port == nil {
			dst_port = evt.Network.DstPort
		}
		if proto == "" {
			proto = evt.Network.Proto
		}
	}

	if evt.File != nil {
		if file_path == "" {
			file_path = evt.File.Path
		}
	}

	if evt.Process != nil {
		if process_pid == nil {
			process_pid = evt.Process.PID
		}
		if process_name == "" {
			process_name = evt.Process.Name
		}
	}

	if evt.Hashes != nil {
		if sha256 == "" {
			sha256 = evt.Hashes.SHA256
		}
	}

	// Сериализуем метки в JSON
	var labels map[string]interface{}
	if evt.Labels != nil {
		labels = make(map[string]interface{})
		for k, v := range evt.Labels {
			labels[k] = v
		}
	}

	// Выполняем вставку
	return c.Exec(ctx, query,
		evt.TS, evt.Host, evt.AgentID, evt.Env, evt.Source, evt.Severity, evt.Category, evt.Subtype, evt.Message,
		user_name, user_uid, src_ip, src_port, dst_ip, dst_port, proto,
		file_path, process_pid, process_name, sha256, labels, geo, asn, ioc, raw,
	)
}

// InsertEventsBatch вставляет события пакетом // v1.0
func (c *Client) InsertEventsBatch(ctx context.Context, events []interface{}) error {
	if len(events) == 0 {
		return nil
	}

	// ClickHouse v2 поддерживает пакетную вставку через Exec с множественными значениями
	query := `
		INSERT INTO events (
			ts, host, agent_id, env, source, severity, category, subtype, message,
			user_name, user_uid, src_ip, src_port, dst_ip, dst_port, proto,
			file_path, process_pid, process_name, sha256, labels, geo, asn, ioc, raw
		) VALUES
	`

	// Формируем пакет значений
	var values []interface{}
	placeholders := make([]string, len(events))

	for i, event := range events {
		evt, ok := event.(*models.Event)
		if !ok {
			return fmt.Errorf("invalid event type at index %d: expected *models.Event, got %T", i, event)
		}

		// Используем плоские поля из Event для совместимости с ClickHouse
		user_name := evt.UserName
		user_uid := evt.UserUID
		src_ip := evt.SrcIP
		dst_ip := evt.DstIP
		src_port := evt.SrcPort
		dst_port := evt.DstPort
		proto := evt.Proto
		file_path := evt.FilePath
		process_pid := evt.ProcessPID
		process_name := evt.ProcessName
		sha256 := evt.SHA256
		geo := evt.Geo
		asn := evt.ASN
		ioc := evt.IOC
		raw := evt.Raw

		// Если плоские поля пустые, используем вложенные структуры
		if evt.User != nil {
			if user_name == "" {
				user_name = evt.User.Name
			}
			if user_uid == nil {
				user_uid = evt.User.UID
			}
		}

		if evt.Network != nil {
			if src_ip == "" {
				src_ip = evt.Network.SrcIP
			}
			if dst_ip == "" {
				dst_ip = evt.Network.DstIP
			}
			if src_port == nil {
				src_port = evt.Network.SrcPort
			}
			if dst_port == nil {
				dst_port = evt.Network.DstPort
			}
			if proto == "" {
				proto = evt.Network.Proto
			}
		}

		if evt.File != nil {
			if file_path == "" {
				file_path = evt.File.Path
			}
		}

		if evt.Process != nil {
			if process_pid == nil {
				process_pid = evt.Process.PID
			}
			if process_name == "" {
				process_name = evt.Process.Name
			}
		}

		if evt.Hashes != nil {
			if sha256 == "" {
				sha256 = evt.Hashes.SHA256
			}
		}

		// Сериализуем метки в JSON
		var labels map[string]interface{}
		if evt.Labels != nil {
			labels = make(map[string]interface{})
			for k, v := range evt.Labels {
				labels[k] = v
			}
		}

		placeholders[i] = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
		values = append(values,
			evt.TS, evt.Host, evt.AgentID, evt.Env, evt.Source, evt.Severity, evt.Category, evt.Subtype, evt.Message,
			user_name, user_uid, src_ip, src_port, dst_ip, dst_port, proto,
			file_path, process_pid, process_name, sha256, labels, geo, asn, ioc, raw,
		)
	}

	// Формируем полный запрос
	query += strings.Join(placeholders, ", ")

	// Выполняем пакетную вставку
	return c.Exec(ctx, query, values...)
}

// QueryEvents выполняет запрос событий // v1.0
func (c *Client) QueryEvents(ctx context.Context, query string, args ...interface{}) (driver.Rows, error) {
	return c.Query(ctx, query, args...)
}

// GetEventCount возвращает количество событий // v1.0
func (c *Client) GetEventCount(ctx context.Context, where string, args ...interface{}) (int64, error) {
	query := "SELECT count() FROM events"
	if where != "" {
		query += " WHERE " + where
	}

	rows, err := c.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to query count: %w", err)
	}
	defer rows.Close()

	// В ClickHouse v2 используем Scan для получения результата
	var count int64
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, fmt.Errorf("failed to scan count: %w", err)
		}
	}

	return count, nil
}

// GetEventsByTimeRange возвращает события в диапазоне времени // v1.0
func (c *Client) GetEventsByTimeRange(ctx context.Context, from, to time.Time, limit int) (driver.Rows, error) {
	query := `
		SELECT * FROM events 
		WHERE ts >= ? AND ts <= ? 
		ORDER BY ts DESC 
		LIMIT ?
	`
	return c.Query(ctx, query, from, to, limit)
}

// GetEventsByHost возвращает события по хосту // v1.0
func (c *Client) GetEventsByHost(ctx context.Context, host string, limit int) (driver.Rows, error) {
	query := `
		SELECT * FROM events 
		WHERE host = ? 
		ORDER BY ts DESC 
		LIMIT ?
	`
	return c.Query(ctx, query, host, limit)
}

// GetEventsByCategory возвращает события по категории // v1.0
func (c *Client) GetEventsByCategory(ctx context.Context, category string, limit int) (driver.Rows, error) {
	query := `
		SELECT * FROM events 
		WHERE category = ? 
		ORDER BY ts DESC 
		LIMIT ?
	`
	return c.Query(ctx, query, category, limit)
}

// GetEventsBySeverity возвращает события по уровню важности // v1.0
func (c *Client) GetEventsBySeverity(ctx context.Context, severity string, limit int) (driver.Rows, error) {
	query := `
		SELECT * FROM events 
		WHERE severity = ? 
		ORDER BY ts DESC 
		LIMIT ?
	`
	return c.Query(ctx, query, severity, limit)
}

// IsConnected проверяет, подключен ли клиент // v1.0
func (c *Client) IsConnected() bool {
	if c.conn == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.Ping(ctx) == nil
}

// GetStats возвращает статистику соединения // v1.0
func (c *Client) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"connected": c.IsConnected(),
		"database":  c.config.Database,
		"host":      c.config.Hosts[0],
		"port":      c.config.Port,
		"secure":    c.config.Secure,
		"compress":  c.config.Compress,
	}
}
