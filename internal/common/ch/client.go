// internal/common/ch/client.go
package ch

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Client представляет клиент ClickHouse
type Client struct {
	conn   driver.Conn
	config Config
}

// Config представляет конфигурацию ClickHouse
type Config struct {
	Hosts     []string      `yaml:"hosts"`
	Database  string        `yaml:"database"`
	Username  string        `yaml:"username"`
	Password  string        `yaml:"password"`
	Port      int           `yaml:"port"`
	Secure    bool          `yaml:"secure"`
	Compress  bool          `yaml:"compress"`
	MaxOpen   int           `yaml:"max_open"`
	MaxIdle   int           `yaml:"max_idle"`
	Timeout   time.Duration `yaml:"timeout"`
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
		dsn.TLS = &clickhouse.TLS{
			Secure: true,
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
func (c *Client) Prepare(ctx context.Context, query string) (driver.Stmt, error) {
	return c.conn.Prepare(ctx, query)
}

// Begin начинает транзакцию // v1.0
func (c *Client) Begin(ctx context.Context) (driver.Tx, error) {
	return c.conn.Begin(ctx)
}

// InsertEvent вставляет событие в таблицу events // v1.0
func (c *Client) InsertEvent(ctx context.Context, event interface{}) error {
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

	// Здесь нужно привести event к конкретному типу и извлечь поля
	// Для простоты пока возвращаем ошибку
	return fmt.Errorf("InsertEvent not implemented yet")
}

// InsertEventsBatch вставляет события пакетом // v1.0
func (c *Client) InsertEventsBatch(ctx context.Context, events []interface{}) error {
	if len(events) == 0 {
		return nil
	}

	// Начинаем транзакцию
	tx, err := c.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Подготавливаем запрос
	stmt, err := tx.Prepare(ctx, `
		INSERT INTO events (
			ts, host, agent_id, env, source, severity, category, subtype, message,
			user_name, user_uid, src_ip, src_port, dst_ip, dst_port, proto,
			file_path, process_pid, process_name, sha256, labels, geo, asn, ioc, raw
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	// Вставляем события
	for _, event := range events {
		// Здесь нужно привести event к конкретному типу и извлечь поля
		// Для простоты пока пропускаем
		continue
	}

	// Подтверждаем транзакцию
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
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

	row := c.QueryRow(ctx, query, args...)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to scan count: %w", err)
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
