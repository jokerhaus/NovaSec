// internal/common/pg/client.go
package pg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Client представляет клиент PostgreSQL
type Client struct {
	db     *sql.DB
	config Config
}

// Config представляет конфигурацию PostgreSQL
type Config struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Database     string        `yaml:"database"`
	Username     string        `yaml:"username"`
	Password     string        `yaml:"password"`
	SSLMode      string        `yaml:"ssl_mode"`
	MaxOpenConns int           `yaml:"max_open_conns"`
	MaxIdleConns int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// NewClient создает новый клиент PostgreSQL // v1.0
func NewClient(config Config) (*Client, error) {
	// Создаем DSN
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		config.Host, config.Port, config.Database, config.Username, config.Password, config.SSLMode)

	// Подключаемся к PostgreSQL
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Настраиваем пул соединений
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)

	// Проверяем соединение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Client{
		db:     db,
		config: config,
	}, nil
}

// Close закрывает соединение с PostgreSQL // v1.0
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Ping проверяет соединение с PostgreSQL // v1.0
func (c *Client) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// Exec выполняет SQL команду // v1.0
func (c *Client) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return c.db.ExecContext(ctx, query, args...)
}

// Query выполняет SQL запрос // v1.0
func (c *Client) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return c.db.QueryContext(ctx, query, args...)
}

// QueryRow выполняет SQL запрос и возвращает одну строку // v1.0
func (c *Client) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return c.db.QueryRowContext(ctx, query, args...)
}

// Prepare подготавливает SQL запрос // v1.0
func (c *Client) Prepare(ctx context.Context, query string) (*sql.Stmt, error) {
	return c.db.PrepareContext(ctx, query)
}

// Begin начинает транзакцию // v1.0
func (c *Client) Begin(ctx context.Context) (*sql.Tx, error) {
	return c.db.BeginTx(ctx, nil)
}

// BeginTx начинает транзакцию с опциями // v1.0
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return c.db.BeginTx(ctx, opts)
}

// IsConnected проверяет, подключен ли клиент // v1.0
func (c *Client) IsConnected() bool {
	if c.db == nil {
		return false
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return c.Ping(ctx) == nil
}

// GetStats возвращает статистику соединения // v1.0
func (c *Client) GetStats() map[string]interface{} {
	if c.db == nil {
		return nil
	}

	stats := c.db.Stats()
	return map[string]interface{}{
		"connected":        c.IsConnected(),
		"database":         c.config.Database,
		"host":            c.config.Host,
		"port":            c.config.Port,
		"ssl_mode":        c.config.SSLMode,
		"max_open_conns":  c.config.MaxOpenConns,
		"max_idle_conns":  c.config.MaxIdleConns,
		"open_connections": stats.OpenConnections,
		"in_use":          stats.InUse,
		"idle":            stats.Idle,
		"wait_count":      stats.WaitCount,
		"wait_duration":   stats.WaitDuration,
		"max_idle_closed": stats.MaxIdleClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	}
}

// GetConnectionInfo возвращает информацию о соединении // v1.0
func (c *Client) GetConnectionInfo() map[string]interface{} {
	return map[string]interface{}{
		"connected":    c.IsConnected(),
		"database":     c.config.Database,
		"host":        c.config.Host,
		"port":        c.config.Port,
		"username":    c.config.Username,
		"ssl_mode":    c.config.SSLMode,
	}
}
