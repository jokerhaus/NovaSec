// filename: internal/common/config/config.go
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config представляет основную конфигурацию приложения
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	NATS       NATSConfig       `mapstructure:"nats"`
	ClickHouse ClickHouseConfig `mapstructure:"clickhouse"`
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	TLS        TLSConfig        `mapstructure:"tls"`
}

// ServerConfig представляет конфигурацию сервера
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

// NATSConfig представляет конфигурацию NATS
type NATSConfig struct {
	URLs        []string `mapstructure:"urls"`
	ClusterID   string   `mapstructure:"cluster_id"`
	ClientID    string   `mapstructure:"client_id"`
	Credentials string   `mapstructure:"credentials"`
	JWT         string   `mapstructure:"jwt"`
	NKey        string   `mapstructure:"nkey"`
}

// ClickHouseConfig представляет конфигурацию ClickHouse
type ClickHouseConfig struct {
	Hosts    []string      `mapstructure:"hosts"`
	Database string        `mapstructure:"database"`
	Username string        `mapstructure:"username"`
	Password string        `mapstructure:"password"`
	Port     int           `mapstructure:"port"`
	Secure   bool          `mapstructure:"secure"`
	Compress bool          `mapstructure:"compress"`
	MaxOpen  int           `mapstructure:"max_open"`
	MaxIdle  int           `mapstructure:"max_idle"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// PostgreSQLConfig представляет конфигурацию PostgreSQL
type PostgreSQLConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Database        string        `mapstructure:"database"`
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// RedisConfig представляет конфигурацию Redis
type RedisConfig struct {
	Host     string        `mapstructure:"host"`
	Port     int           `mapstructure:"port"`
	Password string        `mapstructure:"password"`
	DB       int           `mapstructure:"db"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// LoggingConfig представляет конфигурацию логирования
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// TLSConfig представляет конфигурацию TLS
type TLSConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	CAFile     string `mapstructure:"ca_file"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	MinVersion string `mapstructure:"min_version"`
}

// LoadConfig загружает конфигурацию из файла // v1.0
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Устанавливаем значения по умолчанию
	setDefaults()

	// Читаем конфигурацию
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Валидируем конфигурацию
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults устанавливает значения по умолчанию // v1.0
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")

	// NATS defaults
	viper.SetDefault("nats.urls", []string{"nats://localhost:4222"})
	viper.SetDefault("nats.cluster_id", "novasec")
	viper.SetDefault("nats.client_id", "novasec-client")

	// ClickHouse defaults
	viper.SetDefault("clickhouse.hosts", []string{"localhost"})
	viper.SetDefault("clickhouse.database", "novasec")
	viper.SetDefault("clickhouse.port", 9000)
	viper.SetDefault("clickhouse.secure", false)
	viper.SetDefault("clickhouse.compress", true)
	viper.SetDefault("clickhouse.max_open", 100)
	viper.SetDefault("clickhouse.max_idle", 10)
	viper.SetDefault("clickhouse.timeout", "30s")

	// PostgreSQL defaults
	viper.SetDefault("postgresql.host", "localhost")
	viper.SetDefault("postgresql.port", 5432)
	viper.SetDefault("postgresql.database", "novasec")
	viper.SetDefault("postgresql.ssl_mode", "disable")
	viper.SetDefault("postgresql.max_open_conns", 100)
	viper.SetDefault("postgresql.max_idle_conns", 10)
	viper.SetDefault("postgresql.conn_max_lifetime", "1h")

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.timeout", "5s")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)

	// TLS defaults
	viper.SetDefault("tls.enabled", false)
	viper.SetDefault("tls.min_version", "1.2")
}

// Validate валидирует конфигурацию // v1.0
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if len(c.NATS.URLs) == 0 {
		return fmt.Errorf("at least one NATS URL is required")
	}

	if len(c.ClickHouse.Hosts) == 0 {
		return fmt.Errorf("at least one ClickHouse host is required")
	}

	if c.ClickHouse.Database == "" {
		return fmt.Errorf("ClickHouse database name is required")
	}

	if c.PostgreSQL.Database == "" {
		return fmt.Errorf("PostgreSQL database name is required")
	}

	return nil
}

// GetServerAddr возвращает адрес сервера // v1.0
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// GetClickHouseDSN возвращает DSN для ClickHouse // v1.0
func (c *Config) GetClickHouseDSN() string {
	host := c.ClickHouse.Hosts[0]
	dsn := fmt.Sprintf("tcp://%s:%d?database=%s&username=%s&password=%s",
		host, c.ClickHouse.Port, c.ClickHouse.Database, c.ClickHouse.Username, c.ClickHouse.Password)

	if c.ClickHouse.Secure {
		dsn += "&secure=true"
	}

	if c.ClickHouse.Compress {
		dsn += "&compress=true"
	}

	return dsn
}

// GetPostgreSQLDSN возвращает DSN для PostgreSQL // v1.0
func (c *Config) GetPostgreSQLDSN() string {
	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.PostgreSQL.Host, c.PostgreSQL.Port, c.PostgreSQL.Database,
		c.PostgreSQL.Username, c.PostgreSQL.Password, c.PostgreSQL.SSLMode)
}

// GetRedisAddr возвращает адрес Redis // v1.0
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}
