// filename: internal/common/logging/logger.go
package logging

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

// Logger представляет логгер приложения
type Logger struct {
	*logrus.Logger
}

// Config представляет конфигурацию логирования
type Config struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
}

// NewLogger создает новый логгер // v1.0
func NewLogger(config Config) (*Logger, error) {
	logger := logrus.New()

	// Устанавливаем уровень логирования
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return nil, err
	}
	logger.SetLevel(level)

	// Устанавливаем формат
	switch config.Format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	// Устанавливаем вывод
	if err := setOutput(logger, config); err != nil {
		return nil, err
	}

	return &Logger{Logger: logger}, nil
}

// setOutput устанавливает вывод для логгера // v1.0
func setOutput(logger *logrus.Logger, config Config) error {
	switch config.Output {
	case "stdout":
		logger.SetOutput(os.Stdout)
	case "stderr":
		logger.SetOutput(os.Stderr)
	case "file":
		if err := setFileOutput(logger, config); err != nil {
			return err
		}
	default:
		logger.SetOutput(os.Stdout)
	}

	return nil
}

// setFileOutput устанавливает файловый вывод // v1.0
func setFileOutput(logger *logrus.Logger, config Config) error {
	// Создаем директорию если не существует
	dir := filepath.Dir(config.Output)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Открываем файл
	file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	// Устанавливаем вывод
	logger.SetOutput(io.MultiWriter(os.Stdout, file))

	return nil
}

// WithField добавляет поле к логгеру // v1.0
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithFields добавляет поля к логгеру // v1.0
func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// WithError добавляет ошибку к логгеру // v1.0
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithRequest добавляет информацию о запросе к логгеру // v1.0
func (l *Logger) WithRequest(method, path, remoteAddr string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"method":      method,
		"path":        path,
		"remote_addr": remoteAddr,
	})
}

// WithAgent добавляет информацию об агенте к логгеру // v1.0
func (l *Logger) WithAgent(agentID, host string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"host":     host,
	})
}

// WithEvent добавляет информацию о событии к логгеру // v1.0
func (l *Logger) WithEvent(category, subtype, severity string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"category": category,
		"subtype":  subtype,
		"severity": severity,
	})
}

// WithRule добавляет информацию о правиле к логгеру // v1.0
func (l *Logger) WithRule(ruleID, ruleName string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"rule_id":   ruleID,
		"rule_name": ruleName,
	})
}

// WithAlert добавляет информацию об алерте к логгеру // v1.0
func (l *Logger) WithAlert(alertID, ruleID, severity string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"alert_id": alertID,
		"rule_id":  ruleID,
		"severity": severity,
	})
}

// WithDuration добавляет длительность к логгеру // v1.0
func (l *Logger) WithDuration(duration float64) *logrus.Entry {
	return l.Logger.WithField("duration_ms", duration)
}

// WithMetrics добавляет метрики к логгеру // v1.0
func (l *Logger) WithMetrics(eventsProcessed, alertsGenerated int) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"events_processed": eventsProcessed,
		"alerts_generated": alertsGenerated,
	})
}

// SetLevel устанавливает уровень логирования // v1.0
func (l *Logger) SetLevel(level string) error {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	l.Logger.SetLevel(logLevel)
	return nil
}

// GetLevel возвращает текущий уровень логирования // v1.0
func (l *Logger) GetLevel() string {
	return l.Logger.GetLevel().String()
}

// IsLevelEnabled проверяет, включен ли уровень логирования // v1.0
func (l *Logger) IsLevelEnabled(level string) bool {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return false
	}
	return l.Logger.IsLevelEnabled(logLevel)
}
