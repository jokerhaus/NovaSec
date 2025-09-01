// filename: internal/adminapi/service.go
// NovaSec Admin API Service

package adminapi

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"novasec/internal/adminapi/server"
	"novasec/internal/common/ch"
	"novasec/internal/common/config"
	"novasec/internal/common/errors"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/common/pg"
	"novasec/internal/models"
)

// Service представляет Admin API сервис // v1.0
type Service struct {
	config   *config.Config
	logger   *logging.Logger
	server   *server.Server
	stopChan chan struct{}

	// Реальные клиенты для работы с сервисами
	pgClient   *pg.Client
	chClient   *ch.Client
	natsClient *nats.Client

	// Кэш для оптимизации
	ruleCache  map[string]*models.Rule
	alertCache map[string]*models.Alert
}

// NewService создает новый Admin API сервис // v1.0
func NewService(cfg *config.Config, logger *logging.Logger) *Service {
	// Создаем конфигурацию сервера с дефолтными значениями для Admin API
	serverConfig := &server.Config{
		Host:         "0.0.0.0", // Дефолтный хост для Admin API
		Port:         8080,      // Дефолтный порт для Admin API
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		LogLevel:     cfg.Logging.Level,
	}

	// Создаем HTTP сервер
	httpServer := server.NewServer(serverConfig, logger, nil) // pgClient будет инициализирован позже

	service := &Service{
		config:     cfg,
		logger:     logger,
		server:     httpServer,
		stopChan:   make(chan struct{}),
		ruleCache:  make(map[string]*models.Rule),
		alertCache: make(map[string]*models.Alert),
	}

	// Инициализируем клиенты для работы с сервисами
	service.initClients()

	// Обновляем сервер с инициализированными клиентами
	if service.pgClient != nil {
		service.server = server.NewServer(serverConfig, logger, service.pgClient)
	}

	return service
}

// initClients инициализирует клиенты для работы с сервисами // v1.0
func (s *Service) initClients() {
	var err error

	// Инициализируем PostgreSQL клиент
	pgConfig := pg.Config{
		Host:            s.config.PostgreSQL.Host,
		Port:            s.config.PostgreSQL.Port,
		Database:        s.config.PostgreSQL.Database,
		Username:        s.config.PostgreSQL.Username,
		Password:        s.config.PostgreSQL.Password,
		SSLMode:         s.config.PostgreSQL.SSLMode,
		MaxOpenConns:    s.config.PostgreSQL.MaxOpenConns,
		MaxIdleConns:    s.config.PostgreSQL.MaxIdleConns,
		ConnMaxLifetime: s.config.PostgreSQL.ConnMaxLifetime,
	}

	s.pgClient, err = pg.NewClient(pgConfig)
	if err != nil {
		s.logger.Logger.Error("Failed to initialize PostgreSQL client", err)
	} else {
		s.logger.Logger.Info("PostgreSQL client initialized successfully")
	}

	// Инициализируем ClickHouse клиент
	chConfig := ch.Config{
		Hosts:    s.config.ClickHouse.Hosts,
		Database: s.config.ClickHouse.Database,
		Username: s.config.ClickHouse.Username,
		Password: s.config.ClickHouse.Password,
		Port:     s.config.ClickHouse.Port,
		Secure:   s.config.ClickHouse.Secure,
		Compress: s.config.ClickHouse.Compress,
		MaxOpen:  s.config.ClickHouse.MaxOpen,
		MaxIdle:  s.config.ClickHouse.MaxIdle,
		Timeout:  s.config.ClickHouse.Timeout,
	}

	s.chClient, err = ch.NewClient(chConfig)
	if err != nil {
		s.logger.Logger.Error("Failed to initialize ClickHouse client", err)
	} else {
		s.logger.Logger.Info("ClickHouse client initialized successfully")
	}

	// Инициализируем NATS клиент
	natsConfig := nats.Config{
		URLs:        s.config.NATS.URLs,
		ClusterID:   s.config.NATS.ClusterID,
		ClientID:    s.config.NATS.ClientID,
		Credentials: s.config.NATS.Credentials,
		JWT:         s.config.NATS.JWT,
		NKey:        s.config.NATS.NKey,
		Timeout:     30 * time.Second, // Дефолтный таймаут
	}

	s.natsClient, err = nats.NewClient(natsConfig)
	if err != nil {
		s.logger.Logger.Error("Failed to initialize NATS client", err)
	} else {
		s.logger.Logger.Info("NATS client initialized successfully")
	}
}

// Start запускает Admin API сервис // v1.0
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting Admin API service")

	// Проверяем готовность зависимостей
	if err := s.checkDependencies(ctx); err != nil {
		return fmt.Errorf("dependencies not ready: %w", err)
	}

	// Запускаем фоновые задачи
	go s.startBackgroundTasks(ctx)

	// Запускаем HTTP сервер в горутине
	go func() {
		if err := s.server.Start(); err != nil {
			s.logger.Logger.Error("Failed to start HTTP server", err)
		}
	}()

	// Ждем сигнала остановки или отмены контекста
	select {
	case <-ctx.Done():
		s.logger.Logger.Info("Context cancelled, stopping service")
	case <-s.stopChan:
		s.logger.Logger.Info("Stop signal received, stopping service")
	}

	return nil
}

// checkDependencies проверяет готовность зависимостей // v1.0
func (s *Service) checkDependencies(ctx context.Context) error {
	// Проверяем PostgreSQL
	if s.pgClient != nil {
		if err := s.pgClient.Ping(ctx); err != nil {
			return fmt.Errorf("PostgreSQL not ready: %w", err)
		}
	}

	// Проверяем ClickHouse
	if s.chClient != nil {
		if err := s.chClient.Ping(ctx); err != nil {
			return fmt.Errorf("ClickHouse not ready: %w", err)
		}
	}

	// Проверяем NATS
	if s.natsClient != nil {
		if !s.natsClient.IsConnected() {
			return fmt.Errorf("NATS not connected")
		}
	}

	return nil
}

// startBackgroundTasks запускает фоновые задачи // v1.0
func (s *Service) startBackgroundTasks(ctx context.Context) {
	// Очистка кэша каждые 5 минут
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupCache()
		}
	}
}

// cleanupCache очищает устаревшие данные из кэша // v1.0
func (s *Service) cleanupCache() {
	now := time.Now()

	// Очищаем кэш правил старше 1 часа
	for id, rule := range s.ruleCache {
		if now.Sub(rule.UpdatedAt) > time.Hour {
			delete(s.ruleCache, id)
		}
	}

	// Очищаем кэш алертов старше 30 минут
	for id, alert := range s.alertCache {
		if now.Sub(alert.UpdatedAt) > 30*time.Minute {
			delete(s.alertCache, id)
		}
	}

	s.logger.Logger.Debug("Cache cleanup completed",
		"rules_count", len(s.ruleCache),
		"alerts_count", len(s.alertCache))
}

// Stop останавливает Admin API сервис // v1.0
func (s *Service) Stop() {
	close(s.stopChan)

	// Останавливаем HTTP сервер
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.server.Stop(ctx); err != nil {
			s.logger.Logger.Error("Failed to stop HTTP server gracefully", err)
		}
	}

	// Закрываем соединения с базами данных
	if s.pgClient != nil {
		if err := s.pgClient.Close(); err != nil {
			s.logger.Logger.Error("Failed to close PostgreSQL connection", err)
		}
	}

	if s.chClient != nil {
		if err := s.chClient.Close(); err != nil {
			s.logger.Logger.Error("Failed to close ClickHouse connection", err)
		}
	}

	if s.natsClient != nil {
		if err := s.natsClient.Close(); err != nil {
			s.logger.Logger.Error("Failed to close NATS connection", err)
		}
	}

	s.logger.Logger.Info("Admin API service stopped")
}

// GetServerInfo возвращает информацию о сервере // v1.0
func (s *Service) GetServerInfo() map[string]interface{} {
	if s.server != nil {
		return s.server.GetServerInfo()
	}
	return map[string]interface{}{
		"status": "not_initialized",
	}
}

// GetRouter возвращает роутер для тестирования // v1.0
func (s *Service) GetRouter() interface{} {
	if s.server != nil {
		return s.server.GetRouter()
	}
	return nil
}

// HealthCheck проверяет состояние сервиса // v1.0
func (s *Service) HealthCheck() map[string]interface{} {
	serverInfo := s.GetServerInfo()

	// Проверяем состояние всех зависимостей
	dependencies := s.checkAllDependencies(context.Background())

	health := map[string]interface{}{
		"status":       "healthy",
		"service":      "novasec-adminapi",
		"version":      "1.0.0",
		"timestamp":    time.Now().Format(time.RFC3339),
		"server":       serverInfo,
		"dependencies": dependencies,
	}

	// Определяем общий статус здоровья
	overallStatus := "healthy"
	for _, dep := range dependencies {
		if status, ok := dep.(map[string]interface{})["status"]; ok && status != "healthy" {
			overallStatus = "degraded"
			break
		}
	}

	health["status"] = overallStatus
	return health
}

// checkAllDependencies проверяет состояние всех зависимостей // v1.0
func (s *Service) checkAllDependencies(ctx context.Context) map[string]interface{} {
	deps := make(map[string]interface{})

	// PostgreSQL
	if s.pgClient != nil {
		if err := s.pgClient.Ping(ctx); err != nil {
			deps["postgresql"] = map[string]interface{}{
				"status":  "unhealthy",
				"error":   err.Error(),
				"details": "Connection failed",
			}
		} else {
			deps["postgresql"] = map[string]interface{}{
				"status":  "healthy",
				"details": "Connection established",
			}
		}
	} else {
		deps["postgresql"] = map[string]interface{}{
			"status":  "unavailable",
			"details": "Client not initialized",
		}
	}

	// ClickHouse
	if s.chClient != nil {
		if err := s.chClient.Ping(ctx); err != nil {
			deps["clickhouse"] = map[string]interface{}{
				"status":  "unhealthy",
				"error":   err.Error(),
				"details": "Connection failed",
			}
		} else {
			deps["clickhouse"] = map[string]interface{}{
				"status":  "healthy",
				"details": "Connection established",
			}
		}
	} else {
		deps["clickhouse"] = map[string]interface{}{
			"status":  "unavailable",
			"details": "Client not initialized",
		}
	}

	// NATS
	if s.natsClient != nil {
		if s.natsClient.IsConnected() {
			deps["nats"] = map[string]interface{}{
				"status":  "healthy",
				"details": "Connected to NATS",
			}
		} else {
			deps["nats"] = map[string]interface{}{
				"status":  "unhealthy",
				"details": "Not connected to NATS",
			}
		}
	} else {
		deps["nats"] = map[string]interface{}{
			"status":  "unavailable",
			"details": "Client not initialized",
		}
	}

	return deps
}

// PublishAlertEvent публикует событие алерта в NATS // v1.0
func (s *Service) PublishAlertEvent(alert *models.Alert) error {
	if s.natsClient == nil {
		return errors.New(errors.ErrorCodeNATSConnection, "NATS client not available")
	}

	subject := fmt.Sprintf("alerts.%s.%s", alert.Severity, alert.RuleID)
	return s.natsClient.PublishEvent(subject, alert)
}

// GetRuleFromCache получает правило из кэша или загружает из БД // v1.0
func (s *Service) GetRuleFromCache(ruleID string) (*models.Rule, error) {
	// Проверяем кэш
	if rule, exists := s.ruleCache[ruleID]; exists {
		return rule, nil
	}

	// Загружаем из базы данных
	if s.pgClient == nil {
		return nil, errors.New(errors.ErrorCodePGConnection, "PostgreSQL client not available")
	}

	rule := &models.Rule{}
	query := `SELECT id, name, version, enabled, yaml, created_at, updated_at 
			  FROM rules WHERE id = $1 AND enabled = true`

	ctx := context.Background()
	err := s.pgClient.QueryRow(ctx, query, ruleID).Scan(
		&rule.ID, &rule.Name, &rule.Version, &rule.Enabled,
		&rule.YAML, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.ErrorCodeRuleInvalid, "rule not found")
		}
		return nil, fmt.Errorf("failed to query rule: %w", err)
	}

	// Сохраняем в кэш
	s.ruleCache[ruleID] = rule
	return rule, nil
}

// GetAlertFromCache получает алерт из кэша или загружает из БД // v1.0
func (s *Service) GetAlertFromCache(alertID string) (*models.Alert, error) {
	// Проверяем кэш
	if alert, exists := s.alertCache[alertID]; exists {
		return alert, nil
	}

	// Загружаем из базы данных
	if s.pgClient == nil {
		return nil, errors.New(errors.ErrorCodePGConnection, "PostgreSQL client not available")
	}

	alert := &models.Alert{}
	query := `SELECT id, ts, rule_id, severity, dedup_key, payload, status, env, host, created_at, updated_at 
			  FROM alerts WHERE id = $1`

	ctx := context.Background()
	err := s.pgClient.QueryRow(ctx, query, alertID).Scan(
		&alert.ID, &alert.TS, &alert.RuleID, &alert.Severity, &alert.DedupKey,
		&alert.Payload, &alert.Status, &alert.Env, &alert.Host, &alert.CreatedAt, &alert.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New(errors.ErrorCodeAlertNotFound, "alert not found")
		}
		return nil, fmt.Errorf("failed to query alert: %w", err)
	}

	// Сохраняем в кэш
	s.alertCache[alertID] = alert
	return alert, nil
}
