// filename: internal/adminapi/server/server.go
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/novasec/novasec/internal/adminapi/routes"
	"github.com/novasec/novasec/internal/common/logging"
)

// Server представляет HTTP сервер Admin API // v1.0
type Server struct {
	config *Config
	logger *logging.Logger
	router *gin.Engine
	server *http.Server
}

// Config конфигурация сервера // v1.0
type Config struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	LogLevel     string        `yaml:"log_level"`
}

// NewServer создает новый HTTP сервер // v1.0
func NewServer(config *Config, logger *logging.Logger) *Server {
	// Устанавливаем уровень логирования Gin
	if config.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Добавляем middleware
	router.Use(gin.Recovery())
	router.Use(loggingMiddleware(logger))
	router.Use(corsMiddleware())
	router.Use(rateLimitMiddleware())

	server := &Server{
		config: config,
		logger: logger,
		router: router,
	}

	// Настраиваем роуты
	server.setupRoutes()

	// Создаем HTTP сервер
	server.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Handler:      router,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	return server
}

// setupRoutes настраивает роуты API // v1.0
func (s *Server) setupRoutes() {
	// Создаем обработчики
	healthHandler := routes.NewHealthHandler(s.logger)
	alertsHandler := routes.NewAlertsHandler(s.logger)
	rulesHandler := routes.NewRulesHandler(s.logger)

	// API v1
	v1 := s.router.Group("/api/v1")
	{
		// Health endpoints
		v1.GET("/health", healthHandler.HealthCheck)
		v1.GET("/health/detailed", healthHandler.DetailedHealthCheck)
		v1.GET("/health/ready", healthHandler.ReadinessCheck)
		v1.GET("/health/live", healthHandler.LivenessCheck)
		v1.GET("/health/status", healthHandler.Status)
		v1.GET("/metrics", healthHandler.Metrics)

		// Alerts endpoints
		alerts := v1.Group("/alerts")
		{
			alerts.GET("", alertsHandler.GetAlerts)
			alerts.GET("/stats", alertsHandler.GetAlertStats)
			alerts.POST("/bulk-update", alertsHandler.BulkUpdateAlerts)
			alerts.GET("/:id", alertsHandler.GetAlertByID)
			alerts.PUT("/:id/status", alertsHandler.UpdateAlertStatus)
			alerts.DELETE("/:id", alertsHandler.DeleteAlert)
		}

		// Rules endpoints
		rules := v1.Group("/rules")
		{
			rules.GET("", rulesHandler.GetRules)
			rules.POST("", rulesHandler.CreateRule)
			rules.POST("/test", rulesHandler.TestRule)
			rules.POST("/validate", rulesHandler.ValidateRule)
			rules.GET("/:id", rulesHandler.GetRuleByID)
			rules.PUT("/:id", rulesHandler.UpdateRule)
			rules.DELETE("/:id", rulesHandler.DeleteRule)
			rules.PUT("/:id/enable", rulesHandler.EnableRule)
			rules.PUT("/:id/disable", rulesHandler.DisableRule)
			rules.GET("/:id/stats", rulesHandler.GetRuleStats)
		}
	}

	// Root endpoint
	s.router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":   "NovaSec Admin API",
			"version":   "1.0.0",
			"status":    "running",
			"timestamp": time.Now().Format(time.RFC3339),
			"endpoints": gin.H{
				"health": "/api/v1/health",
				"alerts": "/api/v1/alerts",
				"rules":  "/api/v1/rules",
				"docs":   "/docs",
			},
		})
	})

	// 404 handler
	s.router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Endpoint not found",
			"message": fmt.Sprintf("Method %s %s not found", c.Request.Method, c.Request.URL.Path),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})
}

// Start запускает HTTP сервер // v1.0
func (s *Server) Start() error {
	s.logger.Logger.WithFields(map[string]interface{}{
		"host": s.config.Host,
		"port": s.config.Port,
	}).Info("Starting Admin API server")

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Stop останавливает HTTP сервер // v1.0
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Logger.Info("Stopping Admin API server")

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}

// GetRouter возвращает роутер для тестирования // v1.0
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// GetConfig возвращает конфигурацию сервера // v1.0
func (s *Server) GetConfig() *Config {
	return s.config
}

// loggingMiddleware добавляет логирование запросов // v1.0
func loggingMiddleware(logger *logging.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logger.Logger.WithFields(map[string]interface{}{
			"method":     param.Method,
			"path":       param.Path,
			"status":     param.StatusCode,
			"latency":    param.Latency,
			"client_ip":  param.ClientIP,
			"user_agent": param.Request.UserAgent(),
		}).Info("HTTP request")

		return ""
	})
}

// corsMiddleware добавляет CORS заголовки // v1.0
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// rateLimitMiddleware добавляет базовый rate limiting // v1.0
func rateLimitMiddleware() gin.HandlerFunc {
	// В реальной реализации здесь будет более сложная логика rate limiting
	return func(c *gin.Context) {
		// Простая проверка - всегда пропускаем
		c.Next()
	}
}

// GetServerInfo возвращает информацию о сервере // v1.0
func (s *Server) GetServerInfo() map[string]interface{} {
	return map[string]interface{}{
		"host":         s.config.Host,
		"port":         s.config.Port,
		"read_timeout": s.config.ReadTimeout.String(),
		"write_timeout": s.config.WriteTimeout.String(),
		"idle_timeout": s.config.IdleTimeout.String(),
		"log_level":    s.config.LogLevel,
		"status":       "running",
	}
}
