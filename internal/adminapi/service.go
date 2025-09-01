// filename: internal/adminapi/service.go
// NovaSec Admin API Service

package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
)

// Service represents the admin API service // v1.0
type Service struct {
	config *config.Config
	logger *logging.Logger
	server *http.Server
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new admin API service // v1.0
func NewService(cfg *config.Config, logger *logging.Logger) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// Start starts the admin API service // v1.0
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting admin API service")

	// Create Gin router
	router := gin.Default()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(s.loggingMiddleware())

	// Setup routes
	s.setupRoutes(router)

	// Create HTTP server
	s.server = &http.Server{
		Addr:    ":8080", // Default admin port
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Logger.Error("HTTP server error", err)
		}
	}()

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		s.logger.Logger.Info("Context cancelled, stopping service")
	case <-s.stopChan:
		s.logger.Logger.Info("Stop signal received, stopping service")
	}

	return nil
}

// Stop stops the admin API service // v1.0
func (s *Service) Stop() {
	close(s.stopChan)
	if s.server != nil {
		s.server.Shutdown(context.Background())
	}
}

// setupRoutes configures the API routes // v1.0
func (s *Service) setupRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		// Health check
		api.GET("/health", s.healthHandler)

		// Alerts
		api.GET("/alerts", s.getAlertsHandler)

		// Rules
		api.GET("/rules", s.getRulesHandler)
		api.POST("/rules", s.createRuleHandler)
		api.POST("/rules/test", s.testRuleHandler)
	}
}

// healthHandler handles health check requests // v1.0
func (s *Service) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "novasec-adminapi",
		"version":   "1.0",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// getAlertsHandler handles GET /api/v1/alerts // v1.0
func (s *Service) getAlertsHandler(c *gin.Context) {
	// Получаем параметры запроса
	fromStr := c.Query("from")
	toStr := c.Query("to")
	severity := c.Query("severity")
	ruleID := c.Query("rule_id")
	status := c.Query("status")
	env := c.Query("env")
	cursor := c.Query("cursor")
	limitStr := c.Query("limit")

	// Парсим limit
	limit := 100 // дефолтный лимит
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Парсим даты (в реальной реализации будут использоваться для фильтрации)
	if fromStr != "" {
		if _, err := time.Parse(time.RFC3339, fromStr); err != nil {
			s.logger.Logger.Warn("Invalid from date format", err)
		}
	}
	if toStr != "" {
		if _, err := time.Parse(time.RFC3339, toStr); err != nil {
			s.logger.Logger.Warn("Invalid to date format", err)
		}
	}

	// В реальной реализации здесь будет запрос к базе данных
	// Пока возвращаем заглушку с параметрами
	response := gin.H{
		"alerts": []interface{}{},
		"total":  0,
		"limit":  limit,
		"cursor": cursor,
		"filters": gin.H{
			"from":     fromStr,
			"to":       toStr,
			"severity": severity,
			"rule_id":  ruleID,
			"status":   status,
			"env":      env,
		},
	}

	c.JSON(http.StatusOK, response)
}

// getRulesHandler handles GET /api/v1/rules // v1.0
func (s *Service) getRulesHandler(c *gin.Context) {
	// В реальной реализации здесь будет запрос к базе данных
	// Пока возвращаем заглушку
	rules := []gin.H{
		{
			"id":         "login_bruteforce",
			"name":       "SSH Brute Force Detection",
			"version":    1,
			"enabled":    true,
			"created_at": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		},
		{
			"id":         "fim_critical",
			"name":       "Critical File Changes",
			"version":    1,
			"enabled":    true,
			"created_at": time.Now().Add(-48 * time.Hour).Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// createRuleHandler handles POST /api/v1/rules // v1.0
func (s *Service) createRuleHandler(c *gin.Context) {
	var ruleData map[string]interface{}
	if err := c.ShouldBindJSON(&ruleData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"message": err.Error(),
		})
		return
	}

	// Валидация обязательных полей
	if ruleData["rule_id"] == nil || ruleData["name"] == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing required fields",
			"message": "rule_id and name are required",
		})
		return
	}

	// В реальной реализации здесь будет:
	// 1. Валидация YAML
	// 2. Компиляция правила
	// 3. Сохранение в базу данных

	ruleID := ruleData["rule_id"].(string)
	response := gin.H{
		"message":    "Rule created successfully",
		"id":         ruleID,
		"status":     "active",
		"created_at": time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusCreated, response)
}

// testRuleHandler handles POST /api/v1/rules/test // v1.0
func (s *Service) testRuleHandler(c *gin.Context) {
	var testRequest struct {
		RuleID        string `json:"rule_id" binding:"required"`
		EventsFixture string `json:"events_fixture" binding:"required"`
	}

	if err := c.ShouldBindJSON(&testRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"message": err.Error(),
		})
		return
	}

	// В реальной реализации здесь будет:
	// 1. Загрузка фикстуры событий
	// 2. Применение правила
	// 3. Подсчет результатов

	// Симуляция тестирования
	testResults := gin.H{
		"rule_id":          testRequest.RuleID,
		"events_fixture":   testRequest.EventsFixture,
		"total_events":     25,
		"alerts_generated": 3,
		"test_status":      "passed",
		"execution_time":   "45ms",
		"timestamp":        time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, testResults)
}

// loggingMiddleware adds logging to requests // v1.0
func (s *Service) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		s.logger.Logger.WithField("method", param.Method).
			WithField("path", param.Path).
			WithField("status", param.StatusCode).
			WithField("latency", param.Latency).
			WithField("client_ip", param.ClientIP).
			WithField("user_agent", param.Request.UserAgent()).
			Info("HTTP request")
		return ""
	})
}
