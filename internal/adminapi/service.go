// internal/adminapi/service.go
// NovaSec Admin API Service

package adminapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
)

// Service represents the admin API service
type Service struct {
	config *config.Config
	logger *logging.Logger
	server *http.Server
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new admin API service
func NewService(cfg *config.Config, logger *logging.Logger) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// Start starts the admin API service
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

// Stop stops the admin API service
func (s *Service) Stop() {
	close(s.stopChan)
	if s.server != nil {
		s.server.Shutdown(context.Background())
	}
}

// setupRoutes configures the API routes
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

// healthHandler handles health check requests
func (s *Service) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"service": "novasec-adminapi",
		"version": "1.0",
	})
}

// getAlertsHandler handles GET /api/v1/alerts
func (s *Service) getAlertsHandler(c *gin.Context) {
	// TODO: Implement alerts retrieval from database
	c.JSON(http.StatusOK, gin.H{
		"alerts": []interface{}{},
		"total": 0,
	})
}

// getRulesHandler handles GET /api/v1/rules
func (s *Service) getRulesHandler(c *gin.Context) {
	// TODO: Implement rules retrieval from database
	c.JSON(http.StatusOK, gin.H{
		"rules": []interface{}{},
		"total": 0,
	})
}

// createRuleHandler handles POST /api/v1/rules
func (s *Service) createRuleHandler(c *gin.Context) {
	// TODO: Implement rule creation
	c.JSON(http.StatusCreated, gin.H{
		"message": "Rule created successfully",
		"id": "new-rule-id",
	})
}

// testRuleHandler handles POST /api/v1/rules/test
func (s *Service) testRuleHandler(c *gin.Context) {
	// TODO: Implement rule testing with fixtures
	c.JSON(http.StatusOK, gin.H{
		"message": "Rule test completed",
		"result": "passed",
	})
}

// loggingMiddleware adds logging to requests
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
