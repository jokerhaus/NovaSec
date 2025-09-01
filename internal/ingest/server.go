// filename: internal/ingest/server.go
package server

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/errors"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/models"
)

// Server представляет сервер ingest
type Server struct {
	config     *config.Config
	natsClient *nats.Client
	logger     *logging.Logger
}

// IngestRequest представляет запрос на ingest
type IngestRequest struct {
	Events []string `json:"events" binding:"required"`
}

// IngestResponse представляет ответ на ingest
type IngestResponse struct {
	OK       bool   `json:"ok"`
	Received int    `json:"received"`
	Message  string `json:"message,omitempty"`
}

// NewServer создает новый сервер ingest // v1.0
func NewServer(cfg *config.Config, natsClient *nats.Client, logger *logging.Logger) *Server {
	return &Server{
		config:     cfg,
		natsClient: natsClient,
		logger:     logger,
	}
}

// Router возвращает HTTP роутер // v1.0
func (s *Server) Router() *gin.Engine {
	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(s.loggingMiddleware())
	router.Use(s.rateLimitMiddleware())
	router.Use(s.requestIDMiddleware())

	// API v1
	v1 := router.Group("/api/v1")
	{
		// Health check
		v1.GET("/health", s.healthHandler)

		// Ingest endpoint
		v1.POST("/ingest", s.ingestHandler)
	}

	return router
}

// healthHandler обрабатывает health check // v1.0
func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"service":   "ingest",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// ingestHandler обрабатывает ingest запросы // v1.0
func (s *Server) ingestHandler(c *gin.Context) {
	start := time.Now()

	// Получаем Agent ID из заголовка
	agentID := c.GetHeader("X-Agent-Id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "X-Agent-Id header is required",
		})
		return
	}

	// Проверяем Content-Type
	contentType := c.GetHeader("Content-Type")
	if contentType != "application/x-ndjson" && !strings.Contains(contentType, "text/plain") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Content-Type must be application/x-ndjson or text/plain",
		})
		return
	}

	// Читаем тело запроса
	body, err := c.GetRawData()
	if err != nil {
		s.logger.WithError(err).Error("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read request body",
		})
		return
	}

	// Парсим NDJSON
	events, err := s.parseNDJSON(body)
	if err != nil {
		s.logger.WithError(err).Error("Failed to parse NDJSON")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Failed to parse NDJSON: %v", err),
		})
		return
	}

	// Валидируем и обрабатываем события
	validEvents := 0
	for _, event := range events {
		if err := s.processEvent(event, agentID); err != nil {
			s.logger.WithError(err).WithField("event", event).Error("Failed to process event")
			continue
		}
		validEvents++
	}

	// Публикуем в NATS
	if err := s.publishToNATS(events); err != nil {
		s.logger.WithError(err).Error("Failed to publish to NATS")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to publish events",
		})
		return
	}

	// Логируем метрики
	duration := time.Since(start).Milliseconds()
	s.logger.WithFields(logging.Fields{
		"agent_id":        agentID,
		"events_received": len(events),
		"events_valid":    validEvents,
		"duration_ms":     duration,
		"remote_addr":     c.ClientIP(),
	}).Info("Ingest request processed")

	// Возвращаем ответ
	response := IngestResponse{
		OK:       true,
		Received: validEvents,
		Message:  fmt.Sprintf("Successfully processed %d events", validEvents),
	}

	c.JSON(http.StatusAccepted, response)
}

// parseNDJSON парсит NDJSON данные // v1.0
func (s *Server) parseNDJSON(data []byte) ([]string, error) {
	var events []string
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			events = append(events, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan NDJSON: %w", err)
	}

	return events, nil
}

// processEvent обрабатывает одно событие // v1.0
func (s *Server) processEvent(eventData string, agentID string) error {
	// Парсим событие
	event, err := models.NewEventFromNDJSON(eventData)
	if err != nil {
		return errors.Wrap(err, errors.ErrorCodeEventParseFailed, "failed to parse event")
	}

	// Устанавливаем Agent ID если не указан
	if event.AgentID == "" {
		event.AgentID = agentID
	}

	// Валидируем обязательные поля
	if err := s.validateEvent(event); err != nil {
		return errors.Wrap(err, errors.ErrorCodeEventInvalid, "event validation failed")
	}

	return nil
}

// validateEvent валидирует событие // v1.0
func (s *Server) validateEvent(event *models.Event) error {
	if event.TS.IsZero() {
		return errors.ValidationError("ts", "timestamp is required")
	}

	if event.Host == "" {
		return errors.ValidationError("host", "host is required")
	}

	if event.Category == "" {
		return errors.ValidationError("category", "category is required")
	}

	if event.Subtype == "" {
		return errors.ValidationError("subtype", "subtype is required")
	}

	if event.Message == "" {
		return errors.ValidationError("message", "message is required")
	}

	// Проверяем, что timestamp не в будущем
	if event.TS.After(time.Now().Add(5 * time.Minute)) {
		return errors.ValidationError("ts", "timestamp cannot be in the future")
	}

	// Проверяем, что timestamp не слишком старый (30 дней)
	if event.TS.Before(time.Now().AddDate(0, 0, -30)) {
		return errors.ValidationError("ts", "timestamp is too old")
	}

	return nil
}

// publishToNATS публикует события в NATS // v1.0
func (s *Server) publishToNATS(events []string) error {
	for _, eventData := range events {
		// Публикуем в JetStream subject events.raw
		if err := s.natsClient.PublishEvent("events.raw", eventData); err != nil {
			return fmt.Errorf("failed to publish event to NATS: %w", err)
		}
	}

	return nil
}

// loggingMiddleware добавляет логирование // v1.0
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		s.logger.WithFields(logging.Fields{
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

// rateLimitMiddleware добавляет rate limiting // v1.0
func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	// Простая реализация rate limiting
	// В продакшене лучше использовать Redis или другой механизм
	clients := make(map[string]*rateLimitInfo)

	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		info, exists := clients[clientIP]
		if !exists {
			info = &rateLimitInfo{
				requests: 0,
				window:   time.Now(),
			}
			clients[clientIP] = info
		}

		// Сброс счетчика каждую минуту
		if time.Since(info.window) > time.Minute {
			info.requests = 0
			info.window = time.Now()
		}

		// Проверяем лимит (1000 запросов в минуту)
		if info.requests >= 1000 {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
			})
			c.Abort()
			return
		}

		info.requests++
		c.Next()
	}
}

// requestIDMiddleware добавляет request ID // v1.0
func (s *Server) requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// rateLimitInfo представляет информацию о rate limiting
type rateLimitInfo struct {
	requests int
	window   time.Time
}

// generateRequestID генерирует уникальный ID запроса // v1.0
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
