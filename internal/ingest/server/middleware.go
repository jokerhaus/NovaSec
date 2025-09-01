// filename: internal/ingest/middleware.go
package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitInfo информация о rate limit для клиента // v1.0
type RateLimitInfo struct {
	Count      int
	LastReset  time.Time
	Blocked    bool
	BlockUntil time.Time
}

// RateLimitConfig конфигурация rate limiting // v1.0
type RateLimitConfig struct {
	RequestsPerMinute int
	BurstSize         int
	BlockDuration     time.Duration
}

// rateLimitMiddleware добавляет rate limiting // v1.0
func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	// В продакшене лучше использовать Redis или другой механизм
	clients := make(map[string]*RateLimitInfo)
	var mu sync.RWMutex

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		agentID := c.GetHeader("X-Agent-Id")

		// Если нет Agent-ID, используем IP
		key := agentID
		if key == "" {
			key = clientIP
		}

		mu.Lock()
		info, exists := clients[key]
		if !exists {
			info = &RateLimitInfo{
				LastReset: time.Now(),
			}
			clients[key] = info
		}

		// Проверяем, не заблокирован ли клиент
		if info.Blocked && time.Now().Before(info.BlockUntil) {
			mu.Unlock()
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": info.BlockUntil.Sub(time.Now()).Seconds(),
			})
			c.Abort()
			return
		}

		// Сбрасываем счетчик если прошла минута
		if time.Since(info.LastReset) >= time.Minute {
			info.Count = 0
			info.LastReset = time.Now()
			info.Blocked = false
		}

		// Проверяем лимит
		if info.Count >= s.config.Server.RateLimit.RequestsPerMinute {
			info.Blocked = true
			info.BlockUntil = time.Now().Add(s.config.Server.RateLimit.BlockDuration)
			mu.Unlock()

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": s.config.Server.RateLimit.BlockDuration.Seconds(),
			})
			c.Abort()
			return
		}

		info.Count++
		mu.Unlock()

		// Добавляем заголовки rate limit
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", s.config.Server.RateLimit.RequestsPerMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", s.config.Server.RateLimit.RequestsPerMinute-info.Count))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", info.LastReset.Add(time.Minute).Unix()))

		c.Next()
	}
}

// bodySizeMiddleware ограничивает размер тела запроса // v1.0
func (s *Server) bodySizeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > s.config.Server.BodySizeLimit {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":       "Request body too large",
				"max_size":    s.config.Server.BodySizeLimit,
				"actual_size": c.Request.ContentLength,
			})
			c.Abort()
			return
		}
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

		// Добавляем request_id в контекст для логирования
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// agentValidationMiddleware проверяет обязательные заголовки // v1.0
func (s *Server) agentValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID := c.GetHeader("X-Agent-Id")
		if agentID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Missing required header: X-Agent-Id",
				"code":  "MISSING_AGENT_ID",
			})
			c.Abort()
			return
		}

		// В продакшене здесь можно добавить валидацию agent ID
		// например, проверку в базе данных или по списку разрешенных

		c.Set("agent_id", agentID)
		c.Next()
	}
}

// mTLSMiddleware проверяет mTLS соединение // v1.0
func (s *Server) mTLSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.config.TLS.Enabled {
			c.Next()
			return
		}

		if c.Request.TLS == nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "mTLS connection required",
				"code":  "MTLS_REQUIRED",
			})
			c.Abort()
			return
		}

		// Проверяем, что клиентский сертификат представлен
		if len(c.Request.TLS.PeerCertificates) == 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Client certificate required",
				"code":  "CLIENT_CERT_REQUIRED",
			})
			c.Abort()
			return
		}

		// Извлекаем информацию о клиенте
		clientCert := c.Request.TLS.PeerCertificates[0]
		c.Set("client_cn", clientCert.Subject.CommonName)
		c.Set("client_org", clientCert.Subject.Organization)

		c.Next()
	}
}

// loggingMiddleware добавляет логирование запросов // v1.0
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		requestID := param.Keys["request_id"]
		agentID := param.Keys["agent_id"]

		s.logger.WithFields(map[string]interface{}{
			"method":     param.Method,
			"path":       param.Path,
			"status":     param.StatusCode,
			"latency":    param.Latency,
			"client_ip":  param.ClientIP,
			"user_agent": param.Request.UserAgent(),
			"request_id": requestID,
			"agent_id":   agentID,
		}).Info("HTTP request")

		return ""
	})
}

// recoveryMiddleware восстанавливает после паники // v1.0
func (s *Server) recoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		requestID := c.GetString("request_id")
		agentID := c.GetString("agent_id")

		s.logger.WithFields(map[string]interface{}{
			"error":      recovered,
			"request_id": requestID,
			"agent_id":   agentID,
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
		}).Error("Panic recovered")

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Internal server error",
			"request_id": requestID,
		})
	})
}

// metricsMiddleware собирает метрики // v1.0
func (s *Server) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		// В продакшене здесь можно отправлять метрики в Prometheus
		s.logger.WithFields(map[string]interface{}{
			"method":   c.Request.Method,
			"path":     c.Request.URL.Path,
			"status":   status,
			"duration": duration.Milliseconds(),
		}).Debug("Request metrics")
	}
}

// generateRequestID генерирует уникальный ID запроса // v1.0
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
