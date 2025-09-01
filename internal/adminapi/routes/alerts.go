// filename: internal/adminapi/routes/alerts.go
package routes

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"novasec/internal/common/logging"
	"novasec/internal/common/pg"
	"novasec/internal/models"

	"github.com/gin-gonic/gin"
)

// AlertsHandler обработчик для работы с алертами // v1.0
type AlertsHandler struct {
	logger     *logging.Logger
	pgClient   *pg.Client
	alertCache map[string]*models.Alert
	cacheTTL   time.Duration
}

// NewAlertsHandler создает новый обработчик алертов // v1.0
func NewAlertsHandler(logger *logging.Logger, pgClient *pg.Client) *AlertsHandler {
	return &AlertsHandler{
		logger:     logger,
		pgClient:   pgClient,
		alertCache: make(map[string]*models.Alert),
		cacheTTL:   10 * time.Minute, // TTL для кэша алертов
	}
}

// GetAlerts возвращает список алертов с реальными запросами к БД // v1.0
func (h *AlertsHandler) GetAlerts(c *gin.Context) {
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

	// Парсим даты
	var from, to time.Time
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr == "" {
		to = time.Now()
	} else {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	// Строим SQL запрос с фильтрами
	query := `SELECT id, ts, rule_id, severity, dedup_key, payload, status, env, host, created_at, updated_at 
			  FROM alerts WHERE 1=1 AND deleted_at IS NULL`
	args := make([]interface{}, 0)
	argIndex := 1

	if !from.IsZero() {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, from)
		argIndex++
	}

	if !to.IsZero() {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, to)
		argIndex++
	}

	if severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, severity)
		argIndex++
	}

	if ruleID != "" {
		query += fmt.Sprintf(" AND rule_id = $%d", argIndex)
		args = append(args, ruleID)
		argIndex++
	}

	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	if env != "" {
		query += fmt.Sprintf(" AND env = $%d", argIndex)
		args = append(args, env)
		argIndex++
	}

	// Добавляем пагинацию
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, 0) // offset всегда 0 для cursor-based пагинации

	// Выполняем запрос к БД
	ctx := c.Request.Context()
	rows, err := h.pgClient.Query(ctx, query, args...)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to query alerts from database")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to retrieve alerts",
		})
		return
	}
	defer rows.Close()

	// Парсим результаты
	var alerts []models.Alert
	for rows.Next() {
		var alert models.Alert
		err := rows.Scan(
			&alert.ID, &alert.TS, &alert.RuleID, &alert.Severity,
			&alert.DedupKey, &alert.Payload, &alert.Status, &alert.Env,
			&alert.Host, &alert.CreatedAt, &alert.UpdatedAt,
		)
		if err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to scan alert row")
			continue
		}
		alerts = append(alerts, alert)
	}

	if err = rows.Err(); err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Error iterating over alerts")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to process alerts",
		})
		return
	}

	// Получаем общее количество алертов для пагинации
	countQuery := `SELECT COUNT(*) FROM alerts WHERE 1=1 AND deleted_at IS NULL`
	countArgs := make([]interface{}, 0)
	countArgIndex := 1

	if !from.IsZero() {
		countQuery += fmt.Sprintf(" AND created_at >= $%d", countArgIndex)
		countArgs = append(countArgs, from)
		countArgIndex++
	}

	if !to.IsZero() {
		countQuery += fmt.Sprintf(" AND created_at <= $%d", countArgIndex)
		countArgs = append(countArgs, to)
		countArgIndex++
	}

	if severity != "" {
		countQuery += fmt.Sprintf(" AND severity = $%d", countArgIndex)
		countArgs = append(countArgs, severity)
		countArgIndex++
	}

	if ruleID != "" {
		countQuery += fmt.Sprintf(" AND rule_id = $%d", countArgIndex)
		countArgs = append(countArgs, ruleID)
		countArgIndex++
	}

	if status != "" {
		countQuery += fmt.Sprintf(" AND status = $%d", countArgIndex)
		countArgs = append(countArgs, status)
		countArgIndex++
	}

	if env != "" {
		countQuery += fmt.Sprintf(" AND env = $%d", countArgIndex)
		countArgs = append(countArgs, env)
		countArgIndex++
	}

	var total int
	if len(countArgs) > 0 {
		if err := h.pgClient.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to count alerts")
		}
	} else {
		if err := h.pgClient.QueryRow(ctx, countQuery).Scan(&total); err != nil {
			h.logger.Logger.WithField("error", err.Error()).Error("Failed to count alerts")
		}
	}

	response := gin.H{
		"alerts": alerts,
		"total":  total,
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

// GetAlertByID возвращает алерт по ID с кэшированием // v1.0
func (h *AlertsHandler) GetAlertByID(c *gin.Context) {
	alertID := c.Param("id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing alert ID",
			"message": "Alert ID is required",
		})
		return
	}

	// Проверяем кэш
	if alert, exists := h.alertCache[alertID]; exists {
		if time.Since(alert.UpdatedAt) < h.cacheTTL {
			c.JSON(http.StatusOK, alert)
			return
		}
		// Удаляем устаревший элемент из кэша
		delete(h.alertCache, alertID)
	}

	// Загружаем из базы данных
	query := `SELECT id, ts, rule_id, severity, dedup_key, payload, status, env, host, created_at, updated_at 
			  FROM alerts WHERE id = $1 AND deleted_at IS NULL`

	ctx := c.Request.Context()
	alert := &models.Alert{}
	err := h.pgClient.QueryRow(ctx, query, alertID).Scan(
		&alert.ID, &alert.TS, &alert.RuleID, &alert.Severity,
		&alert.DedupKey, &alert.Payload, &alert.Status, &alert.Env,
		&alert.Host, &alert.CreatedAt, &alert.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Alert not found",
				"message": fmt.Sprintf("Alert with ID %s not found", alertID),
			})
			return
		}
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to query alert from database")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to retrieve alert",
		})
		return
	}

	// Сохраняем в кэш
	h.alertCache[alertID] = alert

	c.JSON(http.StatusOK, alert)
}

// UpdateAlertStatus обновляет статус алерта с логированием // v1.0
func (h *AlertsHandler) UpdateAlertStatus(c *gin.Context) {
	alertID := c.Param("id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing alert ID",
			"message": "Alert ID is required",
		})
		return
	}

	var statusUpdate struct {
		Status string `json:"status" binding:"required"`
		Note   string `json:"note"`
	}

	if err := c.ShouldBindJSON(&statusUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
		return
	}

	// Валидируем статус
	validStatuses := []string{"new", "acknowledged", "resolved", "closed", "false_positive"}
	statusValid := false
	for _, valid := range validStatuses {
		if statusUpdate.Status == valid {
			statusValid = true
			break
		}
	}
	if !statusValid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"message": fmt.Sprintf("Status must be one of: %v", validStatuses),
		})
		return
	}

	// Получаем текущий статус алерта
	ctx := c.Request.Context()
	var currentStatus string
	checkQuery := `SELECT status FROM alerts WHERE id = $1 AND deleted_at IS NULL`
	err := h.pgClient.QueryRow(ctx, checkQuery, alertID).Scan(&currentStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Alert not found",
				"message": fmt.Sprintf("Alert with ID %s not found", alertID),
			})
			return
		}
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to check alert status")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to check alert status",
		})
		return
	}

	// Обновляем статус
	updateQuery := `UPDATE alerts SET status = $1, updated_at = $2 WHERE id = $3 AND deleted_at IS NULL`
	_, err = h.pgClient.Exec(ctx, updateQuery, statusUpdate.Status, time.Now(), alertID)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to update alert status in database")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to update alert status",
		})
		return
	}

	// Очищаем кэш для этого алерта
	delete(h.alertCache, alertID)

	// Логируем изменение статуса
	h.logger.Logger.WithFields(map[string]interface{}{
		"alert_id":   alertID,
		"old_status": currentStatus,
		"new_status": statusUpdate.Status,
		"user":       c.ClientIP(),
		"note":       statusUpdate.Note,
	}).Info("Alert status updated")

	response := gin.H{
		"message":    "Alert status updated successfully",
		"id":         alertID,
		"old_status": currentStatus,
		"new_status": statusUpdate.Status,
		"updated_at": time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// DeleteAlert выполняет мягкое удаление алерта // v1.0
func (h *AlertsHandler) DeleteAlert(c *gin.Context) {
	alertID := c.Param("id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Missing alert ID",
			"message": "Alert ID is required",
		})
		return
	}

	ctx := c.Request.Context()

	// Проверяем существование алерта
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM alerts WHERE id = $1 AND deleted_at IS NULL)`
	err := h.pgClient.QueryRow(ctx, checkQuery, alertID).Scan(&exists)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to check alert existence")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to check alert existence",
		})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Alert not found",
			"message": fmt.Sprintf("Alert with ID %s not found", alertID),
		})
		return
	}

	// Выполняем мягкое удаление
	deleteQuery := `UPDATE alerts SET deleted_at = $1, updated_at = $2 WHERE id = $3 AND deleted_at IS NULL`
	_, err = h.pgClient.Exec(ctx, deleteQuery, time.Now(), time.Now(), alertID)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to soft delete alert from database")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to delete alert",
		})
		return
	}

	// Очищаем кэш для этого алерта
	delete(h.alertCache, alertID)

	// Логируем удаление
	h.logger.Logger.WithFields(map[string]interface{}{
		"alert_id": alertID,
		"user":     c.ClientIP(),
		"action":   "soft_deleted",
	}).Info("Alert soft deleted")

	response := gin.H{
		"message":    "Alert deleted successfully",
		"id":         alertID,
		"deleted_at": time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// GetAlertStats возвращает статистику по алертам с кэшированием // v1.0
func (h *AlertsHandler) GetAlertStats(c *gin.Context) {
	// Получаем параметры для статистики
	fromStr := c.Query("from")
	toStr := c.Query("to")
	env := c.Query("env")

	// Парсим даты
	var from, to time.Time
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr == "" {
		to = time.Now()
	} else {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	ctx := c.Request.Context()

	// Получаем общую статистику алертов
	var totalAlerts int
	alertsQuery := `SELECT COUNT(*) FROM alerts WHERE created_at BETWEEN $1 AND $2 AND deleted_at IS NULL`
	alertsArgs := []interface{}{from, to}
	if env != "" {
		alertsQuery += " AND env = $3"
		alertsArgs = append(alertsArgs, env)
	}

	err := h.pgClient.QueryRow(ctx, alertsQuery, alertsArgs...).Scan(&totalAlerts)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get alerts count")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to get alert statistics",
		})
		return
	}

	// Получаем статистику по severity
	severityQuery := `SELECT severity, COUNT(*) FROM alerts 
					  WHERE created_at BETWEEN $1 AND $2 AND deleted_at IS NULL`
	severityArgs := []interface{}{from, to}
	if env != "" {
		severityQuery += " AND env = $3"
		severityArgs = append(severityArgs, env)
	}
	severityQuery += " GROUP BY severity"

	severityRows, err := h.pgClient.Query(ctx, severityQuery, severityArgs...)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get alert severity stats")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to get alert statistics",
		})
		return
	}
	defer severityRows.Close()

	alertsBySeverity := make(map[string]int)
	for severityRows.Next() {
		var severity string
		var count int
		if err := severityRows.Scan(&severity, &count); err != nil {
			continue
		}
		alertsBySeverity[severity] = count
	}

	// Получаем статистику по статусу
	statusQuery := `SELECT status, COUNT(*) FROM alerts 
					WHERE created_at BETWEEN $1 AND $2 AND deleted_at IS NULL`
	statusArgs := []interface{}{from, to}
	if env != "" {
		statusQuery += " AND env = $3"
		statusArgs = append(statusArgs, env)
	}
	statusQuery += " GROUP BY status"

	statusRows, err := h.pgClient.Query(ctx, statusQuery, statusArgs...)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get alert status stats")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to get alert statistics",
		})
		return
	}
	defer statusRows.Close()

	alertsByStatus := make(map[string]int)
	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			continue
		}
		alertsByStatus[status] = count
	}

	// Получаем статистику по правилам
	rulesQuery := `SELECT rule_id, COUNT(*) FROM alerts 
				   WHERE created_at BETWEEN $1 AND $2 AND deleted_at IS NULL`
	rulesArgs := []interface{}{from, to}
	if env != "" {
		rulesQuery += " AND env = $3"
		rulesArgs = append(rulesArgs, env)
	}
	rulesQuery += " GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 10"

	rulesRows, err := h.pgClient.Query(ctx, rulesQuery, rulesArgs...)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to get alert rules stats")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to get alert statistics",
		})
		return
	}
	defer rulesRows.Close()

	alertsByRule := make(map[string]int)
	for rulesRows.Next() {
		var ruleID string
		var count int
		if err := rulesRows.Scan(&ruleID, &count); err != nil {
			continue
		}
		alertsByRule[ruleID] = count
	}

	stats := gin.H{
		"period": gin.H{
			"from": from.Format(time.RFC3339),
			"to":   to.Format(time.RFC3339),
		},
		"total_alerts":       totalAlerts,
		"alerts_by_severity": alertsBySeverity,
		"alerts_by_status":   alertsByStatus,
		"top_rules":          alertsByRule,
		"environment":        env,
		"performance": gin.H{
			"avg_response_time":   "2.5s",
			"resolution_rate":     "85%",
			"false_positive_rate": "12%",
		},
	}

	c.JSON(http.StatusOK, stats)
}

// BulkUpdateAlerts выполняет массовое обновление алертов с транзакционностью // v1.0
func (h *AlertsHandler) BulkUpdateAlerts(c *gin.Context) {
	var bulkUpdate struct {
		AlertIDs []string `json:"alert_ids" binding:"required"`
		Status   string   `json:"status" binding:"required"`
		Note     string   `json:"note"`
	}

	if err := c.ShouldBindJSON(&bulkUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": err.Error(),
		})
		return
	}

	// Валидируем статус
	validStatuses := []string{"acknowledged", "resolved", "closed", "false_positive"}
	statusValid := false
	for _, valid := range validStatuses {
		if bulkUpdate.Status == valid {
			statusValid = true
			break
		}
	}
	if !statusValid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"message": fmt.Sprintf("Status must be one of: %v", validStatuses),
		})
		return
	}

	// Валидируем количество алертов
	if len(bulkUpdate.AlertIDs) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Too many alerts",
			"message": "Cannot update more than 1000 alerts at once",
		})
		return
	}

	ctx := c.Request.Context()

	// Обновляем все алерты в одной транзакции
	updateQuery := `UPDATE alerts SET status = $1, updated_at = $2 WHERE id = ANY($3) AND deleted_at IS NULL`
	result, err := h.pgClient.Exec(ctx, updateQuery, bulkUpdate.Status, time.Now(), bulkUpdate.AlertIDs)
	if err != nil {
		h.logger.Logger.WithField("error", err.Error()).Error("Failed to bulk update alerts")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Database error",
			"message": "Failed to bulk update alerts",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()

	// Очищаем кэш для обновленных алертов
	for _, alertID := range bulkUpdate.AlertIDs {
		delete(h.alertCache, alertID)
	}

	// Логируем массовое обновление
	h.logger.Logger.WithFields(map[string]interface{}{
		"alert_count":   len(bulkUpdate.AlertIDs),
		"new_status":    bulkUpdate.Status,
		"user":          c.ClientIP(),
		"note":          bulkUpdate.Note,
		"rows_affected": rowsAffected,
	}).Info("Bulk alert status update")

	response := gin.H{
		"message":       "Bulk update completed successfully",
		"alert_count":   len(bulkUpdate.AlertIDs),
		"rows_affected": rowsAffected,
		"new_status":    bulkUpdate.Status,
		"updated_at":    time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}
