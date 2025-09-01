// filename: internal/alerting/router.go
package alerting

import (
	"fmt"
	"strings"
	"time"

	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/models"
)

// Router представляет роутер для маршрутизации алертов // v1.0
type Router struct {
	config  *RouterConfig
	logger  *logging.Logger
	routes  []Route
}

// RouterConfig конфигурация роутера // v1.0
type RouterConfig struct {
	DefaultChannels []string          `yaml:"default_channels"`
	SeverityMapping map[string]string `yaml:"severity_mapping"`
	EnvironmentMapping map[string]string `yaml:"environment_mapping"`
	TeamMapping     map[string]string `yaml:"team_mapping"`
	SuppressRules   map[string]SuppressRule `yaml:"suppress_rules"`
}

// Route представляет маршрут для алерта // v1.0
type Route struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Enabled     bool     `yaml:"enabled"`
	
	// Условия маршрутизации
	Severities  []string `yaml:"severities"`
	Environments []string `yaml:"environments"`
	Teams       []string `yaml:"teams"`
	RuleIDs     []string `yaml:"rule_ids"`
	Hosts       []string `yaml:"hosts"`
	
	// Каналы для отправки
	Channels    []string `yaml:"channels"`
	
	// Настройки подавления
	Suppress    bool     `yaml:"suppress"`
	SuppressKey string   `yaml:"suppress_key"`
	SuppressTTL time.Duration `yaml:"suppress_ttl"`
	
	// Приоритет маршрута (чем выше, тем приоритетнее)
	Priority    int      `yaml:"priority"`
}

// SuppressRule правило подавления // v1.0
type SuppressRule struct {
	Enabled     bool          `yaml:"enabled"`
	Key         string        `yaml:"key"`
	TTL         time.Duration `yaml:"ttl"`
	MaxAlerts   int           `yaml:"max_alerts"`
}

// NewRouter создает новый роутер алертов // v1.0
func NewRouter(config *RouterConfig, logger *logging.Logger) *Router {
	return &Router{
		config: config,
		logger: logger,
		routes: make([]Route, 0),
	}
}

// AddRoute добавляет маршрут в роутер // v1.0
func (r *Router) AddRoute(route Route) error {
	// Валидация маршрута
	if route.ID == "" {
		return fmt.Errorf("route ID is required")
	}
	
	if len(route.Channels) == 0 {
		return fmt.Errorf("at least one channel is required for route %s", route.ID)
	}
	
	// Проверяем уникальность ID
	for _, existingRoute := range r.routes {
		if existingRoute.ID == route.ID {
			return fmt.Errorf("route with ID %s already exists", route.ID)
		}
	}
	
	r.routes = append(r.routes, route)
	
	r.logger.Logger.WithFields(map[string]interface{}{
		"route_id": route.ID,
		"name":     route.Name,
		"channels": route.Channels,
	}).Info("Alert route added")
	
	return nil
}

// RemoveRoute удаляет маршрут из роутера // v1.0
func (r *Router) RemoveRoute(routeID string) error {
	for i, route := range r.routes {
		if route.ID == routeID {
			r.routes = append(r.routes[:i], r.routes[i+1:]...)
			
			r.logger.Logger.WithField("route_id", routeID).Info("Alert route removed")
			return nil
		}
	}
	
	return fmt.Errorf("route with ID %s not found", routeID)
}

// GetRoutes возвращает все маршруты // v1.0
func (r *Router) GetRoutes() []Route {
	return r.routes
}

// RouteAlert маршрутизирует алерт по правилам // v1.0
func (r *Router) RouteAlert(alert *models.Alert) []RouteMatch {
	var matches []RouteMatch
	
	// Проходим по всем маршрутам в порядке приоритета
	for _, route := range r.routes {
		if !route.Enabled {
			continue
		}
		
		// Проверяем соответствие маршруту
		if r.matchesRoute(alert, route) {
			match := RouteMatch{
				Route:   route,
				Alert:   alert,
				Score:   r.calculateMatchScore(alert, route),
				Matched: time.Now(),
			}
			
			matches = append(matches, match)
		}
	}
	
	// Сортируем по приоритету и score
	// В реальной реализации здесь будет сортировка
	
	r.logger.Logger.WithFields(map[string]interface{}{
		"alert_id": alert.ID,
		"matches":  len(matches),
	}).Debug("Alert routed")
	
	return matches
}

// matchesRoute проверяет, соответствует ли алерт маршруту // v1.0
func (r *Router) matchesRoute(alert *models.Alert, route Route) bool {
	// Проверяем severity
	if len(route.Severities) > 0 {
		if !r.contains(route.Severities, alert.Severity) {
			return false
		}
	}
	
	// Проверяем environment
	if len(route.Environments) > 0 {
		if !r.contains(route.Environments, alert.Env) {
			return false
		}
	}
	
	// Проверяем rule_id
	if len(route.RuleIDs) > 0 {
		if !r.contains(route.RuleIDs, alert.RuleID) {
			return false
		}
	}
	
	// Проверяем host
	if len(route.Hosts) > 0 {
		if !r.contains(route.Hosts, alert.Host) {
			return false
		}
	}
	
	// Проверяем team (из payload)
	if len(route.Teams) > 0 {
		team := ""
		if teamVal, exists := alert.Payload["team"]; exists {
			if teamStr, ok := teamVal.(string); ok {
				team = teamStr
			}
		}
		if team == "" || !r.contains(route.Teams, team) {
			return false
		}
	}
	
	return true
}

// calculateMatchScore вычисляет score соответствия алерта маршруту // v1.0
func (r *Router) calculateMatchScore(alert *models.Alert, route Route) int {
	score := 0
	
	// Базовый score за приоритет маршрута
	score += route.Priority * 10
	
	// Дополнительные очки за точные совпадения
	if r.contains(route.Severities, alert.Severity) {
		score += 5
	}
	
	if r.contains(route.Environments, alert.Env) {
		score += 5
	}
	
	if r.contains(route.RuleIDs, alert.RuleID) {
		score += 5
	}
	
	if r.contains(route.Hosts, alert.Host) {
		score += 3
	}
	
	if teamVal, exists := alert.Payload["team"]; exists {
		if team, ok := teamVal.(string); ok && team != "" && r.contains(route.Teams, team) {
			score += 3
		}
	}
	
	return score
}

// contains проверяет, содержится ли значение в слайсе // v1.0
func (r *Router) contains(slice []string, value string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

// GetDefaultChannels возвращает каналы по умолчанию // v1.0
func (r *Router) GetDefaultChannels() []string {
	return r.config.DefaultChannels
}

// GetSuppressRule возвращает правило подавления для алерта // v1.0
func (r *Router) GetSuppressRule(alert *models.Alert) *SuppressRule {
	// Сначала проверяем правила подавления по rule_id
	if rule, exists := r.config.SuppressRules[alert.RuleID]; exists && rule.Enabled {
		return &rule
	}
	
	// Затем проверяем общие правила по severity
	severityKey := fmt.Sprintf("severity_%s", alert.Severity)
	if rule, exists := r.config.SuppressRules[severityKey]; exists && rule.Enabled {
		return &rule
	}
	
	// И по environment
	envKey := fmt.Sprintf("env_%s", alert.Env)
	if rule, exists := r.config.SuppressRules[envKey]; exists && rule.Enabled {
		return &rule
	}
	
	return nil
}

// RouteMatch представляет совпадение алерта с маршрутом // v1.0
type RouteMatch struct {
	Route   Route     `json:"route"`
	Alert   *models.Alert `json:"alert"`
	Score   int       `json:"score"`
	Matched time.Time `json:"matched"`
}

// GetRouterStats возвращает статистику роутера // v1.0
func (r *Router) GetRouterStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_routes": len(r.routes),
		"enabled_routes": 0,
		"disabled_routes": 0,
		"routes_by_priority": make(map[string]int),
	}
	
	for _, route := range r.routes {
		if route.Enabled {
			stats["enabled_routes"] = stats["enabled_routes"].(int) + 1
		} else {
			stats["disabled_routes"] = stats["disabled_routes"].(int) + 1
		}
		
		priorityKey := fmt.Sprintf("priority_%d", route.Priority)
		stats["routes_by_priority"].(map[string]int)[priorityKey]++
	}
	
	return stats
}
