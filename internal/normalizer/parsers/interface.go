// filename: internal/normalizer/parsers/interface.go
package parsers

import "github.com/novasec/novasec/internal/models"

// Parser интерфейс для всех парсеров событий // v1.0
type Parser interface {
	// ParseEvent парсит и нормализует событие
	ParseEvent(rawEvent *models.Event) (*models.Event, error)

	// GetSupportedSources возвращает список поддерживаемых источников
	GetSupportedSources() []string

	// GetSupportedCategories возвращает список поддерживаемых категорий
	GetSupportedCategories() []string

	// GetSupportedSubtypes возвращает список поддерживаемых подтипов
	GetSupportedSubtypes() []string
}

// ParserRegistry реестр всех доступных парсеров // v1.0
type ParserRegistry struct {
	parsers map[string]Parser
}

// NewParserRegistry создает новый реестр парсеров // v1.0
func NewParserRegistry() *ParserRegistry {
	registry := &ParserRegistry{
		parsers: make(map[string]Parser),
	}

	// Регистрируем встроенные парсеры
	registry.RegisterParser("linux_auth", NewLinuxAuthParser())
	registry.RegisterParser("nginx_access", NewNginxAccessParser())
	registry.RegisterParser("windows_eventlog", NewWindowsEventLogParser())

	return registry
}

// RegisterParser регистрирует новый парсер // v1.0
func (r *ParserRegistry) RegisterParser(name string, parser Parser) {
	r.parsers[name] = parser
}

// GetParser возвращает парсер по имени // v1.0
func (r *ParserRegistry) GetParser(name string) (Parser, bool) {
	parser, exists := r.parsers[name]
	return parser, exists
}

// GetAllParsers возвращает все зарегистрированные парсеры // v1.0
func (r *ParserRegistry) GetAllParsers() map[string]Parser {
	return r.parsers
}

// GetParserForSource возвращает подходящий парсер для источника // v1.0
func (r *ParserRegistry) GetParserForSource(source string) Parser {
	for _, parser := range r.parsers {
		for _, supportedSource := range parser.GetSupportedSources() {
			if supportedSource == source {
				return parser
			}
		}
	}
	return nil
}

// GetParserForCategory возвращает подходящий парсер для категории // v1.0
func (r *ParserRegistry) GetParserForCategory(category string) Parser {
	for _, parser := range r.parsers {
		for _, supportedCategory := range parser.GetSupportedCategories() {
			if supportedCategory == category {
				return parser
			}
		}
	}
	return nil
}
