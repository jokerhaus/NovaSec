// internal/common/errors/errors.go
package errors

import (
	"fmt"
	"strings"
)

// ErrorCode представляет код ошибки
type ErrorCode string

const (
	// Общие ошибки
	ErrorCodeInternal     ErrorCode = "INTERNAL_ERROR"
	ErrorCodeValidation   ErrorCode = "VALIDATION_ERROR"
	ErrorCodeNotFound     ErrorCode = "NOT_FOUND"
	ErrorCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrorCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrorCodeConflict     ErrorCode = "CONFLICT"
	ErrorCodeTimeout      ErrorCode = "TIMEOUT"
	ErrorCodeRateLimit    ErrorCode = "RATE_LIMIT"

	// Ошибки событий
	ErrorCodeEventInvalid     ErrorCode = "EVENT_INVALID"
	ErrorCodeEventParseFailed ErrorCode = "EVENT_PARSE_FAILED"
	ErrorCodeEventRequired    ErrorCode = "EVENT_REQUIRED"

	// Ошибки правил
	ErrorCodeRuleInvalid     ErrorCode = "RULE_INVALID"
	ErrorCodeRuleParseFailed ErrorCode = "RULE_PARSE_FAILED"
	ErrorCodeRuleCompileFailed ErrorCode = "RULE_COMPILE_FAILED"

	// Ошибки алертов
	ErrorCodeAlertInvalid     ErrorCode = "ALERT_INVALID"
	ErrorCodeAlertNotFound    ErrorCode = "ALERT_NOT_FOUND"
	ErrorCodeAlertUpdateFailed ErrorCode = "ALERT_UPDATE_FAILED"

	// Ошибки базы данных
	ErrorCodeDBConnection    ErrorCode = "DB_CONNECTION_ERROR"
	ErrorCodeDBQuery         ErrorCode = "DB_QUERY_ERROR"
	ErrorCodeDBTransaction   ErrorCode = "DB_TRANSACTION_ERROR"
	ErrorCodeDBConstraint    ErrorCode = "DB_CONSTRAINT_ERROR"

	// Ошибки NATS
	ErrorCodeNATSConnection ErrorCode = "NATS_CONNECTION_ERROR"
	ErrorCodeNATSPublish    ErrorCode = "NATS_PUBLISH_ERROR"
	ErrorCodeNATSSubscribe  ErrorCode = "NATS_SUBSCRIBE_ERROR"

	// Ошибки ClickHouse
	ErrorCodeCHConnection ErrorCode = "CH_CONNECTION_ERROR"
	ErrorCodeCHQuery      ErrorCode = "CH_QUERY_ERROR"
	ErrorCodeCHInsert     ErrorCode = "CH_INSERT_ERROR"

	// Ошибки PostgreSQL
	ErrorCodePGConnection ErrorCode = "PG_CONNECTION_ERROR"
	ErrorCodePGQuery      ErrorCode = "PG_QUERY_ERROR"
	ErrorCodePGInsert     ErrorCode = "PG_INSERT_ERROR"
)

// NovaSecError представляет ошибку NovaSec
type NovaSecError struct {
	Code       ErrorCode            `json:"code"`
	Message    string               `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Internal   error                `json:"-"`
	StatusCode int                  `json:"status_code"`
}

// Error возвращает строковое представление ошибки // v1.0
func (e *NovaSecError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %s (internal: %v)", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap возвращает внутреннюю ошибку // v1.0
func (e *NovaSecError) Unwrap() error {
	return e.Internal
}

// New создает новую ошибку NovaSec // v1.0
func New(code ErrorCode, message string) *NovaSecError {
	return &NovaSecError{
		Code:       code,
		Message:    message,
		Details:    make(map[string]interface{}),
		StatusCode: getStatusCode(code),
	}
}

// NewWithDetails создает новую ошибку с деталями // v1.0
func NewWithDetails(code ErrorCode, message string, details map[string]interface{}) *NovaSecError {
	return &NovaSecError{
		Code:       code,
		Message:    message,
		Details:    details,
		StatusCode: getStatusCode(code),
	}
}

// Wrap оборачивает существующую ошибку // v1.0
func Wrap(err error, code ErrorCode, message string) *NovaSecError {
	return &NovaSecError{
		Code:       code,
		Message:    message,
		Internal:   err,
		Details:    make(map[string]interface{}),
		StatusCode: getStatusCode(code),
	}
}

// WrapWithDetails оборачивает существующую ошибку с деталями // v1.0
func WrapWithDetails(err error, code ErrorCode, message string, details map[string]interface{}) *NovaSecError {
	return &NovaSecError{
		Code:       code,
		Message:    message,
		Internal:   err,
		Details:    details,
		StatusCode: getStatusCode(code),
	}
}

// AddDetail добавляет деталь к ошибке // v1.0
func (e *NovaSecError) AddDetail(key string, value interface{}) *NovaSecError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// AddDetails добавляет несколько деталей к ошибке // v1.0
func (e *NovaSecError) AddDetails(details map[string]interface{}) *NovaSecError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// SetStatusCode устанавливает HTTP статус код // v1.0
func (e *NovaSecError) SetStatusCode(statusCode int) *NovaSecError {
	e.StatusCode = statusCode
	return e
}

// IsErrorCode проверяет, является ли ошибка определенного кода // v1.0
func IsErrorCode(err error, code ErrorCode) bool {
	if novaSecErr, ok := err.(*NovaSecError); ok {
		return novaSecErr.Code == code
	}
	return false
}

// GetErrorCode возвращает код ошибки // v1.0
func GetErrorCode(err error) ErrorCode {
	if novaSecErr, ok := err.(*NovaSecError); ok {
		return novaSecErr.Code
	}
	return ErrorCodeInternal
}

// getStatusCode возвращает HTTP статус код для кода ошибки // v1.0
func getStatusCode(code ErrorCode) int {
	switch code {
	case ErrorCodeValidation:
		return 400
	case ErrorCodeUnauthorized:
		return 401
	case ErrorCodeForbidden:
		return 403
	case ErrorCodeNotFound:
		return 404
	case ErrorCodeConflict:
		return 409
	case ErrorCodeRateLimit:
		return 429
	case ErrorCodeTimeout:
		return 408
	default:
		return 500
	}
}

// ValidationError создает ошибку валидации // v1.0
func ValidationError(field, message string) *NovaSecError {
	return New(ErrorCodeValidation, fmt.Sprintf("validation failed for field '%s': %s", field, message))
}

// ValidationErrorWithDetails создает ошибку валидации с деталями // v1.0
func ValidationErrorWithDetails(field, message string, details map[string]interface{}) *NovaSecError {
	err := ValidationError(field, message)
	return err.AddDetails(details)
}

// NotFoundError создает ошибку "не найдено" // v1.0
func NotFoundError(resource, id string) *NovaSecError {
	return New(ErrorCodeNotFound, fmt.Sprintf("%s with id '%s' not found", resource, id))
}

// UnauthorizedError создает ошибку авторизации // v1.0
func UnauthorizedError(message string) *NovaSecError {
	if message == "" {
		message = "authentication required"
	}
	return New(ErrorCodeUnauthorized, message)
}

// ForbiddenError создает ошибку доступа // v1.0
func ForbiddenError(message string) *NovaSecError {
	if message == "" {
		message = "access denied"
	}
	return New(ErrorCodeForbidden, message)
}

// ConflictError создает ошибку конфликта // v1.0
func ConflictError(resource, reason string) *NovaSecError {
	return New(ErrorCodeConflict, fmt.Sprintf("conflict with %s: %s", resource, reason))
}

// TimeoutError создает ошибку таймаута // v1.0
func TimeoutError(operation string, duration string) *NovaSecError {
	return New(ErrorCodeTimeout, fmt.Sprintf("operation '%s' timed out after %s", operation, duration))
}

// RateLimitError создает ошибку превышения лимита // v1.0
func RateLimitError(limit, window string) *NovaSecError {
	return New(ErrorCodeRateLimit, fmt.Sprintf("rate limit exceeded: %s per %s", limit, window))
}

// InternalError создает внутреннюю ошибку // v1.0
func InternalError(message string) *NovaSecError {
	return New(ErrorCodeInternal, message)
}

// WrapInternal оборачивает внутреннюю ошибку // v1.0
func WrapInternal(err error, message string) *NovaSecError {
	return Wrap(err, ErrorCodeInternal, message)
}

// AggregateErrors объединяет несколько ошибок в одну // v1.0
func AggregateErrors(errors []error) *NovaSecError {
	if len(errors) == 0 {
		return nil
	}

	if len(errors) == 1 {
		if novaSecErr, ok := errors[0].(*NovaSecError); ok {
			return novaSecErr
		}
		return Wrap(errors[0], ErrorCodeInternal, "aggregated error")
	}

	var messages []string
	for _, err := range errors {
		messages = append(messages, err.Error())
	}

	return New(ErrorCodeInternal, fmt.Sprintf("multiple errors occurred: %s", strings.Join(messages, "; ")))
}
