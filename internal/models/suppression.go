// filename: internal/models/suppression.go
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Suppression представляет подавление алертов
type Suppression struct {
	RuleID  string    `json:"rule_id" db:"rule_id"`
	KeyHash string    `json:"key_hash" db:"key_hash"`
	Until   time.Time `json:"until" db:"until"`
	Created time.Time `json:"created" db:"created"`
	Reason  string    `json:"reason" db:"reason"`
}

// NewSuppression создает новое подавление // v1.0
func NewSuppression(ruleID string, keyValues map[string]string, duration time.Duration, reason string) *Suppression {
	keyHash := generateKeyHash(ruleID, keyValues)
	until := time.Now().Add(duration)

	return &Suppression{
		RuleID:  ruleID,
		KeyHash: keyHash,
		Until:   until,
		Created: time.Now(),
		Reason:  reason,
	}
}

// IsActive проверяет, активно ли подавление // v1.0
func (s *Suppression) IsActive() bool {
	return time.Now().Before(s.Until)
}

// IsExpired проверяет, истекло ли подавление // v1.0
func (s *Suppression) IsExpired() bool {
	return time.Now().After(s.Until)
}

// GetRemainingTime возвращает оставшееся время подавления // v1.0
func (s *Suppression) GetRemainingTime() time.Duration {
	if s.IsExpired() {
		return 0
	}
	return s.Until.Sub(time.Now())
}

// Extend продлевает время подавления // v1.0
func (s *Suppression) Extend(duration time.Duration) {
	s.Until = s.Until.Add(duration)
}

// GetKeyHash возвращает хеш ключа подавления // v1.0
func (s *Suppression) GetKeyHash() string {
	return s.KeyHash
}

// GetRuleID возвращает ID правила // v1.0
func (s *Suppression) GetRuleID() string {
	return s.RuleID
}

// GetReason возвращает причину подавления // v1.0
func (s *Suppression) GetReason() string {
	return s.Reason
}

// SetReason устанавливает причину подавления // v1.0
func (s *Suppression) SetReason(reason string) {
	s.Reason = reason
}

// generateKeyHash генерирует хеш ключа подавления // v1.0
func generateKeyHash(ruleID string, keyValues map[string]string) string {
	if len(keyValues) == 0 {
		return fmt.Sprintf("%s:default", ruleID)
	}

	// Сортируем ключи для детерминированности
	keys := make([]string, 0, len(keyValues))
	for k := range keyValues {
		keys = append(keys, k)
	}

	// Строим строку ключа
	var keyParts []string
	keyParts = append(keyParts, ruleID)

	for _, k := range keys {
		keyParts = append(keyParts, fmt.Sprintf("%s=%s", k, keyValues[k]))
	}

	keyString := strings.Join(keyParts, "|")

	// Генерируем SHA256 хеш
	hash := sha256.Sum256([]byte(keyString))
	return hex.EncodeToString(hash[:])
}

// CreateSuppressionKey создает ключ подавления из значений // v1.0
func CreateSuppressionKey(ruleID string, keyValues map[string]string) string {
	return generateKeyHash(ruleID, keyValues)
}

// SuppressionKey представляет ключ подавления
type SuppressionKey struct {
	RuleID    string            `json:"rule_id"`
	KeyValues map[string]string `json:"key_values"`
	Hash      string            `json:"hash"`
}

// NewSuppressionKey создает новый ключ подавления // v1.0
func NewSuppressionKey(ruleID string, keyValues map[string]string) *SuppressionKey {
	return &SuppressionKey{
		RuleID:    ruleID,
		KeyValues: keyValues,
		Hash:      generateKeyHash(ruleID, keyValues),
	}
}

// GetHash возвращает хеш ключа // v1.0
func (sk *SuppressionKey) GetHash() string {
	return sk.Hash
}

// AddKeyValue добавляет пару ключ-значение // v1.0
func (sk *SuppressionKey) AddKeyValue(key, value string) {
	if sk.KeyValues == nil {
		sk.KeyValues = make(map[string]string)
	}
	sk.KeyValues[key] = value
	sk.Hash = generateKeyHash(sk.RuleID, sk.KeyValues)
}

// RemoveKeyValue удаляет пару ключ-значение // v1.0
func (sk *SuppressionKey) RemoveKeyValue(key string) {
	if sk.KeyValues != nil {
		delete(sk.KeyValues, key)
		sk.Hash = generateKeyHash(sk.RuleID, sk.KeyValues)
	}
}

// IsEmpty проверяет, пуст ли ключ // v1.0
func (sk *SuppressionKey) IsEmpty() bool {
	return len(sk.KeyValues) == 0
}

// GetKeyCount возвращает количество ключей // v1.0
func (sk *SuppressionKey) GetKeyCount() int {
	return len(sk.KeyValues)
}
