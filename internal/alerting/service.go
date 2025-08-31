// internal/alerting/service.go
// NovaSec Alerting Service

package alerting

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/models"
)

// Service represents the alerting service
type Service struct {
	config *config.Config
	logger *logging.Logger
	nats   *nats.Client
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new alerting service
func NewService(cfg *config.Config, logger *logging.Logger, natsClient *nats.Client) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		nats:     natsClient,
		stopChan: make(chan struct{}),
	}
}

// Start starts the alerting service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting alerting service")

	// Subscribe to created alerts
	_ = s.nats.SubscribeToEvents("alerts.created", func(data []byte) {
		if err := s.handleCreatedAlert(data); err != nil {
			s.logger.Logger.Error("Failed to handle created alert", err)
		}
	})

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		s.logger.Logger.Info("Context cancelled, stopping service")
	case <-s.stopChan:
		s.logger.Logger.Info("Stop signal received, stopping service")
	}

	return nil
}

// Stop stops the alerting service
func (s *Service) Stop() {
	close(s.stopChan)
}

// handleCreatedAlert processes created alerts from NATS
func (s *Service) handleCreatedAlert(data []byte) error {
	var alert models.Alert
	if err := json.Unmarshal(data, &alert); err != nil {
		return fmt.Errorf("failed to unmarshal alert: %w", err)
	}

	s.logger.Logger.WithField("alert_id", alert.ID).WithField("severity", alert.Severity).Debug("Processing created alert")

	// TODO: Implement alert routing logic
	// This would involve:
	// 1. Determining alert channels based on severity/env/labels
	// 2. Sending alerts to appropriate channels (email, telegram, webhook)
	// 3. Handling deduplication and suppression

	return nil
}
