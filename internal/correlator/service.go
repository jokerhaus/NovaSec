// internal/correlator/service.go
// NovaSec Correlator Service

package correlator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/models"
)

// Service represents the correlator service
type Service struct {
	config *config.Config
	logger *logging.Logger
	nats   *nats.Client
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new correlator service
func NewService(cfg *config.Config, logger *logging.Logger, natsClient *nats.Client) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		nats:     natsClient,
		stopChan: make(chan struct{}),
	}
}

// Start starts the correlator service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting correlator service")

	// Subscribe to normalized events
	_ = s.nats.SubscribeToEvents("events.normalized", func(data []byte) {
		if err := s.handleNormalizedEvent(data); err != nil {
			s.logger.Logger.Error("Failed to handle normalized event", err)
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

// Stop stops the correlator service
func (s *Service) Stop() {
	close(s.stopChan)
}

// handleNormalizedEvent processes normalized events from NATS
func (s *Service) handleNormalizedEvent(data []byte) error {
	var event models.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	s.logger.Logger.WithField("host", event.Host).WithField("category", event.Category).Debug("Processing normalized event")

	// TODO: Implement correlation logic
	// This would involve:
	// 1. Loading correlation rules from database
	// 2. Evaluating rules against the event
	// 3. Creating alerts when conditions are met
	// 4. Publishing alerts to NATS

	return nil
}
