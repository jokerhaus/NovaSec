// internal/normalizer/service.go
// NovaSec Normalizer Service

package normalizer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/models"
)

// Service represents the normalizer service
type Service struct {
	config *config.Config
	logger *logging.Logger
	nats   *nats.Client
	// v1.0
	stopChan chan struct{}
}

// NewService creates a new normalizer service
func NewService(cfg *config.Config, logger *logging.Logger, natsClient *nats.Client) *Service {
	return &Service{
		config:   cfg,
		logger:   logger,
		nats:     natsClient,
		stopChan: make(chan struct{}),
	}
}

// Start starts the normalizer service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Logger.Info("Starting normalizer service")

	// Subscribe to raw events
	_ = s.nats.SubscribeToEvents("events.raw", func(data []byte) {
		if err := s.handleRawEvent(data); err != nil {
			s.logger.Logger.Error("Failed to handle raw event", err)
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

// Stop stops the normalizer service
func (s *Service) Stop() {
	close(s.stopChan)
}

// handleRawEvent processes raw events from NATS
func (s *Service) handleRawEvent(data []byte) error {
	var event models.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	s.logger.WithField("host", event.Host).WithField("category", event.Category).Debug("Processing raw event")

	// Normalize event
	normalizedEvent := s.normalizeEvent(&event)

	// Publish normalized event
	if err := s.nats.PublishEvent("events.normalized", normalizedEvent); err != nil {
		return fmt.Errorf("failed to publish normalized event: %w", err)
	}

	s.logger.WithField("host", normalizedEvent.Host).WithField("category", normalizedEvent.Category).Debug("Event normalized and published")

	return nil
}

// normalizeEvent applies normalization rules to an event
func (s *Service) normalizeEvent(event *models.Event) *models.Event {
	// Create a copy of the event for normalization
	normalized := *event

	// Apply category-specific normalization
	switch event.Category {
	case "linux_auth":
		s.normalizeLinuxAuth(&normalized)
	case "nginx_access":
		s.normalizeNginxAccess(&normalized)
	case "windows_eventlog":
		s.normalizeWindowsEventLog(&normalized)
	}

	// Add common labels
	if normalized.Labels == nil {
		normalized.Labels = make(map[string]string)
	}
	normalized.Labels["normalized"] = "true"
	normalized.Labels["normalizer_version"] = "1.0"

	return &normalized
}

// normalizeLinuxAuth normalizes Linux authentication events
func (s *Service) normalizeLinuxAuth(event *models.Event) {
	// Add Linux-specific normalization logic here
	if event.Subtype == "ssh" {
		event.Labels["auth_method"] = "ssh"
	}
}

// normalizeNginxAccess normalizes Nginx access log events
func (s *Service) normalizeNginxAccess(event *models.Event) {
	// Add Nginx-specific normalization logic here
	if event.Subtype == "access" {
		event.Labels["web_server"] = "nginx"
	}
}

// normalizeWindowsEventLog normalizes Windows Event Log events
func (s *Service) normalizeWindowsEventLog(event *models.Event) {
	// Add Windows-specific normalization logic here
	if event.Subtype == "security" {
		event.Labels["os"] = "windows"
	}
}
