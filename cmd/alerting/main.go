// filename: cmd/alerting/main.go
// NovaSec Alerting Service - Entry Point

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"novasec/internal/alerting"
	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	// Initialize logger
	logger, err := logging.NewLogger(logging.Config{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		Output:     cfg.Logging.Output,
		MaxSize:    cfg.Logging.MaxSize,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAge,
		Compress:   cfg.Logging.Compress,
	})
	if err != nil {
		panic(err)
	}

	logger.Logger.Info("Starting NovaSec Alerting Service")

	// Initialize NATS client
	natsClient, err := nats.NewClient(nats.Config{
		URLs:        cfg.NATS.URLs,
		ClusterID:   cfg.NATS.ClusterID,
		ClientID:    cfg.NATS.ClientID,
		Credentials: cfg.NATS.Credentials,
		JWT:         cfg.NATS.JWT,
		NKey:        cfg.NATS.NKey,
		Timeout:     30 * time.Second,
	})
	if err != nil {
		logger.Logger.Fatal("Failed to initialize NATS client", err)
	}
	defer natsClient.Close()

	// Create alerting service
	alertingService := alerting.NewService(cfg, logger, natsClient)

	// Start service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := alertingService.Start(ctx); err != nil {
			logger.Logger.Error("Alerting service error", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Logger.Info("Shutting down Alerting Service")
	cancel()
	alertingService.Stop()
}
