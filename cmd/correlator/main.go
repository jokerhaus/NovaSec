// filename: cmd/correlator/main.go
// NovaSec Correlator Service - Entry Point

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/correlator"
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

	logger.Logger.Info("Starting NovaSec Correlator Service")

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

	// Create correlator service
	correlatorService := correlator.NewService(cfg, logger, natsClient)

	// Start service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := correlatorService.Start(ctx); err != nil {
			logger.Logger.Error("Correlator service error", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Logger.Info("Shutting down Correlator Service")
	cancel()
	correlatorService.Stop()
}
