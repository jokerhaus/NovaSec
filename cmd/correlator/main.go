// filename: cmd/correlator/main.go
// NovaSec Correlator Service - Entry Point

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/correlator"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	// Initialize logger
	logger, err := logging.NewLogger(cfg.Logging)
	if err != nil {
		panic(err)
	}

	logger.Logger.Info("Starting NovaSec Correlator Service")

	// Initialize NATS client
	natsClient, err := nats.NewClient(&cfg.NATS)
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
