// filename: cmd/normalizer/main.go
// NovaSec Normalizer Service - Entry Point

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/novasec/novasec/internal/common/config"
	"github.com/novasec/novasec/internal/common/logging"
	"github.com/novasec/novasec/internal/common/nats"
	"github.com/novasec/novasec/internal/normalizer"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	// Initialize logger
	logger := logging.NewLogger(cfg.Logging)
	logger.Info("Starting NovaSec Normalizer Service")

	// Initialize NATS client
	natsClient, err := nats.NewClient(&cfg.NATS)
	if err != nil {
		logger.Fatal("Failed to initialize NATS client", err)
	}
	defer natsClient.Close()

	// Create normalizer service
	normalizerService := normalizer.NewService(cfg, logger, natsClient)

	// Start service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := normalizerService.Start(ctx); err != nil {
			logger.Error("Normalizer service error", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down Normalizer Service")
	cancel()
	normalizerService.Stop()
}
