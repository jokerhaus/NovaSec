// filename: cmd/adminapi/main.go
// NovaSec Admin API Service - Entry Point

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"novasec/internal/adminapi"
	"novasec/internal/common/config"
	"novasec/internal/common/logging"
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

	logger.Logger.Info("Starting NovaSec Admin API Service")

	// Create admin API service
	adminService := adminapi.NewService(cfg, logger)

	// Start service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := adminService.Start(ctx); err != nil {
			logger.Logger.Error("Admin API service error", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Logger.Info("Shutting down Admin API Service")
	cancel()
	adminService.Stop()
}
