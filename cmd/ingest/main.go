// filename: cmd/ingest/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"novasec/internal/common/config"
	"novasec/internal/common/logging"
	"novasec/internal/common/nats"
	"novasec/internal/ingest/server"
)

var (
	configPath = flag.String("config", "configs/ingest.yml", "Path to configuration file")
	version    = "1.0.0"
)

func main() {
	flag.Parse()

	// Выводим версию
	fmt.Printf("NovaSec Ingest Service v%s\n", version)

	// Загружаем конфигурацию
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Инициализируем логгер
	logger, err := logging.NewLogger(logging.Config{
		Level:   cfg.Logging.Level,
		Format:  cfg.Logging.Format,
		Output:  cfg.Logging.Output,
		MaxSize: cfg.Logging.MaxSize,
	})
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger.Info("Starting NovaSec Ingest Service")

	// Инициализируем NATS клиент
	natsClient, err := nats.NewClient(nats.Config{
		URLs:        cfg.NATS.URLs,
		ClusterID:   cfg.NATS.ClusterID,
		ClientID:    cfg.NATS.ClientID + "-ingest",
		Credentials: cfg.NATS.Credentials,
		JWT:         cfg.NATS.JWT,
		NKey:        cfg.NATS.NKey,
		Timeout:     30 * time.Second,
	})
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize NATS client")
	}
	defer natsClient.Close()

	logger.Info("Connected to NATS")

	// Создаем сервер
	srv := server.NewServer(cfg, natsClient, logger)

	// Создаем HTTP сервер
	httpServer := &http.Server{
		Addr:         cfg.GetServerAddr(),
		Handler:      srv.Router(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Запускаем сервер в горутине
	go func() {
		logger.WithField("addr", cfg.GetServerAddr()).Info("Starting HTTP server")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("HTTP server failed")
		}
	}()

	// Ждем сигнал для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	logger.Info("Server exited")
}
