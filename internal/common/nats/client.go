// filename: internal/common/nats/client.go
package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// Client представляет клиент NATS
type Client struct {
	conn     *nats.Conn
	js       nats.JetStreamContext
	config   Config
	subjects map[string]*nats.Subscription
}

// Config представляет конфигурацию NATS
type Config struct {
	URLs        []string      `yaml:"urls"`
	ClusterID   string        `yaml:"cluster_id"`
	ClientID    string        `yaml:"client_id"`
	Credentials string        `yaml:"credentials"`
	JWT         string        `yaml:"jwt"`
	NKey        string        `yaml:"nkey"`
	Timeout     time.Duration `yaml:"timeout"`
}

// NewClient создает новый клиент NATS // v1.0
func NewClient(config Config) (*Client, error) {
	opts := []nats.Option{
		nats.Name(config.ClientID),
		nats.Timeout(config.Timeout),
		nats.ReconnectWait(1 * time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			fmt.Printf("NATS disconnected: %v\n", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			fmt.Printf("NATS reconnected to %s\n", nc.ConnectedUrl())
		}),
	}

	// Добавляем аутентификацию если указана
	if config.Credentials != "" {
		opts = append(opts, nats.UserCredentials(config.Credentials))
	}

	if config.JWT != "" && config.NKey != "" {
		// Создаем JWT с NKey
		opts = append(opts, nats.UserJWTAndSeed(config.JWT, config.NKey))
	}

	// Подключаемся к NATS
	conn, err := nats.Connect(config.URLs[0], opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Создаем JetStream контекст
	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	// Создаем потоки если не существуют
	if err := ensureStreams(js, config.ClusterID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ensure streams: %w", err)
	}

	return &Client{
		conn:     conn,
		js:       js,
		config:   config,
		subjects: make(map[string]*nats.Subscription),
	}, nil
}

// ensureStreams создает необходимые потоки // v1.0
func ensureStreams(js nats.JetStreamContext, clusterID string) error {
	streams := []string{
		"events.raw",
		"events.normalized",
		"alerts.created",
		"alerts.updated",
	}

	for _, streamName := range streams {
		stream, err := js.StreamInfo(streamName)
		if err == nil && stream != nil {
			continue // Поток уже существует
		}

		// Создаем поток
		streamConfig := &nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{streamName + ".*"},
			Storage:   nats.FileStorage,
			Retention: nats.LimitsPolicy,
			MaxAge:    24 * time.Hour, // 24 часа по умолчанию
			MaxMsgs:   1000000,        // 1M сообщений по умолчанию
		}

		if _, err := js.AddStream(streamConfig); err != nil {
			return fmt.Errorf("failed to create stream %s: %w", streamName, err)
		}
	}

	return nil
}

// PublishEvent публикует событие в поток // v1.0
func (c *Client) PublishEvent(subject string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Публикуем в JetStream
	ack, err := c.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	fmt.Printf("Published event to %s, sequence: %d\n", subject, ack.Sequence)
	return nil
}

// SubscribeToEvents подписывается на события // v1.0
func (c *Client) SubscribeToEvents(subject string, handler func([]byte)) error {
	// Создаем подписку
	sub, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
		msg.Ack()
	}, nats.AckWait(30*time.Second))
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
	}

	c.subjects[subject] = sub
	return nil
}

// SubscribeToEventsWithQueue подписывается на события с очередью // v1.0
func (c *Client) SubscribeToEventsWithQueue(subject, queue string, handler func([]byte)) error {
	// Создаем подписку с очередью
	sub, err := c.js.QueueSubscribe(subject, queue, func(msg *nats.Msg) {
		handler(msg.Data)
		msg.Ack()
	}, nats.AckWait(30*time.Second))
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s with queue %s: %w", subject, queue, err)
	}

	c.subjects[subject] = sub
	return nil
}

// Unsubscribe отписывается от субъекта // v1.0
func (c *Client) Unsubscribe(subject string) error {
	if sub, exists := c.subjects[subject]; exists {
		if err := sub.Unsubscribe(); err != nil {
			return fmt.Errorf("failed to unsubscribe from %s: %w", subject, err)
		}
		delete(c.subjects, subject)
	}
	return nil
}

// Close закрывает соединение с NATS // v1.0
func (c *Client) Close() error {
	// Отписываемся от всех субъектов
	for subject := range c.subjects {
		c.Unsubscribe(subject)
	}

	// Закрываем соединение
	if c.conn != nil {
		c.conn.Close()
	}

	return nil
}

// IsConnected проверяет, подключен ли клиент // v1.0
func (c *Client) IsConnected() bool {
	return c.conn != nil && c.conn.IsConnected()
}

// GetConnectionInfo возвращает информацию о соединении // v1.0
func (c *Client) GetConnectionInfo() map[string]interface{} {
	if c.conn == nil {
		return nil
	}

	return map[string]interface{}{
		"connected":      c.conn.IsConnected(),
		"url":            c.conn.ConnectedUrl(),
		"server_id":      c.conn.ConnectedServerId(),
		"server_name":    c.conn.ConnectedServerName(),
		"server_version": c.conn.ConnectedServerVersion(),
		"in_msgs":        c.conn.Stats().InMsgs,
		"out_msgs":       c.conn.Stats().OutMsgs,
		"in_bytes":       c.conn.Stats().InBytes,
		"out_bytes":      c.conn.Stats().OutBytes,
	}
}

// PublishWithContext публикует сообщение с контекстом // v1.0
func (c *Client) PublishWithContext(ctx context.Context, subject string, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return c.PublishEvent(subject, data)
	}
}

// Request выполняет запрос-ответ // v1.0
func (c *Client) Request(subject string, data []byte, timeout time.Duration) ([]byte, error) {
	msg, err := c.conn.Request(subject, data, timeout)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return msg.Data, nil
}

// Flush выполняет flush буферов // v1.0
func (c *Client) Flush() error {
	return c.conn.Flush()
}
