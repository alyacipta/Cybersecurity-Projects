// ©AngelaMos | 2026
// hub.go

package ws

import (
	"context"
	"log/slog"
	"sync"
	"time"

	cdrws "github.com/coder/websocket"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const (
	defaultSubscriberBuf = 16
	defaultPingInterval  = 30 * time.Second
	defaultPingTimeout   = 10 * time.Second
	defaultWriteTimeout  = 5 * time.Second
)

type HubConfig struct {
	SubscriberBufferSize int
	PingInterval         time.Duration
	PingTimeout          time.Duration
	WriteTimeout         time.Duration
	Logger               *slog.Logger
}

type Hub struct {
	mu           sync.Mutex
	subs         map[*subscriber]struct{}
	bufSize      int
	pingInterval time.Duration
	pingTimeout  time.Duration
	writeTimeout time.Duration
	logger       *slog.Logger
}

func NewHub(cfg HubConfig) *Hub {
	if cfg.SubscriberBufferSize <= 0 {
		cfg.SubscriberBufferSize = defaultSubscriberBuf
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = defaultPingInterval
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = defaultPingTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{
		subs:         make(map[*subscriber]struct{}),
		bufSize:      cfg.SubscriberBufferSize,
		pingInterval: cfg.PingInterval,
		pingTimeout:  cfg.PingTimeout,
		writeTimeout: cfg.WriteTimeout,
		logger:       logger,
	}
}

func (h *Hub) Broadcast(topic events.Topic, payload []byte) {
	env, err := EncodeEnvelope(string(topic), payload)
	if err != nil {
		h.logger.Error("encode envelope", "err", err, "topic", topic)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		if _, ok := sub.topics[topic]; !ok {
			continue
		}
		select {
		case sub.msgs <- env:
		default:
			go sub.closeSlow()
		}
	}
}

func (h *Hub) Serve(ctx context.Context, c *cdrws.Conn, topics []events.Topic) error {
	sub := newSubscriber(topics, h.bufSize, func() {
		_ = c.Close(cdrws.StatusPolicyViolation, "slow consumer")
	})
	h.add(sub)
	defer h.remove(sub)

	connCtx := c.CloseRead(ctx)
	pingT := time.NewTicker(h.pingInterval)
	defer pingT.Stop()

	for {
		select {
		case msg := <-sub.msgs:
			wctx, cancel := context.WithTimeout(connCtx, h.writeTimeout)
			err := c.Write(wctx, cdrws.MessageText, msg)
			cancel()
			if err != nil {
				return err
			}
		case <-pingT.C:
			pctx, cancel := context.WithTimeout(connCtx, h.pingTimeout)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				return err
			}
		case <-connCtx.Done():
			_ = c.Close(cdrws.StatusNormalClosure, "")
			return connCtx.Err()
		}
	}
}

func (h *Hub) add(sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs[sub] = struct{}{}
}

func (h *Hub) remove(sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, sub)
}

func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
