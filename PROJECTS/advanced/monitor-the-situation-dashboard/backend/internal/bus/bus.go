// ©AngelaMos | 2026
// bus.go

package bus

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const defaultBufferSize = 512

type Config struct {
	BufferSize  int
	Persister   Persister
	Broadcaster Broadcaster
	Logger      *slog.Logger
}

type Bus struct {
	ch          chan events.Event
	persister   Persister
	broadcaster Broadcaster
	logger      *slog.Logger
	dropped     atomic.Uint64
}

func New(cfg Config) *Bus {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Bus{
		ch:          make(chan events.Event, cfg.BufferSize),
		persister:   cfg.Persister,
		broadcaster: cfg.Broadcaster,
		logger:      logger,
	}
}

func (b *Bus) Emit(ev events.Event) {
	select {
	case b.ch <- ev:
	default:
		b.dropped.Add(1)
		b.logger.Warn("event bus full, dropped",
			"topic", ev.Topic, "source", ev.Source)
	}
}

func (b *Bus) DroppedCount() uint64 {
	return b.dropped.Load()
}

func (b *Bus) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-b.ch:
			if b.persister != nil {
				if err := b.persister.Save(ctx, ev); err != nil {
					b.logger.Error("persist event failed",
						"err", err, "topic", ev.Topic)
				}
			}
			if b.broadcaster != nil {
				payload, err := json.Marshal(ev.Payload)
				if err != nil {
					b.logger.Error("marshal payload failed",
						"err", err, "topic", ev.Topic)
					continue
				}
				b.broadcaster.Broadcast(string(ev.Topic), payload)
			}
		}
	}
}
