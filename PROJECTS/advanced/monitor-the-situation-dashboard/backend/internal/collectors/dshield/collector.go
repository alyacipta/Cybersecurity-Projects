// ©AngelaMos | 2026
// collector.go

package dshield

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const (
	Name            = "dshield"
	defaultInterval = time.Hour
)

type Fetcher interface {
	FetchAll(ctx context.Context) ([]SnapshotPayload, error)
}

type Persister interface {
	PutSnapshot(ctx context.Context, ts time.Time, kind string, payload json.RawMessage) error
}

type Emitter interface {
	Emit(ev events.Event)
}

type StateRecorder interface {
	RecordSuccess(ctx context.Context, name string, eventCount int64) error
	RecordError(ctx context.Context, name, errMsg string) error
}

type CollectorConfig struct {
	Interval  time.Duration
	Fetcher   Fetcher
	Persister Persister
	Emitter   Emitter
	State     StateRecorder
	Logger    *slog.Logger
}

type Collector struct {
	cfg    CollectorConfig
	logger *slog.Logger
}

func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Collector{cfg: cfg, logger: cfg.Logger}
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	c.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.tick(ctx)
		}
	}
}

func (c *Collector) tick(ctx context.Context) {
	snaps, err := c.cfg.Fetcher.FetchAll(ctx)
	if err != nil {
		c.logger.Warn("dshield fetch failed", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		return
	}

	now := time.Now().UTC()
	tsRaw, err := json.Marshal(now.Format(time.RFC3339Nano))
	if err != nil {
		c.logger.Error("dshield marshal ts", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		return
	}

	merged := map[string]json.RawMessage{"ts": tsRaw}
	for _, s := range snaps {
		if perr := c.cfg.Persister.PutSnapshot(ctx, now, s.Kind, s.Payload); perr != nil {
			c.logger.Warn("dshield persist failed", "kind", s.Kind, "err", perr)
		}
		merged[s.Kind] = s.Payload
	}

	body, err := json.Marshal(merged)
	if err != nil {
		c.logger.Error("dshield marshal merged", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		return
	}

	c.cfg.Emitter.Emit(events.Event{
		Topic:     events.TopicScanFirehose,
		Timestamp: now,
		Source:    Name,
		Payload:   json.RawMessage(body),
	})
	_ = c.cfg.State.RecordSuccess(ctx, Name, 1)
}
