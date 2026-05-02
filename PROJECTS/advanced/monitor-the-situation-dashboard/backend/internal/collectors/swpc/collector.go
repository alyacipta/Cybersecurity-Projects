// ©AngelaMos | 2026
// collector.go

package swpc

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const (
	Name                = "swpc"
	defaultFastInterval = time.Minute
	defaultSlowInterval = 3 * time.Hour

	keyPlasma = "swpc:plasma"
	keyMag    = "swpc:mag"
	keyKp     = "swpc:kp"
	keyXray   = "swpc:xray"
	keyAlerts = "swpc:alerts"
)

type Fetcher interface {
	FetchPlasma(ctx context.Context) ([]PlasmaTick, error)
	FetchMag(ctx context.Context) ([]MagTick, error)
	FetchKp(ctx context.Context) ([]KpTick, error)
	FetchXray(ctx context.Context) ([]XrayTick, error)
	FetchAlerts(ctx context.Context) ([]AlertItem, error)
}

type Ring interface {
	Push(ctx context.Context, key string, score int64, payload []byte) error
}

type Emitter interface {
	Emit(ev events.Event)
}

type StateRecorder interface {
	RecordSuccess(ctx context.Context, name string, eventCount int64) error
	RecordError(ctx context.Context, name, errMsg string) error
}

type CollectorConfig struct {
	FastInterval time.Duration
	SlowInterval time.Duration
	Fetcher      Fetcher
	Ring         Ring
	Emitter      Emitter
	State        StateRecorder
	Logger       *slog.Logger
}

type Collector struct {
	cfg    CollectorConfig
	logger *slog.Logger
}

func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.FastInterval <= 0 {
		cfg.FastInterval = defaultFastInterval
	}
	if cfg.SlowInterval <= 0 {
		cfg.SlowInterval = defaultSlowInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Collector{cfg: cfg, logger: cfg.Logger}
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Run(ctx context.Context) error {
	fast := time.NewTicker(c.cfg.FastInterval)
	defer fast.Stop()
	slow := time.NewTicker(c.cfg.SlowInterval)
	defer slow.Stop()

	c.tickFast(ctx)
	c.tickSlow(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-fast.C:
			c.tickFast(ctx)
		case <-slow.C:
			c.tickSlow(ctx)
		}
	}
}

func (c *Collector) tickFast(ctx context.Context) {
	pushed := int64(0)
	hadError := false

	if n, err := c.pushPlasma(ctx); err != nil {
		c.logger.Warn("swpc plasma", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		hadError = true
	} else {
		pushed += n
	}
	if n, err := c.pushMag(ctx); err != nil {
		c.logger.Warn("swpc mag", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		hadError = true
	} else {
		pushed += n
	}
	if n, err := c.pushXray(ctx); err != nil {
		c.logger.Warn("swpc xray", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		hadError = true
	} else {
		pushed += n
	}
	if n, err := c.pushAlerts(ctx); err != nil {
		c.logger.Warn("swpc alerts", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
		hadError = true
	} else {
		pushed += n
	}

	if pushed > 0 {
		body, _ := json.Marshal(map[string]any{
			"ts":     time.Now().UTC(),
			"pushed": pushed,
		})
		c.cfg.Emitter.Emit(events.Event{
			Topic:     events.TopicSpaceWeather,
			Timestamp: time.Now().UTC(),
			Source:    Name,
			Payload:   json.RawMessage(body),
		})
	}

	if !hadError {
		_ = c.cfg.State.RecordSuccess(ctx, Name, pushed)
	}
}

func (c *Collector) tickSlow(ctx context.Context) {
	if _, err := c.pushKp(ctx); err != nil {
		c.logger.Warn("swpc kp", "err", err)
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
	}
}

func (c *Collector) pushPlasma(ctx context.Context) (int64, error) {
	rows, err := c.cfg.Fetcher.FetchPlasma(ctx)
	if err != nil {
		return 0, err
	}
	return pushAll(ctx, c.cfg.Ring, keyPlasma, rows, func(r PlasmaTick) int64 { return r.TimeTag.UnixMilli() })
}

func (c *Collector) pushMag(ctx context.Context) (int64, error) {
	rows, err := c.cfg.Fetcher.FetchMag(ctx)
	if err != nil {
		return 0, err
	}
	return pushAll(ctx, c.cfg.Ring, keyMag, rows, func(r MagTick) int64 { return r.TimeTag.UnixMilli() })
}

func (c *Collector) pushKp(ctx context.Context) (int64, error) {
	rows, err := c.cfg.Fetcher.FetchKp(ctx)
	if err != nil {
		return 0, err
	}
	return pushAll(ctx, c.cfg.Ring, keyKp, rows, func(r KpTick) int64 { return r.TimeTag.UnixMilli() })
}

func (c *Collector) pushXray(ctx context.Context) (int64, error) {
	rows, err := c.cfg.Fetcher.FetchXray(ctx)
	if err != nil {
		return 0, err
	}
	return pushAll(ctx, c.cfg.Ring, keyXray, rows, func(r XrayTick) int64 { return r.TimeTag.UnixMilli() })
}

func (c *Collector) pushAlerts(ctx context.Context) (int64, error) {
	rows, err := c.cfg.Fetcher.FetchAlerts(ctx)
	if err != nil {
		return 0, err
	}
	return pushAll(ctx, c.cfg.Ring, keyAlerts, rows, func(r AlertItem) int64 { return r.IssueDatetime.UnixMilli() })
}

func pushAll[T any](ctx context.Context, ring Ring, key string, rows []T, score func(T) int64) (int64, error) {
	pushed := int64(0)
	for _, r := range rows {
		s := score(r)
		if s == 0 {
			continue
		}
		body, _ := json.Marshal(r)
		if err := ring.Push(ctx, key, s, body); err != nil {
			return pushed, err
		}
		pushed++
	}
	return pushed, nil
}
