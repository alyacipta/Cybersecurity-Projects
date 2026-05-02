// ©AngelaMos | 2026
// collector.go

package coinbase

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/shopspring/decimal"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const (
	Name            = "coinbase"
	defaultURL      = "wss://advanced-trade-ws.coinbase.com"
	defaultThrottle = 250 * time.Millisecond
)

type Repository interface {
	InsertTick(ctx context.Context, t Tick) error
	UpsertMinute(ctx context.Context, b MinuteBar) error
	LatestTick(ctx context.Context, symbol string) (Tick, error)
	History1h(ctx context.Context, symbol string) ([]MinuteBar, error)
}

type Emitter interface {
	Emit(ev events.Event)
}

type StateRecorder interface {
	RecordSuccess(ctx context.Context, name string, eventCount int64) error
	RecordError(ctx context.Context, name, errMsg string) error
}

type CollectorConfig struct {
	URL        string
	ProductIDs []string
	Repo       Repository
	Emitter    Emitter
	State      StateRecorder
	Dialer     Dialer
	Throttle   time.Duration
	Reconnect  ReconnectConfig
	Logger     *slog.Logger
}

type Collector struct {
	cfg      CollectorConfig
	dialer   Dialer
	logger   *slog.Logger
	mu       sync.Mutex
	lastEmit map[string]time.Time
}

func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.URL == "" {
		cfg.URL = defaultURL
	}
	if len(cfg.ProductIDs) == 0 {
		cfg.ProductIDs = []string{defaultProductBTC, defaultProductETH}
	}
	if cfg.Throttle <= 0 {
		cfg.Throttle = defaultThrottle
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	d := cfg.Dialer
	if d == nil {
		d = NewWSDialer(DialerConfig{URL: cfg.URL, ProductIDs: cfg.ProductIDs})
	}

	return &Collector{
		cfg:      cfg,
		dialer:   d,
		logger:   cfg.Logger,
		lastEmit: make(map[string]time.Time),
	}
}

func (c *Collector) Name() string { return Name }

func (c *Collector) Run(ctx context.Context) error {
	err := Reconnect(ctx, c.dialer, c.cfg.Reconnect, c.handleConn)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		_ = c.cfg.State.RecordError(ctx, Name, err.Error())
	}
	return err
}

func (c *Collector) handleConn(ctx context.Context, conn *Conn) error {
	seq := NewSequencer()
	agg := NewAggregator()
	count := int64(0)

	loopErr := ReadLoop(ctx, conn, seq, func(hctx context.Context, f Frame) error {
		switch f.Kind {
		case FrameTypeTicker, FrameTypeSnapshot:
			for _, tk := range f.Tickers {
				tick := Tick{
					Symbol:    tk.ProductID,
					TS:        tk.Time.UTC(),
					Price:     tk.Price,
					Volume24h: tk.Volume24h,
				}
				if err := c.cfg.Repo.InsertTick(hctx, tick); err != nil {
					c.logger.Warn("insert tick", "symbol", tick.Symbol, "err", err)
					continue
				}
				if closed, _ := agg.Push(tick); closed != nil {
					if err := c.cfg.Repo.UpsertMinute(hctx, *closed); err != nil {
						c.logger.Warn("upsert minute", "symbol", closed.Symbol, "minute", closed.Minute, "err", err)
					}
				}
				if c.shouldEmit(tick.Symbol) {
					c.emitTick(tick)
					count++
				}
			}
		}
		return nil
	})

	if loopErr == nil || errors.Is(loopErr, ErrSequenceGap) {
		_ = c.cfg.State.RecordSuccess(ctx, Name, count)
	}
	return loopErr
}

func (c *Collector) shouldEmit(symbol string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	last, ok := c.lastEmit[symbol]
	now := time.Now()
	if !ok || now.Sub(last) >= c.cfg.Throttle {
		c.lastEmit[symbol] = now
		return true
	}
	return false
}

type tickPayload struct {
	Symbol    string          `json:"symbol"`
	TS        time.Time       `json:"ts"`
	Price     decimal.Decimal `json:"price"`
	Volume24h decimal.Decimal `json:"volume_24h"`
}

func (c *Collector) emitTick(t Tick) {
	body, _ := json.Marshal(tickPayload{
		Symbol:    t.Symbol,
		TS:        t.TS,
		Price:     t.Price,
		Volume24h: t.Volume24h,
	})
	c.cfg.Emitter.Emit(events.Event{
		Topic:     events.TopicCoinbasePrice,
		Timestamp: t.TS,
		Source:    Name,
		Payload:   json.RawMessage(body),
	})
}
