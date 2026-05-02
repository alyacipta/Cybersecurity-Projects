// ©AngelaMos | 2026
// aggregator.go

package coinbase

import "time"

type Aggregator struct {
	open map[string]MinuteBar
}

func NewAggregator() *Aggregator {
	return &Aggregator{open: make(map[string]MinuteBar)}
}

func (a *Aggregator) Push(t Tick) (*MinuteBar, MinuteBar) {
	minute := t.TS.UTC().Truncate(time.Minute)
	cur, exists := a.open[t.Symbol]

	if !exists {
		cur = MinuteBar{
			Symbol: t.Symbol,
			Minute: minute,
			Open:   t.Price,
			High:   t.Price,
			Low:    t.Price,
			Close:  t.Price,
			Volume: t.Volume24h,
		}
		a.open[t.Symbol] = cur
		return nil, cur
	}

	if minute.After(cur.Minute) {
		closed := cur
		cur = MinuteBar{
			Symbol: t.Symbol,
			Minute: minute,
			Open:   t.Price,
			High:   t.Price,
			Low:    t.Price,
			Close:  t.Price,
			Volume: t.Volume24h,
		}
		a.open[t.Symbol] = cur
		return &closed, cur
	}

	if t.Price.GreaterThan(cur.High) {
		cur.High = t.Price
	}
	if t.Price.LessThan(cur.Low) {
		cur.Low = t.Price
	}
	cur.Close = t.Price
	if t.Volume24h.GreaterThan(cur.Volume) {
		cur.Volume = t.Volume24h
	}
	a.open[t.Symbol] = cur
	return nil, cur
}

func (a *Aggregator) Flush() []MinuteBar {
	out := make([]MinuteBar, 0, len(a.open))
	for _, bar := range a.open {
		out = append(out, bar)
	}
	a.open = make(map[string]MinuteBar)
	return out
}
