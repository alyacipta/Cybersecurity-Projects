// ©AngelaMos | 2026
// sequencer.go

package coinbase

import "sync"

type Sequencer struct {
	mu   sync.Mutex
	last map[string]int64
}

func NewSequencer() *Sequencer {
	return &Sequencer{last: make(map[string]int64)}
}

func (s *Sequencer) Observe(productID string, seq int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.last[productID]
	s.last[productID] = seq
	if !ok {
		return false
	}
	return seq != prev+1
}

func (s *Sequencer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = make(map[string]int64)
}
