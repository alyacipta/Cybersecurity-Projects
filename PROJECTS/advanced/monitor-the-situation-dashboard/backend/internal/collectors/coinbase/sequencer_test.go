// ©AngelaMos | 2026
// sequencer_test.go

package coinbase_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/collectors/coinbase"
)

func TestSequencer_FirstTickIsAlwaysInOrder(t *testing.T) {
	s := coinbase.NewSequencer()
	gap := s.Observe("BTC-USD", 100)
	require.False(t, gap, "first sequence number must not be a gap")
}

func TestSequencer_ConsecutiveSequencesAreInOrder(t *testing.T) {
	s := coinbase.NewSequencer()
	for i := int64(50); i < 60; i++ {
		gap := s.Observe("BTC-USD", i)
		require.False(t, gap, "i=%d", i)
	}
}

func TestSequencer_GapTriggersReportSignal(t *testing.T) {
	s := coinbase.NewSequencer()
	require.False(t, s.Observe("BTC-USD", 50))
	require.False(t, s.Observe("BTC-USD", 51))
	require.True(t, s.Observe("BTC-USD", 60), "skipping 52-59 must report gap")
}

func TestSequencer_GapsArePerProduct(t *testing.T) {
	s := coinbase.NewSequencer()
	require.False(t, s.Observe("BTC-USD", 100))
	require.False(t, s.Observe("ETH-USD", 200))
	require.False(t, s.Observe("BTC-USD", 101))
	require.True(t, s.Observe("ETH-USD", 250))
	require.False(t, s.Observe("BTC-USD", 102))
}

func TestSequencer_ResetClearsAllProducts(t *testing.T) {
	s := coinbase.NewSequencer()
	s.Observe("BTC-USD", 100)
	s.Observe("ETH-USD", 200)
	s.Reset()
	require.False(t, s.Observe("BTC-USD", 9999))
	require.False(t, s.Observe("ETH-USD", 8888))
}

func TestSequencer_DuplicateSequenceTreatedAsGap(t *testing.T) {
	s := coinbase.NewSequencer()
	require.False(t, s.Observe("BTC-USD", 100))
	require.True(t, s.Observe("BTC-USD", 100), "replaying the same seq is a gap")
}

func TestSequencer_BackwardSequenceTreatedAsGap(t *testing.T) {
	s := coinbase.NewSequencer()
	require.False(t, s.Observe("BTC-USD", 100))
	require.True(t, s.Observe("BTC-USD", 90))
}
