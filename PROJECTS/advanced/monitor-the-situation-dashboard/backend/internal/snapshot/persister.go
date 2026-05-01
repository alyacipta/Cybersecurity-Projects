// ©AngelaMos | 2026
// persister.go

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

type StorePersister struct {
	Store *Store
}

func (s StorePersister) Save(ctx context.Context, ev events.Event) error {
	raw, err := json.Marshal(ev.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	return s.Store.PutLatest(ctx, ev.Topic, raw)
}
