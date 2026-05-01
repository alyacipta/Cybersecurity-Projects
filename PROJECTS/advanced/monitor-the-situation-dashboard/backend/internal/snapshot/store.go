// ©AngelaMos | 2026
// store.go

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

const keyPrefix = "state:"

type Store struct {
	rdb *redis.Client
}

func NewStore(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

func (s *Store) PutLatest(ctx context.Context, topic events.Topic, payload json.RawMessage) error {
	if err := s.rdb.Set(ctx, keyPrefix+string(topic), []byte(payload), 0).Err(); err != nil {
		return fmt.Errorf("redis set %s: %w", topic, err)
	}
	return nil
}

func (s *Store) GetAll(ctx context.Context) (map[string]json.RawMessage, error) {
	keys, err := s.rdb.Keys(ctx, keyPrefix+"*").Result()
	if err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(keys))
	for _, k := range keys {
		v, err := s.rdb.Get(ctx, k).Bytes()
		if err != nil {
			continue
		}
		topic := k[len(keyPrefix):]
		out[topic] = json.RawMessage(v)
	}
	return out, nil
}
