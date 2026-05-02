// ©AngelaMos | 2026
// repo.go

package gdelt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

const (
	sourceGDELTSpike = "gdelt_spike"
)

type SpikeRow struct {
	ID         string
	Theme      string
	OccurredAt time.Time
	Headline   string
	Payload    json.RawMessage
}

type Repo struct {
	db *sqlx.DB
}

func NewRepo(db *sqlx.DB) *Repo { return &Repo{db: db} }

func (r *Repo) Insert(ctx context.Context, row SpikeRow) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO world_events (id, source, occurred_at, headline, payload)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING`,
		row.ID, sourceGDELTSpike, row.OccurredAt, row.Headline, []byte(row.Payload),
	)
	if err != nil {
		return fmt.Errorf("insert gdelt spike %s: %w", row.ID, err)
	}
	return nil
}
