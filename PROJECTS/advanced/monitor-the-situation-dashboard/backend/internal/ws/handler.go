// ©AngelaMos | 2026
// handler.go

package ws

import (
	"net/http"
	"strings"

	cdrws "github.com/coder/websocket"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
)

type Handler struct {
	hub *Hub
}

func NewHandler(hub *Hub) *Handler { return &Handler{hub: hub} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := cdrws.Accept(w, r, &cdrws.AcceptOptions{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return
	}

	topics := parseTopics(r.URL.Query().Get("topics"))
	_ = h.hub.Serve(r.Context(), c, topics)
}

func parseTopics(raw string) []events.Topic {
	if raw == "" {
		return events.AllTopics()
	}
	parts := strings.Split(raw, ",")
	out := make([]events.Topic, 0, len(parts))
	for _, p := range parts {
		t := events.Topic(strings.TrimSpace(p))
		if t.IsValid() {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return events.AllTopics()
	}
	return out
}
