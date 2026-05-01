// ©AngelaMos | 2026
// handler.go

package snapshot

import (
	"encoding/json"
	"net/http"
)

type Handler struct {
	store *Store
}

func NewHandler(store *Store) *Handler { return &Handler{store: store} }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	all, err := h.store.GetAll(r.Context())
	if err != nil {
		http.Error(w, "snapshot read failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if err := json.NewEncoder(w).Encode(all); err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
}
