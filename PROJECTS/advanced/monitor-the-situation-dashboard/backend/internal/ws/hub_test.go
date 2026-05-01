// ©AngelaMos | 2026
// hub_test.go

package ws_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cdrws "github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/events"
	"github.com/carterperez-dev/monitor-the-situation/backend/internal/ws"
)

func TestHub_SubscribeAndReceive(t *testing.T) {
	hub := ws.NewHub(ws.HubConfig{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := cdrws.Accept(w, r, &cdrws.AcceptOptions{InsecureSkipVerify: true})
		require.NoError(t, err)
		_ = hub.Serve(r.Context(), c, []events.Topic{events.TopicHeartbeat})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := cdrws.Dial(ctx, wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()

	require.Eventually(t, func() bool {
		return hub.SubscriberCount() == 1
	}, time.Second, 10*time.Millisecond)

	hub.Broadcast(events.TopicHeartbeat, []byte(`{"ts":"x"}`))

	_, msg, err := conn.Read(ctx)
	require.NoError(t, err)
	require.Contains(t, string(msg), `"ch":"heartbeat"`)
}

func TestHub_TopicFiltering(t *testing.T) {
	hub := ws.NewHub(ws.HubConfig{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := cdrws.Accept(w, r, &cdrws.AcceptOptions{InsecureSkipVerify: true})
		require.NoError(t, err)
		_ = hub.Serve(r.Context(), c, []events.Topic{events.TopicHeartbeat})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := cdrws.Dial(ctx, wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()

	require.Eventually(t, func() bool {
		return hub.SubscriberCount() == 1
	}, time.Second, 10*time.Millisecond)

	hub.Broadcast(events.TopicCVENew, []byte(`{"id":"CVE-2026-0001"}`))
	hub.Broadcast(events.TopicHeartbeat, []byte(`{"ts":"y"}`))

	readCtx, readCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer readCancel()

	_, msg, err := conn.Read(readCtx)
	require.NoError(t, err)
	require.Contains(t, string(msg), `"ch":"heartbeat"`)
	require.NotContains(t, string(msg), "CVE-2026-0001")
}

func TestHub_SlowConsumerClosed(t *testing.T) {
	hub := ws.NewHub(ws.HubConfig{SubscriberBufferSize: 2})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := cdrws.Accept(w, r, &cdrws.AcceptOptions{InsecureSkipVerify: true})
		require.NoError(t, err)
		_ = hub.Serve(r.Context(), c, []events.Topic{events.TopicHeartbeat})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := cdrws.Dial(ctx, wsURL, nil)
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()

	require.Eventually(t, func() bool {
		return hub.SubscriberCount() == 1
	}, time.Second, 10*time.Millisecond)

	for i := 0; i < 200; i++ {
		hub.Broadcast(events.TopicHeartbeat, []byte(`{"i":1}`))
	}

	var ce cdrws.CloseError
	for {
		_, _, err = conn.Read(ctx)
		if err == nil {
			continue
		}
		if errors.As(err, &ce) {
			break
		}
		t.Fatalf("expected close error, got %v", err)
	}
	require.Equal(t, cdrws.StatusPolicyViolation, ce.Code)
}
