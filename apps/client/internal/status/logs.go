// logs.go — /logs and /logs/stream endpoints.
//
// Two endpoints, both read-only:
//
//	GET /logs?tail=N
//	  Returns the last N lines from the in-process ring buffer as JSON
//	  {"lines": ["...","..."]}. N defaults to 200, capped at the ring
//	  size (~2000). Used by the UI's logs page for the initial render
//	  before the SSE handshake completes.
//
//	GET /logs/stream
//	  Server-Sent Events stream. Each "data:" frame is one log line.
//	  Subscribes to internal/logging.Hub for the lifetime of the
//	  request — close the connection (or send a context cancel from
//	  the browser) to unsubscribe.
//
// Why not WebSocket? SSE works over plain HTTP/1.1, doesn't need a
// special upgrade dance, browsers auto-reconnect, and we're strictly
// server→client here (logs only flow one way). The day we add a UI
// terminal we'll revisit.
//
// Auth: none. The status server binds to 127.0.0.1 only, and logs are
// not user data we want to gate aggressively. If the threat model
// grows to "another local user on the same Windows machine", the
// local-token middleware can be extended to cover these too.
package status

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/calabi/calabi/apps/client/internal/logging"
)

const (
	defaultTail = 200
	maxTail     = 5000
)

// registerLogsRoutes wires /logs and /logs/stream onto mux.
func registerLogsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/logs", handleLogsTail)
	mux.HandleFunc("/logs/stream", handleLogsStream)
}

func handleLogsTail(w http.ResponseWriter, r *http.Request) {
	n := defaultTail
	if v := r.URL.Query().Get("tail"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > maxTail {
		n = maxTail
	}
	hub := logging.GetHub()
	lines := hub.Tail(n)
	if lines == nil {
		lines = []string{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"lines": lines,
		"count": len(lines),
	})
}

// handleLogsStream is the SSE endpoint. Flow:
//
//  1. Set the SSE headers + a comment heartbeat every 25s so corporate
//     proxies don't close us as idle.
//  2. Push the last 50 lines as the initial backlog (so a refresh
//     doesn't lose context).
//  3. Subscribe to the hub; pump every received line as "data: <line>\n\n".
//  4. On context cancel (browser closed tab, server shutdown), unsubscribe.
func handleLogsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Bare cross-origin guard: SSE shouldn't be reachable from a 3p
	// origin even by accident. Browsers respect Access-Control-Allow-Origin
	// here; setting it to the loopback ensures only our own UI loads it.
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:7400")

	hub := logging.GetHub()
	// Initial backlog so a refresh isn't a blank screen.
	for _, ln := range hub.Tail(50) {
		writeSSE(w, ln)
	}
	flusher.Flush()

	sub := hub.Subscribe(r.Context())
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ln, ok := <-sub:
			if !ok {
				return
			}
			writeSSE(w, ln)
			flusher.Flush()
		case <-heartbeat.C:
			// SSE comment line; browsers ignore but proxies see traffic.
			_, _ = fmt.Fprintf(w, ": ping %d\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

// writeSSE emits one event. Multi-line payloads (rare, but possible if
// a slog handler embeds '\n' in a value) split into multiple "data:"
// lines per the SSE spec.
func writeSSE(w http.ResponseWriter, ln string) {
	// Fast path: single-line message. Avoid the bytes.Buffer overhead.
	_, _ = fmt.Fprintf(w, "data: %s\n\n", ln)
}
