// inspector.go — glue between session's ConnectionInspector interface
// and the internal/inspect ring buffers. Lives in cmd/ so the inspect
// package itself doesn't need to know about the session protocol.
//
// What this wires up:
//
//   - daemonInspector implements session.ConnectionInspector. On Begin
//     it opens a Connection row in the per-tunnel ConnectionLog and,
//     if the tunnel is HTTP-flavoured, allocates two CapBuffers for
//     the per-conn byte capture. On End it closes the Connection row
//     and triggers HTTP parsing if buffers were used.
//
//   - daemonInspector also exposes Snapshot* methods the statusapi
//     handlers call to render /v1/tunnels/{id}/connections and
//     /v1/tunnels/{id}/captures.
//
// Why per-tunnel buffers and not shared global ones? Two reasons:
// (a) different tunnels have wildly different traffic shapes — a busy
// HTTP API would starve a low-traffic SSH tunnel out of a shared ring;
// (b) the UI page filters by proxy_id anyway, so the lookup is
// cheaper if we don't have to scan.
package main

import (
	"io"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/inspect"
	"github.com/calabi/calabi/apps/client/internal/session"
)

// daemonInspector is the single ConnectionInspector instance shared
// by all tunnels in a daemon run. Internally it keyed-by-proxy_id.
type daemonInspector struct {
	mu sync.Mutex
	// One ConnectionLog and HTTPLog per proxy_id, lazily allocated on
	// first Begin. Bounded sizes per tunnel (200 conns + 100 captures
	// + 256KB per-conn capture buf = ~6.5MB max per HTTP tunnel).
	conns    map[string]*inspect.ConnectionLog
	captures map[string]*inspect.HTTPLog
}

func newDaemonInspector() *daemonInspector {
	return &daemonInspector{
		conns:    make(map[string]*inspect.ConnectionLog),
		captures: make(map[string]*inspect.HTTPLog),
	}
}

func (d *daemonInspector) logsFor(proxyID, kind string) (*inspect.ConnectionLog, *inspect.HTTPLog) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cl, ok := d.conns[proxyID]
	if !ok {
		cl = inspect.NewConnectionLog(200)
		d.conns[proxyID] = cl
	}
	var hl *inspect.HTTPLog
	if kind == "http" || kind == "https" {
		hl, ok = d.captures[proxyID]
		if !ok {
			hl = inspect.NewHTTPLog(100, 64*1024)
			d.captures[proxyID] = hl
		}
	}
	return cl, hl
}

// inspectorState bundles the per-conn objects shuttled between Begin
// and End. Stored as the opaque session "handle".
//
// HTTP-flavoured connections get reqPipe/respPipe (PipeBufs) and a
// background parser goroutine started in Begin; End just Close()s
// the pipes which lets the parser drain and exit. Non-HTTP
// connections leave the pipe fields nil.
type inspectorState struct {
	connRow   *inspect.Connection
	tap       *inspect.HTTPTap
	reqPipe   *inspect.PipeBuf
	respPipe  *inspect.PipeBuf
	parseDone <-chan struct{}
	startedAt time.Time
}

// Begin implements session.ConnectionInspector.
func (d *daemonInspector) Begin(proxyID, visitorIP, kind string) (any, io.Writer, io.Writer) {
	cl, hl := d.logsFor(proxyID, kind)
	row := cl.Begin(proxyID, visitorIP)
	state := &inspectorState{
		connRow:   row,
		startedAt: time.Now(),
	}
	if hl != nil {
		// Streaming capture: spawn a parser goroutine NOW so HTTPCapture
		// rows show up in the UI within ms of each request/response pair
		// completing, instead of waiting for the TCP conn to die (which
		// for HTTP/1.1 keep-alive is ~120s of idle after the last request).
		state.tap = inspect.NewHTTPTap(hl, proxyID)
		state.reqPipe = inspect.NewPipeBuf(hl.BufMax())
		state.respPipe = inspect.NewPipeBuf(hl.BufMax())
		state.parseDone = state.tap.StreamParse(state.reqPipe, state.respPipe, state.startedAt)
		return state, state.reqPipe, state.respPipe
	}
	return state, nil, nil
}

// End implements session.ConnectionInspector. Closes the connection
// row; for HTTP-capture connections, also closes the streaming pipes
// so the parser goroutine sees EOF and exits cleanly. Captures are
// already emitted live by StreamParse — there is NO final batch parse.
func (d *daemonInspector) End(handle any, bytesIn, bytesOut int64, err error) {
	st, ok := handle.(*inspectorState)
	if !ok || st == nil {
		return
	}
	// Find the right ConnectionLog to call End on. We don't have proxy_id
	// in scope here, so we fetch it via the row pointer.
	d.mu.Lock()
	cl := d.conns[st.connRow.ProxyID]
	d.mu.Unlock()
	if cl != nil {
		cl.End(st.connRow, bytesIn, bytesOut, err)
	}
	// Signal EOF to the streaming parser. Don't wait on parseDone —
	// the parser exits within a tick and any in-flight capture lands
	// in the next UI poll; blocking End would slow the data plane.
	if st.reqPipe != nil {
		_ = st.reqPipe.Close()
	}
	if st.respPipe != nil {
		_ = st.respPipe.Close()
	}
}

// SnapshotConnections returns the per-tunnel connection ring.
func (d *daemonInspector) SnapshotConnections(proxyID string) []inspect.Connection {
	d.mu.Lock()
	cl, ok := d.conns[proxyID]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	return cl.SnapshotProxy(proxyID)
}

// SnapshotCaptures returns the per-tunnel HTTP capture ring.
func (d *daemonInspector) SnapshotCaptures(proxyID string) []inspect.HTTPCapture {
	d.mu.Lock()
	hl, ok := d.captures[proxyID]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	return hl.SnapshotProxy(proxyID)
}

// GetCapture returns one capture by (proxy_id, capture_id) for the
// replay endpoint.
func (d *daemonInspector) GetCapture(proxyID string, captureID uint64) *inspect.HTTPCapture {
	d.mu.Lock()
	hl, ok := d.captures[proxyID]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	return hl.Get(captureID)
}

// Compile-time assertion that we implement the session interface.
var _ session.ConnectionInspector = (*daemonInspector)(nil)
