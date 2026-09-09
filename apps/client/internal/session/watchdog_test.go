package session

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// THE OUTAGE THIS PINS, as the user measured it.
//
// A simulated network drop, restored at 08:15:33. The mesh relay was back at
// 08:15:33.6 — under a second. The tunnel did not come back until 08:18:23,
// nearly three minutes later, and when it finally did, the whole reconnect
// took 243ms. So the time was not spent reconnecting; it was spent not yet
// knowing there was anything to reconnect.
//
// Nothing in the session watched for silence. The control loop parks in Read(),
// and a dropped network does not make that return: the socket stays
// "established" until the kernel stops retransmitting. The heartbeat's writes
// go into the local send buffer and succeed. Both halves looked healthy.
//
// The mesh had this right already — relayPool.sweep reaps a link that has gone
// relayDeadAfter without an inbound frame — which is exactly why the two planes
// recovered minutes apart from one outage.
func TestSilentLinkEndsTheSessionInsteadOfWaitingOnTheKernel(t *testing.T) {
	mux, srvCtrl := newYamuxMuxPair(t)
	// The server accepts everything and answers NOTHING. That is what a dropped
	// network looks like from in here: writes still succeed, nothing comes back.
	go io.Copy(io.Discard, srvCtrl)

	c := &Client{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		mux:    mux,
		ctrl:   newFrameStream(mux.Control),
		// 50ms beat => a 150ms deadline, so the test measures the mechanism
		// rather than the production constant.
		heartbeatInterval: 50 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(context.Background(), func(string) (Tunnel, bool) { return Tunnel{}, false })
	}()

	select {
	case <-done:
		// Ended on its own, without the caller cancelling and without the TCP
		// stack giving up.
	case <-time.After(3 * time.Second):
		t.Fatal("a session that received nothing at all ran on indefinitely; " +
			"recovery is left waiting for the OS to time out the socket")
	}
}

// The deadline must not fire on a link that is answering. Three missed beats is
// the budget; a link replying every beat has to survive comfortably longer than
// that, or every healthy idle tunnel reconnects in a loop.
func TestAnAnsweringLinkIsNotKilled(t *testing.T) {
	mux, srvCtrl := newYamuxMuxPair(t)

	// Echo the client's frames back, which is what the edge does with Ping
	// (it answers every one with a Pong, unconditionally).
	go io.Copy(srvCtrl, srvCtrl)

	c := &Client{
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		mux:               mux,
		ctrl:              newFrameStream(mux.Control),
		heartbeatInterval: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, func(string) (Tunnel, bool) { return Tunnel{}, false })
	}()

	// Ten beats — well past the three-beat deadline.
	select {
	case <-done:
		t.Fatal("the watchdog ended a session whose peer was answering every beat; " +
			"a healthy idle tunnel would reconnect in a loop")
	case <-time.After(500 * time.Millisecond):
	}
}

// failingWriter accepts nothing and never returns from a read: the shape of a
// link whose writes have started erroring while the control loop is still
// parked waiting for a frame that will never come.
type failingWriter struct{ blocked chan struct{} }

func (f *failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (f *failingWriter) Read([]byte) (int, error)  { <-f.blocked; return 0, io.EOF }
func (f *failingWriter) Close() error              { close(f.blocked); return nil }

// A heartbeat that cannot be written must END the session, not merely stop.
//
// It used to log a warning and return, quietly, from a goroutine nobody was
// watching. The session then continued with NO heartbeat at all, still parked in
// the control read, until the kernel eventually failed the socket. The single
// earliest signal available that the link was gone was being discarded — which
// is the same shape as every other fault in this release: a real detection
// wired to nothing.
func TestAFailedHeartbeatEndsTheSession(t *testing.T) {
	c := &Client{
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ctrl:              newFrameStream(&failingWriter{blocked: make(chan struct{})}),
		heartbeatInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go c.heartbeat(ctx, cancel)

	select {
	case <-ctx.Done():
		// The heartbeat cancelled the session's context, which is what closes the
		// mux and unblocks the parked read.
	case <-time.After(2 * time.Second):
		t.Fatal("a heartbeat that could not be written left the session running; " +
			"the earliest warning that the link is gone is being thrown away")
	}
}
