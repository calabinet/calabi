package selfupdate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// silentHost is a manifest host that accepts the connection and then says
// nothing — not a refusal, not a 404, silence. It is the one failure shape with
// no natural end, which is why it is the one worth pinning.
func silentHost(t *testing.T) string {
	t.Helper()
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block
	}))
	// LIFO: release the handler first, THEN close the server. httptest.Close
	// waits for outstanding requests, so closing first would hang the test on
	// the very request it is testing.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })
	return srv.URL + "/latest.json"
}

// A check against such a host must end by itself.
//
// http.DefaultClient has no timeout, so before manifestFetchTimeout this call
// never returned. That is not "a slow check": Check holds the agent's
// single-operation claim, so the snapshot is stuck at state="checking" — which
// is exactly what the console's "check now" spinner is wired to — every later
// check answers 409 ErrBusy, and the periodic loop never fetches again. One
// unlucky network moment and that machine has no updates and no complaint.
func TestCheckDoesNotHangOnASilentManifestHost(t *testing.T) {
	a := NewAgent(&Updater{
		ManifestURL:    silentHost(t),
		CurrentVersion: "1.0.0",
		DownloadDir:    t.TempDir(),
		FetchTimeout:   200 * time.Millisecond,
	}, nil)

	done := make(chan Snapshot, 1)
	go func() {
		snap, _ := a.Check(context.Background())
		done <- snap
	}()

	select {
	case snap := <-done:
		// The spinner stops on what the RESPONSE says, not on what a later poll
		// says. A returned snapshot still reading "checking" spins for another
		// polling interval even though the work is over.
		if snap.State == StateChecking {
			t.Errorf("a check that gave up answered state=%q — the console would keep spinning", snap.State)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Check never returned against a host that accepts the connection and then says nothing: " +
			"the agent is wedged in state=\"checking\", no later check can run, and the button spins forever")
	}

	// And the claim has to be released, or the spinner is only the first symptom.
	if _, err := a.Check(context.Background()); errors.Is(err, ErrBusy) {
		t.Error("the timed-out check never released the agent: every later check answers 409 and nothing checks again")
	}
	if got := a.Snapshot().State; got == StateChecking {
		t.Errorf("snapshot left at state=%q after the check gave up", got)
	}
}
