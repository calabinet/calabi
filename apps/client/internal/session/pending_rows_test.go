// pending_rows_test.go — whose tunnels a CONFIG_PUSH belongs to.
//
// The edge catches EVERY new session up on the org's tunnels, so a foreground
// `calabi http` receives the same UpsertProxies list the daemon does. It will
// never claim any of them (autoClaim is set by `calabi daemon` and nothing
// else), so recording them as its own rows describes work it does not do.
//
// And one of them is normally the tunnel the command just created. It comes
// back keyed "pending:<tunnel_id>" while the command's own row is keyed by
// proxy_id, and nothing removes the twin — RemovePendingByTunnelID fires on a
// successful CLAIM, which this process never performs. Reported 2026-09-15: the
// one-off status page listed testcli02 twice, the two rows differing only in
// whether the public address carried its scheme.
//
// RUN: go test./apps/client/internal/session/ -run TestConfigPushPending -v
package session

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// pendingRecorder records only what this test asks about; every other
// StatusTracker method is an explicit no-op, so the test cannot be tripped by
// whichever other callbacks handleConfigPush happens to make.
type pendingRecorder struct {
	pending []int64
}

func (p *pendingRecorder) SetConnected(bool, string, string, string, string, string, uint32, uint32) {
}
func (p *pendingRecorder) AddBytes(string, string, int64)                                {}
func (p *pendingRecorder) AddConnection(string)                                          {}
func (p *pendingRecorder) RemovePendingByTunnelID(int64)                                 {}
func (p *pendingRecorder) AddActiveTunnel(string, int64, string, string, string, string) {}
func (p *pendingRecorder) RemoveActiveTunnel(string)                                     {}
func (p *pendingRecorder) ReconcileToTunnelIDs(map[int64]struct{}) []string              { return nil }

func (p *pendingRecorder) UpsertPending(tunnelID int64, _, _, _, _ string, _ uint32) {
	p.pending = append(p.pending, tunnelID)
}

func pushOneTunnel(t *testing.T, autoClaim bool) []int64 {
	t.Helper()
	rec := &pendingRecorder{}
	c := &Client{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		tracker:   rec,
		autoClaim: autoClaim,
	}
	body, err := json.Marshal(&proto.ConfigPush{
		UpsertProxies: []proto.UpsertProxy{{
			TunnelID: 11, Name: "testcli02", Type: proto.ProxyKindHTTP,
			LocalAddr: "127.0.0.1:8083", Domain: "u000011.sgp.calabi.online",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.handleConfigPush(context.Background(), body)
	return rec.pending
}

func TestConfigPushPendingRowsAreTheDaemonsAlone(t *testing.T) {
	if got := pushOneTunnel(t, false); len(got) != 0 {
		t.Fatalf("a foreground command recorded pending rows %v. It never claims them, "+
			"and the one that is its OWN tunnel becomes a duplicate row that nothing "+
			"ever removes", got)
	}
}

func TestConfigPushPendingRowsStillReachTheDaemon(t *testing.T) {
	got := pushOneTunnel(t, true)
	if len(got) != 1 || got[0] != 11 {
		t.Fatalf("pending rows = %v, want [11] — the daemon is about to claim this "+
			"tunnel and the dashboard shows it as pending until it does", got)
	}
}
