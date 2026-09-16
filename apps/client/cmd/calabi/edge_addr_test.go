// edge_addr_test.go — where a one-shot tunnel command gets its edge address.
//
// The bug these pin: a platform RELEASE bakes defaultServer EMPTY, so for as
// long as these commands refused to discover an edge, `calabi login` followed by
// `calabi http 8080` — the opening move in the docs — could not work on any
// official binary. It printed "no edge address" and exited 2.
//
// Each test below names the line whose removal turns it red.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestRequireEdgeAddr -v
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// edgeDirectory stands in for bff-console's GET /v1/edges. It counts calls,
// because "did not ask at all" is the assertion in half of these tests and a
// returned address cannot tell you whether a round-trip happened.
type edgeDirectory struct {
	*httptest.Server
	calls  atomic.Int32
	bearer atomic.Value // string: the Authorization header of the last call
}

func newEdgeDirectory(t *testing.T, items ...map[string]any) *edgeDirectory {
	t.Helper()
	d := &edgeDirectory{}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		d.bearer.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/edges" {
			http.NotFound(w, r)
			return
		}
		// Mirror bff-console: ?region=<r> returns that region's edges, PLUS the
		// caller org's own (owned) edges from every region — the over-answer
		// that lets a BYOI daemon reach its own edge from anywhere. Filtering
		// here is not decoration: a fake that returns everything regardless of
		// region makes the region-lock tests pass for the wrong reason (they
		// did, until this was added).
		want := r.URL.Query().Get("region")
		out := items
		if want != "" {
			out = nil
			for _, e := range items {
				if e["region"] == want || e["owned"] == true {
					out = append(out, e)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
	}))
	t.Cleanup(d.Close)
	return d
}

func edge(id int64, addr, region string) map[string]any {
	return map[string]any{
		"edge_node_id": id, "public_addr": addr, "region": region,
		"healthy": true, "active_clients": 0,
	}
}

// releaseBuild puts the process in the state an official platform binary is in:
// no compile-time edge address, a real control-plane URL, a private creds file,
// and none of the env overrides a developer's shell tends to carry.
func releaseBuild(t *testing.T, d *edgeDirectory) {
	t.Helper()
	prev := defaultServer
	defaultServer = "" // what scripts/package-release-client.sh stamps
	t.Cleanup(func() { defaultServer = prev })

	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_BFF_CONSOLE", d.URL)
	for _, k := range []string{"CALABI_SERVER", "CALABI_MODE", "CALABI_API_KEY",
		"CALABI_TOKEN", "CALABI_EDGE_REGION"} {
		t.Setenv(k, "")
	}
}

func signedIn(t *testing.T, c *creds.Config) {
	t.Helper()
	if c.AccessToken == "" {
		c.AccessToken = "eyJ-not-a-real-jwt"
	}
	if err := creds.Save(c); err != nil {
		t.Fatalf("save creds: %v", err)
	}
}

// (captureStderr lives in security_note_test.go. The messages here ARE the
// product — a user who cannot dial an edge gets nothing else — so several of
// these assert on them rather than just suppressing them.)

// THE REGRESSION. Remove the edgepicker.Pick call from requireEdgeAddr and this
// is the test that goes red.
func TestRequireEdgeAddrDiscoversAnEdgeOnAReleaseBuild(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})

	got := captureEdgeAddr(t, "http")
	if got != "edge-sfo.example.com:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the edge /v1/edges named. This is the "+
			"`calabi login` → `calabi http 8080` path the docs open with.", got)
	}
	if d.calls.Load() == 0 {
		t.Fatal("no /v1/edges call was made, so the address came from somewhere else")
	}
	// Discovery must authenticate as the same identity the handshake will use;
	// an anonymous query just 401s.
	if b, _ := d.bearer.Load().(string); !strings.HasPrefix(b, "Bearer ") {
		t.Fatalf("Authorization = %q, want the saved credential as a bearer", b)
	}
}

// An explicit address is an instruction, not a hint: honour it and do not spend
// a round-trip second-guessing it. (Also what keeps the e2e suite and the
// self-hosting docs — both of which set CALABI_SERVER — working.)
func TestRequireEdgeAddrExplicitServerWinsWithoutAskingAnyone(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})
	t.Setenv("CALABI_SERVER", "my-edge.internal:7443")

	if got := captureEdgeAddr(t, "tcp"); got != "my-edge.internal:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the CALABI_SERVER override", got)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("/v1/edges was called %d time(s) despite an explicit address", n)
	}
}

// A build that bakes its own edge keeps dialling it. Discovery was added BELOW
// the baked default on purpose: the dev stack and any self-hoster who set
// EDGE_DEFAULT must behave exactly as they did before. Move the discovery call
// above this check and this test goes red.
func TestRequireEdgeAddrBakedDefaultStillWins(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})
	defaultServer = "localhost:7443" // the dev stack's stamp

	if got := captureEdgeAddr(t, "udp"); got != "localhost:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the compile-time default", got)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("/v1/edges was called %d time(s) despite a baked default", n)
	}
}

// Standalone has no control plane. Asking one anyway would report a network
// failure for a question that should never have been asked.
func TestRequireEdgeAddrStandaloneDoesNotAsk(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{Mode: clientModeStandalone})

	var got string
	msg := captureStderr(t, func() { got = requireEdgeAddr(setupLogger(), "http") })
	if got != "" {
		t.Fatalf("requireEdgeAddr = %q, want \"\" — standalone has no control plane", got)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("/v1/edges was called %d time(s) from a standalone client", n)
	}
	if !strings.Contains(msg, "CALABI_SERVER") || !strings.Contains(msg, "standalone") {
		t.Fatalf("message should name standalone and the variable that fixes it, got:\n%s", msg)
	}
}

// No credential means no discovery AND no handshake. The message has to say
// "sign in", not "lookup failed" — the second sends people to check their DNS.
func TestRequireEdgeAddrWithoutCredentialsSaysSignIn(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d) // creds file never written: resolveCredential → credDefault

	var got string
	msg := captureStderr(t, func() { got = requireEdgeAddr(setupLogger(), "http") })
	if got != "" {
		t.Fatalf("requireEdgeAddr = %q, want \"\" with no credential", got)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("/v1/edges was called %d time(s) with the demo token", n)
	}
	if !strings.Contains(msg, "calabi login") {
		t.Fatalf("message should tell the user to sign in, got:\n%s", msg)
	}
}

// Discovery reached the control plane and it has nothing healthy. Fail with the
// reason attached rather than dialling an address nobody chose.
func TestRequireEdgeAddrDiscoveryCameBackEmpty(t *testing.T) {
	d := newEdgeDirectory(t) // no items
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})

	var got string
	msg := captureStderr(t, func() { got = requireEdgeAddr(setupLogger(), "http") })
	if got != "" {
		t.Fatalf("requireEdgeAddr = %q, want \"\" when discovery found nothing", got)
	}
	if !strings.Contains(msg, "CALABI_SERVER") {
		t.Fatalf("message should offer the manual escape hatch, got:\n%s", msg)
	}
}

// The machine's anchored edge is followed, because per-edge wildcard DNS makes
// a different edge a different subdomain zone — but it is READ, never written.
// A 30-second `calabi http` must not re-aim the installed daemon's next boot.
func TestRequireEdgeAddrFollowsTheStickyEdgeAndWritesNothingBack(t *testing.T) {
	d := newEdgeDirectory(t,
		edge(41, "edge-sfo.example.com:7443", "us-west"),
		edge(77, "edge-nrt.example.com:7443", "ap-east"),
	)
	releaseBuild(t, d)
	signedIn(t, &creds.Config{LastEdgeNodeID: 77})

	if got := captureEdgeAddr(t, "http"); got != "edge-nrt.example.com:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the sticky edge #77", got)
	}
	after, err := creds.Load()
	if err != nil || after == nil {
		t.Fatalf("reload creds: %v", err)
	}
	if after.LastEdgeNodeID != 77 || after.LastEdgeRegion != "" {
		t.Fatalf("creds were rewritten (last_edge_node_id=%d last_edge_region=%q): "+
			"a one-shot command reads the daemon's anchor, it does not move it",
			after.LastEdgeNodeID, after.LastEdgeRegion)
	}
}

// captureEdgeAddr runs requireEdgeAddr with stderr swallowed, for the cases
// where a returned address is the whole assertion.
func captureEdgeAddr(t *testing.T, cmd string) string {
	t.Helper()
	var got string
	_ = captureStderr(t, func() { got = requireEdgeAddr(setupLogger(), cmd) })
	return got
}

// BYOI soft-affinity is the picker's default and it is NOT "use the platform":
// an org that self-hosts gets its own edge unless it says otherwise. These two
// pin that the one-shot commands inherit it, and that the same env knob the
// daemon takes flips it here too — without persisting anything, which is the
// daemon's job (`--edge-affinity` also clears the edge anchor).
func TestRequireEdgeAddrDefaultsToTheOrgsOwnEdge(t *testing.T) {
	own := edge(9001, "byoi.example.com:7443", "us-west")
	own["owned"] = true
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"), own)
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})

	if got := captureEdgeAddr(t, "http"); got != "byoi.example.com:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the org's own edge — BYOI affinity is "+
			"the default, and a platform edge here would move the org's traffic "+
			"(and its custom domains) onto someone else's data plane", got)
	}
}

func TestRequireEdgeAddrAffinityEnvFlipsToPlatformWithoutPersisting(t *testing.T) {
	own := edge(9001, "byoi.example.com:7443", "us-west")
	own["owned"] = true
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"), own)
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})
	t.Setenv("CALABI_EDGE_AFFINITY", "platform")

	if got := captureEdgeAddr(t, "http"); got != "edge-sfo.example.com:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the platform edge", got)
	}
	after, err := creds.Load()
	if err != nil || after == nil {
		t.Fatalf("reload creds: %v", err)
	}
	if after.PreferPlatformEdge {
		t.Fatal("the env override was persisted: `calabi http` must not change what " +
			"the installed daemon does on its next boot")
	}
}

// THE cd-vps CASE. The machine's anchor points at a self-hosted region whose
// edge is down. The daemon locks to that anchor on purpose — it serves tunnels
// whose URLs live in that edge's wildcard zone. A one-shot command is creating a
// NEW tunnel and has no such URL, so the anchor must be a preference it can fall
// through, not a wall it stops at. Locking here means "your own edge rebooted,
// so the CLI does not work" while a healthy platform edge sits unused.
func TestRequireEdgeAddrAnchoredRegionIsAPreferenceNotAWall(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{LastEdgeRegion: "cd-vps", LastEdgeNodeID: 9001})

	if got := captureEdgeAddr(t, "http"); got != "edge-sfo.example.com:7443" {
		t.Fatalf("requireEdgeAddr = %q, want the healthy edge in another region. "+
			"LastEdgeRegion is where the daemon last connected, not a region the "+
			"user asked for — refusing to create a brand-new tunnel over it "+
			"protects no URL and strands the command.", got)
	}
}

// A region somebody actually CHOSE is an instruction, and quietly serving the
// tunnel from a different region would be ignoring it. This is the one case
// that must still refuse — and the message has to say where the region came
// from, or the user goes hunting for a setting they do not remember making.
func TestRequireEdgeAddrChosenRegionStillRefusesRatherThanWander(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{EdgeRegion: "cd-vps"})

	var got string
	msg := captureStderr(t, func() { got = requireEdgeAddr(setupLogger(), "http") })
	if got != "" {
		t.Fatalf("requireEdgeAddr = %q, want \"\" — the user pinned a region and "+
			"us-west is not it", got)
	}
	if !strings.Contains(msg, "cd-vps") || !strings.Contains(msg, "CALABI_EDGE_REGION") {
		t.Fatalf("message must name the region and how to change it, got:\n%s", msg)
	}
}

// Same shape via the env, which is the knob the message tells people to use:
// it has to be honoured as an instruction too, not treated as an anchor.
func TestRequireEdgeAddrRegionEnvIsAlsoAnInstruction(t *testing.T) {
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	signedIn(t, &creds.Config{})
	t.Setenv("CALABI_EDGE_REGION", "cd-vps")

	if got := captureEdgeAddr(t, "http"); got != "" {
		t.Fatalf("requireEdgeAddr = %q, want \"\" — CALABI_EDGE_REGION named a "+
			"region with no healthy edge", got)
	}
}
