package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/platform/statusapi"
)

// Exercise the real UI endpoint, disk reload, and startup flag defaults together:
// the regression was a service environment overwriting a successful UI save.
func TestStartupEdgeAffinityRemembersUIChoice(t *testing.T) {
	for _, tc := range []struct {
		name, env, choice string
		initial           bool
	}{
		{"switch to own", "platform", "own", true},
		{"confirm default own", "platform", "own", false},
		{"switch to platform", "own", "platform", false},
		{"confirm platform", "own", "platform", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateCreds(t)
			t.Setenv("LOCALAPPDATA", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("CALABI_EDGE_AFFINITY", tc.env)
			if err := creds.Save(&creds.Config{PreferPlatformEdge: tc.initial}); err != nil {
				t.Fatal(err)
			}
			s := statusapi.New(nil, statusapi.Config{})
			mux := http.NewServeMux()
			s.Register(mux)
			token, err := creds.MintLocalToken()
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/edge-affinity", strings.NewReader(`{"affinity":"`+tc.choice+`"}`))
			req.Header.Set("X-Local-Token", token)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("UI switch: %d %s", rr.Code, rr.Body.String())
			}
			// Two cold starts must both preserve the choice and the new anchor.
			c, _ := creds.Load()
			c.LastEdgeNodeID, c.LastEdgeRegion, c.EdgeRegion = 42, "chosen", "chosen"
			if err := creds.Save(c); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				runAffinityStartup(t)
				c, err = creds.Load()
				if err != nil {
					t.Fatal(err)
				}
				if c.PreferPlatformEdge != (tc.choice == "platform") || !c.EdgeAffinitySelected || c.LastEdgeNodeID != 42 || c.EdgeRegion != "chosen" || meshHomePreference() != tc.choice {
					t.Fatal("restart changed the UI choice, anchor, or mesh preference")
				}
			}
			// A deliberately supplied CLI flag still overrides the saved choice.
			runAffinityStartup(t, "--edge-affinity="+tc.env)
			c, _ = creds.Load()
			if c.PreferPlatformEdge != (tc.env == "platform") || c.LastEdgeNodeID != 0 || c.EdgeRegion != "" {
				t.Fatal("explicit CLI choice did not replace the saved choice and clear anchors")
			}
		})
	}
}

func runAffinityStartup(t *testing.T, args ...string) {
	t.Helper()
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	aff := fs.String("edge-affinity", envOr("CALABI_EDGE_AFFINITY", ""), "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if err := persistStartupEdgeAffinity(fs, *aff); err != nil {
		t.Fatal(err)
	}
}

func TestStartupEdgeAffinitySeedsLegacyConfig(t *testing.T) {
	isolateCreds(t)
	t.Setenv("CALABI_EDGE_AFFINITY", "platform")
	runAffinityStartup(t)
	c, err := creds.Load()
	if err != nil || !c.PreferPlatformEdge || c.EdgeAffinitySelected {
		t.Fatal("install-time environment should seed a config without claiming a user choice")
	}
}
