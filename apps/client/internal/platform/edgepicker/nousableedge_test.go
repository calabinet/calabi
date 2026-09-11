package edgepicker

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A release binary carries the DEV default edge address (localhost:7443 — it is
// not stamped by the release ldflags). Dialling it because the control plane was
// briefly unreachable turns "cannot reach the control plane" into "connection
// refused by localhost:7443", which reads like a dev build shipped by mistake.
// Observed 2026-09-06, where the real fault (DNS) was three layers up.
func TestPickRefusesALoopbackFallbackWhenAControlPlaneWasConfigured(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	// A control plane that is configured but gets discovery nowhere. Local and
	// immediate on purpose: this used to be the production URL, so the test
	// reached the production host, and on a machine with no route to it every
	// case waited out the whole query budget. The branch under test is the same
	// whether the control plane is down or failing.
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	down := failing.URL

	cases := []struct {
		name         string
		bff          string
		def          string
		wantNoUsable bool
	}{
		// The case that broke: a real control plane, unreachable, dev default.
		{"production build, discovery down", down, "localhost:7443", true},
		{"127.0.0.1 spelled out", down, "127.0.0.1:7443", true},
		{"all interfaces is not an edge either", down, "0.0.0.0:7443", true},
		{"nothing to fall back to", down, "", true},

		// A dev / self-hosted build has no control plane URL: localhost is
		// exactly what it should dial, and refusing would break it.
		{"dev build with no bff-console", "", "localhost:7443", false},
		// A real address stays usable even when discovery fails — that is what
		// the tier-4 fallback is for.
		{"a real default edge", down, "edge01-lax.calabi.net:7443", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// No AccessToken and a control plane that only fails, so discovery
			// cannot succeed and Pick lands on tier 4 — the branch under test.
			got := Pick(context.Background(), logger, Input{
				BFFConsoleURL: c.bff,
				DefaultAddr:   c.def,
			})
			if got.NoUsableEdge != c.wantNoUsable {
				t.Fatalf("NoUsableEdge=%v, want %v (addr=%q reason=%q)",
					got.NoUsableEdge, c.wantNoUsable, got.Addr, got.Reason)
			}
			if c.wantNoUsable {
				if got.Addr != "" {
					t.Errorf("Addr=%q, want empty — the daemon must not dial it", got.Addr)
				}
				if got.Reason == "" {
					t.Error("no reason given; the operator is left with nothing to act on")
				}
			} else if got.Addr != c.def {
				t.Errorf("Addr=%q, want the default %q", got.Addr, c.def)
			}
		})
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	yes := []string{"", "   ", "localhost:7443", "LOCALHOST:1", "127.0.0.1:7443", "127.0.0.53:53",
		"[::1]:7443", "0.0.0.0:7443", ":7443", "localhost"}
	no := []string{"edge01-lax.calabi.net:7443", "10.0.0.5:7443", "203.0.113.9:7443", "example.com"}
	for _, a := range yes {
		if !isLoopbackAddr(a) {
			t.Errorf("isLoopbackAddr(%q) = false, want true", a)
		}
	}
	for _, a := range no {
		if isLoopbackAddr(a) {
			t.Errorf("isLoopbackAddr(%q) = true, want false", a)
		}
	}
}
