// sni_ingress_test.go — which nodes take TLS passthrough (sni) tunnels, and
// through which port; and that the router bridge refuses an sni route on a node
// no passthrough visitor can reach, filing nothing.
//
// RUN: go test ./apps/calabi-edge/cmd/calabi-edge/ -run 'TestRouterBridgeSNI|TestTLSPassthroughNodes' -v
package main

import (
	"errors"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

// port 443 passes TLS through only on a node that
// serves one organization. A platform node serves every org and never does,
// whatever it is configured with; sni_port stays the explicit opt-in it was.
func TestTLSPassthroughNodes(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.Config
		want443 bool
		wantSNI bool // acceptsTLSPassthrough
	}{
		{"platform node (the default)",
			config.Config{Tunnel: config.TunnelService{HTTPSPort: 443}}, false, false},
		{"platform node with sni_port",
			config.Config{Tunnel: config.TunnelService{HTTPSPort: 443, SNIPort: 8443}}, false, true},
		{"self-hosted node (certificate names its org)",
			config.Config{OrgID: 7, Tunnel: config.TunnelService{HTTPSPort: 443}}, true, true},
		{"self-hosted node without an HTTPS port",
			config.Config{OrgID: 7}, false, false},
		{"standalone node",
			config.Config{Mode: "standalone", Tunnel: config.TunnelService{HTTPSPort: 443}}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tlsPassthroughOn443(tc.cfg); got != tc.want443 {
				t.Errorf("tlsPassthroughOn443 = %v, want %v", got, tc.want443)
			}
			if got := acceptsTLSPassthrough(tc.cfg); got != tc.wantSNI {
				t.Errorf("acceptsTLSPassthrough = %v, want %v", got, tc.wantSNI)
			}
		})
	}
}

func TestRouterBridgeSNI(t *testing.T) {
	for _, on := range []bool{false, true} {
		r := router.New()
		b := newRouterBridge(r, nil, nil, nil, on)
		sess := &session.Session{ID: "s1"}

		err := b.RegisterSNI("app.example.com", sess, "p1")
		_, routed := r.LookupSNI("app.example.com")
		if on {
			if err != nil || !routed {
				t.Fatalf("passthrough reachable: err = %v, routed = %v; want nil, true", err, routed)
			}
			continue
		}
		if !errors.Is(err, session.ErrSNIIngressOff) {
			t.Fatalf("passthrough unreachable: err = %v, want session.ErrSNIIngressOff", err)
		}
		if routed {
			t.Fatal("passthrough unreachable: the route was filed anyway")
		}
	}
}
