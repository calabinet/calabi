package main

import (
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
)

// control.addr is a BIND address, public.addr an ADVERTISED one. What the edge
// registers in the directory — the string daemons dial, and the host a platform
// relay's DERP endpoint is cut from — must be the advertised one; falling back
// to the bind address only survives when caller and callee share a host.
func TestAdvertisedAddr(t *testing.T) {
	bffEdge := config.MultiRegionConfig{Mode: "bff-edge"}

	for _, tc := range []struct {
		name            string
		cfg             config.Config
		wantAddr        string
		wantUnreachable bool
	}{
		{
			name:     "public addr wins",
			cfg:      config.Config{Control: config.ControlListener{Addr: ":7443"}, Public: config.PublicConfig{Addr: "edge01-sgp.calabi.net:7443"}, MultiRegion: bffEdge},
			wantAddr: "edge01-sgp.calabi.net:7443",
		},
		{
			// Single host: ":7443" is a usable dial string (Go reads it as
			// localhost), so a dev config may legitimately omit public.addr.
			name:     "single-host fallback is fine",
			cfg:      config.Config{Control: config.ControlListener{Addr: ":7443"}},
			wantAddr: ":7443",
		},
		{
			// Reaching the control plane through bff-edge means this node is
			// not on its daemons' host, so a bind address advertised here is
			// registered-but-undialable.
			name:            "bff-edge fallback is undialable",
			cfg:             config.Config{Control: config.ControlListener{Addr: ":7443"}, MultiRegion: bffEdge},
			wantAddr:        ":7443",
			wantUnreachable: true,
		},
		{
			name:     "whitespace-only public addr is not an address",
			cfg:      config.Config{Control: config.ControlListener{Addr: ":7443"}, Public: config.PublicConfig{Addr: "   "}, MultiRegion: bffEdge},
			wantAddr: ":7443", wantUnreachable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, unreachable := advertisedAddr(tc.cfg)
			if addr != tc.wantAddr || unreachable != tc.wantUnreachable {
				t.Errorf("advertisedAddr = (%q, %v), want (%q, %v)",
					addr, unreachable, tc.wantAddr, tc.wantUnreachable)
			}
		})
	}
}
