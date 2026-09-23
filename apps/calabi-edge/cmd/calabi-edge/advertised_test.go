package main

import (
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
)

// What this node registers as its dial string is composed, not configured: the
// one host it publishes plus the port its control listener binds.
//
// It used to be a setting of its own (`public.addr`) that repeated the control
// port, with a fallback to the BIND address when it was missing. On one machine
// ":7443" happens to work as a dial string, which is how that fallback survived;
// anywhere else it registered the node as reachable at an address nothing could
// reach, and the node looked healthy throughout.
func TestAdvertisedAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Config
		want string
	}{
		{
			name: "host plus the control port",
			cfg: config.Config{
				Public: config.PublicConfig{Host: "edge01-sgp.calabi.net"},
				Tunnel: config.TunnelService{ControlPort: 7443},
			},
			want: "edge01-sgp.calabi.net:7443",
		},
		{
			name: "IPv6 is bracketed",
			cfg: config.Config{
				Public: config.PublicConfig{Host: "2001:db8::1"},
				Tunnel: config.TunnelService{ControlPort: 7443},
			},
			want: "[2001:db8::1]:7443",
		},
		{
			// A relay-only node: no control listener, so nothing to compose. The
			// caller skips the directory registration rather than publishing an
			// address this node never bound.
			name: "no control port",
			cfg:  config.Config{Public: config.PublicConfig{Host: "relay-tokyo.calabi.net"}},
			want: "",
		},
		{
			name: "no host",
			cfg:  config.Config{Tunnel: config.TunnelService{ControlPort: 7443}},
			want: "",
		},
		{
			name: "whitespace is not a host",
			cfg: config.Config{
				Public: config.PublicConfig{Host: "   "},
				Tunnel: config.TunnelService{ControlPort: 7443},
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.AdvertisedAddr(); got != tc.want {
				t.Errorf("AdvertisedAddr() = %q, want %q", got, tc.want)
			}
		})
	}
}
