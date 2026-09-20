// device_register_test.go — when a one-shot tunnel command registers the machine.
//
// Registration used to happen only on the daemon path, so a machine that had
// only ever run `calabi http` had creds.DeviceID == 0. Everything downstream
// followed from that: the tunnel row stored client_id = 0, the console's client
// list had no row for the machine, and the shared state derivation skipped every
// client-side signal — which is how a tunnel with an unreachable upstream still
// read 正常.
//
// Each "no" below is a rule, not a detail: this costs an HTTP round-trip in
// front of a command whose appeal is that it starts immediately, so it must
// happen exactly once per machine and never where it would be useless.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestShouldRegisterDevice -v
package main

import (
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

func TestShouldRegisterDeviceOnlyWhenTheIdIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standalone bool
		cfg        *creds.Config
		kind       credentialKind
		want       bool
	}{
		{"fresh machine, signed in", false, &creds.Config{}, credLogin, true},
		{"fresh machine, api key", false, &creds.Config{}, credAPIKey, true},
		// THE LATENCY RULE. Every `calabi http` on an already-registered machine
		// would otherwise pay for a round-trip that changes nothing.
		{"already registered", false, &creds.Config{DeviceID: 77}, credLogin, false},
		// Standalone has no control plane; there is nobody to register with.
		{"standalone", true, &creds.Config{}, credLogin, false},
		// The demo token would just 401.
		{"no real credential", false, &creds.Config{}, credDefault, false},
		{"no creds file", false, nil, credLogin, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRegisterDevice(tc.standalone, tc.cfg, tc.kind); got != tc.want {
				t.Fatalf("shouldRegisterDevice = %v, want %v", got, tc.want)
			}
		})
	}
}

// A registered machine must stay on its existing id. Minting a second one would
// split one machine into two rows in the client list and hand the tunnel a
// client_id whose presence nobody reports.
func TestShouldRegisterDeviceNeverReRegistersUnderAnyCredential(t *testing.T) {
	for _, k := range []credentialKind{credLogin, credAPIKey, credDefault} {
		if shouldRegisterDevice(false, &creds.Config{DeviceID: 1}, k) {
			t.Fatalf("credential kind %v re-registered an already-registered device", k)
		}
	}
}
