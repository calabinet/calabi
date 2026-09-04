package core

import (
	"context"
	"testing"
)

// The daemon reports "" for its Publish-side fingerprint whenever it has no
// device registration yet — a fresh install whose mesh session comes up before
// the device row exists, or one whose creds file momentarily won't load. It is
// the same value a pre-2026-08-22 daemon sends, since that build never reported
// one at all.
//
// Re-enrollment used to copy that "" straight over a good value, so the
// console's "open this machine's client record" link appeared and disappeared
// across daemon restarts. A fingerprint is only ever REPLACED by another
// fingerprint now.
func TestRegisterKeepsFingerprintWhenNodeReportsNone(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()

	first, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "laptop", NodeKey: key(1), DeviceFingerprint: "fp_abc",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if first.DeviceFingerprint != "fp_abc" {
		t.Fatalf("initial fingerprint = %q", first.DeviceFingerprint)
	}

	again, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "laptop", NodeKey: key(1), // no fingerprint reported
	})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if again.ID != first.ID {
		t.Fatalf("re-enrollment churned the node id: %d → %d", first.ID, again.ID)
	}
	if again.DeviceFingerprint != "fp_abc" {
		t.Fatalf("fingerprint erased by a silent re-enrollment: %q", again.DeviceFingerprint)
	}

	// A node that reports a DIFFERENT fingerprint still wins — the machine was
	// re-registered on the Publish side and this is the new truth.
	moved, err := c.Register(ctx, RegisterInput{
		Meshnet: 1, Name: "laptop", NodeKey: key(1), DeviceFingerprint: "fp_xyz",
	})
	if err != nil {
		t.Fatalf("re-register with new fingerprint: %v", err)
	}
	if moved.DeviceFingerprint != "fp_xyz" {
		t.Fatalf("fingerprint = %q, want the newly reported one", moved.DeviceFingerprint)
	}
}
