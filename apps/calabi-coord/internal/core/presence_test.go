package core

import "testing"

func TestPresence_ConnectRelease(t *testing.T) {
	p := NewPresence()
	if p.IsOnline(1) {
		t.Fatal("node 1 should start offline")
	}
	rel := p.Connected(1)
	if !p.IsOnline(1) {
		t.Fatal("node 1 should be online after Connected")
	}
	rel()
	if p.IsOnline(1) {
		t.Fatal("node 1 should be offline after release")
	}
	// Double release must not underflow / panic.
	rel()
	if p.IsOnline(1) {
		t.Fatal("still offline after a redundant release")
	}
}

// Overlapping streams keep the node online until the last one releases (a
// reconnect where the new stream opens before the old one is torn down).
func TestPresence_OverlapStaysOnline(t *testing.T) {
	p := NewPresence()
	r1 := p.Connected(2)
	r2 := p.Connected(2)
	r1()
	if !p.IsOnline(2) {
		t.Fatal("node 2 should stay online while a second stream is live")
	}
	r2()
	if p.IsOnline(2) {
		t.Fatal("node 2 offline after both streams release")
	}
}

func TestPresence_OnlineSet(t *testing.T) {
	p := NewPresence()
	defer p.Connected(1)()
	defer p.Connected(3)()
	set := p.Online([]int64{1, 2, 3})
	if !set[1] || set[2] || !set[3] {
		t.Fatalf("online set = %v, want {1,3}", set)
	}
}

// A nil Presence is safe (reports offline / empty).
func TestPresence_NilSafe(t *testing.T) {
	var p *Presence
	if p.IsOnline(1) {
		t.Fatal("nil presence should report offline")
	}
	if len(p.Online([]int64{1, 2})) != 0 {
		t.Fatal("nil presence Online should be empty")
	}
	p.Connected(1)() // must not panic
}
