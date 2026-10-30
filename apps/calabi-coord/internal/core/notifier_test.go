package core

import (
	"testing"
	"time"
)

func TestNotifierCoalescesOnlyOrdinaryChanges(t *testing.T) {
	n := NewNotifier()
	sig, closeSub := n.Subscribe(1, 7)
	defer closeSub()
	version, changed := n.Version(1)
	for i := 0; i < 200; i++ {
		n.BumpOrdinary(1)
	}
	if v, _ := n.Version(1); v != version {
		t.Fatal("ordinary update bypassed debounce")
	}
	select {
	case <-sig:
		t.Fatal("ordinary update sent immediately")
	default:
	}
	select {
	case <-sig:
	case <-time.After(time.Second):
		t.Fatal("debounced update lost")
	}
	select {
	case <-changed:
	default:
		t.Fatal("old version remained usable")
	}
	_, changed = n.Version(1)
	n.BumpOrdinary(1)
	n.Bump(1) // disable/ACL mutation must not wait for the ordinary timer
	select {
	case <-changed:
	default:
		t.Fatal("security update was delayed")
	}
	select {
	case <-sig:
	default:
		t.Fatal("security update not signalled")
	}
	select {
	case <-sig:
		t.Fatal("cancelled timer sent another update")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNotifierDropsInactiveVersionsAndDoesNotReuseThem(t *testing.T) {
	n := NewNotifier()
	_, done := n.Subscribe(1, 7)
	v, changed := n.Version(1)
	n.BumpOrdinary(1)
	done()
	if id, _ := n.Version(1); id != 0 {
		t.Fatal("inactive group retained")
	}
	select {
	case <-changed:
	default:
		t.Fatal("last subscriber did not retire version")
	}
	sig, done := n.Subscribe(1, 7)
	defer done()
	if id, _ := n.Version(1); id == v {
		t.Fatal("generation reused after reconnect")
	}
	select {
	case <-sig:
		t.Fatal("old timer hit new subscription")
	case <-time.After(200 * time.Millisecond):
	}
}
