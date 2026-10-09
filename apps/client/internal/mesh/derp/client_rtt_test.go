package derp

import (
	"testing"
	"time"
)

// THE BUG THIS PINS: the relay's round trip was measured every 15 seconds and
// then thrown away on every machine running the default configuration.
//
// observeKeepalivePong read `if sent == 0 || c.sndbuf == nil { return }` — the
// measurement was owned by the adaptive send-buffer controller, and 8a198d67
// turned that controller OFF by default. So the one number that could have
// answered "how far away is my relay" existed, was computed, and was discarded
// before anything could read it.
//
// The controller is a CONSUMER of this measurement, not its owner.
func TestRelayRTTIsRecordedEvenWithTheBufferControllerOff(t *testing.T) {
	c := &Client{} // sndbuf nil: the default build
	c.pingAt.Store(time.Now().Add(-25 * time.Millisecond).UnixNano())

	c.observeKeepalivePong()

	got := c.RTT()
	if got <= 0 {
		t.Fatal("no RTT recorded with a nil send-buffer controller; the measurement is being dropped again")
	}
	if got < 20*time.Millisecond || got > 5*time.Second {
		t.Errorf("RTT = %v, want roughly the 25ms that was staged", got)
	}
}

// A Pong with no outstanding keepalive must not be timed from nothing: the
// zero mark would date from the epoch and report a round trip of decades.
func TestAnUnmatchedPongDoesNotInventAnRTT(t *testing.T) {
	c := &Client{}
	c.observeKeepalivePong() // no Ping was ever stamped
	if got := c.RTT(); got != 0 {
		t.Errorf("RTT = %v after an unmatched Pong, want none", got)
	}
}

// A Pong that came back is a measurement even when the clock cannot tell its
// round trip from nothing. A relay on the same machine or LAN answers inside one
// step of a coarse clock — Windows keeps time in steps of up to 15.6ms — so the
// round trip read as zero, and zero is what RTT gives for "no Pong yet". The
// relay pool takes an RTT as its proof that a relay which had been turning the
// device away has let it in again; on such a clock it went on remembering the
// refusal sweep after sweep.
//
// The mark is staged ahead of the clock, which is what a clock that has not
// moved since the Ping, or has been set back, makes of it.
func TestARoundTripTheClockCannotSeeIsStillAnRTT(t *testing.T) {
	c := &Client{}
	c.pingAt.Store(time.Now().Add(time.Hour).UnixNano())

	c.observeKeepalivePong()

	if got := c.RTT(); got != time.Microsecond {
		t.Fatalf("RTT = %v after a Pong whose round trip the clock timed at zero or less, want %v: the Pong did come back", got, time.Microsecond)
	}
}

// The mark is consumed, so one Ping yields at most one measurement — a repeated
// Pong (a duplicate, or a probe's) must not re-time the same round trip.
func TestTheKeepaliveMarkIsConsumedOnce(t *testing.T) {
	c := &Client{}
	c.pingAt.Store(time.Now().Add(-30 * time.Millisecond).UnixNano())
	c.observeKeepalivePong()
	first := c.RTT()

	c.observeKeepalivePong() // second Pong, same Ping
	if got := c.RTT(); got != first {
		t.Errorf("a second Pong moved the RTT from %v to %v; the mark was not consumed", first, got)
	}
}
