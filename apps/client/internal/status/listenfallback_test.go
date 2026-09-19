package status

import "testing"

// THE FALSE ALARM, from a field log 2026-09-09:
//
//	msg="status page up (requested port busy — fell back)" url=http://[::]:7500 requested=0.0.0.0:7500
//
// Nothing was busy. net.Listen("tcp", "0.0.0.0:7500") on a dual-stack host
// returns an IPv6 socket whose Addr() prints "[::]:7500" — the same port, spelled
// differently — and the check compared the two strings. The operator was already
// debugging a startup failure and now had a second daemon to look for that did
// not exist.
//
// The fallback message must fire on a different PORT and nothing else.
func TestTheFallbackNoticeFiresOnADifferentPortNotADifferentSpelling(t *testing.T) {
	for _, tc := range []struct {
		name             string
		bound, requested string
		wantNotice       bool
	}{
		{"the field case: dual-stack renames the wildcard", "[::]:7500", "0.0.0.0:7500", false},
		{"identical", "127.0.0.1:7400", "127.0.0.1:7400", false},
		{"v6 wildcard for a bare port", "[::]:7400", ":7400", false},
		{"actually fell back", "0.0.0.0:7401", "0.0.0.0:7400", true},
		{"fell back on loopback", "127.0.0.1:7402", "127.0.0.1:7400", true},
		// CALABI_STATUS_ADDR=127.0.0.1:0 asks for any port (tests, scripts).
		{"any port was asked for", "127.0.0.1:60785", "127.0.0.1:0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fellBack(tc.bound, tc.requested)
			if got != tc.wantNotice {
				t.Fatalf("bound %q vs requested %q: notice=%v, want %v",
					tc.bound, tc.requested, got, tc.wantNotice)
			}
		})
	}
}

// An address with no port to take falls back to itself, so the comparison stays
// self-consistent (equal strings still compare equal) instead of collapsing every
// unparseable address onto one value and silencing the notice for all of them.
func TestBoundPortFallsBackToTheWholeStringWhenThereIsNoPort(t *testing.T) {
	if got := boundPort("7400"); got != "7400" {
		t.Fatalf("boundPort(%q) = %q, want the input back", "7400", got)
	}
	if boundPort("somewhere") == boundPort("elsewhere") {
		t.Error("two different portless addresses compared equal; the notice can never fire for them")
	}
}
