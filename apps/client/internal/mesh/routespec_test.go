package mesh

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseRouteAcceptsBareAddressAsHostRoute(t *testing.T) {
	for _, in := range []string{"192.168.1.22", " 192.168.1.22 ", "192.168.1.22/32"} {
		got, err := ParseRoute(in)
		if err != nil {
			t.Fatalf("ParseRoute(%q): %v", in, err)
		}
		if want := netip.MustParsePrefix("192.168.1.22/32"); got != want {
			t.Fatalf("ParseRoute(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseRouteMasksToNetwork(t *testing.T) {
	got, err := ParseRoute("192.168.1.5/24")
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	if want := netip.MustParsePrefix("192.168.1.0/24"); got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRouteRefusesWiderThanSlash24(t *testing.T) {
	for _, in := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.9.0.0/23", "0.0.0.0/0"} {
		if _, err := ParseRoute(in); err == nil {
			t.Fatalf("ParseRoute(%q) was accepted; a route wider than /24 can never be aliased", in)
		}
	}
}

// The error has to tell the operator what to do instead. "Too broad" alone
// leaves them guessing at the limit, and the whole point of refusing at parse
// time is that the answer arrives with the complaint.
func TestTooBroadErrorNamesAUsableAlternative(t *testing.T) {
	_, err := ParseRoute("192.168.0.0/16")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "192.168.0.0/24") {
		t.Fatalf("error does not suggest a concrete /24: %v", err)
	}
}

func TestParseRouteAcceptsExactlySlash24AndNarrower(t *testing.T) {
	for _, in := range []string{"192.168.1.0/24", "192.168.1.0/25", "192.168.1.16/28", "192.168.1.22/32"} {
		if _, err := ParseRoute(in); err != nil {
			t.Fatalf("ParseRoute(%q): %v", in, err)
		}
	}
}

// IPv6 is not aliased at all, so the IPv4 width rule must not leak onto it.
func TestParseRouteLeavesIPv6Alone(t *testing.T) {
	for _, in := range []string{"fd00::/8", "fd00::1", "fd12:3456::/48"} {
		if _, err := ParseRoute(in); err != nil {
			t.Fatalf("ParseRoute(%q): %v", in, err)
		}
	}
}

func TestParseRouteListDedupesAndReportsTheOffender(t *testing.T) {
	got, err := ParseRouteList("192.168.1.0/24, 192.168.1.22, 192.168.1.0/24")
	if err != nil {
		t.Fatalf("ParseRouteList: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 entries after de-duplication", got)
	}
	_, err = ParseRouteList("192.168.1.0/24,10.0.0.0/8")
	if err == nil || !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("error should name the route that failed, got %v", err)
	}
}

// FormatRoute is the inverse of the bare-address rule: what the console shows
// must be something ParseRoute takes back.
func TestFormatRouteRoundTrips(t *testing.T) {
	for _, in := range []string{"192.168.1.22/32", "192.168.1.0/24", "192.168.1.16/28"} {
		p := netip.MustParsePrefix(in)
		back, err := ParseRoute(FormatRoute(p))
		if err != nil {
			t.Fatalf("ParseRoute(FormatRoute(%v)): %v", p, err)
		}
		if back != p {
			t.Fatalf("round trip: %v -> %q -> %v", p, FormatRoute(p), back)
		}
	}
	if got := FormatRoute(netip.MustParsePrefix("192.168.1.22/32")); got != "192.168.1.22" {
		t.Fatalf("host route rendered as %q, want the bare address", got)
	}
}
