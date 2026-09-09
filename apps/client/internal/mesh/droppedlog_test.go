package mesh

import (
	"net/netip"
	"testing"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func dr(adv, local string, k byte) droppedRoute {
	var key meshproto.NodeKey
	key[0] = k
	return droppedRoute{
		Advertised: netip.MustParsePrefix(adv),
		Local:      netip.MustParsePrefix(local),
		Peer:       key,
	}
}

// The netmap is re-pushed several times a minute and the peer order in it is not
// promised. A fingerprint that moved with the order would re-log an unchanged
// set — which is the bug this exists to prevent, just less often.
func TestDroppedFingerprintIgnoresOrder(t *testing.T) {
	a := dr("192.168.1.22/32", "192.168.1.0/24", 1)
	b := dr("10.9.1.0/24", "10.9.1.0/24", 2)
	if droppedFingerprint([]droppedRoute{a, b}) != droppedFingerprint([]droppedRoute{b, a}) {
		t.Fatal("fingerprint changed when only the order did")
	}
}

func TestDroppedFingerprintDistinguishesRealChanges(t *testing.T) {
	base := []droppedRoute{dr("192.168.1.22/32", "192.168.1.0/24", 1)}
	fp := droppedFingerprint(base)
	cases := map[string][]droppedRoute{
		"a different advertised prefix": {dr("192.168.1.23/32", "192.168.1.0/24", 1)},
		"a different local subnet":      {dr("192.168.1.22/32", "192.168.2.0/24", 1)},
		"a different peer":              {dr("192.168.1.22/32", "192.168.1.0/24", 9)},
		"an added drop":                 {base[0], dr("10.9.1.0/24", "10.9.1.0/24", 2)},
	}
	for name, in := range cases {
		if droppedFingerprint(in) == fp {
			t.Fatalf("fingerprint did not change for %s", name)
		}
	}
	if droppedFingerprint(nil) != "" {
		t.Fatal("the empty set must fingerprint as empty, so the first apply logs nothing extra")
	}
}
