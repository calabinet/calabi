package core

import "testing"

// The port spellings validation accepts and the compiler resolves are ONE
// parser, so anything that saves is something that compiles. A spec that parsed
// on the way in but not on the way out would be a rule that silently opens
// nothing.
func TestParsePortSpec(t *testing.T) {
	ok := map[string]portSpec{
		"*":             {first: 0, last: 65535},
		"443":           {first: 443, last: 443},
		" 443 ":         {first: 443, last: 443},
		"8000-8100":     {first: 8000, last: 8100},
		"tcp:5432":      {proto: "tcp", first: 5432, last: 5432},
		"UDP:53":        {proto: "udp", first: 53, last: 53},
		"tcp:*":         {proto: "tcp", first: 0, last: 65535},
		"tcp:8000-8100": {proto: "tcp", first: 8000, last: 8100},
		"svc:web":       {service: "web"},
		"SVC:Web":       {service: "web"},
	}
	for in, want := range ok {
		got, valid := parsePortSpec(in)
		if !valid {
			t.Errorf("parsePortSpec(%q) refused a valid spec", in)
			continue
		}
		if got != want {
			t.Errorf("parsePortSpec(%q) = %+v, want %+v", in, got, want)
		}
	}

	for _, bad := range []string{"", "  ", "http", "0", "65536", "900-800", "443-", "-443",
		"svc:", "sctp:443", "tcp:", "1,2", "svc:bad name"} {
		if _, valid := parsePortSpec(bad); valid {
			t.Errorf("parsePortSpec(%q) accepted an unusable spec", bad)
		}
	}
}

// The current model: dst names machines, ports is a separate list. One rule can
// mix a literal with a service, and the service resolves against the RECEIVING
// node — which is the whole reason to name one instead of a number.
func TestCompileRuleLevelPorts(t *testing.T) {
	laptop := &Node{ID: 1, Name: "laptop", Overlay: mustAddr("100.64.0.1"), Tags: []string{"tag:laptop"}}
	a := &Node{ID: 2, Name: "a", Overlay: mustAddr("100.64.0.2"), Tags: []string{"tag:web"},
		Services: []Service{{Name: "web", Proto: "tcp", Port: 443}}}
	b := &Node{ID: 3, Name: "b", Overlay: mustAddr("100.64.0.3"), Tags: []string{"tag:web"},
		Services: []Service{{Name: "web", Proto: "tcp", Port: 8443}}}

	doc := &ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"tag:laptop"}, Dst: []string{"tag:web"}, Ports: []string{"22", "svc:web"}}}}

	for _, tc := range []struct {
		self *Node
		want string
	}{
		{a, "22-22,tcp 443-443"},
		{b, "22-22,tcp 8443-8443"},
	} {
		got := CompilePacketFilter(tc.self, []*Node{laptop, a, b}, doc)
		if len(got) != 1 {
			t.Fatalf("%s: rules = %+v, want exactly one (ports are rule-level)", tc.self.Name, got)
		}
		if p := portsOf(got); p != tc.want {
			t.Errorf("%s: ports = %q, want %q", tc.self.Name, p, tc.want)
		}
		if len(got[0].SrcCIDRs) != 1 || got[0].SrcCIDRs[0] != "100.64.0.1/32" {
			t.Errorf("%s: srcs = %v, want the laptop only", tc.self.Name, got[0].SrcCIDRs)
		}
	}
}

// A rule that opens only a service the receiver does not declare must compile to
// NOTHING, never to a rule with no ports (which the client reads as a rule) and
// never to every port.
func TestCompileServicePortAbsentOnReceiver(t *testing.T) {
	src := &Node{ID: 1, Name: "src", Overlay: mustAddr("100.64.0.1")}
	bare := &Node{ID: 2, Name: "bare", Overlay: mustAddr("100.64.0.2")}
	doc := &ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"src"}, Dst: []string{"bare"}, Ports: []string{"svc:web"}}}}
	if got := CompilePacketFilter(bare, []*Node{src}, doc); len(got) != 0 {
		t.Fatalf("compiled %+v, want nothing", got)
	}
}

// A spec that cannot be parsed grants no port rather than every port. Only a
// hand-edited document reaches this (the write path rejects it), and the safe
// reading of something we do not understand is "denies", per the filter's
// fail-closed stance.
func TestCompileUnparseablePortGrantsNothing(t *testing.T) {
	src := &Node{ID: 1, Name: "src", Overlay: mustAddr("100.64.0.1")}
	db := &Node{ID: 2, Name: "db", Overlay: mustAddr("100.64.0.2")}
	doc := &ACLPolicy{ACLs: []ACLRule{{Action: "accept",
		Src: []string{"src"}, Dst: []string{"db"}, Ports: []string{"http"}}}}
	if got := CompilePacketFilter(db, []*Node{src}, doc); len(got) != 0 {
		t.Fatalf("compiled %+v, want nothing", got)
	}
	// A rule with one good and one bad spec keeps the good one — the bad half is
	// dropped, not promoted.
	doc.ACLs[0].Ports = []string{"http", "22"}
	if p := portsOf(CompilePacketFilter(db, []*Node{src}, doc)); p != "22-22" {
		t.Fatalf("ports = %q, want just 22", p)
	}
}
