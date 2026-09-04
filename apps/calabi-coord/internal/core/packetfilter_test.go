package core

import (
	"net/netip"
	"strings"
	"testing"
)

type netipPrefix = netip.Prefix

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func portsOf(rules []FilterRule) string {
	var b []string
	for _, r := range rules {
		for _, p := range r.DstPorts {
			prefix := ""
			if p.Proto != "" {
				prefix = p.Proto + " "
			}
			b = append(b, prefix+itoa16(p.First)+"-"+itoa16(p.Last))
		}
	}
	return strings.Join(b, ",")
}

func itoa16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}

// A meshnet with no stored ACL runs allow-all, and must compile to a filter that
// changes nothing — otherwise shipping this feature would cut every existing
// deployment the moment clients start enforcing.
func TestCompileAllowAllDefault(t *testing.T) {
	self := &Node{ID: 1, Name: "a"}
	got := CompilePacketFilter(self, nil, nil)
	if len(got) != 1 || len(got[0].DstPorts) != 1 || got[0].DstPorts[0] != allPorts() {
		t.Fatalf("allow-all compiled to %+v", got)
	}
	if len(got[0].SrcCIDRs) != 2 {
		t.Fatalf("src = %v, want both address families", got[0].SrcCIDRs)
	}
}

// The service registry is what turns "svc:web" into a port number: the filter
// opens exactly what the node declared, and nothing when it declares nothing.
func TestCompileServicePorts(t *testing.T) {
	laptop := &Node{ID: 1, Name: "laptop", Overlay: mustAddr("100.64.0.1"), Tags: []string{"tag:laptop"}}
	web := &Node{ID: 2, Name: "web", Overlay: mustAddr("100.64.0.2"),
		Services: []Service{{Name: "web", Proto: "tcp", Port: 443}, {Name: "admin", Proto: "tcp", Port: 8443}}}
	bare := &Node{ID: 3, Name: "bare", Overlay: mustAddr("100.64.0.3")}

	doc := &ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"svc:web"}},
	}}

	got := CompilePacketFilter(web, []*Node{laptop, bare}, doc)
	if len(got) != 1 {
		t.Fatalf("rules = %+v, want one", got)
	}
	if p := portsOf(got); p != "tcp 443-443" {
		t.Fatalf("ports = %q, want just the declared 443/tcp (not 8443)", p)
	}
	if len(got[0].SrcCIDRs) != 1 || got[0].SrcCIDRs[0] != "100.64.0.1/32" {
		t.Fatalf("srcs = %v, want the laptop's overlay only", got[0].SrcCIDRs)
	}
	// A node that declares no such service gets no rule from it.
	if got := CompilePacketFilter(bare, []*Node{laptop}, doc); len(got) != 0 {
		t.Fatalf("a node without the service compiled %+v, want nothing", got)
	}
}

// A literal port in the ACL text works for any selector form, and a selector
// with no port at all opens every port on the matched host.
func TestCompileLiteralAndBarePorts(t *testing.T) {
	src := &Node{ID: 1, Name: "src", Overlay: mustAddr("100.64.0.1")}
	db := &Node{ID: 2, Name: "db", Overlay: mustAddr("100.64.0.2"), Tags: []string{"tag:server"}}

	doc := &ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"src"}, Dst: []string{"tag:server:5432"}},
	}}
	if p := portsOf(CompilePacketFilter(db, []*Node{src}, doc)); p != "5432-5432" {
		t.Fatalf("ports = %q, want 5432 (prefixed selector with a port)", p)
	}

	bare := &ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"src"}, Dst: []string{"db"}}}}
	if p := portsOf(CompilePacketFilter(db, []*Node{src}, bare)); p != "0-65535" {
		t.Fatalf("ports = %q, want every port for a host selector", p)
	}
}

// Sources include a subnet router's advertised CIDRs: traffic it forwards
// arrives with a LAN source address, so a filter that only listed overlay /32s
// would silently break MESH.7 routing.
func TestCompileIncludesSubnetRoutes(t *testing.T) {
	router := &Node{ID: 1, Name: "router", Overlay: mustAddr("100.64.0.1"),
		AdvertisedRoutes: []netipPrefix{mustPrefix("192.168.1.0/24")}}
	db := &Node{ID: 2, Name: "db", Overlay: mustAddr("100.64.0.2")}
	doc := &ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"router"}, Dst: []string{"db:5432"}}}}

	got := CompilePacketFilter(db, []*Node{router}, doc)
	if len(got) != 1 {
		t.Fatalf("rules = %+v", got)
	}
	joined := strings.Join(got[0].SrcCIDRs, ",")
	if !strings.Contains(joined, "100.64.0.1/32") || !strings.Contains(joined, "192.168.1.0/24") {
		t.Fatalf("srcs = %v, want the overlay AND the advertised subnet", got[0].SrcCIDRs)
	}
}

// "*" compiles to everything rather than an enumeration that grows with the
// meshnet; a disabled peer is never a source.
func TestCompileWildcardAndDisabled(t *testing.T) {
	a := &Node{ID: 1, Name: "a", Overlay: mustAddr("100.64.0.1")}
	parked := &Node{ID: 2, Name: "parked", Overlay: mustAddr("100.64.0.2"), Disabled: true}
	me := &Node{ID: 3, Name: "me", Overlay: mustAddr("100.64.0.3")}

	star := &ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"me:22"}}}}
	got := CompilePacketFilter(me, []*Node{a, parked}, star)
	if len(got) != 1 || len(got[0].SrcCIDRs) != 2 {
		t.Fatalf("wildcard src = %+v, want the two any-address CIDRs", got)
	}

	named := &ACLPolicy{ACLs: []ACLRule{{Action: "accept", Src: []string{"parked"}, Dst: []string{"me:22"}}}}
	if got := CompilePacketFilter(me, []*Node{a, parked}, named); len(got) != 0 {
		t.Fatalf("a disabled peer must not be a source: %+v", got)
	}
}

// End to end through the coordinator: the netmap a node pulls carries the filter
// compiled from the live policy + the live service registry.
func TestNetMapCarriesCompiledFilter(t *testing.T) {
	c, ctx := serviceCoord(t)
	c.ACL = NewMemACLStore()
	c.Policy = ACLFilter{Store: c.ACL, Fallback: AllowAllPolicy{}}
	laptop, _ := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), Tags: []string{"tag:laptop"}})
	web := declareApproved(t, c, ctx, RegisterInput{Meshnet: 1, Name: "web", NodeKey: key(2),
		DeclaredServices: []Service{{Name: "web", Proto: "tcp", Port: 443}}})
	if err := c.SaveACL(ctx, 1, ACLPolicy{ACLs: []ACLRule{
		{Action: "accept", Src: []string{"tag:laptop"}, Dst: []string{"web"}, Ports: []string{"svc:web"}},
	}}, "user:1"); err != nil {
		t.Fatal(err)
	}

	nm, err := c.NetMapFor(ctx, web.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nm.PacketFilter) != 1 || portsOf(nm.PacketFilter) != "tcp 443-443" {
		t.Fatalf("web's filter = %+v", nm.PacketFilter)
	}
	if got := nm.PacketFilter[0].SrcCIDRs; len(got) != 1 || !strings.HasPrefix(got[0], laptop.Overlay.String()) {
		t.Fatalf("srcs = %v, want the laptop", got)
	}
	// The laptop itself is not a destination in any rule, so it opens nothing.
	nmL, err := c.NetMapFor(ctx, laptop.ID)
	if err != nil {
		t.Fatalf("netmap: %v", err)
	}
	if len(nmL.PacketFilter) != 0 {
		t.Fatalf("laptop's filter = %+v, want empty", nmL.PacketFilter)
	}
}
