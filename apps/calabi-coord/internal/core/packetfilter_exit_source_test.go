package core

import (
	"net/netip"
	"testing"
)

// An exit advertisement selects where to send internet traffic. It must not
// turn a grant to that device into an any-source grant on another receiver.
func TestCompileExitSourceDoesNotGrantOtherDevices(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, family := range []struct{ exit, denied, self, def string }{
			{"100.64.0.16", "100.64.0.30", "100.64.0.21", "0.0.0.0/0"},
			{"fd00::16", "fd00::30", "fd00::21", "::/0"},
		} {
			exit := &Node{ID: 1, Name: "exit", Overlay: mustAddr(family.exit), AdvertisedRoutes: []netip.Prefix{mustPrefix(family.def)}}
			denied := &Node{ID: 2, Name: "windows", Overlay: mustAddr(family.denied)}
			self := &Node{ID: 3, Name: "phone", Overlay: mustAddr(family.self)}
			rule := ACLRule{Action: "accept", Src: []string{"exit"}, Dst: []string{"phone"}, Ports: []string{"*"}}
			if legacy {
				rule.Ports = nil
			}
			policy := &ACLPolicy{ACLs: []ACLRule{
				rule,
				{Action: "accept", Src: []string{"windows"}, Dst: []string{"phone"}, Ports: []string{"1-17400", "17402-65535"}},
			}}
			filter := CompilePacketFilter(self, []*Node{exit, denied}, policy)
			if !compiledAllowsTCP(filter, exit.Overlay, 17401) {
				t.Fatal("exit device itself lost its grant")
			}
			if compiledAllowsTCP(filter, denied.Overlay, 17401) {
				t.Fatalf("legacy=%v default=%s: exit grant bypassed windows file restriction: %+v", legacy, family.def, filter)
			}
			if !compiledAllowsTCP(filter, denied.Overlay, 17402) {
				t.Fatal("unrelated permitted port was lost")
			}
		}
	}
}

func compiledAllowsTCP(rules []FilterRule, source netip.Addr, port uint16) bool {
	for _, rule := range rules {
		for _, cidr := range rule.SrcCIDRs {
			if !mustPrefix(cidr).Contains(source) {
				continue
			}
			for _, ports := range rule.DstPorts {
				if (ports.Proto == "" || ports.Proto == "tcp") && ports.First <= port && port <= ports.Last {
					return true
				}
			}
		}
	}
	return false
}
