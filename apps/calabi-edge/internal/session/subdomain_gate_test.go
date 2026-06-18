package session

import (
	"testing"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// allocWithBase is a DomainAllocator that also exposes Base(), like the real
// router.SubdomainAllocator. isManagedSubdomain reads the base via the optional
// Base() method.
type allocWithBase struct{ base string }

func (a allocWithBase) Allocate(_ proto.ProxyKind) string { return "u000001." + a.base }
func (a allocWithBase) Base() string                      { return a.base }

// allocNoBase is a DomainAllocator that does NOT expose Base() — exercises the
// fail-open path (treated as a custom domain, gate skipped).
type allocNoBase struct{}

func (allocNoBase) Allocate(_ proto.ProxyKind) string { return "u000001.example.test" }

func TestIsManagedSubdomain(t *testing.T) {
	managed := allocWithBase{base: "cn-a.calabi.net"}

	cases := []struct {
		name   string
		alloc  DomainAllocator
		domain string
		want   bool
	}{
		{"exact base", managed, "cn-a.calabi.net", true},
		{"managed subdomain", managed, "myname.cn-a.calabi.net", true},
		{"managed subdomain uppercase", managed, "MyName.CN-A.Calabi.Net", true},
		{"custom domain not under base", managed, "app.example.com", false},
		{"sibling base not a subdomain", managed, "evilcn-a.calabi.net", false},
		{"empty domain", managed, "", false},
		{"allocator without Base()", allocNoBase{}, "x.example.test", false},
		{"allocator with empty base", allocWithBase{base: ""}, "x.calabi.net", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isManagedSubdomain(tc.alloc, tc.domain); got != tc.want {
				t.Fatalf("isManagedSubdomain(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}
