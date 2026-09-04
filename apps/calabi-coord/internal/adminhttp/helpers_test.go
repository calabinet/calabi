package adminhttp_test

import (
	"log/slog"
	"os"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// helpers_test.go — fixtures shared by every test in this package.
//
// They used to live in adminhttp_contract_test.go. That file pins coord's admin
// JSON against pkg/coordadmin (the client bff-console and bff-admin share), so
// it is one of the few files that CANNOT ship in the public tree — and the
// export dropping it took rename_test.go's fixtures with it, breaking a build
// that is green in the monorepo. Keeping the fixtures separate from the one
// private-tree test is what makes the two independent.

func newContractCoord() *core.Coordinator {
	return &core.Coordinator{
		Nodes:  core.NewMemNodeStore(),
		Policy: core.AllowAllPolicy{},
		IPAM:   core.NewMemIPAM(),
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
		Quota:  core.StaticNodeQuota{Limit: 10},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

func ckey(b byte) meshproto.NodeKey {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
