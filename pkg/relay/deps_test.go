package relay

import (
	"os"
	"strings"
	"testing"
)

// The relay hub's isolation guarantee:
// it forwards ciphertext by node key and MUST NOT link edge / TLS-termination /
// control-plane code. After the edge/derp merge the tunnel and relay datapaths
// share a PROCESS, so the isolation is no longer a process boundary — it is this
// module's dependency graph. pkg/relay's only intra-repo dependency is the public
// frame contract (pkg/mesh-proto); a require on anything else (an apps/* service,
// a TLS-terminating package) is the only way edge code could enter the relay's
// import graph, and this test fails the moment one appears.
func TestRelayDepsStayMinimal(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	// The complete allow-list of intra-repo modules pkg/relay may depend on.
	// Growing it is a deliberate act that should be weighed against the merge
	// invariant, not a routine `go mod tidy` side effect.
	allowed := map[string]bool{
		"github.com/calabi/calabi/pkg/mesh-proto": true,
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "github.com/calabi/calabi/") {
			continue // external / stdlib deps are fine
		}
		if strings.HasPrefix(line, "module ") || strings.HasPrefix(line, "replace ") {
			continue // our own module decl + replace targets, not requires
		}
		fields := strings.Fields(strings.TrimPrefix(line, "require "))
		if len(fields) == 0 {
			continue
		}
		mod := fields[0]
		if strings.HasPrefix(mod, "github.com/calabi/calabi/") && !allowed[mod] {
			t.Errorf("pkg/relay must not depend on %q — the relay forwards ciphertext and must not link edge / control-plane code (see edge-relay-merge-plan.md §二). If this is truly intended, update the allow-list AND reconsider the merge isolation invariant.", mod)
		}
	}
}
