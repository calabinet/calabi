//go:build linux && !android

package mesh

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// realNetfilterEnv opts the NAT scenarios in subnetrouter_test.go into running
// against this machine's real netfilter as well as the model. It programs the
// nat table of the CURRENT network namespace, so set it only somewhere
// disposable — a privileged container, or `unshare -n`:
//
//	CALABI_TEST_REAL_NETFILTER=1 go test -run 'NAT'./internal/mesh/
//
// CALABI_TEST_IPTABLES lists extra iptables binaries to run them against too
// (e.g. "iptables-legacy iptables-nft"); the production runner, which calls
// plain `iptables`, always runs.
const realNetfilterEnv = "CALABI_TEST_REAL_NETFILTER"

func init() {
	if os.Getenv(realNetfilterEnv) != "1" {
		return
	}
	realIptablesHarnesses = func(t *testing.T) []iptablesHarness {
		if _, err := exec.LookPath("iptables"); err != nil {
			t.Fatalf("%s=1 but there is no iptables: %v", realNetfilterEnv, err)
		}
		hs := []iptablesHarness{{"iptables", runIptables}}
		for _, bin := range strings.Fields(os.Getenv("CALABI_TEST_IPTABLES")) {
			hs = append(hs, iptablesHarness{bin, func(args ...string) ([]byte, error) {
				ctx, cancel := context.WithTimeout(context.Background(), iptablesTimeout)
				defer cancel()
				return exec.CommandContext(ctx, bin, append([]string{"-w"}, args...)...).CombinedOutput()
			}})
		}
		return hs
	}
}

// The nft scenario against real nft: per-node tables, legacy table cleared.
func TestNftNATPerNodeTables_RealNetfilter(t *testing.T) {
	if os.Getenv(realNetfilterEnv) != "1" {
		t.Skipf("set %s=1 in a disposable network namespace", realNetfilterEnv)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatalf("no nft: %v", err)
	}
	tables := func() string {
		out, err := runNft("list", "tables")
		if err != nil {
			t.Fatalf("nft list tables: %v: %s", err, out)
		}
		return string(out)
	}
	if out, err := runNft("add", "table", "ip", nftLegacyTable); err != nil {
		t.Fatalf("seed legacy table: %v: %s", err, out)
	}
	be := nftNAT{run: runNft}
	a, b := testNode(1), testNode(2)
	routes := []netip.Prefix{mustPfx(testLAN), mustPfx("0.0.0.0/0")}

	cleanupB, _, err := be.masquerade(b, routes)
	if err != nil {
		t.Fatal(err)
	}
	var cleanupA func()
	for range 3 {
		if cleanupA, _, err = be.masquerade(a, routes); err != nil {
			t.Fatal(err)
		}
	}
	got := tables()
	if strings.Contains(got, "table ip "+nftLegacyTable+"\n") {
		t.Errorf("legacy table survived:\n%s", got)
	}
	if !strings.Contains(got, nftTableFor(a)) || !strings.Contains(got, nftTableFor(b)) {
		t.Errorf("want one table per node:\n%s", got)
	}
	out, err := runNft("list", "table", "ip", nftTableFor(a))
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if n := strings.Count(string(out), "masquerade"); n != 2 {
		t.Errorf("A's table holds %d masquerade rules after unclean restarts, want 2:\n%s", n, out)
	}
	cleanupA()
	if got := tables(); !strings.Contains(got, nftTableFor(b)) || strings.Contains(got, nftTableFor(a)) {
		t.Errorf("after A stopped, want only B's table:\n%s", got)
	}
	cleanupB()
	if got := tables(); strings.Contains(got, "calabi_mesh") {
		t.Errorf("tables left after both stopped:\n%s", got)
	}
}
