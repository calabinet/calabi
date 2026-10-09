package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// selfHostedEnv states the whole environment wire() reads, for a self-hosted
// coordinator with no database whose ACL comes from policyFile, so a case can't
// inherit a DSN, an identity service or a DERP map from the shell.
func selfHostedEnv(t *testing.T, policyFile string) {
	t.Helper()
	for _, p := range []string{envPrefix, legacyEnvPrefix} {
		for _, k := range []string{
			"IDENTITY_ADDR", "DB_DSN", "AUTHKEYS_FILE", "DEV_AUTH_KEY",
			"DERP_MAP_FILE", "DERP_ADDR", "DERP_HOME_REGION", "DERP_STUN_PORT",
			"QUOTA_ADDR", "NODE_QUOTA", "METERING_ADDR", "CONN_RECORDS", "CONN_RECORD_RETENTION_DAYS",
			edgeAddrEnv, edgePinEnv, edgeTrustEnv, edgeProbeAddrEnv,
			relayGrantKeyEnv, grantPubkeyFileEnv, "POLICY_FILE",
		} {
			t.Setenv(p+"_"+k, "")
		}
	}
	t.Setenv("CALABI_DB_DSN", "")
	t.Setenv("QUOTA_SVC_ADDR", "")
	// Self-hosted, wire() creates a relay grant key, by default in the working
	// directory: under go test, the source tree.
	t.Setenv(envPrefix+"_"+relayGrantKeyEnv, filepath.Join(t.TempDir(), "coord-grant.key"))
	t.Setenv(envPrefix+"_POLICY_FILE", policyFile)
}

// wireWithPolicyFile starts the coordinator's real wiring with doc as its
// CALABI_COORD_POLICY_FILE.
func wireWithPolicyFile(t *testing.T, doc string) *core.Coordinator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	selfHostedEnv(t, path)
	coord, _, err := wire(quietLogger())
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	return coord
}

func registerTagged(t *testing.T, coord *core.Coordinator, name string, keyByte byte, tags ...string) *core.Node {
	t.Helper()
	var k meshproto.NodeKey
	for i := range k {
		k[i] = keyByte
	}
	n, err := coord.Register(context.Background(), core.RegisterInput{Meshnet: 1, Name: name, NodeKey: k, Tags: tags})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return n
}

// The policy file decides "who reaches whom, on which ports"
// (docs/self-hosting.md). With nothing saved through the admin API the file is
// only ACLFilter's fallback, and its ports still have to reach the filter the
// destination enforces — not just its peer list.
func TestPolicyFilePortsReachThePacketFilter(t *testing.T) {
	coord := wireWithPolicyFile(t, `{"acls":[{"action":"accept","src":["tag:dev"],"dst":["tag:db"],"ports":["5432"]}]}`)
	dev := registerTagged(t, coord, "dev", 1, "tag:dev")
	db := registerTagged(t, coord, "db", 2, "tag:db")

	nm, err := coord.NetMapFor(context.Background(), db.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Name != "dev" {
		t.Fatalf("db's peers = %+v, want dev", nm.Peers)
	}
	want := []core.FilterRule{{
		SrcCIDRs: []string{dev.Overlay.String() + "/32"},
		DstPorts: []core.PortRange{{First: 5432, Last: 5432}},
	}}
	if !reflect.DeepEqual(nm.PacketFilter, want) {
		t.Fatalf("db's filter = %+v, want %+v", nm.PacketFilter, want)
	}
}

// "A file that is broken when the coordinator starts denies all traffic"
// (docs/self-hosting.md): in the filter as well as the peer list.
func TestPolicyFileBrokenAtStartDeniesInTheFilterToo(t *testing.T) {
	coord := wireWithPolicyFile(t, `{"acls": [`)
	registerTagged(t, coord, "dev", 1, "tag:dev")
	db := registerTagged(t, coord, "db", 2, "tag:db")

	nm, err := coord.NetMapFor(context.Background(), db.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 0 || len(nm.PacketFilter) != 0 {
		t.Fatalf("peers = %+v, filter = %+v; want neither", nm.Peers, nm.PacketFilter)
	}
}
