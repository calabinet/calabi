package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// Exercise the same admin write + live netmap push used by the console, with
// an exit device still allowed while another device loses the file port.
func TestACLExitSourceLivePortRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	store := core.NewMemACLStore()
	coord := &core.Coordinator{
		Nodes: core.NewMemNodeStore(), IPAM: core.NewMemIPAM(), ACL: store,
		Policy: core.ACLFilter{Store: store},
		DERP:   core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "test"}}}},
	}
	notif := core.NewNotifier()
	lis := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(server, New(coord, core.StaticAuth{Keys: map[string]core.Identity{"k": {Meshnet: 1}}}, notif, slog.Default()))
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.Stop(); _ = lis.Close() })
	conn, err := grpc.NewClient("passthrough:///acl-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := meshpb.NewCoordinatorClient(conn)
	pub, priv := newKeyPair(t)
	exit, err := enrollAs(ctx, client, "k", "exit", pub, priv, func(req *meshpb.RegisterNodeRequest) {
		req.AdvertisedRoutes = []string{"0.0.0.0/0", "::/0"}
	})
	if err != nil {
		t.Fatal(err)
	}
	windows := enroll(t, client, "k", "windows")
	phone := enroll(t, client, "k", "phone")
	stream, err := client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: phone.id, SessionToken: phone.token})
	if err != nil {
		t.Fatal(err)
	}
	recv := func() *meshpb.NetMap {
		t.Helper()
		nm, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		return nm
	}
	if !wireFilterAllowsTCP(recv(), windows.overlay, 17401) {
		t.Fatal("baseline must allow the file port")
	}
	handler := adminhttp.New(coord, notif, slog.Default())
	save := func(policy core.ACLPolicy) {
		t.Helper()
		body, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/admin/meshnets/1/acl", bytes.NewReader(body)))
		if resp.Code != http.StatusOK {
			t.Fatalf("save ACL: %d %s", resp.Code, resp.Body.String())
		}
	}
	save(core.ACLPolicy{ACLs: []core.ACLRule{
		{Action: "accept", Src: []string{"*"}, Dst: []string{"exit", "windows"}, Ports: []string{"*"}},
		{Action: "accept", Src: []string{"exit"}, Dst: []string{"phone"}, Ports: []string{"*"}},
		{Action: "accept", Src: []string{"windows"}, Dst: []string{"phone"}, Ports: []string{"1-17400", "17402-65535"}},
	}})
	nm := recv()
	if wireFilterAllowsTCP(nm, windows.overlay, 17401) {
		t.Fatal("live ACL push still permits the revoked file port")
	}
	if !wireFilterAllowsTCP(nm, exit.GetOverlayAddr(), 17401) || !wireFilterAllowsTCP(nm, windows.overlay, 17402) {
		t.Fatal("revocation affected unrelated grants")
	}
	save(core.ACLPolicy{ACLs: []core.ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"*"}}}})
	if !wireFilterAllowsTCP(recv(), windows.overlay, 17401) {
		t.Fatal("restoring the original policy did not restore access")
	}
}

func wireFilterAllowsTCP(nm *meshpb.NetMap, source string, port uint32) bool {
	if !nm.GetFilterEnabled() {
		return true
	}
	for _, rule := range nm.GetPacketFilter() {
		for _, cidr := range rule.GetSrcCidrs() {
			if !netip.MustParsePrefix(cidr).Contains(netip.MustParseAddr(source)) {
				continue
			}
			for _, p := range rule.GetDstPorts() {
				if (p.GetProto() == "" || p.GetProto() == "tcp") && p.GetFirst() <= port && port <= p.GetLast() {
					return true
				}
			}
		}
	}
	return false
}
