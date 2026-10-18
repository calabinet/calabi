// persist_refusal_test.go — what the client is told when tunnel-svc refuses a
// create, end to end through the real NEW_PROXY handler and the real Persist
// adapter.
//
// THE BUG. The adapter read every FailedPrecondition from CreateTunnel as the
// org security baseline and tagged it session.ErrProxyPolicyRequired, so the
// client printed
//
//	calabi: this organization requires every tunnel to have access protection: …
//
// in front of tunnel-svc's "custom domain "x" is not registered" — a sentence
// about a rule that has nothing to do with it. The baseline is not the only
// FailedPrecondition on that path: the custom-domain gate and the zone check
// return it too. The baseline's own refusals now carry a machine-readable
// reason (google.rpc.ErrorInfo); that, not the code, is what makes one.
//
// RUN: go test ./apps/calabi-edge/cmd/calabi-edge/ -run TestPersistRefusal -v
package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/yamux"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// refusingRPC is tunnel-svc answering every CreateTunnel with one error.
type refusingRPC struct {
	portBoundRPC
	createErr error
}

func (f *refusingRPC) CreateTunnel(context.Context, *pb.CreateTunnelRequest, ...grpc.CallOption) (*pb.Tunnel, error) {
	f.creates++
	return nil, f.createErr
}

// scriptedCtrl is the client's control stream: it delivers the frames it was
// given, then EOF (the client going away, which ends Loop), and keeps what the
// edge wrote back.
type scriptedCtrl struct {
	in  *bytes.Reader
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *scriptedCtrl) Read(b []byte) (int, error) { return c.in.Read(b) }
func (c *scriptedCtrl) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(b)
}
func (c *scriptedCtrl) Close() error { return nil }

type fixedDomains struct{}

func (fixedDomains) Allocate(proto.ProxyKind) string { return "u000001.cn-a.calabi.net" }

// newProxyThroughPersist sends one NEW_PROXY through session.Loop with the real
// router bridge and the real platform persister, and returns the answer.
func newProxyThroughPersist(t *testing.T, createErr error, req proto.NewProxyRequest) proto.NewProxyResponse {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var in bytes.Buffer
	f, err := proto.EncodePayload(proto.FrameNewProxy, &req)
	if err != nil {
		t.Fatalf("encode NEW_PROXY: %v", err)
	}
	if _, err := proto.WriteFrame(&in, f); err != nil {
		t.Fatalf("write NEW_PROXY: %v", err)
	}
	ctrl := &scriptedCtrl{in: bytes.NewReader(in.Bytes())}

	local, remote := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	t.Cleanup(func() { _ = remote.Close() })
	ycfg := yamux.DefaultConfig()
	ycfg.EnableKeepAlive = false
	ycfg.LogOutput = io.Discard
	mux, err := yamux.Server(local, ycfg)
	if err != nil {
		t.Fatalf("yamux: %v", err)
	}
	sess := session.New(log, mux, ctrl)
	sess.TenantID, sess.DeviceID = "4", 7

	rpc := &refusingRPC{createErr: createErr}
	persister := &tunnelPersisterAdapter{
		tc:        tunnelstore.Wrap(log, rpc, testEdgeID, "edge-a", "cn-a.calabi.net"),
		logger:    log,
		edgeLabel: "edge-a",
		index:     &tunnelIDIndex{},
	}
	reg := newRouterBridge(router.New(), log, nil, nil, false)
	sess.Loop(context.Background(), reg, fixedDomains{}, router.NewPortPool(20000, 20999), nil, persister)
	if rpc.creates != 1 {
		t.Fatalf("CreateTunnel ran %d times, want 1", rpc.creates)
	}

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	r := bytes.NewReader(ctrl.out.Bytes())
	for {
		fr, err := proto.ReadFrame(r)
		if err != nil {
			t.Fatal("no NEW_PROXY_RESP was written")
		}
		if fr.Type != proto.FrameNewProxyResp {
			continue
		}
		var resp proto.NewProxyResponse
		if err := proto.Unmarshal(fr.Payload, &resp); err != nil {
			t.Fatalf("decode NEW_PROXY_RESP: %v", err)
		}
		return resp
	}
}

// baselineErr is how tunnel-svc refuses on the org security baseline: the code
// plus the reason that says so.
func baselineErr(t *testing.T, msg string) error {
	t.Helper()
	st, err := status.New(codes.FailedPrecondition, msg).WithDetails(&errdetails.ErrorInfo{
		Reason: "ORG_PROTECTION_REQUIRED", Domain: "tunnel-svc.calabi",
	})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	return st.Err()
}

func TestPersistRefusalOtherPreconditionsAreNotTheBaseline(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
		msg  string
	}{
		{"custom domain not registered", codes.FailedPrecondition,
			"custom domain \"shop.example.com\" is not registered; run `calabi domains create shop.example.com` first"},
		{"custom domain not verified", codes.FailedPrecondition,
			"custom domain \"shop.example.com\" is not verified (TXT record not found); run `calabi domains verify shop.example.com`"},
		{"zone check", codes.FailedPrecondition,
			"cross-edge claim rejected: tunnel.domain \"a.cn-b.calabi.net\" is under managed base \"cn-b.calabi.net\" but the calling edge (id=3) declared base \"cn-a.calabi.net\""},
		// Not FailedPrecondition, but the same kind of answer: these went out as
		// 3001 "duplicate".
		{"platform name on an sni tunnel", codes.InvalidArgument,
			"sni (TLS passthrough) tunnels cannot use a platform domain (\"x.calabi.net\"); use a domain of your own, registered with `calabi domains create`"},
		{"platform name on a BYOI edge", codes.PermissionDenied,
			"BYOI edge may only serve custom domains, not platform-managed domains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := newProxyThroughPersist(t, status.Error(tc.code, tc.msg), proto.NewProxyRequest{
				Name: "web", Type: proto.ProxyKindHTTP, LocalAddr: "127.0.0.1:8080", Domain: "shop.example.com",
			})
			if resp.Error == nil {
				t.Fatal("a refused create was reported as registered")
			}
			if resp.Error.Code == proto.CodeProxyPolicyRequired {
				t.Errorf("refusal sent as %d CodeProxyPolicyRequired — the client prints "+
					"\"this organization requires every tunnel to have access protection\" in front of it",
					resp.Error.Code)
			}
			// Code 3001 says "this already exists", which none of these is.
			if resp.Error.Code == proto.CodeProxyDuplicate {
				t.Errorf("refusal sent as %d CodeProxyDuplicate", resp.Error.Code)
			}
			if resp.Error.MessageEN != tc.msg {
				t.Errorf("message = %q\nwant tunnel-svc's sentence as written: %q", resp.Error.MessageEN, tc.msg)
			}
		})
	}
}

// The control: a failure that is not the control plane refusing anything — the
// transport, here — keeps its old handling.
func TestPersistRefusalTransportFailureKeepsItsOldHandling(t *testing.T) {
	resp := newProxyThroughPersist(t, status.Error(codes.Unavailable, "connection refused"), proto.NewProxyRequest{
		Name: "web", Type: proto.ProxyKindHTTP, LocalAddr: "127.0.0.1:8080", Domain: "shop.example.com",
	})
	if resp.Error == nil || resp.Error.Code != proto.CodeProxyDuplicate {
		t.Fatalf("transport failure = %+v, want the old code %d", resp.Error, proto.CodeProxyDuplicate)
	}
}

// The control: the baseline itself still arrives as the policy refusal, with
// its sentence and nothing in front of it.
func TestPersistRefusalBaselineIsStillThePolicyRefusal(t *testing.T) {
	const msg = "this organization requires every tunnel to have access protection before it is published. " +
		"Add an IP allowlist, HTTP Basic auth, or an OAuth login to this tunnel in the console."
	resp := newProxyThroughPersist(t, baselineErr(t, msg), proto.NewProxyRequest{
		Name: "web", Type: proto.ProxyKindHTTP, LocalAddr: "127.0.0.1:8080",
	})
	if resp.Error == nil || resp.Error.Code != proto.CodeProxyPolicyRequired {
		t.Fatalf("baseline refusal = %+v, want code %d", resp.Error, proto.CodeProxyPolicyRequired)
	}
	if resp.Error.MessageEN != msg {
		t.Fatalf("message = %q\nwant the baseline's sentence as written: %q", resp.Error.MessageEN, msg)
	}
	if strings.Contains(resp.Error.MessageEN, "rpc error") {
		t.Fatalf("the gRPC envelope reached the client: %q", resp.Error.MessageEN)
	}
}
