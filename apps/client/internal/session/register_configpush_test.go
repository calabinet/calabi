package session

import (
	"context"
	"net"
	"testing"
	"time"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// TestRegisterTunnelSkipsConfigPush reproduces the bug where a foreground
// `calabi http` aborted with "want NEW_PROXY_RESP, got CONFIG_PUSH": the edge
// interleaves a CONFIG_PUSH (and may ping) before the NEW_PROXY_RESP — e.g.
// when a daemon for the same client is already online. RegisterTunnel must
// skip those benign frames and keep reading until its response.
func TestRegisterTunnelSkipsConfigPush(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	c := &Client{ctrl: newFrameStream(clientEnd)}
	server := newFrameStream(serverEnd)

	srvErr := make(chan error, 1)
	go func() {
		// 1) read the NEW_PROXY the client sends
		f, err := server.Read()
		if err != nil {
			srvErr <- err
			return
		}
		if f.Type != proto.FrameNewProxy {
			srvErr <- errFrame("NEW_PROXY", f.Type)
			return
		}
		// 2) interleave benign frames BEFORE the response
		if err := server.WritePayload(proto.FrameConfigPush, &proto.ConfigPush{}); err != nil {
			srvErr <- err
			return
		}
		if err := server.WritePayload(proto.FramePing, &proto.Ping{}); err != nil {
			srvErr <- err
			return
		}
		// 3) finally the response the client asked for
		srvErr <- server.WritePayload(proto.FrameNewProxyResp, &proto.NewProxyResponse{
			ProxyID: "px-1",
			Domain:  "quick-fox-1234.a.localtest.me",
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := c.RegisterTunnel(ctx, Tunnel{Type: proto.ProxyKindHTTP, LocalAddr: "127.0.0.1:8085"})
	if err != nil {
		t.Fatalf("RegisterTunnel: unexpected error: %v", err)
	}
	if got.Domain != "quick-fox-1234.a.localtest.me" || got.ProxyID != "px-1" {
		t.Fatalf("RegisterTunnel = %+v, want domain/proxy from NEW_PROXY_RESP", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func errFrame(want string, got proto.FrameType) error {
	return &frameMismatch{want: want, got: got}
}

type frameMismatch struct {
	want string
	got  proto.FrameType
}

func (e *frameMismatch) Error() string { return "want " + e.want + ", got " + e.got.String() }
