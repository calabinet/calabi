package derp

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
)

// The relay link carries the tunnel. On Android that socket must be protected
// from the VPN, which only happens if it is opened through hostnet.
func TestDialOpensTheRelaySocketThroughHostnet(t *testing.T) {
	refused := errors.New("protect refused")
	hostnet.SetSocketHook(func(uintptr) error { return refused })
	t.Cleanup(func() { hostnet.SetSocketHook(nil) })

	addr := startRelay(t, key(1), func(net.Conn) {})
	_, err := Dial(context.Background(), addr, key(1), Auth{}, nil, nil)
	if !errors.Is(err, refused) {
		t.Fatalf("Dial err = %v, want the socket hook's refusal (was the socket opened without hostnet?)", err)
	}
}
