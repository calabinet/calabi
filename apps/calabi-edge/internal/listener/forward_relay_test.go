package listener

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
)

type fakeResolver struct {
	addr string
	id   int64
	ok   bool
}

func (f fakeResolver) ResolveOwner(string) (string, int64, bool) {
	return f.addr, f.id, f.ok
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRelayToPeerNilResolver(t *testing.T) {
	if relayToPeer(discardLogger(), nil, 1, nil, mesh.KindHTTP, "h", "/", nil, nil, nil) {
		t.Fatal("nil resolver should not forward")
	}
}

func TestRelayToPeerResolverMiss(t *testing.T) {
	r := fakeResolver{ok: false}
	if relayToPeer(discardLogger(), r, 1, nil, mesh.KindHTTP, "h", "/", nil, nil, nil) {
		t.Fatal("resolver miss should not forward")
	}
}

func TestRelayToPeerDialFailure(t *testing.T) {
	// Point at a closed port: dial fails → fall back (false), no panic.
	r := fakeResolver{addr: "127.0.0.1:1", id: 9, ok: true}
	// Need a real visitor conn for extractIP; a loopback pair works.
	visLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer visLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := visLn.Accept(); accepted <- c }()
	vc, err := net.Dial("tcp", visLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	vs := <-accepted
	defer vs.Close()
	if relayToPeer(discardLogger(), r, 1, nil, mesh.KindHTTP, "h", "/", vs, bufio.NewReader(vs), []byte("HEAD")) {
		t.Fatal("dial failure should fall back (return false)")
	}
}

func TestRelayToPeerForwardsAndSplices(t *testing.T) {
	// Fake owner edge: read the frame, reply to the visitor, then read the
	// relayed visitor body.
	ownerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ownerLn.Close()

	type ownerResult struct {
		hdr  mesh.ForwardHeader
		head string
		body string
		err  error
	}
	ownerCh := make(chan ownerResult, 1)
	go func() {
		c, e := ownerLn.Accept()
		if e != nil {
			ownerCh <- ownerResult{err: e}
			return
		}
		defer c.Close()
		rd := bufio.NewReader(c)
		hdr, head, e := mesh.ReadFrame(rd)
		if e != nil {
			ownerCh <- ownerResult{err: e}
			return
		}
		// Reply that should reach the visitor through the relay.
		_, _ = io.WriteString(c, "OWNER-REPLY")
		// Read exactly the relayed visitor body.
		bodyBuf := make([]byte, len("VISITOR-BODY"))
		_, e = io.ReadFull(rd, bodyBuf)
		ownerCh <- ownerResult{hdr: hdr, head: string(head), body: string(bodyBuf), err: e}
	}()

	// Visitor loopback pair: vs is handed to relayToPeer; vc plays the
	// browser.
	visLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer visLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := visLn.Accept(); accepted <- c }()
	vc, err := net.Dial("tcp", visLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	vs := <-accepted
	defer vs.Close()

	r := fakeResolver{addr: ownerLn.Addr().String(), id: 42, ok: true}
	done := make(chan bool, 1)
	go func() {
		done <- relayToPeer(discardLogger(), r, 7, nil,
			mesh.KindHTTP, "x.example.com", "/p", vs, bufio.NewReader(vs), []byte("HEAD"))
	}()

	// Browser sends body bytes after the (already-sniffed) head.
	if _, err := io.WriteString(vc, "VISITOR-BODY"); err != nil {
		t.Fatal(err)
	}
	// Browser reads the owner's reply, relayed back.
	replyBuf := make([]byte, len("OWNER-REPLY"))
	_ = vc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(vc, replyBuf); err != nil {
		t.Fatalf("read owner reply via relay: %v", err)
	}
	if string(replyBuf) != "OWNER-REPLY" {
		t.Errorf("visitor got %q, want OWNER-REPLY", replyBuf)
	}

	// Closing the browser EOFs the visitor->owner copy, which unblocks
	// relayToPeer and tears down the owner conn.
	_ = vc.Close()

	res := <-ownerCh
	if res.err != nil && res.body != "VISITOR-BODY" {
		t.Fatalf("owner side error: %v (body=%q)", res.err, res.body)
	}
	if res.hdr.Kind != mesh.KindHTTP || res.hdr.Host != "x.example.com" ||
		res.hdr.Path != "/p" || res.hdr.OriginEdge != 7 {
		t.Errorf("owner saw header %+v", res.hdr)
	}
	if res.head != "HEAD" {
		t.Errorf("owner head = %q, want HEAD", res.head)
	}
	if res.body != "VISITOR-BODY" {
		t.Errorf("owner body = %q, want VISITOR-BODY", res.body)
	}
	if handled := <-done; !handled {
		t.Error("relayToPeer should report handled=true on success")
	}
}
