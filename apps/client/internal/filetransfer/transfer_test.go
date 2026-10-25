package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	r       *Receiver
	s       *Sender
	dir     string
	allowed atomic.Bool
}

func setup(t *testing.T, rate int) *fixture {
	t.Helper()
	x := &fixture{dir: t.TempDir()}
	x.allowed.Store(true)
	a, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	x.r, err = NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: a.Fingerprint}, Directory: x.dir, Kbps: rate, MaxBytes: 8 << 20, Allowed: x.allowed.Load})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, done := x.r.Serve(l, b)
	pacer, _ := NewPacer(rate)
	x.s, err = NewSender(a, ip, Peer{IP: ip, Fingerprint: b.Fingerprint}, l.Addr().(*net.TCPAddr).Port, pacer, x.allowed.Load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.s.Close(); _ = srv.Close(); <-done; _ = x.r.Close() })
	return x
}

func (x *fixture) accept(t *testing.T, ctx context.Context) {
	t.Helper()
	for ctx.Err() == nil {
		for _, f := range x.r.List() {
			if f.State == "waiting" {
				if err := x.r.Decide(f.ID, true); err != nil {
					t.Error(err)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRoundTripOverMutualTLS(t *testing.T) {
	for _, size := range []int{0, 17, BlockSize*2 + 37} {
		t.Run(string(rune('a'+size%26)), func(t *testing.T) {
			x := setup(t, 32768)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go x.accept(t, ctx)
			data := bytes.Repeat([]byte{0xA7}, size)
			var previous int64
			result, err := x.s.Send(ctx, bytes.NewReader(data), "file.txt", int64(size), func(f Transfer) {
				if f.Offset < previous || f.Offset > int64(size) {
					t.Errorf("invalid persisted progress: %d", f.Offset)
				}
				previous = f.Offset
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.State != "completed" || result.Offset != int64(size) {
				t.Fatalf("bad receipt: %+v", result)
			}
			var got bytes.Buffer
			if err := x.r.CopyCompleted(ctx, result.ID, &got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), data) {
				t.Fatal("exported data differs")
			}
			entries, _ := os.ReadDir(x.dir)
			if len(entries) != 1 || entries[0].Name() != result.ID+".received" {
				t.Fatalf("unexpected inbox: %v", entries)
			}
		})
	}
}

func newOffer(t *testing.T, x *fixture, data []byte) offerReply {
	t.Helper()
	h := sha256.Sum256(data)
	body, _ := json.Marshal(Offer{Name: "test.txt", Size: int64(len(data)), SHA256: hex.EncodeToString(h[:])})
	var reply offerReply
	if err := x.s.request(context.Background(), x.s.client, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func requireStatus(t *testing.T, err error, code int) {
	t.Helper()
	var e *requestError
	if !errors.As(err, &e) || e.status != code {
		t.Fatalf("want HTTP %d, got %v", code, err)
	}
}

func TestAcceptanceCredentialsOffsetsAndHash(t *testing.T) {
	x := setup(t, 32768)
	o := newOffer(t, x, []byte("abc"))
	path := "/transfers/" + o.ID
	call := func(method, token string, data []byte, offset int64, out any) error {
		return x.s.request(context.Background(), x.s.client, method, path, token, bytes.NewReader(data), int64(len(data)), offset, out)
	}
	requireStatus(t, call("GET", "wrong", nil, 0, nil), 403)
	requireStatus(t, call("PUT", o.Token, []byte("abc"), 0, nil), 409)
	if err := x.r.Decide(o.ID, true); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, call("PUT", o.Token, []byte("abc"), 1, nil), 409)
	if err := call("PUT", o.Token, []byte("xyz"), 0, nil); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, x.s.request(context.Background(), x.s.client, "POST", path+"/commit", o.Token, nil, 0, 0, nil), 422)
	if entries, _ := os.ReadDir(x.dir); len(entries) != 0 {
		t.Fatal("checksum failure left data on disk")
	}
}

func TestRevocationAndDecline(t *testing.T) {
	x := setup(t, 32768)
	o := newOffer(t, x, []byte("abc"))
	if err := x.r.Decide(o.ID, false); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, x.s.request(context.Background(), x.s.client, "PUT", "/transfers/"+o.ID, o.Token, strings.NewReader("abc"), 3, 0, nil), 409)
	// Keep the already-authenticated TLS connection, then revoke on the server.
	x.allowed.Store(false)
	x.s.allowed = func() bool { return true }
	requireStatus(t, x.s.request(context.Background(), x.s.client, "GET", "/ping", "", nil, 0, 0, nil), 403)
}

func TestWrongServerPinAndMissingClientCertificate(t *testing.T) {
	x := setup(t, 32768)
	transport := x.s.client.Transport.(*http.Transport)
	transport.CloseIdleConnections()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error { return checkCertificate(cs, strings.Repeat("0", 64)) }
	if err := x.s.request(context.Background(), x.s.client, "GET", "/ping", "", nil, 0, 0, nil); err == nil {
		t.Fatal("accepted wrong server certificate")
	}
	transport.TLSClientConfig = x.s.control.Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = nil
	if err := x.s.request(context.Background(), x.s.client, "GET", "/ping", "", nil, 0, 0, nil); err == nil {
		t.Fatal("accepted missing client certificate")
	}
}

type loseResponse struct {
	inner  http.RoundTripper
	lost   atomic.Bool
	commit bool
}

func (l *loseResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := l.inner.RoundTrip(req)
	wanted := req.Method == "PUT"
	if l.commit {
		wanted = req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/commit")
	}
	if err == nil && wanted && resp.StatusCode == 200 && l.lost.CompareAndSwap(false, true) {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("simulated response loss AFTER receiver persisted the block")
	}
	return resp, err
}

func TestLostBlockReceiptResumesAtPersistedOffset(t *testing.T) {
	x := setup(t, 32768)
	x.s.client.Transport = &loseResponse{inner: x.s.client.Transport}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go x.accept(t, ctx)
	data := bytes.Repeat([]byte("data"), BlockSize/4+7)
	result, err := x.s.Send(ctx, bytes.NewReader(data), "resume.bin", int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := x.r.CopyCompleted(ctx, result.ID, &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("resume failed: %v", err)
	}
}

func TestLostCompletionReceiptIsIdempotent(t *testing.T) {
	x := setup(t, 32768)
	x.s.client.Transport = &loseResponse{inner: x.s.client.Transport, commit: true}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go x.accept(t, ctx)
	result, err := x.s.Send(ctx, strings.NewReader("abc"), "receipt.txt", 3, nil)
	if err != nil || result.State != "completed" {
		t.Fatalf("lost completion receipt: %v %+v", err, result)
	}
	if entries, _ := os.ReadDir(x.dir); len(entries) != 1 {
		t.Fatal("commit retry duplicated file")
	}
}

type brokenBody struct{ first bool }

func (b *brokenBody) Read(dst []byte) (int, error) {
	if !b.first {
		b.first = true
		return copy(dst, []byte("ab")), nil
	}
	return 0, errors.New("simulated mid-body disconnection")
}

type interruptBlock struct {
	inner       http.RoundTripper
	interrupted atomic.Bool
}

func (b *interruptBlock) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == "PUT" && b.interrupted.CompareAndSwap(false, true) {
		clone := req.Clone(req.Context())
		clone.Body = io.NopCloser(&brokenBody{})
		defer req.Body.Close()
		return b.inner.RoundTrip(clone)
	}
	return b.inner.RoundTrip(req)
}

func TestInterruptedBlockIsRolledBackAndRetried(t *testing.T) {
	x := setup(t, 32768)
	x.s.client.Transport = &interruptBlock{inner: x.s.client.Transport}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go x.accept(t, ctx)
	data := bytes.Repeat([]byte("c"), 8192)
	result, err := x.s.Send(ctx, bytes.NewReader(data), "partial.bin", int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := x.r.CopyCompleted(ctx, result.ID, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("partial block corrupted output: %v", err)
	}
}

func TestPacerSharedRateAndCancellation(t *testing.T) {
	p, _ := NewPacer(1024) // 128 KiB/s, with at most one 4 KiB initial burst
	start := time.Now()
	if err := p.Wait(context.Background(), 32*1024); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("source rate limit was bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx, paceChunk); err == nil {
		t.Fatal("cancelled pacing succeeded")
	}
	p.Observe(10*time.Millisecond, false)
	p.Observe(300*time.Millisecond, false)
	p.Observe(300*time.Millisecond, false)
	if p.Kbps() != 1024 {
		t.Fatal("isolated latency spikes reduced the rate")
	}
	p.Observe(300*time.Millisecond, false)
	if p.Kbps() != 512 {
		t.Fatalf("congestion did not halve rate: %d", p.Kbps())
	}
	p.Observe(10*time.Millisecond, false)
	if p.Kbps() <= 512 || p.Kbps() > 1024 {
		t.Fatal("recovery exceeded ceiling")
	}
}

func TestSimultaneousSendAndReceiveShareDeviceBudget(t *testing.T) {
	p, _ := NewPacer(1024)
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: netip.MustParseAddr("127.0.0.1"), Fingerprint: strings.Repeat("0", 64)}, Directory: t.TempDir(), Kbps: 1024, MaxBytes: 1 << 20, Budget: p, Allowed: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	start := time.Now()
	done := make(chan error, 2)
	go func() { done <- p.Wait(context.Background(), 64*1024) }()
	go func() { done <- r.pacer.Wait(context.Background(), 64*1024) }()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) < 700*time.Millisecond {
		t.Fatal("simultaneous receive obtained a second device allowance")
	}
}

func TestMetadataAndResourceBounds(t *testing.T) {
	for _, name := range []string{"../secret", `C:\secret`, "a/b", " a", "a\n", ".."} {
		if validName(name) {
			t.Fatalf("accepted name %q", name)
		}
	}
	x := setup(t, 32768)
	o := newOffer(t, x, []byte("abc"))
	// A second sender cannot reserve another full allowance/inbox allocation.
	body := `{"name":"b","size":0,"sha256":"` + strings.Repeat("0", 64) + `"}`
	requireStatus(t, x.s.request(context.Background(), x.s.client, "POST", "/offers", "", strings.NewReader(body), 0, 0, nil), 409)
	if err := x.r.Cancel(o.ID); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(x.dir); len(entries) != 0 {
		t.Fatal("declined offer created a file")
	}
}

func TestCancelInterruptsStalledUpload(t *testing.T) {
	x := setup(t, 32768)
	o := newOffer(t, x, bytes.Repeat([]byte("a"), 4096))
	if err := x.r.Decide(o.ID, true); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(x.s.base)
	conn, err := tls.Dial("tcp", u.Host, x.s.client.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "PUT /file/p0/transfers/%s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4096\r\nX-File-Offset: 0\r\nAuthorization: Bearer %s\r\n\r\nab", o.ID, u.Host, o.Token)
	if err != nil {
		t.Fatal(err)
	}
	session := x.r.find(o.ID)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !session.mu.TryLock() {
			break
		}
		session.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("upload did not start")
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- x.r.Cancel(o.ID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel waited for a stalled network read")
	}
	if entries, _ := os.ReadDir(x.dir); len(entries) != 0 {
		t.Fatal("cancel left a partial file")
	}
}

func TestCompletedFilesRemainExportableAndCountTowardInboxLimit(t *testing.T) {
	x := setup(t, 32768)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go x.accept(t, ctx)
	result, err := x.s.Send(ctx, strings.NewReader("abc"), "file.txt", 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.r.cfg.MaxBytes = 4
	body := `{"name":"b","size":2,"sha256":"` + strings.Repeat("0", 64) + `"}`
	requireStatus(t, x.s.request(ctx, x.s.client, "POST", "/offers", "", strings.NewReader(body), 0, 0, nil), 409)
	x.r.Stop()
	var out bytes.Buffer
	if err := x.r.CopyCompleted(ctx, result.ID, &out); err != nil || out.String() != "abc" {
		t.Fatalf("stopping lost verified file: %v", err)
	}
}
