package certclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/calabinet/calabi/pkg/edge-proto/edgepb"
)

// This package had no tests at all until the org-scope bug, which is part of
// why the bug lived so long: the one comment describing the scope ("0 = all
// orgs") had been wrong since the day it was written, and nothing anywhere
// executed the claim.

// fakeRPC serves a fixed catalog. It records the last ListCerts request so a
// test can see what scope the client asked for.
type fakeRPC struct {
	catalog  []*pb.CertMeta
	material map[int64]*pb.GetCertResponse
	lastList *pb.ListCertsRequest
	listCall int
}

func (f *fakeRPC) ListCerts(_ context.Context, in *pb.ListCertsRequest, _ ...grpc.CallOption) (*pb.ListCertsResponse, error) {
	f.listCall++
	f.lastList = in
	return &pb.ListCertsResponse{Items: f.catalog}, nil
}

func (f *fakeRPC) GetCert(_ context.Context, in *pb.GetCertRequest, _ ...grpc.CallOption) (*pb.GetCertResponse, error) {
	if got, ok := f.material[in.GetId()]; ok {
		return got, nil
	}
	return &pb.GetCertResponse{}, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newClient builds a Client without the poller, so a test drives refresh()
// itself and nothing races with it.
func newClient(t *testing.T, rpc RPC, orgID int64) *Client {
	t.Helper()
	return &Client{rpc: rpc, logger: quietLogger(), orgID: orgID, stopCh: make(chan struct{})}
}

func TestRefreshBuildsThePoolFromTheListing(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "a.example.com")
	addCert(t, f, 2, 42, "b.example.com")

	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for _, sni := range []string{"a.example.com", "b.example.com"} {
		if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err != nil {
			t.Errorf("%s not in the pool: %v", sni, err)
		}
	}
	// Two different orgs. Before bff-edge could ask for all of them, a platform
	// edge's listing carried one org and the other cert was simply not there.
	if c.PoolSize() != 2 {
		t.Errorf("pool size = %d, want 2", c.PoolSize())
	}
}

// TestAReconcileReplacesThePool is the mechanism behind the org-scope bug,
// pinned as behaviour rather than left as a surprise.
//
// The 5-minute reconcile is not a merge: it rebuilds the pool from the listing
// and swaps it in. So a cert the push path added survives only while the
// listing keeps returning it, and the SCOPE of that listing decides which
// tenants a node can serve — not just how fresh its pool is.
func TestAReconcileReplacesThePool(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 7, "stays.example.com")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// A cert for a DIFFERENT org arrives by push, exactly as onUpsert would
	// install it.
	pushed := addCert(t, f, 2, 42, "pushed.example.com")
	f.catalog = f.catalog[:1] // ...but the listing does not cover org 42
	installPushed(t, c, "pushed.example.com", pushed)

	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "pushed.example.com"}); err != nil {
		t.Fatalf("the pushed cert should be serving straight away: %v", err)
	}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "pushed.example.com"}); err == nil {
		t.Fatal("a reconcile whose listing omits a cert must drop it — if this ever merges instead, " +
			"the listing's scope stops being load-bearing and this test should say so")
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "stays.example.com"}); err != nil {
		t.Errorf("the listed cert should survive: %v", err)
	}
}

// The wildcard fallback, which decides whether a platform node can serve
// u<N>.<region>.calabi.online out of one *.region cert.
func TestWildcardFallback(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	addCert(t, f, 1, 1, "*.sgp.calabi.online")
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "u000001.sgp.calabi.online"}); err != nil {
		t.Errorf("wildcard did not cover a one-label subdomain: %v", err)
	}
	// One label only — a wildcard cert is not valid two levels down, and
	// serving it there would be worse than failing the handshake.
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.b.sgp.calabi.online"}); err == nil {
		t.Error("wildcard matched two levels down")
	}
}

// A SNI the pool does not cover fails the handshake rather than fetching. That
// is what makes the listing the only way certs get in, and therefore why its
// scope matters.
func TestUnknownSNIDoesNotFetch(t *testing.T) {
	f := &fakeRPC{material: map[int64]*pb.GetCertResponse{}}
	c := newClient(t, f, 0)
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	before := f.listCall
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "nobody.example.com"}); err != ErrNoCertForSNI {
		t.Errorf("err = %v, want ErrNoCertForSNI", err)
	}
	if f.listCall != before {
		t.Error("a miss triggered a fetch; this client has no on-demand path")
	}
}

// ---------- helpers ----------

// addCert appends a cert to the fake catalog and returns its PEM pair.
func addCert(t *testing.T, f *fakeRPC, id, org int64, sans ...string) *pb.GetCertResponse {
	t.Helper()
	fullchain, key := genPair(t, sans)
	got := &pb.GetCertResponse{FullchainPem: fullchain, PrivateKeyPem: key}
	f.material[id] = got
	f.catalog = append(f.catalog, &pb.CertMeta{
		Meta:    &pb.ResourceMeta{Id: id},
		OrgId:   org,
		Sans:    sans,
		Subject: sans[0],
	})
	return got
}

// installPushed puts a cert into the pool the way onUpsert does, without
// needing a bus.
func installPushed(t *testing.T, c *Client, sni string, got *pb.GetCertResponse) {
	t.Helper()
	tc, err := tls.X509KeyPair(got.GetFullchainPem(), got.GetPrivateKeyPem())
	if err != nil {
		t.Fatalf("parse pushed pair: %v", err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	next := clonePool(c.pool.Load())
	next.bySNI[sni] = &tc
	c.pool.Store(next)
}

func genPair(t *testing.T, sans []string) (fullchain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
