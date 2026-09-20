package listener

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type countingObserver struct {
	mu       sync.Mutex
	failures []string
}

func (o *countingObserver) OnHandshakeFailure(reason string) {
	o.mu.Lock()
	o.failures = append(o.failures, reason)
	o.mu.Unlock()
}

type noGrants struct{}

func (noGrants) VerifyGrant([]byte, time.Time) (meshproto.RelayGrant, error) {
	return meshproto.RelayGrant{}, errors.New("no grants in this test")
}

type noRegistrar struct{}

func (noRegistrar) RegisterHTTP(string, *session.Session, string) error { return nil }
func (noRegistrar) RegisterSNI(string, *session.Session, string) error  { return nil }
func (noRegistrar) RegisterTCP(uint32, *session.Session, string) (io.Closer, error) {
	return io.NopCloser(nil), nil
}
func (noRegistrar) RegisterUDP(uint32, *session.Session, string) (io.Closer, error) {
	return io.NopCloser(nil), nil
}
func (noRegistrar) UnregisterByProxyID(string) {}

// A self-hosted coordinator reads its edge's certificate once a minute: it
// completes TLS and hangs up. That — or any TCP/TLS health check — is not a
// client whose handshake failed, and must not put a warning in the edge's log
// every minute for as long as it runs.
func TestControlDoesNotWarnAboutAPeerThatOnlyLooks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	var logs lockedBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	obs := &countingObserver{}
	c := NewControl(logger, ControlOptions{
		Addr:      addr,
		TLS:       &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"calabi/1"}},
		Manager:   session.NewManager(logger, nil),
		Grants:    noGrants{},
		Registrar: noRegistrar{},
		Observer:  obs,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	var conn *tls.Conn
	for i := 0; i < 100; i++ {
		if conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"calabi/1"}}); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(300 * time.Millisecond)

	if out := logs.String(); strings.Contains(out, "level=WARN") {
		t.Fatalf("a peer that only completed TLS was logged as a warning:\n%s", out)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.failures) != 0 {
		t.Fatalf("counted as a failed handshake: %v", obs.failures)
	}
}
