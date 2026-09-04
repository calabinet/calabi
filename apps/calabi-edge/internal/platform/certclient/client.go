// Package certclient pulls TLS certificates from cert-svc into an
// in-process atomic map keyed by SNI server_name. Designed to back
// tls.Config.GetCertificate for the edge HTTPS listener.
//
// PRIMARY PATH
// ----------------------------
//   - On Start(), dial cert-svc, ListCerts(org=0 → all orgs), then for
//     every cert call GetCert to pull the decrypted private key. Build
//     the initial pool.
//   - Subscribe to calabi.cert.upsert.> and calabi.cert.delete.> on
//     NATS. Each event names a (cert_id, org_id, sans...) tuple; the
//     handler refetches that one cert (or evicts on delete) and swaps
//     the pool atomically.
//   - Periodic ListCerts continues as a low-cadence fallback (default
//     5 minutes; was 30s) to reconcile any dropped events.
//
// FALLBACK PATH
// -------------------------------------
// When the caller passes an empty Bus, no NATS subscribe happens; the
// poll cadence stays at the legacy 30s default so the behaviour
// (full pool refresh every 30s) is preserved bit-for-bit. This makes
// the change forwards-compatible: a single-binary dev runner without
// NATS still works.
//
// org_id scoping: still fetches the whole catalog because edge doesn't
// yet know which org owns which tunnel domain (tunnel-svc holds that
// map, not surfaced to edge). will tighten it.
package certclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabi/calabi/pkg/certevents"
	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// DefaultRefreshInterval governs how often the client re-polls cert-svc
// when NATS is wired (push primary, poll as belt-and-suspenders).
const DefaultRefreshInterval = 5 * time.Minute

// LegacyPollInterval is the original cadence — used when no NATS bus
// is configured so the edge keeps full visibility via polling alone.
const LegacyPollInterval = 30 * time.Second

// ErrNoCertForSNI is what GetCertificate returns when a TLS visitor's
// ClientHello.ServerName isn't in the active map. crypto/tls turns this
// into a TLS-level "no_cert" alert; the visitor sees a handshake failure.
var ErrNoCertForSNI = errors.New("certclient: no certificate for SNI")

// Options configures Start.
type Options struct {
	// Addr is the cert-svc gRPC endpoint, e.g. "127.0.0.1:7005".
	Addr string
	// OrgID limits the fetch to one org. 0 = all orgs.
	OrgID int64
	// RefreshInterval overrides the default poll cadence. Zero picks
	// the right default for the wiring: 5 minutes when a Bus is set
	// (push primary, poll as backstop), 30 seconds when not (poll-only).
	RefreshInterval time.Duration
	// Bus, when non-nil, enables the cert-push path. The client
	// subscribes to calabi.cert.upsert.> and calabi.cert.delete.>
	// during Start() and applies events incrementally.
	Bus eventbus.Bus
}

// Client owns the cert-svc grpc connection + the polling goroutine + the
// atomic pool of *tls.Certificate keyed by SNI host.
//
// Safe for concurrent reads (GetCertificate); writes happen only on the
// polling goroutine or NATS handler goroutine; the writeMu serialises
// the two so they don't trample each other's pool snapshots.
// RPC is the narrow subset of pb.CertClient edge uses. bff_edge.BFFEdgeClient satisfies it directly — names + signatures match.
type RPC interface {
	GetCert(ctx context.Context, in *pb.GetCertRequest, opts ...grpc.CallOption) (*pb.GetCertResponse, error)
	ListCerts(ctx context.Context, in *pb.ListCertsRequest, opts ...grpc.CallOption) (*pb.ListCertsResponse, error)
}

type Client struct {
	conn   *grpc.ClientConn // nil when constructed via StartWrap
	rpc    RPC
	logger *slog.Logger
	orgID  int64

	pool atomic.Pointer[certPool]

	// writeMu serialises pool mutations across the polling goroutine
	// and the NATS event handler. Reads (GetCertificate) bypass the
	// mutex by going through pool.Load().
	writeMu sync.Mutex

	bus    eventbus.Bus
	upsert eventbus.Subscription
	delete eventbus.Subscription

	stopCh   chan struct{}
	stopOnce func()
}

// certPool is the snapshot we swap in atomically. Multiple SAN entries
// can point at the same *tls.Certificate.
//
// fingerprints tracks the leaf-DER SHA256s currently installed so the
// push handler can short-circuit redundant GetCert RPCs when NATS
// redelivers an event.
type certPool struct {
	bySNI        map[string]*tls.Certificate
	fingerprints map[string]bool
}

// The direct-dial constructor was removed in F3 step 2b: every edge now
// reaches the control plane through bff-edge, so this package is only ever
// handed a ready client.
// logInitialFetchErr logs a failed initial cert fetch at the right level. A
// BYOI / single-tenant edge is DENIED cert listing by design — bff-edge
// enforces org isolation and refuses ListCerts (it could otherwise leak another
// org's private key) — so that PermissionDenied is EXPECTED, not a problem:
// the edge provisions its certs locally / via self-service ACME. Log it at INFO
// so self-hosters aren't alarmed; everything else stays a WARN.
func (c *Client) logInitialFetchErr(err error, addr string) {
	if status.Code(err) == codes.PermissionDenied {
		c.logger.Info("cert-svc listing disabled for this edge (BYOI / single-tenant) — serving certs provisioned locally or via self-service ACME")
		return
	}
	c.logger.Warn("initial cert-svc fetch failed; serving with empty pool", "err", err, "addr", addr)
}

// StartWithClient is Start's sibling for bff-edge mode: the caller
// passes a pre-made RPC (typically a shared bff_edge.BFFEdgeClient)
// and Bus (typically bffedgeclient.NewBus), and StartWithClient skips
// the cert-svc dial.
func StartWithClient(ctx context.Context, logger *slog.Logger, client RPC, opts Options) (*Client, error) {
	if client == nil {
		return nil, errors.New("certclient: nil RPC")
	}
	if opts.RefreshInterval <= 0 {
		if opts.Bus != nil {
			opts.RefreshInterval = DefaultRefreshInterval
		} else {
			opts.RefreshInterval = LegacyPollInterval
		}
	}
	c := &Client{
		rpc:    client,
		logger: logger.With("component", "certclient"),
		orgID:  opts.OrgID,
		bus:    opts.Bus,
		stopCh: make(chan struct{}),
	}
	if err := c.refresh(ctx); err != nil {
		c.logInitialFetchErr(err, "")
		c.pool.Store(&certPool{bySNI: map[string]*tls.Certificate{}})
	}
	if c.bus != nil {
		if err := c.subscribeEvents(); err != nil {
			c.logger.Warn("cert push subscribe failed; falling back to poll-only",
				"err", err)
			opts.RefreshInterval = LegacyPollInterval
		} else {
			c.logger.Info("cert push subscribed (bff-edge mode)",
				"reconcile_interval", opts.RefreshInterval)
		}
	}
	c.startPoller(opts.RefreshInterval)
	return c, nil
}

// startPoller is the goroutine shared by Start and StartWithClient.
func (c *Client) startPoller(interval time.Duration) {
	stopped := make(chan struct{})
	c.stopOnce = func() {
		select {
		case <-c.stopCh:
		default:
			close(c.stopCh)
		}
	}
	go func() {
		defer close(stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := c.refresh(ctx); err != nil {
					c.logger.Warn("cert refresh failed", "err", err)
				}
				cancel()
			}
		}
	}()
}

// subscribeEvents wires the NATS cert.upsert / cert.delete handlers.
// Returns the first non-nil subscribe error; partial subscriptions are
// cleaned up so the caller can fall through to poll-only.
func (c *Client) subscribeEvents() error {
	up, err := c.bus.Subscribe(certevents.SubjectUpsertPrefix+">", c.onUpsert)
	if err != nil {
		return fmt.Errorf("subscribe upsert: %w", err)
	}
	del, err := c.bus.Subscribe(certevents.SubjectDeletePrefix+">", c.onDelete)
	if err != nil {
		_ = up.Drain()
		return fmt.Errorf("subscribe delete: %w", err)
	}
	c.upsert = up
	c.delete = del
	return nil
}

// onUpsert handles a single calabi.cert.upsert.<org> message: refetch
// the named cert + merge into the pool atomically. We pull a fresh
// pool snapshot, mutate the copy, store the swap — readers never
// a torn map.
//
// Errors during refetch are warned, not retried. The 5-minute poll
// will reconcile if NATS dropped the event or the GetCert hiccupped.
func (c *Client) onUpsert(m *eventbus.Msg) {
	var ev certevents.CertEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		c.logger.Warn("cert upsert: bad payload", "err", err, "subject", m.Subject)
		return
	}
	if ev.CertID <= 0 {
		return
	}
	// Short-circuit: if our pool already has a cert with this exact
	// fingerprint installed, the event is a redelivery — skip GetCert.
	if ev.Fingerprint != "" {
		if cur := c.pool.Load(); cur != nil && cur.fingerprints[ev.Fingerprint] {
			c.logger.Debug("cert upsert: fingerprint already in pool, skipping refetch",
				"cert_id", ev.CertID, "fp", ev.Fingerprint)
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := c.rpc.GetCert(ctx, &pb.GetCertRequest{Id: ev.CertID, OrgId: ev.OrgID})
	if err != nil {
		c.logger.Warn("cert upsert: GetCert failed", "err", err, "cert_id", ev.CertID)
		return
	}
	tc, err := tls.X509KeyPair(got.GetFullchainPem(), got.GetPrivateKeyPem())
	if err != nil {
		c.logger.Warn("cert upsert: parse pair", "err", err, "cert_id", ev.CertID)
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	prev := c.pool.Load()
	next := clonePool(prev)
	// Drop any old SAN/Subject keys this cert previously occupied so a
	// re-issued cert that no longer covers an old domain doesn't leave
	// a stale entry. We approximate by deleting entries pointing at the
	// previous *tls.Certificate with matching cert_id (we don't store
	// cert_id per-entry, so we use SAN list from the event as the
	// authoritative new set and add only those).
	for _, san := range ev.SANs {
		key := strings.ToLower(strings.TrimSpace(san))
		if key == "" {
			continue
		}
		certCopy := tc
		next.bySNI[key] = &certCopy
	}
	if cn := strings.ToLower(strings.TrimSpace(ev.Subject)); cn != "" {
		if _, exists := next.bySNI[cn]; !exists {
			certCopy := tc
			next.bySNI[cn] = &certCopy
		}
	}
	if ev.Fingerprint != "" {
		next.fingerprints[ev.Fingerprint] = true
	}
	c.pool.Store(next)
	c.logger.Info("cert pool updated via push",
		"cert_id", ev.CertID, "sans", ev.SANs)
}

// onDelete drops every pool entry whose SAN matches the event's SAN
// list. We don't have a cert_id → entries reverse map (the pool is
// flat), so we rely on the event's SAN list as the authoritative key
// set to evict.
func (c *Client) onDelete(m *eventbus.Msg) {
	var ev certevents.CertEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		c.logger.Warn("cert delete: bad payload", "err", err, "subject", m.Subject)
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	prev := c.pool.Load()
	next := clonePool(prev)
	for _, san := range ev.SANs {
		delete(next.bySNI, strings.ToLower(strings.TrimSpace(san)))
	}
	if cn := strings.ToLower(strings.TrimSpace(ev.Subject)); cn != "" {
		delete(next.bySNI, cn)
	}
	if ev.Fingerprint != "" {
		delete(next.fingerprints, ev.Fingerprint)
	}
	c.pool.Store(next)
	c.logger.Info("cert pool evicted via push",
		"cert_id", ev.CertID, "sans", ev.SANs)
}

// clonePool returns a deep-enough copy of the pool for safe mutation.
// We copy the maps but not the *tls.Certificate values — they're
// immutable after parsing, so sharing pointers is safe.
func clonePool(p *certPool) *certPool {
	if p == nil {
		return &certPool{
			bySNI:        map[string]*tls.Certificate{},
			fingerprints: map[string]bool{},
		}
	}
	out := &certPool{
		bySNI:        make(map[string]*tls.Certificate, len(p.bySNI)),
		fingerprints: make(map[string]bool, len(p.fingerprints)),
	}
	for k, v := range p.bySNI {
		out.bySNI[k] = v
	}
	for k, v := range p.fingerprints {
		out.fingerprints[k] = v
	}
	return out
}

// Close terminates the polling goroutine + cert-svc conn + NATS subs.
// Idempotent.
func (c *Client) Close() error {
	if c.upsert != nil {
		_ = c.upsert.Drain()
	}
	if c.delete != nil {
		_ = c.delete.Drain()
	}
	if c.stopOnce != nil {
		c.stopOnce()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetCertificate is the closure for tls.Config.GetCertificate.
//
// crypto/tls calls it once per incoming handshake with a populated
// ServerName. We do an O(1) map lookup; nothing fancy.
func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	pool := c.pool.Load()
	if pool == nil {
		return nil, ErrNoCertForSNI
	}
	host := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if cert, ok := pool.bySNI[host]; ok {
		return cert, nil
	}
	// Wildcard fallback: if ClientHello asks for `foo.example.com`,
	// try `*.example.com` too.
	if i := strings.Index(host, "."); i > 0 {
		wild := "*" + host[i:]
		if cert, ok := pool.bySNI[wild]; ok {
			return cert, nil
		}
	}
	return nil, ErrNoCertForSNI
}

// PoolSize is exposed for /metrics or debug pages.
func (c *Client) PoolSize() int {
	p := c.pool.Load()
	if p == nil {
		return 0
	}
	return len(p.bySNI)
}

// refresh pulls the full cert catalog and atomically swaps it in.
// Used at startup and as the periodic reconcile (5min when push is
// wired; 30s in poll-only mode).
//
// The writeMu is held for the duration of the rebuild so a concurrent
// push handler doesn't lay down a snapshot that we then overwrite.
func (c *Client) refresh(ctx context.Context) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	list, err := c.rpc.ListCerts(ctx, &pb.ListCertsRequest{OrgId: c.orgID})
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}
	newPool := &certPool{
		bySNI:        make(map[string]*tls.Certificate, 2*len(list.GetItems())),
		fingerprints: make(map[string]bool, len(list.GetItems())),
	}
	for _, meta := range list.GetItems() {
		got, err := c.rpc.GetCert(ctx, &pb.GetCertRequest{Id: meta.GetMeta().GetId()})
		if err != nil {
			c.logger.Warn("get cert", "err", err, "id", meta.GetMeta().GetId())
			continue
		}
		tc, err := tls.X509KeyPair(got.GetFullchainPem(), got.GetPrivateKeyPem())
		if err != nil {
			c.logger.Warn("parse cert pair", "err", err, "id", meta.GetMeta().GetId())
			continue
		}
		certCopy := tc // local-pointer dance; tc is per-iteration
		for _, san := range meta.GetSans() {
			key := strings.ToLower(strings.TrimSpace(san))
			if key == "" {
				continue
			}
			newPool.bySNI[key] = &certCopy
		}
		// Also key by Subject CN for legacy single-name certs lacking SANs.
		if cn := strings.ToLower(strings.TrimSpace(meta.GetSubject())); cn != "" {
			if _, exists := newPool.bySNI[cn]; !exists {
				newPool.bySNI[cn] = &certCopy
			}
		}
		if fp := strings.TrimSpace(meta.GetFingerprint()); fp != "" {
			newPool.fingerprints[fp] = true
		}
	}
	c.pool.Store(newPool)
	c.logger.Debug("cert pool refreshed", "entries", len(newPool.bySNI))
	return nil
}
