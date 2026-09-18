// Package meshenroll is how a platform client finds and joins its org's
// meshnet: ask bff-console whether this device is enrolled and where the
// coordinator is, dial the coordinator, and decide when a refused credential is
// worth renewing.
//
// It is shared by the desktop daemon (cmd/calabi) and the phone core. What to DO with an enrollment —
// which session to run, when an org switch or a changed setting restarts it —
// depends on where a client keeps its settings and stays with each client.
//
// The node's coordinator auth key is the client's own data-plane credential (a
// tk_ API key or a login token): calabi-coord resolves it through identity-svc to
// the owning org, which IS the meshnet. No separate key is minted.
package meshenroll

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
	"github.com/calabi/calabi/apps/client/internal/transport"
)

// Enrollment is the control plane's answer to GET /v1/mesh/enrollment. When
// Enabled is false (org not entitled, or the platform hasn't wired a
// coordinator) the device stays off the mesh entirely.
type Enrollment struct {
	Enabled   bool   `json:"enabled"`
	CoordAddr string `json:"coord_addr"`
	RelayAddr string `json:"relay_addr"`
	NodeName  string `json:"node_name"` // optional; the client falls back to its own name
	// OrgID is the meshnet this enrollment is for (meshnet == org). It is the
	// ONLY field that changes when the user switches org: coord/relay are
	// platform-wide and NodeName is the device's. 0 from a bff that predates it.
	OrgID int64 `json:"org_id"`
}

// WantsRun reports whether this enrollment should bring the datapath up.
func (e Enrollment) WantsRun() bool {
	return e.Enabled && e.CoordAddr != "" && e.RelayAddr != ""
}

// Fetch calls GET <bffURL>/v1/mesh/enrollment with token as the bearer. An empty
// token (not signed in yet) or a non-200 answer is an error, so a caller polling
// on a timer keeps its current state instead of tearing a live meshnet down.
func Fetch(ctx context.Context, hc *http.Client, bffURL, token string) (Enrollment, error) {
	bffURL = strings.TrimRight(bffURL, "/")
	if bffURL == "" {
		return Enrollment{}, errors.New("no bff-console URL")
	}
	if token == "" {
		return Enrollment{}, errors.New("no credential yet")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bffURL+"/v1/mesh/enrollment", nil)
	if err != nil {
		return Enrollment{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return Enrollment{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return Enrollment{}, fmt.Errorf("enrollment: %s", resp.Status)
	}
	var enr Enrollment
	if err := json.Unmarshal(body, &enr); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment: %w", err)
	}
	return enr, nil
}

// coordKeepalive makes a dead control-plane connection FAIL rather than hang.
//
// Without it the netmap stream can sit on a half-open TCP indefinitely: the
// client believes it is watching a stream that will never deliver another
// netmap, and its runner never gets the error it needs to reconnect. That is
// exactly the state a machine wakes up from standby in — the far side dropped
// the connection while this one was asleep and there is nobody left to send a
// RST. 30s + 10s puts a ceiling of about 40s on how long that can last.
//
// PermitWithoutStream keeps the connection proven between netmaps too. NOTE: this
// pings more often than a stock gRPC server's default enforcement policy allows
// (MinTime 5m), so calabi-coord sets a matching EnforcementPolicy — DEPLOY COORD-SVC
// FIRST. Against an un-upgraded coordinator these pings are tolerated only
// because the server resets its ping-strike counter whenever it sends data, and
// coord pushes netmaps regularly; a quiet stretch would earn a GOAWAY.
var coordKeepalive = grpc.WithKeepaliveParams(keepalive.ClientParameters{
	Time:                30 * time.Second,
	Timeout:             10 * time.Second,
	PermitWithoutStream: true,
})

// DialCoord opens the gRPC connection to the mesh coordinator.
//
// Coord's public gRPC is the one internal control-plane surface a client dials
// directly over the public internet, and the client sends its auth key over it,
// so it is dialed over TLS — verified against the embedded platform edge CA (the
// SAME root the edge :7443 control transport trusts). coord presents an
// edge-CA-signed server cert, so no extra trust root has to be shipped. The TLS
// ServerName is the host in addr, which must match the cert SAN (e.g.
// coord.calabi.net).
//
// plaintext dials without TLS, for dev / smoke stacks whose coord serves none.
// The desktop daemon sets it from CALABI_INSECURE=1, the same escape hatch the
// edge control transport honors.
//
// When a hostnet socket hook is installed (a phone: the connection carries the
// tunnel's control plane and must stay out of the tunnel), the connection is
// opened through hostnet. Otherwise gRPC dials on its own, as it always has —
// including honoring an HTTPS_PROXY, which a custom dialer would switch off.
func DialCoord(addr string, plaintext bool) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{coordKeepalive}
	if hostnet.HasSocketHook() {
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
			return hostnet.Dialer().DialContext(ctx, "tcp", target)
		}))
	}
	if plaintext {
		return grpc.NewClient(addr, append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	}
	pool, err := transport.EdgeRootCAs()
	if err != nil {
		return nil, fmt.Errorf("coord TLS trust root: %w (set CALABI_INSECURE=1 for a plaintext dev coordinator)", err)
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr // addr may already be a bare host
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	return grpc.NewClient(addr, append(opts, grpc.WithTransportCredentials(creds))...)
}

const (
	// RefreshCooldown bounds how often a refused registration may spend a token
	// refresh. From the client a refusal also looks like an expired SESSION, a
	// revoked key, or a coordinator that cannot reach identity-svc, and no refresh
	// fixes any of those; a retry loop runs every 30s at worst, so without a
	// cooldown a dead session would cost a refresh round trip every 30s forever.
	RefreshCooldown = time.Minute
	// RefreshTimeout caps one refresh, so a control plane that is slow to answer
	// holds the retry loop up by seconds rather than by an HTTP client's 30s.
	RefreshTimeout = 10 * time.Second
)

// RefreshGate is the mesh's half of keeping a login session usable: after the
// coordinator refuses a registration, it decides whether renewing the credential
// is worth a try, and tries. The zero value is ready; it is not safe for
// concurrent use (one retry loop owns it).
//
// Why the mesh has to do this itself: an access token lives 15 minutes, and the
// other things that refresh one run only when THEY need to — the edge session
// on a reconnect, the console on a proxied call. A device whose edge session
// stays up and whose console nobody opens refreshes nothing, so the first time
// the mesh has to re-register after the token expired (any coordinator blip will
// do), it is refused — and every retry then sends the same expired token again.
// The symptom is `mesh: register: ... auth key denied` every 30s, forever.
type RefreshGate struct {
	last time.Time
}

// AfterDenial reports whether it came back with a new credential, so the retry
// loop can retry at once instead of waiting out its backoff. refresh returns the
// renewed credential, or "" when there is nothing to renew (nil = never renew).
//
// Unauthenticated is the only code worth acting on: it is what coord answers for
// a credential it will not accept, from GetRegisterChallenge and RegisterNode
// alike. Anything else is a network or server problem a new token does not change.
func (g *RefreshGate) AfterDenial(ctx context.Context, err error, refresh func(context.Context) string) bool {
	if refresh == nil || status.Code(err) != codes.Unauthenticated {
		return false
	}
	if !g.last.IsZero() && time.Since(g.last) < RefreshCooldown {
		return false
	}
	g.last = time.Now()
	rctx, cancel := context.WithTimeout(ctx, RefreshTimeout)
	defer cancel()
	return refresh(rctx) != ""
}
