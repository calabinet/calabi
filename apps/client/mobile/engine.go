package mobile

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/meshenroll"
)

// Connection states reported by GET /v1/mesh.
const (
	stateStopped     = "stopped"      // not connected
	stateConnecting  = "connecting"   // asking the control plane / registering
	stateConnected   = "connected"    // registered and watching the netmap
	stateNotEnrolled = "not_enrolled" // signed in, but this org has no meshnet access
	stateSignedOut   = "signed_out"   // the session was refused and could not be renewed
	stateRetrying    = "retrying"     // the last attempt failed; trying again
)

// phoneTiming is how often a phone's session does its periodic work
// (mesh.Timing). Starting values, to be tuned against battery measurements:
//   - no suspend detection: the platform reports network changes instead
//   - no WireGuard keepalive: a phone starts its connections, and the relay
//     keeps it reachable
//   - endpoints re-reported every 5 minutes instead of every minute, and on
//     every network change
//   - relay regions re-measured on network changes only
//   - no service self-checks: a phone declares no services
var phoneTiming = mesh.Timing{
	DiscoProbe:     5 * time.Second,
	EndpointReport: 5 * time.Minute,
	ConnReport:     15 * time.Minute,
}

const (
	minBackoff = time.Second
	maxBackoff = time.Minute
	// notEnrolledRecheck is how often a signed-in phone without meshnet access
	// asks again, so an upgrade or an admin enabling it takes effect.
	notEnrolledRecheck = 2 * time.Minute
	// fastRetryWindow is how long after a network change retries stay at
	// minBackoff instead of doubling. While the network is still coming back
	// every attempt fails at once, and doubling through that gap left the phone
	// waiting seconds on a network that had already returned. Measured on a real
	// phone: Wi-Fi was usable 2-4s after it was switched back on, and Android's
	// "network available" callback, the other way back in, arrived up to 5s
	// after that.
	fastRetryWindow = 30 * time.Second
	// settleAfterConnect is how long a new session ignores network-change
	// callbacks: it was built on the network that is current, and the callback
	// announcing that network routinely lands just after it.
	settleAfterConnect = 3 * time.Second
)

// engine is one connected session: from enrollment to a running datapath. It
// lives from Core.Connect to Core.Disconnect and retries on its own in between.
type engine struct {
	c      *Core
	cancel context.CancelFunc
	done   chan struct{}
	// kick cuts a retry wait short. A network change is when a connection that
	// just failed is most likely to work again, and on a phone the change that
	// broke a session usually ends it before the platform's callback arrives,
	// so there is no session left to tell (see networkChanged). Buffered by one:
	// a burst of changes is one retry.
	kick chan struct{}

	mu       sync.Mutex
	state    string
	lastErr  string
	enr      meshenroll.Enrollment
	settings settings
	dp       *mesh.WGDatapath
	ctrl     *mesh.Controller
	// sessionStarted is when ctrl's session began; lastChange when the platform
	// last reported a network change.
	sessionStarted time.Time
	lastChange     time.Time
}

func startEngine(c *Core) *engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &engine{c: c, cancel: cancel, done: make(chan struct{}), kick: make(chan struct{}, 1), state: stateConnecting}
	go e.run(ctx)
	return e
}

func (e *engine) stop() {
	e.cancel()
	<-e.done
}

// networkChanged repairs a running session and cuts short the wait for the
// next one. Both, because on a phone the network going away usually kills the
// coordinator stream at once: by the time the platform reports the change the
// session is gone and the engine is backing off, and without the kick the
// phone would sit out that backoff (up to a minute) on a network that works.
func (e *engine) networkChanged() {
	e.mu.Lock()
	ctrl := e.ctrl
	settling := time.Since(e.sessionStarted) < settleAfterConnect
	e.lastChange = time.Now()
	e.mu.Unlock()
	if ctrl != nil && !settling {
		ctrl.NetworkChanged()
	}
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *engine) setState(state string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = state
	e.lastErr = ""
	if err != nil {
		e.lastErr = err.Error()
	}
}

// sleep waits d, or returns false when the engine is stopping.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// nextBackoff is the wait after cur: doubled, except within fastRetryWindow of
// a network change, when it stays at minBackoff.
func (e *engine) nextBackoff(cur time.Duration) time.Duration {
	e.mu.Lock()
	recent := !e.lastChange.IsZero() && time.Since(e.lastChange) < fastRetryWindow
	e.mu.Unlock()
	if recent {
		return minBackoff
	}
	return min(cur*2, maxBackoff)
}

// retryWait waits d before a retry. kicked reports that a network change cut it
// short, in which case the caller retries now and starts its backoff over; ok
// is false when the engine is stopping.
func (e *engine) retryWait(ctx context.Context, d time.Duration) (ok, kicked bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-t.C:
		return true, false
	case <-e.kick:
		e.c.logger.Info("network changed; retrying now", "component", "mesh")
		return true, true
	}
}

func (e *engine) run(ctx context.Context) {
	defer close(e.done)
	defer e.setState(stateStopped, nil)
	logger := e.c.logger.With("component", "mesh")

	enr, ok := e.enroll(ctx)
	if !ok {
		return
	}
	priv, err := mesh.LoadOrCreateKey(filepath.Join(e.c.cfg.StateDir, "mesh.key"))
	if err != nil {
		e.setState(stateRetrying, fmt.Errorf("device key: %w", err))
		logger.Error("cannot load or create the device key", "err", err)
		<-ctx.Done()
		return
	}
	st := e.c.loadSettings()

	tunDev := newSwapTUN(mesh.DefaultMTU)
	routing := newVPNRouting(e.c.platform, tunDev, mesh.DefaultMTU)
	// Requests made before the VPN existed (sign-in, the device list) left
	// unprotected keep-alive connections in the pool. Once the VPN routes their
	// destination — an exit device routes everything — their packets enter the
	// tunnel with the Wi-Fi source address and are dropped, and an HTTP/2
	// connection is reused for every later request. Found on a real phone: the
	// device list timed out for as long as an exit device was in use.
	routing.routesChanged = e.c.hc.CloseIdleConnections
	dp, err := mesh.NewWGDatapathOnTUN(tunDev, routing, priv, enr.RelayAddr, logger)
	if err != nil {
		e.setState(stateRetrying, err)
		logger.Error("datapath did not start", "err", err)
		<-ctx.Done()
		return
	}
	defer dp.Close()
	e.mu.Lock()
	e.enr, e.settings, e.dp = enr, st, dp
	e.mu.Unlock()

	var gate meshenroll.RefreshGate
	backoff := minBackoff
	for ctx.Err() == nil {
		e.setState(stateConnecting, nil)
		// A change from before this attempt is already reflected in it.
		select {
		case <-e.kick:
		default:
		}
		started := time.Now()
		err := e.session(ctx, enr, priv, st, dp)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = minBackoff
		}
		if gate.AfterDenial(ctx, err, e.c.refreshBearer) {
			backoff = minBackoff
		} else if isDenied(err) {
			e.setState(stateSignedOut, err)
		} else {
			e.setState(stateRetrying, err)
		}
		logger.Warn("mesh session ended; reconnecting", "backoff", backoff.String(), "err", err)
		ok, kicked := e.retryWait(ctx, backoff)
		switch {
		case !ok:
			return
		case kicked:
			backoff = minBackoff
		default:
			backoff = e.nextBackoff(backoff)
		}
	}
}

// enroll asks the control plane where this phone's meshnet is, until it gets an
// answer that says to run or the engine stops.
func (e *engine) enroll(ctx context.Context) (meshenroll.Enrollment, bool) {
	backoff := minBackoff
	for {
		tok := e.c.bearer()
		enr, err := meshenroll.Fetch(ctx, e.c.hc, e.c.cfg.BFFURL, tok)
		if err != nil && tok != "" && ctx.Err() == nil {
			// The only renewable failure is an expired token; RefreshSession
			// backs off on its own when the session itself is dead.
			if fresh := e.c.refresh(ctx, tok); fresh != "" {
				enr, err = meshenroll.Fetch(ctx, e.c.hc, e.c.cfg.BFFURL, fresh)
			}
		}
		switch {
		case ctx.Err() != nil:
			return meshenroll.Enrollment{}, false
		case err != nil:
			if e.c.bearer() == "" {
				e.setState(stateSignedOut, err)
			} else {
				e.setState(stateRetrying, err)
			}
			ok, kicked := e.retryWait(ctx, backoff)
			switch {
			case !ok:
				return meshenroll.Enrollment{}, false
			case kicked:
				backoff = minBackoff
			default:
				backoff = e.nextBackoff(backoff)
			}
		case !enr.WantsRun():
			e.setState(stateNotEnrolled, nil)
			if ok, _ := e.retryWait(ctx, notEnrolledRecheck); !ok {
				return meshenroll.Enrollment{}, false
			}
		default:
			return enr, true
		}
	}
}

// session is one coordinator connection: register, then apply netmaps until
// the stream ends.
func (e *engine) session(ctx context.Context, enr meshenroll.Enrollment, priv mesh.PrivateKey, st settings, dp *mesh.WGDatapath) error {
	conn, err := meshenroll.DialCoord(enr.CoordAddr, e.c.cfg.CoordPlaintext)
	if err != nil {
		return fmt.Errorf("coordinator dial: %w", err)
	}
	defer conn.Close()
	timing := phoneTiming
	ctrl := &mesh.Controller{
		Coord:    mesh.NewCoordClient(conn),
		Datapath: dp,
		Params: mesh.RegisterParams{
			AuthKey:     e.c.bearer(),
			NodeKey:     priv.Public(),
			NodePrivate: priv,
			Name:        st.DeviceName,
		},
		ExitNode: st.ExitNode,
		Routes:   mesh.RoutePolicy{Accept: st.AcceptRoutes},
		Timing:   &timing,
		Logger:   e.c.logger.With("component", "mesh"),
	}
	if st.ExitNode != "" {
		dp.SetExitBypassHosts([]string{enr.CoordAddr, enr.RelayAddr})
	}
	e.mu.Lock()
	e.ctrl, e.sessionStarted = ctrl, time.Now()
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		if e.ctrl == ctrl {
			e.ctrl = nil
		}
		e.mu.Unlock()
	}()
	// Connected once the first netmap has been applied; Run blocks until the
	// stream ends, so watch for the overlay from the side.
	go func() {
		for ctx.Err() == nil {
			if overlay := dp.Snapshot().Overlay; overlay != "" {
				e.c.rememberSelf(enr.OrgID, overlay)
				e.mu.Lock()
				if e.ctrl == ctrl && e.state == stateConnecting {
					e.state, e.lastErr = stateConnected, ""
				}
				e.mu.Unlock()
				return
			}
			if !sleep(ctx, 200*time.Millisecond) {
				return
			}
			e.mu.Lock()
			gone := e.ctrl != ctrl
			e.mu.Unlock()
			if gone {
				return
			}
		}
	}()
	return ctrl.Run(ctx)
}

// refreshBearer is the RefreshGate's renew function: a fresh access token for
// the one the coordinator refused.
func (c *Core) refreshBearer(ctx context.Context) string {
	return c.refresh(ctx, c.bearer())
}

// isDenied reports whether the coordinator refused the credential.
func isDenied(err error) bool {
	return status.Code(err) == codes.Unauthenticated
}

// meshStatus is GET /v1/mesh: this phone's connection and what it can reach.
type meshStatus struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Name is the name this phone joined with; Overlay its mesh address while
	// connected. SelfOverlay is its address in this organization's meshnet
	// whether or not it is connected — the org's device list includes the
	// phone, and this is how the app leaves it out.
	Name        string `json:"name,omitempty"`
	Overlay     string `json:"overlay,omitempty"`
	SelfOverlay string `json:"self_overlay,omitempty"`
	// Relay is the relay this phone is homed at; DerpHome its region code.
	Relay    string `json:"relay,omitempty"`
	DerpHome string `json:"derp_home,omitempty"`
	// ExitNode is the chosen exit device ("" = none). Direct paths stay on while
	// one is in use: the core's sockets are protected from the VPN.
	ExitNode     string     `json:"exit_node,omitempty"`
	AcceptRoutes bool       `json:"accept_routes"`
	Peers        []meshPeer `json:"peers"`
}

// meshPeer is one device this phone can reach, as the live datapath sees it.
// Field names follow the desktop client's /v1/mesh peers.
type meshPeer struct {
	PublicKey        string            `json:"public_key"`
	Name             string            `json:"name,omitempty"`
	OS               string            `json:"os,omitempty"`
	AllowedIPs       []string          `json:"allowed_ips"`
	LastHandshakeSec int64             `json:"last_handshake_sec"`
	RxBytes          int64             `json:"rx_bytes"`
	TxBytes          int64             `json:"tx_bytes"`
	Path             string            `json:"path"`
	Endpoint         string            `json:"endpoint,omitempty"`
	RTTMicros        int64             `json:"rtt_micros,omitempty"`
	RelayRTTMicros   int64             `json:"relay_rtt_micros,omitempty"`
	Services         []meshPeerService `json:"services,omitempty"`
}

type meshPeerService struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Port  uint32 `json:"port"`
}

func (e *engine) status() meshStatus {
	e.mu.Lock()
	st := meshStatus{
		State: e.state, Error: e.lastErr,
		Name: e.settings.DeviceName, ExitNode: e.settings.ExitNode, AcceptRoutes: e.settings.AcceptRoutes,
		Relay: e.enr.RelayAddr, Peers: []meshPeer{},
	}
	dp, ctrl := e.dp, e.ctrl
	e.mu.Unlock()
	if dp == nil {
		return st
	}
	snap := dp.Snapshot()
	st.Overlay = snap.Overlay
	if snap.Relay != "" {
		st.Relay = snap.Relay
	}
	var facts map[string]mesh.PeerFacts
	if ctrl != nil {
		st.DerpHome = ctrl.HomeRegion()
		facts = ctrl.PeerFactsByKey()
	}
	for _, p := range snap.Peers {
		f := facts[p.PublicKey]
		mp := meshPeer{
			PublicKey: p.PublicKey, Name: f.Name, OS: f.OS, AllowedIPs: p.AllowedIPs,
			LastHandshakeSec: p.LastHandshakeSec, RxBytes: p.RxBytes, TxBytes: p.TxBytes,
			Path: p.Path, Endpoint: p.Endpoint, RTTMicros: p.RTTMicros, RelayRTTMicros: p.RelayRTTMicros,
		}
		if mp.AllowedIPs == nil {
			mp.AllowedIPs = []string{}
		}
		for _, sv := range f.Services {
			mp.Services = append(mp.Services, meshPeerService{Name: sv.Name, Proto: sv.Proto, Port: uint32(sv.Port)})
		}
		st.Peers = append(st.Peers, mp)
	}
	return st
}
