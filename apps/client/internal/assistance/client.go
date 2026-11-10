package assistance

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const requestTimeout = 18 * time.Second

type frameHandshakeError struct{ error }

func (s *Controller) CallWithFrameRecovery(ctx context.Context, route Route, config *tls.Config, c Command, refresh func(context.Context, bool) error) (Reply, error) {
	reply, err := s.Call(ctx, route, config, c)
	var handshake *frameHandshakeError
	if c.ID == "" || (c.Op != "frame" && c.Op != "frame_delta" && c.Op != "frame_next") || !errors.As(err, &handshake) {
		return reply, err
	}
	// The host rejected TLS before seeing the read. Re-advertise our own
	// identity, then resync the original session through a normal frame read.
	repair, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := refresh(repair, true); err != nil {
		return Reply{}, err
	}
	if c.Op == "frame_next" {
		c.Op = "frame_delta"
	}
	for _, delay := range []time.Duration{150 * time.Millisecond, 350 * time.Millisecond, 700 * time.Millisecond} {
		select {
		case <-repair.Done():
			return Reply{}, err
		case <-time.After(delay):
		}
		if err := refresh(repair, false); err != nil {
			return Reply{}, err
		}
		// Keep the session context for control renewal after a successful read.
		reply, err = s.Call(ctx, route, config, c)
		if !errors.As(err, &handshake) {
			break
		}
	}
	return reply, err
}

// Keep a transport only while the device, local identity and pinned peer identity match.
type Route struct {
	Local, Remote                    netip.Addr
	Port                             uint16
	Scope, Device, LocalPin, PeerPin string
}

func (s *Controller) Call(ctx context.Context, route Route, config *tls.Config, c Command) (Reply, error) {
	if c.Op == "frame_next" {
		if s.client == nil || s.route != route || c.ID == "" || c.Epoch <= 0 {
			s.Suspend()
			return Reply{}, errors.New("target desktop transport unavailable")
		}
		return s.nextFrame(ctx, route, c)
	}
	if s.client == nil || s.route != route || c.Op == "request" {
		s.stop()
		if s.client != nil {
			s.client.CloseIdleConnections()
		}
		dial := net.Dialer{LocalAddr: &net.TCPAddr{IP: route.Local.AsSlice()}, Timeout: 4 * time.Second}
		transport := &http.Transport{DialContext: dial.DialContext, TLSClientConfig: config, IdleConnTimeout: 3 * time.Second}
		s.client = &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		s.route = route
	}
	var result Reply
	var err error
	if c.Op == "request" {
		result, err = s.request(ctx, route, c)
	} else {
		result, err = s.Do(ctx, s.client, route.Remote, route.Port, c)
	}
	if err != nil || c.Op == "end" {
		s.stop()
		s.client.CloseIdleConnections()
		s.client = nil
	}
	return result, err
}

// A fresh sender declaration can reach the peer after our first ClientHello.
// Retry only a server internal_error observed during TLS negotiation: no HTTP
// request has been delivered. Never replay an ambiguous POST or user input.
func (s *Controller) request(ctx context.Context, route Route, c Command) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	delays := [...]time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 2 * time.Second}
	for attempt := 0; ; attempt++ {
		var retry atomic.Bool
		trace := &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			var remote *net.OpError
			retry.Store(errors.As(err, &remote) && remote.Op == "remote error" && remote.Err.Error() == "tls: internal error")
		}}
		result, err := s.Do(httptrace.WithClientTrace(ctx, trace), s.client, route.Remote, route.Port, c)
		if err == nil || !retry.Load() || attempt == len(delays) {
			return result, err
		}
		select {
		case <-ctx.Done():
			return Reply{}, ctx.Err()
		case <-time.After(delays[attempt]):
		}
	}
}

// Controller is owned by the serialized desktop action loop. Its renewal
// requests travel independently of a pending preview or input response.
type Controller struct {
	viewPingSession string
	route           Route
	client          *http.Client
	active          *renewal
	frame           *pendingFrame
}

type renewal struct {
	id         string
	epoch      int
	start      time.Time
	until      atomic.Int64
	frameUntil atomic.Int64
	cancel     context.CancelFunc
	done       chan struct{}
}

// Suspend stops renewal immediately when local device metadata loses authorization.
func (s *Controller) Suspend() { s.stop() }

func (s *Controller) stop() {
	s.discardFrame()
	if s.active != nil {
		s.active.cancel()
		s.active = nil
	}
}

func (s *Controller) Do(ctx context.Context, client *http.Client, remote netip.Addr, port uint16, c Command) (Reply, error) {
	r := s.active
	if r != nil {
		select {
		case <-r.done:
			s.stop()
			r = nil
		default:
		}
	}
	if r != nil {
		if r.id != c.ID || r.epoch != c.Epoch || c.Op == "end" {
			s.stop()
		} else {
			r.until.Store(int64(time.Since(r.start) + requestTimeout))
		}
	}
	if (c.Op == "frame" || c.Op == "frame_delta") && c.ID != "" && s.viewPingSession == c.ID && r == nil {
		heartbeat, stop := context.WithTimeout(ctx, requestTimeout)
		defer stop()
		go keepViewingDuringRead(heartbeat, client, remote, port, c.ID)
	}
	result, err := Exchange(ctx, client, remote, port, c)
	if c.Op == "request" || c.Op == "end" {
		s.viewPingSession = ""
		if c.Op == "request" && err == nil && result.ViewPing {
			s.viewPingSession = result.ID
		}
	}
	if err != nil || result.State != "control" {
		s.stop()
		return result, err
	}
	if s.active == nil || s.active.epoch != result.Epoch {
		s.stop()
		pulseCtx, cancel := context.WithCancel(ctx)
		r = &renewal{id: c.ID, epoch: result.Epoch, start: time.Now(), cancel: cancel, done: make(chan struct{})}
		s.active = r
		r.until.Store(int64(600 * time.Millisecond))
		go r.run(pulseCtx, client, remote, port)
	} else {
		s.active.until.Store(int64(time.Since(s.active.start) + 600*time.Millisecond))
	}
	return result, nil
}

// Only while reading a frame. No epoch, control renewal or input is sent.
func keepViewingDuringRead(ctx context.Context, client *http.Client, remote netip.Addr, port uint16, id string) {
	tick := time.NewTicker(900 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			attempt, cancel := context.WithTimeout(ctx, 650*time.Millisecond)
			r, e := Exchange(attempt, client, remote, port, Command{Op: "view_ping", ID: id})
			cancel()
			if e == nil && r.State != "pending" && r.State != "view" {
				return
			}
		}
	}
}

// A lost acknowledgement must not postpone the next renewal. Limit concurrent
// attempts so a disconnected or throttled peer cannot grow a queue of pulses.
func (r *renewal) run(ctx context.Context, client *http.Client, remote netip.Addr, port uint16) {
	defer close(r.done)
	defer r.cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	slots := make(chan struct{}, 4)
	for time.Since(r.start) < time.Duration(max(r.until.Load(), r.frameUntil.Load())) && ctx.Err() == nil {
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				attempt, stop := context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
				reply, err := Exchange(attempt, client, remote, port, Command{Op: "pulse", ID: r.id, Epoch: r.epoch})
				if err == nil && (reply.State != "control" || reply.Epoch != r.epoch) {
					r.cancel()
				}
			}()
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Exchange uses the supplied authenticated mesh client.
func Exchange(ctx context.Context, client *http.Client, remote netip.Addr, port uint16, c Command) (Reply, error) {
	var result Reply
	var rejected atomic.Bool
	if c.Op == "frame" || c.Op == "frame_delta" {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			var remote *net.OpError
			rejected.Store(errors.As(err, &remote) && remote.Op == "remote error" && remote.Err.Error() == "tls: internal error")
		}})
	}
	body, err := json.Marshal(c)
	if err != nil {
		return result, err
	}
	addr := netip.AddrPortFrom(remote, port).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/assist/v1/session", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if rejected.Load() {
			return result, &frameHandshakeError{err}
		}
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == http.StatusConflict {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
			reason := strings.TrimSpace(string(body))
			switch reason {
			case "viewer_idle_timeout", "consent_timeout", "desktop_session_changed", "helper_pipe_closed", "another assistance request is active", "assistance session ended", "assistance window is closing":
				return result, fmt.Errorf("assistance peer: HTTP 409 (%s: %s)", c.Op, reason)
			}
		}
		return result, fmt.Errorf("assistance peer: HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 3<<20)).Decode(&result)
	return result, err
}
