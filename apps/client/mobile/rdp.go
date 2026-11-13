package mobile

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// Local in-process capabilities only. No Windows credentials cross Core.Call.
var errRDPMeshRecovering = errors.New("mesh_reconnecting")

type rdpTarget struct {
	Key       string `json:"device_key"`
	Name      string `json:"name"`
	Overlay   string `json:"overlay"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type rdpTicket struct {
	engine                         *engine
	context, key, local, peer, pin string
	expires                        time.Time
	port                           int
}

func (c *Core) rdpPeers() (*engine, string, []mesh.Peer, error) {
	e := c.currentEngine()
	if e == nil || c.fileContext() == "" {
		return nil, "", nil, errors.New("connect to the mesh first")
	}
	e.mu.Lock()
	ctrl, dp, state := e.ctrl, e.dp, e.state
	e.mu.Unlock()
	if state != stateConnected || ctrl == nil || dp == nil || !ctrl.Registered() || !ctrl.MembershipReady() {
		if state == stateConnecting || state == stateRetrying || state == stateConnected {
			return nil, "", nil, errRDPMeshRecovering
		}
		return nil, "", nil, errors.New("mesh identity is unavailable")
	}
	local := dp.Snapshot().Overlay
	ip, err := netip.ParseAddr(local)
	if err != nil || !ip.Is4() {
		return nil, "", nil, errors.New("mesh address is unavailable")
	}
	return e, local, ctrl.FileMembers(), nil
}

func rdpReason(p mesh.Peer) string {
	if !p.SameOwner {
		return "same_owner_required"
	}
	if p.OS != "windows" {
		return "windows_required"
	}
	if !p.Overlay.Is4() || p.NodeKey == (meshproto.NodeKey{}) {
		return "identity_unavailable"
	}
	pin, err := hex.DecodeString(p.RDPPin)
	if err != nil || len(pin) != 32 {
		return "certificate_unavailable"
	}
	return ""
}

func (c *Core) resolveRDP(key string) (rdpTicket, error) {
	e, local, peers, err := c.rdpPeers()
	if err != nil {
		return rdpTicket{}, err
	}
	for _, p := range peers {
		if p.NodeKey.String() != key {
			continue
		}
		if reason := rdpReason(p); reason != "" {
			return rdpTicket{}, errors.New(reason)
		}
		return rdpTicket{engine: e, context: c.fileContext(), key: key, local: local, peer: p.Overlay.String(), pin: strings.ToLower(p.RDPPin)}, nil
	}
	return rdpTicket{}, errors.New("device_not_available")
}

func (c *Core) handleRDPTargets(w http.ResponseWriter, r *http.Request) {
	_, _, peers, err := c.rdpPeers()
	items := []rdpTarget{}
	if err == nil {
		for _, p := range peers {
			if p.OS != "windows" {
				continue
			}
			reason := rdpReason(p)
			items = append(items, rdpTarget{p.NodeKey.String(), p.Name, p.Overlay.String(), reason == "", reason})
		}
	}
	writeJSON(w, 200, map[string]any{"available": err == nil, "items": items})
}

func decodeRDP(r *http.Request, out any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 4096))
	d.DisallowUnknownFields() // Windows passwords, arbitrary hosts and trust overrides are forbidden.
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("unexpected request data")
	}
	return nil
}

func (c *Core) handleRDPPrepare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key  string `json:"device_key"`
		Port *int   `json:"port"`
	}
	if err := decodeRDP(r, &in); err != nil {
		writeError(w, 400, "invalid RDP request")
		return
	}
	port := 3389
	if in.Port != nil {
		port = *in.Port
	}
	if port < 1 || port > 65535 {
		writeError(w, 400, "invalid RDP port")
		return
	}
	ticket, err := c.resolveRDP(in.Key)
	if err != nil {
		writeError(w, 403, err.Error())
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeError(w, 500, "could not prepare session")
		return
	}
	token := hex.EncodeToString(b)
	ticket.port = port
	ticket.expires = time.Now().Add(2 * time.Minute)
	c.rdpMu.Lock()
	if c.rdpTickets == nil {
		c.rdpTickets = make(map[string]rdpTicket)
	}
	for k, t := range c.rdpTickets {
		if time.Now().After(t.expires) {
			delete(c.rdpTickets, k)
		}
	}
	if len(c.rdpTickets) >= 8 {
		c.rdpMu.Unlock()
		writeError(w, 409, "close the previous remote session")
		return
	}
	c.rdpTickets[token] = ticket
	c.rdpMu.Unlock()
	writeJSON(w, 200, map[string]any{"token": token, "host": ticket.peer, "local": ticket.local, "port": ticket.port, "certificate_sha256": ticket.pin})
}

func (c *Core) handleRDPVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		Pin   string `json:"certificate_sha256"`
		Port  *int   `json:"port"`
	}
	if err := decodeRDP(r, &in); err != nil {
		writeError(w, 400, "invalid RDP verification")
		return
	}
	c.rdpMu.Lock()
	ticket, exists := c.rdpTickets[in.Token]
	c.rdpMu.Unlock()
	if !exists || time.Now().After(ticket.expires) {
		writeError(w, 403, "session_expired")
		return
	}
	port := 3389
	if in.Port != nil {
		port = *in.Port
	}
	if port != ticket.port {
		writeError(w, 403, "remote_identity_changed")
		return
	}
	// A temporary coordinator reconnect is not a new authority. Retain the ticket
	// for a paused client, but never authorize a socket until the full check passes.
	current, err := c.resolveRDP(ticket.key)
	if errors.Is(err, errRDPMeshRecovering) && c.currentEngine() == ticket.engine && c.fileContext() == ticket.context &&
		subtle.ConstantTimeCompare([]byte(strings.ToLower(in.Pin)), []byte(ticket.pin)) == 1 {
		c.rdpMu.Lock()
		if _, ok := c.rdpTickets[in.Token]; ok {
			ticket.expires = time.Now().Add(30 * time.Second)
			c.rdpTickets[in.Token] = ticket
		}
		c.rdpMu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "mesh_reconnecting", "reason": "mesh_reconnecting"})
		return
	}
	valid := err == nil && current.engine == ticket.engine && current.context == ticket.context &&
		current.local == ticket.local && current.peer == ticket.peer && current.pin == ticket.pin &&
		subtle.ConstantTimeCompare([]byte(strings.ToLower(in.Pin)), []byte(ticket.pin)) == 1
	if !valid {
		writeError(w, 403, "remote_identity_changed")
		return
	}
	c.rdpMu.Lock()
	if _, ok := c.rdpTickets[in.Token]; !ok {
		c.rdpMu.Unlock()
		writeError(w, 403, "session_closed")
		return
	}
	ticket.expires = time.Now().Add(30 * time.Second)
	c.rdpTickets[in.Token] = ticket
	c.rdpMu.Unlock()
	writeJSON(w, 200, map[string]bool{"valid": true})
}

func (c *Core) handleRDPClose(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := decodeRDP(r, &in); err != nil {
		writeError(w, 400, "invalid RDP close request")
		return
	}
	c.rdpMu.Lock()
	delete(c.rdpTickets, in.Token)
	c.rdpMu.Unlock()
	writeJSON(w, 200, map[string]bool{"closed": true})
}
