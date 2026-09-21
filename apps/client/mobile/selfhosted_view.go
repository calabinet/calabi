package mobile

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
)

// What a self-hosted server lists — its devices, the tunnels its daemons serve,
// its traffic — read for the app.
// Connected, the phone reads over its live session. Not connected, it proves
// its node key for a read-only view session (OpenViewSession), which neither
// connects it nor ends a session it holds: the app shows the server either way.

// liveCoord is the engine's session client while it is connected, else nil.
func (c *Core) liveCoord() *mesh.CoordClient {
	e := c.currentEngine()
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctrl != nil && e.ctrl.Coord != nil && e.state == stateConnected {
		return e.ctrl.Coord
	}
	return nil
}

// viewNode is who this phone is on its self-hosted server, for a view session.
func (c *Core) viewNode() (selfhosted.Node, error) {
	p := c.selfHosted()
	if p == nil {
		return selfhosted.Node{}, errors.New("not joined to a self-hosted server")
	}
	priv, err := mesh.LoadOrCreateKey(filepath.Join(c.cfg.StateDir, "mesh.key"))
	if err != nil {
		return selfhosted.Node{}, err
	}
	return selfhosted.Node{Server: p.Server, Trust: p.Trust, NodeID: p.NodeID, Reauth: p.Reauth, Key: priv}, nil
}

// readSelfHosted runs read over the live session, or a view session when the
// phone is not connected.
func (c *Core) readSelfHosted(ctx context.Context, read func(*mesh.CoordClient) error) error {
	return c.viewer.Read(ctx, c.liveCoord(), c.viewNode, read)
}

// dropView forgets the view session: the phone left or changed servers, or
// its trust in the server changed.
func (c *Core) dropView() { c.viewer.Drop() }

// readError answers a read that failed.
//
// EVERY code gets a sentence here. The switch used to fall through to
// err.Error() for anything it did not name, and the one it did not name —
// "unreachable", the coordinator not answering at all — is the failure a
// self-hoster hits most: their server is off, or their phone is on mobile data
// rather than the LAN it lives on. The app printed the gRPC dialer's own words
// at them, three tabs at a time:
//
//	rpc error: code = Unavailable desc = connection error: desc = "transport:
//	Error while dialing: dial tcp 192.168.1.5:7012: connect: network is unreachable"
//
// The raw error still reaches the diagnostic log, which is where it is useful.
func (c *Core) readError(w http.ResponseWriter, err error) {
	st, code := selfhosted.ReadFailure(err)
	msg := ""
	switch code {
	case "not_connected":
		msg = "connect to see this"
	case "needs_invite":
		msg = "the server no longer knows this phone"
	case "disabled":
		msg = "this phone is disabled on the server"
	case "unreachable":
		msg = "cannot reach the server"
	}
	if msg == "" {
		// A code with no sentence is this function's own bug, not the user's.
		// Say something true rather than nothing, and log what it really was.
		msg = "cannot read from the server"
	}
	c.logger.Warn("self-hosted read failed", "code", code, "err", err)
	joinError(w, st, code, msg, nil)
}

// handleSelfHostedTunnels is GET /v1/tunnels on a self-hosted server: what its
// daemons reported, in the shape the platform's list has, so the app's tunnel
// screens need no second parser.
func (c *Core) handleSelfHostedTunnels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var list []mesh.TunnelInfo
	if err := c.readSelfHosted(ctx, func(cc *mesh.CoordClient) (err error) {
		list, err = cc.ListTunnels(ctx)
		return err
	}); err != nil {
		c.readError(w, err)
		return
	}
	items := make([]map[string]any, 0, len(list))
	for _, t := range list {
		// A device that is not connected may no longer serve what it reported.
		st := t.Status
		if !t.NodeOnline {
			st = "offline"
		}
		item := map[string]any{
			"id": t.ID, "name": t.Name, "type": t.Type, "local_addr": t.LocalAddr,
			"status": st, "self_hosted": true, "device_name": t.NodeName,
			"client_id": t.NodeID, "client_online": t.NodeOnline,
			"traffic_30d": t.Traffic30d, "created_at": t.FirstSeen.UTC().Format(time.RFC3339),
		}
		if t.PublicAddr != "" {
			// Served by the user's own edge; the app's list reads a non-zero
			// edge id as "has an address".
			item["edge_node_id"], item["edge_owned"] = 1, true
			switch t.Type {
			case "tcp", "udp":
				if host, port, err := net.SplitHostPort(t.PublicAddr); err == nil {
					p, _ := strconv.Atoi(port)
					item["edge_host"], item["remote_port"] = host, p
				}
			default:
				item["domain"] = strings.TrimSuffix(t.PublicAddr, ".")
			}
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleSelfHostedUsage is GET /v1/usage/overview?tz= on a self-hosted server,
// in the shape the platform's overview has. No limits: a self-hosted server
// has none, and its month is the viewer's, not a billing one.
func (c *Core) handleSelfHostedUsage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var u mesh.Usage
	if err := c.readSelfHosted(ctx, func(cc *mesh.CoordClient) (err error) {
		u, err = cc.GetUsage(ctx, r.URL.Query().Get("tz"), 7)
		return err
	}); err != nil {
		c.readError(w, err)
		return
	}
	out := map[string]any{
		"plan": "self_hosted",
		"devices": map[string]any{
			"used": u.DevicesUsed, "disabled": u.DevicesDisabled, "limit": u.DevicesLimit, "own": false,
		},
	}
	if u.Unavailable != "" {
		out["unavailable"] = u.Unavailable
	}
	if u.RelayNotRecorded {
		out["relay_not_recorded"] = true
	}
	if m := u.Month; m != nil {
		out["month"] = map[string]any{
			"used_bytes": m.TunnelBytes + m.RelayBytes, "limit_bytes": -1,
			"tunnel_bytes": m.TunnelBytes, "relay_bytes": m.RelayBytes,
			"from": m.From.UTC().Format(time.RFC3339), "to": m.To.UTC().Format(time.RFC3339),
		}
	}
	days := make([]map[string]any, 0, len(u.Days))
	for _, d := range u.Days {
		days = append(days, map[string]any{"start": d.Start.UTC().Format(time.RFC3339), "bytes": d.Bytes})
	}
	out["days"] = days
	writeJSON(w, http.StatusOK, out)
}
