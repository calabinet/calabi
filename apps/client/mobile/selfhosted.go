package mobile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/platform/meshenroll"
	"github.com/calabi/calabi/apps/client/internal/selfhosted"
	"github.com/calabi/calabi/apps/client/internal/trust"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// A phone joined to a self-hosted coordinator instead of calabi.net. There is no account and no
// control plane: the phone knows the coordinator's address, how to trust it,
// and — only until the coordinator has agreed to take it back by proof of its
// node key — the auth key it joined with.

// profile is the saved connection, selfhosted.json. The auth key is not in it:
// it has its own file, which exists only until the coordinator offers
// node_reauth, so a config shown in a bug report never carries it.
type profile struct {
	Server string       `json:"server"`
	Trust  trust.Config `json:"trust"`
	// NodeID is the node this phone is; Reauth that the coordinator lets it come
	// back by proof alone. Kept so the auth key can be forgotten.
	NodeID int64 `json:"node_id,omitempty"`
	Reauth bool  `json:"reauth,omitempty"`
}

func (c *Core) profilePath() string { return filepath.Join(c.cfg.StateDir, "selfhosted.json") }
func (c *Core) keyPath() string     { return filepath.Join(c.cfg.StateDir, "selfhosted.key") }

// selfHosted returns the saved connection, or nil when the phone is not joined
// to a self-hosted server.
func (c *Core) selfHosted() *profile {
	b, err := os.ReadFile(c.profilePath())
	if err != nil {
		return nil
	}
	var p profile
	if json.Unmarshal(b, &p) != nil || p.Server == "" {
		return nil
	}
	return &p
}

func (c *Core) saveProfile(p *profile) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeFileAtomic(c.profilePath(), b)
}

// authKey is the saved auth key, or "" once it has been forgotten.
func (c *Core) authKey() string {
	b, err := os.ReadFile(c.keyPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// recordReauth is the ReauthState's onChange for a self-hosted engine: keep what
// the coordinator said, and once it lets the phone back by proof alone, forget
// the key — it has done its job, and a key on a phone is one more thing a lost
// phone gives away.
func (c *Core) recordReauth(nodeID int64, offered bool) {
	p := c.selfHosted()
	if p == nil {
		return
	}
	p.NodeID, p.Reauth = nodeID, offered
	if err := c.saveProfile(p); err != nil {
		c.logger.Warn("could not save the self-hosted connection", "err", err)
		return
	}
	if offered {
		if err := os.Remove(c.keyPath()); err == nil {
			c.logger.Info("the coordinator takes this phone back by its own key now; the auth key is forgotten")
		}
	}
}

func (c *Core) forgetSelfHosted() {
	c.dropView()
	_ = os.Remove(c.keyPath())
	_ = os.Remove(c.profilePath())
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Core) handleProbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Server string `json:"server"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&in); err != nil || strings.TrimSpace(in.Server) == "" {
		writeError(w, http.StatusBadRequest, "server required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := selfhosted.ProbeServer(ctx, strings.TrimSpace(in.Server), selfhosted.CoordALPN)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "code": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// joinError is a join that failed in a way the app explains.
func joinError(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	body := map[string]any{"error": msg, "code": code}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

// handleJoin joins a self-hosted server: {"link": "calabi://join?..."}, or
// {"server", "key", "pin"?, "plaintext"?} typed in. The key is checked the only
// way that means anything — by enrolling with it — and only then is anything
// saved. {"replace": true} signs out of whatever the phone is signed in to.
//
// Codes the app tells apart: signed_in / joined (already connected somewhere;
// ask, then send replace), untrusted (the certificate needs confirming: pin is
// in the answer), pin_mismatch, no_tls (the server speaks no TLS and plaintext
// was not asked for), key_refused, disabled, full, unreachable.
func (c *Core) handleJoin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Link      string `json:"link"`
		Server    string `json:"server"`
		Key       string `json:"key"`
		Pin       string `json:"pin"`
		Plaintext bool   `json:"plaintext"`
		Replace   bool   `json:"replace"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	inv := selfhosted.Invite{Server: strings.TrimSpace(in.Server), Key: strings.TrimSpace(in.Key), Pin: strings.TrimSpace(in.Pin), Plaintext: in.Plaintext}
	if in.Link != "" {
		var err error
		if inv, err = selfhosted.ParseInvite(in.Link); err != nil {
			joinError(w, http.StatusBadRequest, "bad_link", err.Error(), nil)
			return
		}
	}
	if _, _, err := net.SplitHostPort(inv.Server); err != nil || inv.Key == "" {
		joinError(w, http.StatusBadRequest, "bad_input", "server (host:port) and key are required", nil)
		return
	}
	if inv.Pin != "" {
		pin, err := meshproto.ParseCertPin(inv.Pin)
		if err != nil {
			joinError(w, http.StatusBadRequest, "bad_input", err.Error(), nil)
			return
		}
		inv.Pin = pin
	}

	// One network at a time.
	if cfg, _ := creds.Load(); cfg != nil && cfg.AccessToken != "" {
		if !in.Replace {
			joinError(w, http.StatusConflict, "signed_in", "signed in to calabi.net", nil)
			return
		}
		c.signOutPlatform(r.Context())
	}
	if old := c.selfHosted(); old != nil {
		if !in.Replace {
			joinError(w, http.StatusConflict, "joined", "already joined to "+old.Server, map[string]any{"server": old.Server})
			return
		}
		c.signOutSelfHosted(r.Context(), old)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	// How to trust the server, settled before the key goes anywhere.
	t := trust.Config{Mode: trust.System}
	switch {
	case inv.Plaintext:
		t = trust.Config{Mode: trust.Plaintext}
	case inv.Pin != "":
		t = trust.Config{Mode: trust.Pin, Pins: []string{inv.Pin}}
	}
	if !inv.Plaintext {
		pr, err := selfhosted.ProbeServer(ctx, inv.Server, selfhosted.CoordALPN)
		switch {
		case err != nil:
			joinError(w, http.StatusBadGateway, "unreachable", err.Error(), nil)
			return
		case !pr.TLS:
			joinError(w, http.StatusConflict, "no_tls", "the server does not use TLS", nil)
			return
		case inv.Pin != "" && pr.Pin != inv.Pin:
			// Only the leaf is compared here; the pin also admits a CA in the
			// chain, and the real handshake below checks that properly.
			if !selfhosted.PinnedInChain(ctx, inv.Server, t, selfhosted.CoordALPN) {
				joinError(w, http.StatusConflict, "pin_mismatch", "the server's certificate does not match the fingerprint",
					map[string]any{"pin": pr.Pin, "subject": pr.Subject})
				return
			}
		case inv.Pin == "" && !pr.SystemTrusted:
			joinError(w, http.StatusConflict, "untrusted", "the server's certificate is not one this phone trusts",
				map[string]any{"pin": pr.Pin, "subject": pr.Subject, "issuer": pr.Issuer, "not_after": pr.NotAfter})
			return
		}
	}

	priv, err := mesh.LoadOrCreateKey(filepath.Join(c.cfg.StateDir, "mesh.key"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "device key: "+err.Error())
		return
	}
	tlsCfg, err := t.TLS(inv.Server)
	if err != nil {
		joinError(w, http.StatusBadRequest, "bad_input", err.Error(), nil)
		return
	}
	conn, err := meshenroll.DialCoord(inv.Server, tlsCfg)
	if err != nil {
		joinError(w, http.StatusBadGateway, "unreachable", err.Error(), nil)
		return
	}
	defer conn.Close()
	reg, err := mesh.NewCoordClient(conn).Register(ctx, mesh.RegisterParams{
		AuthKey: inv.Key, NodeKey: priv.Public(), NodePrivate: priv, Name: c.loadSettings().DeviceName,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			joinError(w, http.StatusUnauthorized, "key_refused", "the server did not accept this key: it may be used up, expired or revoked", nil)
		case codes.PermissionDenied:
			joinError(w, http.StatusForbidden, "disabled", "this device is disabled on that server", nil)
		case codes.ResourceExhausted:
			joinError(w, http.StatusForbidden, "full", "that network has no room for another device", nil)
		default:
			joinError(w, http.StatusBadGateway, "unreachable", err.Error(), nil)
		}
		return
	}

	offered := reg.Capabilities.Supports(meshproto.CapNodeReauth)
	p := &profile{Server: inv.Server, Trust: t, NodeID: reg.NodeID, Reauth: offered}
	if !offered {
		// A coordinator that does not take devices back by proof alone (older
		// than 1.13) needs the key on every reconnect.
		if err := writeFileAtomic(c.keyPath(), []byte(inv.Key)); err != nil {
			writeError(w, http.StatusInternalServerError, "save key: "+err.Error())
			return
		}
	}
	if err := c.saveProfile(p); err != nil {
		_ = os.Remove(c.keyPath())
		writeError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	// An exit device chosen on calabi.net names a device of another network.
	c.clearExitNode()
	c.rememberSelf(serverKey(inv.Server), reg.Overlay.String())
	c.logger.Info("joined a self-hosted server", "server", inv.Server, "node_id", reg.NodeID, "trust", t.Mode, "reauth", offered)
	writeJSON(w, http.StatusOK, map[string]any{"server": inv.Server, "node_id": reg.NodeID, "overlay": reg.Overlay.String()})
}

// handleTrust is POST /v1/selfhosted/trust {"pin"}: the person compared the
// certificate the server presents now with what `calabi-coord fingerprint`
// prints, and it is the server's. The pin has to be the one the server presents
// at this moment — a confirmation covers what was shown and nothing else — and
// it replaces the saved trust.
func (c *Core) handleTrust(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Pin string `json:"pin"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	pin, err := meshproto.ParseCertPin(strings.TrimSpace(in.Pin))
	if err != nil {
		joinError(w, http.StatusBadRequest, "bad_input", err.Error(), nil)
		return
	}
	p := c.selfHosted()
	if p == nil {
		joinError(w, http.StatusConflict, "not_joined", "not joined to a self-hosted server", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pr, err := selfhosted.ProbeServer(ctx, p.Server, selfhosted.CoordALPN)
	switch {
	case err != nil:
		joinError(w, http.StatusBadGateway, "unreachable", err.Error(), nil)
		return
	case !pr.TLS:
		joinError(w, http.StatusConflict, "no_tls", "the server does not use TLS", nil)
		return
	case pr.Pin != pin:
		joinError(w, http.StatusConflict, "pin_mismatch", "the server presents another certificate now", map[string]any{"pin": pr.Pin})
		return
	}
	old := p.Trust
	p.Trust = trust.Config{Mode: trust.Pin, Pins: []string{pin}}
	if err := c.saveProfile(p); err != nil {
		writeError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	c.logger.Warn("the self-hosted server's new certificate was confirmed", "server", p.Server, "was", old.Mode, "pin", pin)
	c.dropView() // dialled with the trust just replaced
	c.reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"server": p.Server, "pin": pin})
}

func (c *Core) clearExitNode() {
	cfg, _ := creds.Load()
	if cfg == nil || cfg.MeshExitNode == "" {
		return
	}
	cfg.MeshExitNode = ""
	if err := creds.Save(cfg); err != nil {
		c.logger.Warn("could not clear the exit device", "err", err)
	}
}

// signOutSelfHosted tells the coordinator this phone signed out — so it will not
// take the phone back by proof alone — and forgets the connection. Best effort:
// being offline must not keep the phone joined.
func (c *Core) signOutSelfHosted(ctx context.Context, p *profile) {
	c.Disconnect()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := c.coordSignOut(ctx, p); err != nil {
		c.logger.Warn("could not tell the server this phone signed out; forgetting it anyway", "err", err)
	}
	c.forgetSelfHosted()
}

// coordSignOut opens a session — by proof alone, or with the saved key — just to
// end it with SignOut.
func (c *Core) coordSignOut(ctx context.Context, p *profile) error {
	priv, err := mesh.LoadOrCreateKey(filepath.Join(c.cfg.StateDir, "mesh.key"))
	if err != nil {
		return err
	}
	tlsCfg, err := p.Trust.TLS(p.Server)
	if err != nil {
		return err
	}
	conn, err := meshenroll.DialCoord(p.Server, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	cc := mesh.NewCoordClient(conn)
	if _, err := cc.Register(ctx, mesh.RegisterParams{
		AuthKey: c.authKey(), NodeKey: priv.Public(), NodePrivate: priv, Name: c.loadSettings().DeviceName,
		NodeID: p.NodeID, Reauth: p.Reauth,
	}); err != nil {
		return err
	}
	return cc.SignOut(ctx)
}

// signOutPlatform is handleLogout's platform half, for a join that replaces the
// calabi.net session.
func (c *Core) signOutPlatform(ctx context.Context) {
	c.Disconnect()
	cfg, _ := creds.Load()
	if cfg == nil {
		return
	}
	if cfg.AccessToken != "" {
		_, _, _ = c.bff(ctx, http.MethodPost, "/v1/auth/logout", nil, cfg.AccessToken)
	}
	cfg.AccessToken, cfg.RefreshToken, cfg.APIKey, cfg.ActiveOrgID = "", "", "", 0
	if err := creds.Save(cfg); err != nil {
		c.logger.Warn("could not forget the calabi.net session", "err", err)
	}
}

// handleSelfHostedNodes is GET /v1/mesh/nodes on a self-hosted server: the
// coordinator's own list, over the live session or a view session
// (selfhosted_view.go). Only a coordinator too old for either answers
// not_connected; the app then says "connect to see your devices".
func (c *Core) handleSelfHostedNodes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var nodes []mesh.NodeInfo
	if err := c.readSelfHosted(ctx, func(cc *mesh.CoordClient) (err error) {
		nodes, err = cc.ListNodes(ctx)
		return err
	}); err != nil {
		readError(w, err)
		return
	}
	type service struct {
		Name  string `json:"name"`
		Proto string `json:"proto"`
		Port  int    `json:"port"`
	}
	type node struct {
		ID             int64     `json:"id"`
		Name           string    `json:"name"`
		OS             string    `json:"os"`
		Overlay        string    `json:"overlay"`
		Online         bool      `json:"online"`
		Disabled       bool      `json:"disabled"`
		Approved       bool      `json:"approved"`
		Services       []service `json:"services"`
		ApprovedRoutes []string  `json:"approved_routes"`
		LastSeen       string    `json:"last_seen,omitempty"`
	}
	out := make([]node, 0, len(nodes))
	for _, n := range nodes {
		v := node{ID: n.ID, Name: n.Name, OS: n.OS, Overlay: n.Overlay, Online: n.Online, Disabled: n.Disabled,
			Approved: n.Approved, Services: []service{}, ApprovedRoutes: n.ApprovedRoutes}
		if v.ApprovedRoutes == nil {
			v.ApprovedRoutes = []string{}
		}
		for _, s := range n.Services {
			v.Services = append(v.Services, service{s.Name, s.Proto, s.Port})
		}
		if !n.LastSeen.IsZero() {
			v.LastSeen = n.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
