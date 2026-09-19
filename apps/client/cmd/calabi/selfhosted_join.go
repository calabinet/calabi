package main

// Connecting a desktop to a self-hosted server from the :7400 console or `calabi join`: joining its
// coordinator is signing in — the coordinator then names the edge for tunnels
// and signs this device's way in.
// The key is checked by enrolling, before anything is saved, and the
// coordinator's certificate is one the system trusts, one whose fingerprint
// came with the invite, or one a person confirmed.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/selfhosted"
	"github.com/calabi/calabi/apps/client/internal/trust"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// joinRequest is POST /v1/selfhosted/join.
type joinRequest struct {
	Mesh *joinMesh `json:"mesh"`
	// Replace: connect even though this device already joined a server.
	Replace bool `json:"replace"`
}

// joinMesh is the coordinator to join: a calabi://join link, or server + key
// (+ pin, or plaintext). A pin given with a link that carries none is the one a
// person confirmed. Name: this device's name there (default: the host name).
type joinMesh struct {
	Link      string `json:"link"`
	Server    string `json:"server"`
	Key       string `json:"key"`
	Pin       string `json:"pin"`
	Plaintext bool   `json:"plaintext"`
	Name      string `json:"name,omitempty"`
}

// joinFailure is a join the console explains: codes bad_input, bad_link,
// joined (this device already joined a server; send replace), untrusted (the
// certificate needs confirming: its pin is in the answer), pin_mismatch, no_tls,
// key_refused, disabled, full, unreachable. part is "mesh".
type joinFailure struct {
	status int
	body   map[string]any
}

func joinFail(status int, part, code, msg string, extra map[string]any) *joinFailure {
	body := map[string]any{"error": msg, "code": code}
	if part != "" {
		body["part"] = part
	}
	for k, v := range extra {
		body[k] = v
	}
	return &joinFailure{status: status, body: body}
}

// joinSelfHosted joins the coordinator in in and returns cur with it applied.
// Nothing is written.
//
// In two steps, so nothing is spent on a join that stops halfway: first the
// coordinator's certificate is settled (a person may have to confirm it), then
// the enrollment, which spends a one-time invite.
func joinSelfHosted(ctx context.Context, cur localConfig, in joinRequest) (localConfig, *joinFailure) {
	if in.Mesh == nil {
		return cur, joinFail(http.StatusBadRequest, "", "bad_input", "nothing to join: give the server's invite", nil)
	}
	mj, fail := prepareMesh(ctx, cur.Mesh, in)
	if fail != nil {
		return cur, fail
	}
	m, fail := mj.enroll(ctx, cur.Mesh)
	if fail != nil {
		return cur, fail
	}
	next := cur
	next.Mesh = m
	return next, nil
}

// serverTrust settles how a server's certificate is checked before any secret
// goes to it: the invite's pin, the system's roots, or — neither — an answer
// asking a person to compare the fingerprint.
func serverTrust(ctx context.Context, part, server, pin string, alpn []string) (trust.Config, *joinFailure) {
	pr, err := selfhosted.ProbeServer(ctx, server, alpn)
	switch {
	case err != nil:
		return trust.Config{}, joinFail(http.StatusBadGateway, part, "unreachable", err.Error(), nil)
	case !pr.TLS:
		return trust.Config{}, joinFail(http.StatusConflict, part, "no_tls", "the server does not use TLS", nil)
	case pin != "":
		t := trust.Config{Mode: trust.Pin, Pins: []string{pin}}
		// The probe compares the leaf only; a pin may also name a CA in the chain.
		if pr.Pin != pin && !selfhosted.PinnedInChain(ctx, server, t, alpn) {
			return trust.Config{}, joinFail(http.StatusConflict, part, "pin_mismatch", "the server's certificate does not match the fingerprint",
				map[string]any{"pin": pr.Pin, "subject": pr.Subject})
		}
		return t, nil
	case pr.SystemTrusted:
		return trust.Config{Mode: trust.System}, nil
	}
	return trust.Config{}, joinFail(http.StatusConflict, part, "untrusted", "the server's certificate is not one this device trusts",
		map[string]any{"pin": pr.Pin, "subject": pr.Subject, "issuer": pr.Issuer, "not_after": pr.NotAfter})
}

func parsePin(part, s string) (string, *joinFailure) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	pin, err := meshproto.ParseCertPin(s)
	if err != nil {
		return "", joinFail(http.StatusBadRequest, part, "bad_input", err.Error(), nil)
	}
	return pin, nil
}

// meshJoin is a coordinator whose address, key and certificate are settled.
type meshJoin struct {
	inv   selfhosted.Invite
	trust trust.Config
	name  string
}

func prepareMesh(ctx context.Context, cur meshConfig, in joinRequest) (*meshJoin, *joinFailure) {
	inv := selfhosted.Invite{
		Server: strings.TrimSpace(in.Mesh.Server), Key: strings.TrimSpace(in.Mesh.Key),
		Pin: strings.TrimSpace(in.Mesh.Pin), Plaintext: in.Mesh.Plaintext,
	}
	if in.Mesh.Link != "" {
		var err error
		if inv, err = selfhosted.ParseInvite(in.Mesh.Link); err != nil {
			return nil, joinFail(http.StatusBadRequest, "mesh", "bad_link", err.Error(), nil)
		}
		if inv.Pin == "" {
			inv.Pin = strings.TrimSpace(in.Mesh.Pin)
		}
	}
	if _, _, err := net.SplitHostPort(inv.Server); err != nil || inv.Key == "" {
		return nil, joinFail(http.StatusBadRequest, "mesh", "bad_input", "the coordinator's address (host:port) and a key are required", nil)
	}
	pin, fail := parsePin("mesh", inv.Pin)
	if fail != nil {
		return nil, fail
	}
	if cur.Coord != "" && !in.Replace {
		return nil, joinFail(http.StatusConflict, "mesh", "joined", "this device is already on "+cur.Coord, map[string]any{"server": cur.Coord})
	}
	t := trust.Config{Mode: trust.Plaintext}
	if !inv.Plaintext {
		if t, fail = serverTrust(ctx, "mesh", inv.Server, pin, selfhosted.CoordALPN); fail != nil {
			return nil, fail
		}
	}
	return &meshJoin{inv: inv, trust: t, name: strings.TrimSpace(in.Mesh.Name)}, nil
}

// enroll joins the coordinator — the only check of a key that means anything —
// and returns the mesh block to keep.
func (j *meshJoin) enroll(ctx context.Context, cur meshConfig) (meshConfig, *joinFailure) {
	inv, t := j.inv, j.trust
	priv, err := meshNodeKey(cur)
	if err != nil {
		return cur, joinFail(http.StatusInternalServerError, "mesh", "device_key", "device key: "+err.Error(), nil)
	}
	conn, err := dialCoord(inv.Server, t)
	if err != nil {
		return cur, joinFail(http.StatusBadGateway, "mesh", "unreachable", err.Error(), nil)
	}
	defer conn.Close()
	if j.name != "" {
		cur.Name = j.name
	}
	name := cur.Name
	if name == "" {
		name = defaultNodeName()
	}
	reg, err := mesh.NewCoordClient(conn).Register(ctx, mesh.RegisterParams{
		AuthKey: inv.Key, NodeKey: priv.Public(), NodePrivate: priv, Name: name,
	})
	if err != nil {
		switch grpcCode(err) {
		case codes.Unauthenticated:
			return cur, joinFail(http.StatusUnauthorized, "mesh", "key_refused", "the server did not accept this key: it may be used up, expired or revoked", nil)
		case codes.PermissionDenied:
			return cur, joinFail(http.StatusForbidden, "mesh", "disabled", "this device is disabled on that server", nil)
		case codes.ResourceExhausted:
			return cur, joinFail(http.StatusForbidden, "mesh", "full", "that network has no room for another device", nil)
		}
		return cur, joinFail(http.StatusBadGateway, "mesh", "unreachable", err.Error(), nil)
	}
	offered := reg.Capabilities.Supports(meshproto.CapNodeReauth)
	if err := saveMeshReauth(meshReauthRecord{Coord: inv.Server, NodeID: reg.NodeID, Reauth: offered}); err != nil {
		return cur, joinFail(http.StatusInternalServerError, "mesh", "save", "save: "+err.Error(), nil)
	}

	next := meshConfig{Enabled: true, Coord: inv.Server, Name: cur.Name, KeyFile: cur.KeyFile}
	if cur.Coord == inv.Server {
		// The same coordinator again: keep what this machine offers and accepts.
		next = cur
		next.Enabled, next.Relay = true, ""
	}
	next.Trust, next.Pins, next.CAFile = string(t.Mode), t.Pins, ""
	// The key stays only where the coordinator cannot take the device back by
	// proof alone (older than node_reauth), which is the one case it is needed.
	next.AuthKey = ""
	if !offered {
		next.AuthKey = inv.Key
	}
	return next, nil
}

// --- on the platform daemon ------------------------------------------------------

// platformSelfHosted serves /v1/selfhosted on the calabi.net daemon: the way
// from its sign-in page to a self-hosted server.
type platformSelfHosted struct {
	logger    *slog.Logger
	agentMode bool
}

func (h *platformSelfHosted) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/selfhosted", h.handleStatus)
	mux.HandleFunc("POST /v1/selfhosted/join", h.handleJoin)
}

// canJoin: nothing pins this daemon to calabi.net. An api-key service is an
// identity someone installed on purpose; CALABI_MODE in the environment would
// bring the daemon straight back after the switch.
func (h *platformSelfHosted) canJoin() (bool, string) {
	switch {
	case h.agentMode:
		return false, "agent"
	case strings.TrimSpace(os.Getenv("CALABI_MODE")) != "":
		return false, "mode_forced"
	}
	return true, ""
}

func (h *platformSelfHosted) handleStatus(w http.ResponseWriter, _ *http.Request) {
	ok, why := h.canJoin()
	out := map[string]any{"mode": "platform", "can_join": ok}
	if why != "" {
		out["reason"] = why
	}
	shJSON(w, http.StatusOK, out)
}

// handleJoin switches this machine to a self-hosted server: the device joins
// its coordinator, the console's tunnels.yaml is written, the mode saved, and
// the daemon starts again as the local one. Signed in to calabi.net, it answers
// signed_in first — the page signs out, then asks again.
func (h *platformSelfHosted) handleJoin(w http.ResponseWriter, r *http.Request) {
	got := r.Header.Get("X-Local-Token")
	if !creds.CompareLocalToken(got) {
		shError(w, http.StatusUnauthorized, "local_token", "local-token mismatch (fetch /v1/local-token)", nil)
		return
	}
	if ok, why := h.canJoin(); !ok {
		shError(w, http.StatusForbidden, why, "this daemon cannot be switched to a self-hosted server from the console", nil)
		return
	}
	var in joinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		shError(w, http.StatusBadRequest, "bad_input", "parse: "+err.Error(), nil)
		return
	}
	if c, _ := creds.Load(); c != nil && (c.AccessToken != "" || c.RefreshToken != "" || c.APIKey != "") {
		shError(w, http.StatusConflict, "signed_in", "signed in to calabi.net", map[string]any{"email": c.User.Email})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	path := managedConfigPath()
	cur, _, err := loadLocalConfigOrEmpty(path, true)
	if err != nil {
		// A file the console cannot read is not one to merge into; start over.
		h.logger.Warn("the console's tunnels.yaml is unreadable; replacing it", "err", err)
		cur = &localConfig{}
	}
	next, fail := joinSelfHosted(ctx, *cur, in)
	if fail != nil {
		shJSON(w, fail.status, fail.body)
		return
	}
	if err := writeLocalConfig(path, next); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save: "+err.Error(), nil)
		return
	}
	if err := setClientMode(clientModeStandalone); err != nil {
		shError(w, http.StatusInternalServerError, "save", "save the mode: "+err.Error(), nil)
		return
	}
	h.logger.Info("connected to a self-hosted server from the console; starting again as the local daemon",
		"coord", next.Mesh.Coord)
	requestDaemonRestart(300 * time.Millisecond)
	shJSON(w, http.StatusOK, map[string]any{"switching": true})
}
