package mobile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// routes is the core's local API: what the app's screens read and change.
//
// Paths and JSON follow the desktop client's :7400 API where the two overlap
// (/v1/auth/login, /v1/orgs, /v1/mesh/nodes, ...), so both clients speak one
// dialect to the same control plane. The phone-only parts are /v1/state,
// /v1/settings and the shape of /v1/mesh, which describes this phone's own
// connection.
func (c *Core) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/state", c.handleState)
	mux.HandleFunc("POST /v1/auth/login", c.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", c.handleLogout)
	// A self-hosted server instead of calabi.net (selfhosted.go). While joined
	// to one, the routes below that ask calabi.net either ask the server or
	// answer that there is nothing there.
	mux.HandleFunc("POST /v1/selfhosted/probe", c.handleProbe)
	mux.HandleFunc("POST /v1/selfhosted/join", c.handleJoin)
	mux.HandleFunc("POST /v1/selfhosted/trust", c.handleTrust)
	mux.HandleFunc("GET /v1/me", c.onPlatform(c.proxyTo("/v1/account/me"), jsonBody(`{"role":""}`)))
	mux.HandleFunc("GET /v1/orgs", c.onPlatform(c.proxyTo("/v1/orgs"), jsonBody(`{"items":[]}`)))
	mux.HandleFunc("POST /v1/orgs/switch", c.onPlatform(c.handleOrgSwitch, notOnSelfHosted))
	mux.HandleFunc("GET /v1/mesh/nodes", c.onPlatform(c.proxyTo("/v1/mesh/nodes"), c.handleSelfHostedNodes))
	mux.HandleFunc("GET /v1/mesh", c.handleMesh)
	mux.HandleFunc("GET /v1/mesh/replaceable", c.onPlatform(c.handleReplaceable, jsonBody(`{"items":[]}`)))
	mux.HandleFunc("POST /v1/mesh/replace", c.onPlatform(c.handleReplace, notOnSelfHosted))
	mux.HandleFunc("GET /v1/usage/overview", c.onPlatform(c.handleUsageOverview, c.handleSelfHostedUsage))
	// Tunnels are read-only on a phone. The list rows
	// carry everything the detail screen shows, so there is no single-tunnel
	// route. Each access-log read writes an audit event upstream: the app loads
	// it when asked, never on a timer.
	mux.HandleFunc("GET /v1/tunnels", c.onPlatform(c.proxyTo("/v1/tunnels"), c.handleSelfHostedTunnels))
	mux.HandleFunc("GET /v1/tunnels/{id}/access", c.onPlatform(c.proxyByID("/v1/tunnels/%d/access"), notOnSelfHosted))
	mux.HandleFunc("GET /v1/settings", c.handleGetSettings)
	mux.HandleFunc("PUT /v1/settings", c.handlePutSettings)
	mux.HandleFunc("GET /v1/logs", c.handleLogs)
	return mux
}

// onPlatform routes to platform while signed in to calabi.net and to selfHosted
// while joined to a self-hosted server.
func (c *Core) onPlatform(platform, selfHosted http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.selfHosted() != nil {
			selfHosted(w, r)
			return
		}
		platform(w, r)
	}
}

func jsonBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeRaw(w, http.StatusOK, []byte(body)) }
}

// notOnSelfHosted answers what only calabi.net has.
func notOnSelfHosted(w http.ResponseWriter, _ *http.Request) {
	joinError(w, http.StatusNotFound, "not_on_self_hosted", "not available on a self-hosted server", nil)
}

// state is GET /v1/state: what the app needs to decide which screen to show.
type state struct {
	SignedIn bool `json:"signed_in"`
	// Mode is "platform" or "self_hosted" while signed in, "" otherwise;
	// Server is the self-hosted server's address.
	Mode        string `json:"mode,omitempty"`
	Server      string `json:"server,omitempty"`
	Email       string `json:"email,omitempty"`
	UserID      int64  `json:"user_id,omitempty"`
	ActiveOrgID int64  `json:"active_org_id,omitempty"`
	// Connected is whether the core is trying to be on the meshnet (Connect was
	// called); /v1/mesh says how far it got.
	Connected bool `json:"connected"`
}

func (c *Core) handleState(w http.ResponseWriter, _ *http.Request) {
	cfg, _ := creds.Load()
	st := state{Connected: c.currentEngine() != nil}
	switch p := c.selfHosted(); {
	case p != nil:
		st.SignedIn, st.Mode, st.Server = true, "self_hosted", p.Server
	case cfg != nil && cfg.AccessToken != "":
		st.SignedIn, st.Mode = true, "platform"
		st.Email, st.UserID, st.ActiveOrgID = cfg.User.Email, cfg.User.ID, cfg.ActiveOrgID
	}
	writeJSON(w, http.StatusOK, st)
}

// handleLogin signs in with email + password (+ TOTP) and keeps the session.
// The control plane's answer is passed through as-is on failure, so the app
// can tell a wrong password from "two-step code required".
func (c *Core) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		TotpCode   string `json:"totp_code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	if req.Identifier == "" {
		req.Identifier = req.Email
	}
	if req.Identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "identifier + password required")
		return
	}
	body, _ := json.Marshal(map[string]any{
		"identifier": req.Identifier,
		"password":   req.Password,
		"totp_code":  req.TotpCode,
		// A client opens in the user's personal space, like the desktop client,
		// rather than in whatever team they last used on the web.
		"prefer_personal_org": true,
	})
	status, resp, err := c.bff(r.Context(), http.MethodPost, "/v1/auth/login", body, "")
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	if status != http.StatusOK {
		writeRaw(w, status, resp)
		return
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		UserID       int64  `json:"user_id"`
		Email        string `json:"email"`
		ActiveOrgID  int64  `json:"active_org_id"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "upstream returned no access_token")
		return
	}
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	cfg.AccessToken, cfg.RefreshToken = out.AccessToken, out.RefreshToken
	cfg.User.ID, cfg.User.Email = out.UserID, out.Email
	cfg.ActiveOrgID = out.ActiveOrgID
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save session: "+err.Error())
		return
	}
	c.logger.Info("signed in", "user_id", out.UserID)
	// A session running under the previous identity must not keep going.
	c.reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"user_id": out.UserID, "email": out.Email, "active_org_id": out.ActiveOrgID})
}

// handleLogout leaves the meshnet, revokes the session and forgets it. The
// revoke is best-effort: being offline must not keep the user signed in.
func (c *Core) handleLogout(w http.ResponseWriter, r *http.Request) {
	if p := c.selfHosted(); p != nil {
		// The mesh key stays, as below: joining the same server again is the
		// same device.
		c.signOutSelfHosted(r.Context(), p)
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	c.Disconnect()
	cfg, _ := creds.Load()
	if cfg != nil && cfg.AccessToken != "" {
		_, _, _ = c.bff(r.Context(), http.MethodPost, "/v1/auth/logout", nil, cfg.AccessToken)
	}
	if cfg != nil {
		cfg.AccessToken, cfg.RefreshToken, cfg.APIKey, cfg.ActiveOrgID = "", "", "", 0
		// The exit device belongs to the organization signed out of; the next
		// sign-in may be another account's.
		cfg.MeshExitNode = ""
		// The email stays to pre-fill the next sign-in; the mesh key stays in
		// its own file, so signing back in is the same device, not a new seat.
		if err := creds.Save(cfg); err != nil {
			writeError(w, http.StatusInternalServerError, "save: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleOrgSwitch switches the active org. The meshnet IS the org, so a running
// session restarts onto the new one.
func (c *Core) handleOrgSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetOrgID int64 `json:"target_org_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&req); err != nil || req.TargetOrgID <= 0 {
		writeError(w, http.StatusBadRequest, "target_org_id required")
		return
	}
	body, _ := json.Marshal(req)
	status, resp, err := c.bffAuthed(r.Context(), http.MethodPost, "/v1/orgs/switch", body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	if status != http.StatusOK {
		writeRaw(w, status, resp)
		return
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ActiveOrgID  int64  `json:"active_org_id"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.AccessToken == "" {
		writeError(w, http.StatusBadGateway, "upstream returned no access_token")
		return
	}
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	// The exit device is a device of the organization just left, chosen by
	// name: the new one's device of that name — if it has one — is someone
	// else's machine. Joining a self-hosted server forgets it the same way.
	if req.TargetOrgID != cfg.ActiveOrgID {
		cfg.MeshExitNode = ""
	}
	cfg.AccessToken, cfg.RefreshToken = out.AccessToken, out.RefreshToken
	if out.ActiveOrgID != 0 {
		cfg.ActiveOrgID = out.ActiveOrgID
	}
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save session: "+err.Error())
		return
	}
	c.reconnect()
	writeJSON(w, http.StatusOK, map[string]int64{"active_org_id": cfg.ActiveOrgID})
}

// settings is GET/PUT /v1/settings: this phone's own choices.
type settings struct {
	// DeviceName is the name this phone joins the meshnet with.
	DeviceName string `json:"device_name"`
	// ExitNode is the peer (name or overlay IP) all internet traffic goes
	// through; "" = none.
	ExitNode string `json:"exit_node"`
	// AcceptRoutes installs the subnet routes peers advertise. ON by default on
	// a phone, unlike a desktop.
	AcceptRoutes bool `json:"accept_routes"`
	// BlockIncoming refuses every inbound CONNECTION to this phone, whatever the
	// org's access rules allow; replies to conversations this phone started still
	// come back. It is the one access-control decision that belongs to the person
	// holding the device rather than to an admin — see mesh-console-ux-plan
	//
	// Flat bool here, unlike the desktop's pointer: this API has exactly one
	// caller, the app in the same process, and it is never older than the core.
	// creds keeps the pointer, so a phone that has never touched the switch still
	// reports "unknown" to the console instead of claiming it accepts.
	BlockIncoming bool `json:"block_incoming"`
}

// loadSettings reads the settings, minting and saving the device name the first
// time so the phone keeps one name across restarts.
func (c *Core) loadSettings() settings {
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	s := settings{DeviceName: cfg.MeshNodeName, ExitNode: cfg.MeshExitNode, AcceptRoutes: true}
	if cfg.MeshAcceptRoutes != nil {
		s.AcceptRoutes = *cfg.MeshAcceptRoutes
	}
	if cfg.MeshBlockIncoming != nil {
		s.BlockIncoming = *cfg.MeshBlockIncoming
	}
	if s.DeviceName == "" {
		s.DeviceName = defaultDeviceName(c.cfg.DeviceName)
		cfg.MeshNodeName = s.DeviceName
		if err := creds.Save(cfg); err != nil {
			c.logger.Warn("could not save the device name", "err", err)
		}
	}
	return s
}

// defaultDeviceName is the phone's model as a mesh name, or a random one when
// the model gives nothing usable — never a shared constant, which would make two
// phones answer to one name.
func defaultDeviceName(model string) string {
	if name := meshNameFor(model); name != "phone" {
		return name
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "phone-" + hex.EncodeToString(b[:])
}

func (c *Core) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, c.loadSettings())
}

// handlePutSettings changes any subset of the settings; a field left out keeps
// its value. A running session restarts to apply them.
func (c *Core) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceName    *string `json:"device_name"`
		ExitNode      *string `json:"exit_node"`
		AcceptRoutes  *bool   `json:"accept_routes"`
		BlockIncoming *bool   `json:"block_incoming"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "parse: "+err.Error())
		return
	}
	c.loadSettings() // mint the name first, so saving below does not race it
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	if in.DeviceName != nil {
		if strings.TrimSpace(*in.DeviceName) == "" {
			writeError(w, http.StatusBadRequest, "device_name must not be empty")
			return
		}
		cfg.MeshNodeName = meshNameFor(*in.DeviceName)
	}
	if in.ExitNode != nil {
		cfg.MeshExitNode = strings.TrimSpace(*in.ExitNode)
	}
	if in.AcceptRoutes != nil {
		v := *in.AcceptRoutes
		cfg.MeshAcceptRoutes = &v
	}
	if in.BlockIncoming != nil {
		v := *in.BlockIncoming
		cfg.MeshBlockIncoming = &v
	}
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	c.reconnect()
	writeJSON(w, http.StatusOK, c.loadSettings())
}

func (c *Core) handleMesh(w http.ResponseWriter, _ *http.Request) {
	st := meshStatus{State: stateStopped, Peers: []meshPeer{}}
	if e := c.currentEngine(); e != nil {
		st = e.status()
	}
	st.SelfOverlay = st.Overlay
	if st.SelfOverlay == "" {
		st.SelfOverlay = c.selfOverlay()
	}
	writeJSON(w, http.StatusOK, st)
}

func (c *Core) handleLogs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.logs.write(w)
}

// proxyTo forwards the request to the same-shaped control-plane endpoint with
// the session's credential.
func (c *Core) proxyTo(upstream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := upstream
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 256*1024))
		}
		status, resp, err := c.bffAuthed(r.Context(), r.Method, path, body)
		if err != nil {
			// Same code the self-hosted reads use, so the app has ONE state for
			// "the phone could not reach what it reads from" rather than one per
			// screen. The transport's own words go to the diagnostic log.
			c.logger.Warn("control-plane read failed", "path", upstream, "err", err)
			joinError(w, http.StatusBadGateway, "unreachable", "cannot reach calabi.net", nil)
			return
		}
		writeRaw(w, status, resp)
	}
}

// proxyByID is proxyTo for an upstream path with the request's numeric {id} in
// it. Anything else is refused here rather than spliced into the upstream URL.
func (c *Core) proxyByID(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "invalid id")
			return
		}
		c.proxyTo(fmt.Sprintf(format, id))(w, r)
	}
}

// bffAuthed calls the control plane as the signed-in user, renewing the access
// token once if it was refused. A 401 that survives that reaches the app, which
// shows the sign-in screen.
func (c *Core) bffAuthed(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	cfg, _ := creds.Load()
	tok := ""
	if cfg != nil {
		tok = cfg.AccessToken
	}
	if tok == "" {
		return http.StatusUnauthorized, []byte(`{"error":"not signed in"}`), nil
	}
	status, resp, err := c.bff(ctx, method, path, body, tok)
	if err != nil || status != http.StatusUnauthorized {
		return status, resp, err
	}
	if fresh := c.refresh(ctx, tok); fresh != "" {
		return c.bff(ctx, method, path, body, fresh)
	}
	return status, resp, nil
}

// refresh returns an access token newer than refused, or "". The exchange is
// creds.RefreshSession, which serializes it across this process and across
// processes sharing the creds file.
func (c *Core) refresh(ctx context.Context, refused string) string {
	return creds.RefreshSession(ctx, refused, func(ctx context.Context, spent string) (string, string, error) {
		body, _ := json.Marshal(map[string]string{"refresh_token": spent})
		status, resp, err := c.bff(ctx, http.MethodPost, "/v1/auth/refresh", body, "")
		if err != nil {
			return "", "", err
		}
		if status != http.StatusOK {
			return "", "", fmt.Errorf("refresh: HTTP %d", status)
		}
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(resp, &out); err != nil {
			return "", "", err
		}
		return out.AccessToken, out.RefreshToken, nil
	})
}

// bearer is the session's current access token, or "".
func (c *Core) bearer() string {
	if cfg, err := creds.Load(); err == nil && cfg != nil {
		return cfg.AccessToken
	}
	return ""
}

// bff performs one control-plane request. tok "" = unauthenticated.
func (c *Core) bff(ctx context.Context, method, path string, body []byte, tok string) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BFFURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "calabi-mobile")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
