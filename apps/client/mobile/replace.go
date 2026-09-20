package mobile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// Replacing an old device. A reinstalled or new phone
// is a new device: the mesh key lives in the app's private storage and goes with
// it. The old entry stays behind offline, holding its name and a seat. Replacing
// it deletes that entry and gives its name to this phone.
//
// The name only. Overlay addresses come from one allocator shared by every org,
// and a freed address goes to whoever registers next; nothing lets a device ask
// for a particular one.

// replaceCandidate is an entry this phone could be replacing.
type replaceCandidate struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Overlay  string `json:"overlay"`
	LastSeen string `json:"last_seen,omitempty"`
	Disabled bool   `json:"disabled"`
}

// replaceCandidates lists the caller's offline devices on this platform other
// than this phone. Tagged devices and subnet routers are left out: those are
// shared infrastructure, not someone's old phone, and a member could not delete
// a router anyway. On failure it returns the control plane's answer to pass on.
func (c *Core) replaceCandidates(r *http.Request) ([]replaceCandidate, *fetched) {
	cfg, _ := creds.Load()
	if cfg == nil || cfg.AccessToken == "" || cfg.User.ID == 0 {
		return nil, &fetched{status: http.StatusUnauthorized, body: []byte(`{"error":"not signed in"}`)}
	}
	status, body, err := c.bffAuthed(r.Context(), http.MethodGet, "/v1/mesh/nodes", nil)
	if err != nil {
		return nil, &fetched{status: http.StatusBadGateway, body: errorBody("upstream: " + err.Error())}
	}
	if status != http.StatusOK {
		return nil, &fetched{status: status, body: body}
	}
	var list struct {
		Items []struct {
			ID             int64    `json:"id"`
			Name           string   `json:"name"`
			Overlay        string   `json:"overlay"`
			OS             string   `json:"os"`
			Online         bool     `json:"online"`
			Disabled       bool     `json:"disabled"`
			Owner          int64    `json:"owner_user_id"`
			Tags           []string `json:"tags"`
			ApprovedRoutes []string `json:"approved_routes"`
			LastSeen       string   `json:"last_seen"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, &fetched{status: http.StatusBadGateway, body: errorBody("upstream: " + err.Error())}
	}
	self := c.selfOverlay()
	if e := c.currentEngine(); e != nil {
		if o := e.status().Overlay; o != "" {
			self = o
		}
	}
	out := []replaceCandidate{}
	for _, n := range list.Items {
		if n.Owner != cfg.User.ID || n.OS != runtime.GOOS || n.Online || n.ID <= 0 {
			continue
		}
		if self != "" && n.Overlay == self {
			continue
		}
		if len(n.Tags) > 0 || len(n.ApprovedRoutes) > 0 {
			continue
		}
		out = append(out, replaceCandidate{ID: n.ID, Name: n.Name, Overlay: n.Overlay, LastSeen: n.LastSeen, Disabled: n.Disabled})
	}
	// Most recently seen first: the likeliest one to be replacing.
	sort.SliceStable(out, func(i, j int) bool { return instant(out[i].LastSeen).After(instant(out[j].LastSeen)) })
	return out, nil
}

// handleReplaceable is GET /v1/mesh/replaceable.
func (c *Core) handleReplaceable(w http.ResponseWriter, r *http.Request) {
	items, failed := c.replaceCandidates(r)
	if failed != nil {
		writeRaw(w, failed.status, failed.body)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleReplace is POST /v1/mesh/replace {"node_id": n}: delete that device and
// take its name. Answers with the settings, like PUT /v1/settings.
func (c *Core) handleReplace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		NodeID int64 `json:"node_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&in); err != nil || in.NodeID <= 0 {
		writeError(w, http.StatusBadRequest, "node_id required")
		return
	}
	// Checked again here, not trusted from the list the app showed: the device
	// may have come back online since, and an online device is someone's.
	items, failed := c.replaceCandidates(r)
	if failed != nil {
		writeRaw(w, failed.status, failed.body)
		return
	}
	var old *replaceCandidate
	for i := range items {
		if items[i].ID == in.NodeID {
			old = &items[i]
		}
	}
	if old == nil {
		writeError(w, http.StatusConflict, "that device can no longer be replaced")
		return
	}
	status, body, err := c.bffAuthed(r.Context(), http.MethodDelete, fmt.Sprintf("/v1/mesh/nodes/%d", old.ID), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream: "+err.Error())
		return
	}
	// 404: deleted meanwhile, which is what was asked for.
	if status >= 300 && status != http.StatusNotFound {
		writeRaw(w, status, body)
		return
	}

	c.loadSettings() // mint the name first, so saving below does not race it
	cfg, _ := creds.Load()
	if cfg == nil {
		cfg = &creds.Config{}
	}
	cfg.MeshNodeName = meshNameFor(old.Name)
	if err := creds.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	c.logger.Info("replaced an old device", "node_id", old.ID, "name", cfg.MeshNodeName)
	// The coordinator hands out the freed name when this phone next registers.
	c.reconnect()
	writeJSON(w, http.StatusOK, c.loadSettings())
}

func errorBody(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}
