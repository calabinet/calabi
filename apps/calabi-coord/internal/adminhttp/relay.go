package adminhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// Self-hosted relay registry (R2) — the admin surface behind bff-console.
//
// The meshnet is ALWAYS the one in the path, which the gateway sets from the
// caller's authenticated org and never from a request body. An org's relay
// appearing in another org's map would hand its operator that org's traffic
// metadata, and the id in a URL is the weakest link in keeping that from
// happening — so every mutation re-resolves the relay inside that meshnet and
// answers "not found" for anything else.

// relayView is the wire shape. region_code is derived, not stored, and is
// included because it is what the user will see in a node's "relay home" and in
// their relay's own logs.
type relayView struct {
	ID          int64  `json:"id"`
	Label       string `json:"label"`
	RegionCode  string `json:"region_code"`
	HostName    string `json:"host_name"`
	DERPPort    int    `json:"derp_port"`
	STUNPort    int    `json:"stun_port"`
	Enabled     bool   `json:"enabled"`
	NodesHomed  int    `json:"nodes_homed"`
	CreatedAtMS int64  `json:"created_at_ms"`
}

func toRelayView(r core.Relay, homed int) relayView {
	return relayView{
		ID: r.ID, Label: r.Label, RegionCode: r.RegionCode(), HostName: r.HostName,
		DERPPort: r.DERPPort, STUNPort: r.STUNPort, Enabled: r.Enabled,
		NodesHomed: homed, CreatedAtMS: r.CreatedAt.UnixMilli(),
	}
}

// listRelays returns a meshnet's registrations, each with how many of its
// devices are online now AND call it home.
//
// That count is the honest liveness signal, and it is why the coordinator does
// NOT probe the relay: nodes measure every region themselves and report the one
// they chose, so "3 devices are using it" is an observed fact rather than a
// theoretical reachability check. Probing a user's VPS from the control plane is
// also how a user's outage becomes the control plane's outage.
func (h *handler) listRelays(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	relays, err := h.coord.RelaysFor(r.Context(), meshnet)
	if err != nil {
		http.Error(w, "list relays: "+err.Error(), http.StatusInternalServerError)
		return
	}
	homed := map[string]int{}
	if nodes, err := h.nodes.ListMeshnet(r.Context(), meshnet); err == nil {
		for _, n := range nodes {
			// Count only nodes that are ONLINE right now (hold a live control
			// stream). A node's DERPHome persists after it disconnects, so counting
			// every node that ever picked a home would report devices that stopped
			// days ago as "using" the relay. Presence is the same online signal the
			// node list shows (nil-safe: an unwired tracker reports everyone offline).
			if n.DERPHome != "" && h.coord.Presence.IsOnline(n.ID) {
				homed[n.DERPHome]++
			}
		}
	}
	out := make([]relayView, 0, len(relays))
	for _, rl := range relays {
		out = append(out, toRelayView(rl, homed[rl.RegionCode()]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"relays": out})
}

type registerRelayRequest struct {
	Label    string `json:"label"`
	HostName string `json:"host_name"`
	DERPPort int    `json:"derp_port"`
	STUNPort int    `json:"stun_port"`
}

func (h *handler) registerRelay(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	var body registerRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	rl, err := h.coord.RegisterRelay(r.Context(), meshnet, core.Relay{
		Label: body.Label, HostName: body.HostName,
		DERPPort: body.DERPPort, STUNPort: body.STUNPort,
	})
	switch {
	case errors.Is(err, core.ErrInvalidRelay), errors.Is(err, core.ErrTooManyRelays):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, core.ErrRelayExists):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "register relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// A new region changes what every node in this meshnet should measure, so
	// push it rather than making them wait for the next refresh.
	h.notif.Bump(meshnet)
	writeJSON(w, http.StatusCreated, toRelayView(*rl, 0))
}

// upsertRelay is the idempotent registration a merged edge/relay node calls on
// every heartbeat (via bff-edge). Re-registering the same label rewrites the
// mutable fields instead of 409-ing, and only bumps the netmap when the map
// actually moved (edge/derp merge-B).
func (h *handler) upsertRelay(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	var body registerRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	rl, changed, err := h.coord.UpsertRelay(r.Context(), meshnet, core.Relay{
		Label: body.Label, HostName: body.HostName,
		DERPPort: body.DERPPort, STUNPort: body.STUNPort,
	})
	switch {
	case errors.Is(err, core.ErrInvalidRelay), errors.Is(err, core.ErrTooManyRelays):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "upsert relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Only push a fresh netmap when the map actually changed — a steady-state
	// heartbeat (same host/ports) must not churn every node every interval.
	if changed {
		h.notif.Bump(meshnet)
	}
	writeJSON(w, http.StatusOK, toRelayView(*rl, 0))
}

func (h *handler) setRelayEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meshnet, ok := meshnetFromPath(w, r)
		if !ok {
			return
		}
		relayID, err := strconv.ParseInt(r.PathValue("relayID"), 10, 64)
		if err != nil {
			http.Error(w, "bad relay id", http.StatusBadRequest)
			return
		}
		rl, err := h.coord.SetRelayEnabled(r.Context(), meshnet, relayID, enabled)
		if errors.Is(err, core.ErrRelayNotFound) {
			http.Error(w, "relay not found in this meshnet", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "set relay enabled: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.notif.Bump(meshnet)
		writeJSON(w, http.StatusOK, toRelayView(*rl, 0))
	}
}

func (h *handler) deleteRelay(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	relayID, err := strconv.ParseInt(r.PathValue("relayID"), 10, 64)
	if err != nil {
		http.Error(w, "bad relay id", http.StatusBadRequest)
		return
	}
	err = h.coord.DeleteRelay(r.Context(), meshnet, relayID)
	if errors.Is(err, core.ErrRelayNotFound) {
		http.Error(w, "relay not found in this meshnet", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "delete relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Nodes homed on the removed region have to re-measure; without the push they
	// would keep reporting a home that no longer exists in their map.
	h.notif.Bump(meshnet)
	w.WriteHeader(http.StatusNoContent)
}

// meshnetFromPath parses {id}, writing the error response itself.
func meshnetFromPath(w http.ResponseWriter, r *http.Request) (core.MeshnetID, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return 0, false
	}
	return core.MeshnetID(id), true
}
