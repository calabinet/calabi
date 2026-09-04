// Package adminhttp is the coordinator's node-admin surface (MESH.8b): list a
// meshnet's nodes and flip a node's disabled kill switch. It speaks ONLY core
// types, so every coordinator mounts it — a self-hosted one gets the same ops
// surface the platform uses.
//
// This is an INTERNAL ops API: bind it to a PRIVATE address
// (CALABI_COORD_MESH_ADMIN_ADDR). The handlers here carry NO authorization of
// their own — the tenant boundary is the meshnet id in the PATH, which the
// calling gateway (bff-console / bff-admin / bff-edge) fills in from the
// authenticated user. Per-user RBAC therefore remains the gateway's job.
//
// AUTHENTICATION, however, is no longer only the gateway's job: because
// whoever reaches this port is effectively an admin of EVERY meshnet, the
// caller must present a shared bearer token and coord refuses to start when
// the surface is enabled without one. See cmd/calabi-coord/meshadminauth.go
// (CALABI_COORD_MESH_ADMIN_TOKEN) — the gate wraps this mux from the outside, so
// nothing in this package needs to know about it.
package adminhttp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// Notifier is the slice of core.Notifier the admin surface needs to push a fresh
// netmap after a change (so a disable takes effect immediately).
type Notifier interface{ Bump(core.MeshnetID) }

// New returns an http.Handler serving the node-admin routes.
func New(coord *core.Coordinator, notif Notifier, logger *slog.Logger) http.Handler {
	h := &handler{coord: coord, nodes: coord.Nodes, notif: notif, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/meshnets/{id}/nodes", h.listNodes)
	mux.HandleFunc("GET /admin/meshnets/{id}/usage", h.seatUsage)
	mux.HandleFunc("GET /admin/meshnets/{id}/settings", h.getSettings)
	mux.HandleFunc("PUT /admin/meshnets/{id}/settings", h.putSettings)
	mux.HandleFunc("POST /admin/meshnets/{id}/nodes/{nodeID}/approve", h.setApproved(true))
	mux.HandleFunc("POST /admin/meshnets/{id}/nodes/{nodeID}/unapprove", h.setApproved(false))
	mux.HandleFunc("DELETE /admin/meshnets/{id}/nodes/{nodeID}", h.deleteNode)
	mux.HandleFunc("POST /admin/meshnets/{id}/nodes/{nodeID}/routes", h.approveRoutes)
	mux.HandleFunc("POST /admin/nodes/{id}/name", h.renameNode)
	mux.HandleFunc("POST /admin/meshnets/{id}/nodes/{nodeID}/tags", h.setTags)
	mux.HandleFunc("POST /admin/nodes/{id}/disable", h.setDisabled(true))
	mux.HandleFunc("POST /admin/nodes/{id}/enable", h.setDisabled(false))
	// Per-org ACL editor (MESH.8e-2). NotImplemented when the build has no
	// writable ACL store (self-hosted — its ACL is a file).
	mux.HandleFunc("GET /admin/meshnets/{id}/acl", h.getACL)
	mux.HandleFunc("PUT /admin/meshnets/{id}/acl", h.putACL)
	// Pre-save impact + "why can/can't A reach B" (MESH.8e-3).
	// Declared services (MESH.8e-4): what each node OFFERS, registered by a human.
	mux.HandleFunc("POST /admin/meshnets/{id}/services/{svcID}/approve", h.setServiceApproved(true))
	mux.HandleFunc("POST /admin/meshnets/{id}/services/{svcID}/unapprove", h.setServiceApproved(false))
	// Console-authored services (F4a): an admin entering one IS the
	// authorization, so it is created confirmed and a device can never modify or
	// shadow it. Delete only applies to console rows — see core.DeleteConsoleService.
	mux.HandleFunc("POST /admin/meshnets/{id}/services", h.createService)
	mux.HandleFunc("DELETE /admin/meshnets/{id}/services/{svcID}", h.deleteService)
	mux.HandleFunc("GET /admin/meshnets/{id}/acl/revisions", h.listACLRevisions)
	mux.HandleFunc("POST /admin/meshnets/{id}/acl/preview", h.previewACL)
	mux.HandleFunc("POST /admin/meshnets/{id}/acl/check", h.checkAccess)
	// Self-hosted relays (R2): the org registers a calabi-derp it runs itself.
	// The meshnet in the path is the tenant boundary — the gateway sets it from
	// the caller's org, never from a body.
	mux.HandleFunc("GET /admin/meshnets/{id}/relays", h.listRelays)
	mux.HandleFunc("POST /admin/meshnets/{id}/relays", h.registerRelay)
	// PUT is the idempotent upsert a merged edge/relay node self-registers with
	// (edge/derp merge-B). POST stays strict (409 on duplicate) for the console.
	mux.HandleFunc("PUT /admin/meshnets/{id}/relays", h.upsertRelay)
	mux.HandleFunc("POST /admin/meshnets/{id}/relays/{relayID}/enable", h.setRelayEnabled(true))
	mux.HandleFunc("POST /admin/meshnets/{id}/relays/{relayID}/disable", h.setRelayEnabled(false))
	mux.HandleFunc("DELETE /admin/meshnets/{id}/relays/{relayID}", h.deleteRelay)
	return mux
}

type handler struct {
	coord  *core.Coordinator
	nodes  core.NodeStore
	notif  Notifier
	logger *slog.Logger
}

// serviceView is one declared service in the admin JSON.
type serviceView struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	// Target is what the DEVICE dials to reach the app; empty = 127.0.0.1:<port>.
	// Distinct from Port, which is what mesh peers dial on the overlay address —
	// an app bound to loopback answers the first and not the second.
	Target string `json:"target"`
	Note   string `json:"note"`
	// What the NODE ITSELF last observed (F3b). health_checked=false means
	// nothing has been reported — NOT that the service is broken. The pair
	// target_ok=true, mesh_ok=false is the loopback-only case: the app answers
	// where the machine dials it, but not on the address peers use.
	HealthChecked bool `json:"health_checked"`
	TargetOK      bool `json:"target_ok"`
	MeshOK        bool `json:"mesh_ok"`
	// Approved gates ACL visibility; a node declaration starts false.
	Approved bool `json:"approved"`
	// Source is "node" (the machine's config declares it — a claim) or "console"
	// (an admin entered it — an authorization). It decides what the UI may offer:
	// a console row can be deleted, a node row can only be un-confirmed, because
	// deleting one just brings it back on the machine's next registration.
	Source string `json:"source"`
}

// nodeView is the JSON shape of a node in the admin list.
type nodeView struct {
	ID      int64  `json:"id"`
	Meshnet int64  `json:"meshnet"`
	Name    string `json:"name"`
	// HostName is what the node reports at registration; NamePinned says the
	// name above was set by an admin (so the hostname no longer drives it).
	// Together they let the console show "which machine is this, really".
	HostName   string `json:"host_name"`
	NamePinned bool   `json:"name_pinned"`
	// TagsPinned: an admin set the tags, so the daemon no longer overwrites them.
	TagsPinned bool `json:"tags_pinned"`
	// OwnerUserID is the human whose key enrolled the node (0 = unattributed).
	OwnerUserID int64 `json:"owner_user_id"`
	// DeviceFingerprint is the daemon's self-reported per-install id; the BFF
	// resolves it against the org's devices to offer a link. Display only.
	DeviceFingerprint string `json:"device_fingerprint"`
	// Approved is device approval: false = enrolled but reaching nothing.
	Approved bool   `json:"approved"`
	Overlay  string `json:"overlay"`
	// Services are what this node declares it offers (never discovered).
	Services []serviceView `json:"services"`
	// Online is the node's LIVE connection state (holds a control stream), from
	// core.Presence — distinct from Disabled (the admin kill switch) and LastSeen.
	Online   bool     `json:"online"`
	Disabled bool     `json:"disabled"`
	Tags     []string `json:"tags"`
	DERPHome string   `json:"derp_home"`
	// AdvertisedRoutes is what the node CLAIMS; ApprovedRoutes is what an admin
	// allowed (and therefore what the mesh actually routes here). RoutesReviewed
	// false means nobody has managed them yet, and claims are being honoured.
	AdvertisedRoutes []string `json:"advertised_routes"`
	ApprovedRoutes   []string `json:"approved_routes"`
	RoutesReviewed   bool     `json:"routes_reviewed"`
	LastSeen         string   `json:"last_seen"`
}

func (h *handler) listNodes(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	nodes, err := h.nodes.ListMeshnet(r.Context(), core.MeshnetID(id))
	if err != nil {
		http.Error(w, "list nodes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ids := make([]int64, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	online := h.coord.Presence.Online(ids) // nil-safe (empty set)
	// Declared services, grouped per node. A registry read failure degrades to
	// "no services" rather than failing the node list — the list is what an
	// operator needs to act on a node at all.
	byNode := map[int64][]serviceView{}
	if svcs, err := h.coord.ServicesFor(r.Context(), core.MeshnetID(id)); err != nil {
		h.logger.Warn("list services failed; node list will show none", "meshnet", id, "err", err)
	} else {
		for _, s := range svcs {
			v := serviceView{
				ID: s.ID, Name: s.Name, Proto: s.Proto, Port: s.Port, Target: s.Target, Note: s.Note,
				Approved: s.Approved, Source: s.Source,
			}
			// Only an ONLINE node's observation is current. The tracker keeps the
			// last report with nothing to invalidate it, so an offline node still
			// holds whatever it said before it dropped — surfacing that would show
			// a green "reachable" for a machine that is gone. Presence is the
			// authority on "is this current"; when the node is offline we render
			// the service as unobserved (health_checked=false), the same honest
			// "—" as a node that has never reported. It re-appears within one
			// reporting interval after the node reconnects.
			if online[s.NodeID] {
				if hh, ok := h.coord.ServiceHealth.Get(s.NodeID, s.Name); ok {
					v.HealthChecked, v.TargetOK, v.MeshOK = true, hh.TargetOK, hh.MeshOK
				}
			}
			byNode[s.NodeID] = append(byNode[s.NodeID], v)
		}
	}
	out := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		v := toView(n, online[n.ID])
		v.Services = byNode[n.ID]
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// seatUsage reports a meshnet's mesh-node seat accounting (MESH.8d): seats used
// (active nodes), disabled (parked, not consuming a seat), total, and the plan's
// seat allowance — the source the account/billing view reflects.
func (h *handler) seatUsage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	u, err := h.coord.SeatUsage(r.Context(), core.MeshnetID(id))
	if err != nil {
		http.Error(w, "seat usage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// aclEnvelope is the GET/PUT shape: the document plus whether one is stored
// (so the console can seed a fresh editor with a default when exists=false).
type aclEnvelope struct {
	Exists bool           `json:"exists"`
	Policy core.ACLPolicy `json:"policy"`
}

// getACL returns a meshnet's stored ACL doc (or exists=false + an empty doc).
func (h *handler) getACL(w http.ResponseWriter, r *http.Request) {
	if h.coord.ACL == nil {
		http.Error(w, "acl editing not supported on this build", http.StatusNotImplemented)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	doc, ok, err := h.coord.ACL.GetACL(r.Context(), core.MeshnetID(id))
	if err != nil {
		http.Error(w, "get acl: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, aclEnvelope{Exists: ok, Policy: doc})
}

// putACL validates and stores a meshnet's ACL doc, then bumps the meshnet so
// every node re-pulls its (now re-filtered) netmap. A malformed or semantically
// invalid doc is a 400 with the reason — the edit is rejected, the old policy
// stands.
func (h *handler) putACL(w http.ResponseWriter, r *http.Request) {
	if h.coord.ACL == nil {
		http.Error(w, "acl editing not supported on this build", http.StatusNotImplemented)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	var doc core.ACLPolicy
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		http.Error(w, "parse acl: "+err.Error(), http.StatusBadRequest)
		return
	}
	// One write path (core.SaveACL): validate, store, then record the revision —
	// history that a caller could bypass would not be worth having. The actor is
	// whoever the BFF says is calling (X-Calabi-Actor); this port is internal and
	// the BFF is its authenticated front door.
	if err := h.coord.SaveACL(r.Context(), core.MeshnetID(id), doc, r.Header.Get("X-Calabi-Actor")); err != nil {
		if errors.Is(err, core.ErrInvalidACL) {
			http.Error(w, "invalid acl: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "save acl: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.notif.Bump(core.MeshnetID(id))
	h.logger.Info("admin set meshnet acl", "meshnet", id, "rules", len(doc.ACLs), "groups", len(doc.Groups))
	writeJSON(w, http.StatusOK, aclEnvelope{Exists: true, Policy: doc})
}

// renameNode sets a node's MagicDNS name. The name is what peers resolve, so
// coord validates it as a DNS label and enforces uniqueness within the meshnet
// (core.RenameNode); an invalid or taken name is a 400 and the old name stands.
// On success the meshnet is bumped so peers re-pull and MagicDNS follows.
func (h *handler) renameNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad node id", http.StatusBadRequest)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
		return
	}
	node, err := h.coord.RenameNode(r.Context(), id, body.Name)
	switch {
	case errors.Is(err, core.ErrNodeNotFound):
		http.Error(w, "node not found", http.StatusNotFound)
		return
	case errors.Is(err, core.ErrInvalidNodeName), errors.Is(err, core.ErrNodeNameTaken):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "rename node: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.notif.Bump(node.Meshnet)
	writeJSON(w, http.StatusOK, toView(node, h.coord.Presence.IsOnline(node.ID)))
}

// getSettings / putSettings expose a meshnet's org-level switches. Turning
// device approval on grandfathers the existing fleet (core.UpdateSettings).
func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	set, err := h.coord.SettingsFor(r.Context(), core.MeshnetID(id))
	if err != nil {
		http.Error(w, "read settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (h *handler) putSettings(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	var in core.MeshnetSettings
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.coord.UpdateSettings(r.Context(), core.MeshnetID(id), in); err != nil {
		http.Error(w, "save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, in)
}

// setApproved flips one device's approval and re-pushes the meshnet: approving
// makes the node visible to peers (and them to it) immediately.
func (h *handler) setApproved(approved bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meshnet, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad meshnet id", http.StatusBadRequest)
			return
		}
		nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
		if err != nil {
			http.Error(w, "bad node id", http.StatusBadRequest)
			return
		}
		node, err := h.coord.SetNodeApproved(r.Context(), core.MeshnetID(meshnet), nodeID, approved)
		if errors.Is(err, core.ErrNodeNotFound) {
			http.Error(w, "node not found in this meshnet", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "set approved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.notif.Bump(node.Meshnet)
		writeJSON(w, http.StatusOK, toView(node, h.coord.Presence.IsOnline(node.ID)))
	}
}

// deleteNode removes a device from the meshnet and re-pushes it, so peers drop
// it right away. Scoped to the meshnet in the path (which the BFF pins to the
// caller's org), so another org's node id 404s.
func (h *handler) deleteNode(w http.ResponseWriter, r *http.Request) {
	meshnet, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
	if err != nil {
		http.Error(w, "bad node id", http.StatusBadRequest)
		return
	}
	err = h.coord.DeleteNode(r.Context(), core.MeshnetID(meshnet), nodeID)
	if errors.Is(err, core.ErrNodeNotFound) {
		http.Error(w, "node not found in this meshnet", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "delete node: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.notif.Bump(core.MeshnetID(meshnet))
	w.WriteHeader(http.StatusNoContent)
}

// setServiceApproved confirms (or un-confirms) a service a node declared, then
// re-pushes the meshnet: confirming makes "svc:" rules start matching it.
func (h *handler) setServiceApproved(approved bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meshnet, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad meshnet id", http.StatusBadRequest)
			return
		}
		svcID, err := strconv.ParseInt(r.PathValue("svcID"), 10, 64)
		if err != nil {
			http.Error(w, "bad service id", http.StatusBadRequest)
			return
		}
		svc, err := h.coord.SetServiceApproved(r.Context(), core.MeshnetID(meshnet), svcID, approved)
		if errors.Is(err, core.ErrServiceNotFound) {
			http.Error(w, "service not found in this meshnet", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "set service approved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.notif.Bump(core.MeshnetID(meshnet))
		writeJSON(w, http.StatusOK, serviceView{
			ID: svc.ID, Name: svc.Name, Proto: svc.Proto, Port: svc.Port, Target: svc.Target, Note: svc.Note,
			Approved: svc.Approved, Source: svc.Source,
		})
	}
}

type createServiceRequest struct {
	NodeID int64  `json:"node_id"`
	Name   string `json:"name"`
	Proto  string `json:"proto"`
	Port   int    `json:"port"`
	Target string `json:"target"`
	Note   string `json:"note"`
}

// createService records a service an admin entered.
func (h *handler) createService(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	var body createServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	svc, err := h.coord.CreateConsoleService(r.Context(), meshnet, body.NodeID, body.Name, body.Proto, body.Port, body.Target, body.Note)
	switch {
	case errors.Is(err, core.ErrNodeNotFound):
		http.Error(w, "node not found in this meshnet", http.StatusNotFound)
		return
	case errors.Is(err, core.ErrServiceExists):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, core.ErrInvalidService):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "create service: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// A confirmed service changes what "svc:" rules resolve to, so push it.
	h.notif.Bump(meshnet)
	writeJSON(w, http.StatusCreated, serviceView{
		ID: svc.ID, Name: svc.Name, Proto: svc.Proto, Port: svc.Port, Target: svc.Target, Note: svc.Note,
		Approved: svc.Approved, Source: svc.Source,
	})
}

// deleteService removes an admin-authored service. A device-declared one is
// refused with an explanation rather than deleted and silently recreated.
func (h *handler) deleteService(w http.ResponseWriter, r *http.Request) {
	meshnet, ok := meshnetFromPath(w, r)
	if !ok {
		return
	}
	svcID, err := strconv.ParseInt(r.PathValue("svcID"), 10, 64)
	if err != nil {
		http.Error(w, "bad service id", http.StatusBadRequest)
		return
	}
	err = h.coord.DeleteConsoleService(r.Context(), meshnet, svcID)
	switch {
	case errors.Is(err, core.ErrServiceNotFound):
		http.Error(w, "service not found in this meshnet", http.StatusNotFound)
		return
	case errors.Is(err, core.ErrInvalidService):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "delete service: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.notif.Bump(meshnet)
	w.WriteHeader(http.StatusNoContent)
}

// setTags replaces a node's ACL tags. Tags are an authorization input, so this
// is an admin-only surface (a node may never assert its own) and the meshnet in
// the path is the tenant boundary.
func (h *handler) setTags(w http.ResponseWriter, r *http.Request) {
	meshnet, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
	if err != nil {
		http.Error(w, "bad node id", http.StatusBadRequest)
		return
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
		return
	}
	node, err := h.coord.SetNodeTags(r.Context(), core.MeshnetID(meshnet), nodeID, body.Tags)
	switch {
	case errors.Is(err, core.ErrNodeNotFound):
		http.Error(w, "node not found in this meshnet", http.StatusNotFound)
		return
	case errors.Is(err, core.ErrInvalidNodeTag):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "set tags: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.notif.Bump(node.Meshnet)
	writeJSON(w, http.StatusOK, toView(node, h.coord.Presence.IsOnline(node.ID)))
}

// approveRoutes sets which of a node's claimed subnet routes the mesh will route
// to it. Approving a CIDR hands this node other nodes' traffic for it, so it is
// an admin decision — and one that can only pick from what the node claims.
func (h *handler) approveRoutes(w http.ResponseWriter, r *http.Request) {
	meshnet, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(r.PathValue("nodeID"), 10, 64)
	if err != nil {
		http.Error(w, "bad node id", http.StatusBadRequest)
		return
	}
	var body struct {
		Approved []string `json:"approved"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
		return
	}
	routes := make([]netip.Prefix, 0, len(body.Approved))
	for _, raw := range body.Approved {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			http.Error(w, "route "+raw+": "+err.Error(), http.StatusBadRequest)
			return
		}
		routes = append(routes, pfx)
	}
	node, err := h.coord.ApproveRoutes(r.Context(), core.MeshnetID(meshnet), nodeID, routes)
	switch {
	case errors.Is(err, core.ErrNodeNotFound):
		http.Error(w, "node not found in this meshnet", http.StatusNotFound)
		return
	case errors.Is(err, core.ErrRouteNotAdvertised):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "approve routes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Peers must re-pull: approving changes their allowed_ips for this node.
	h.notif.Bump(node.Meshnet)
	writeJSON(w, http.StatusOK, toView(node, h.coord.Presence.IsOnline(node.ID)))
}

func (h *handler) listACLRevisions(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	revs, err := h.coord.ACLRevisionsFor(r.Context(), core.MeshnetID(id), limit)
	if err != nil {
		http.Error(w, "list acl revisions: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if revs == nil {
		revs = []core.ACLRevision{}
	}
	writeJSON(w, http.StatusOK, revs)
}

// previewACL reports what saving this doc WOULD change, in node pairs, against
// what the meshnet runs on right now. Deliberately does NOT validate the doc:
// the most valuable preview is of the doc we refuse to save (zero rules), where
// the answer — "this cuts all N connections" — is the explanation for the
// refusal. Validation still guards the actual write.
func (h *handler) previewACL(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	var doc core.ACLPolicy
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		http.Error(w, "parse acl: "+err.Error(), http.StatusBadRequest)
		return
	}
	diff, err := h.coord.PreviewACL(r.Context(), core.MeshnetID(id), doc)
	if err != nil {
		http.Error(w, "preview acl: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

// checkAccess answers one src→dst question, naming the rule that decided it.
// An absent "policy" asks about the LIVE policy; sending one asks about a draft
// the admin hasn't saved yet.
func (h *handler) checkAccess(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad meshnet id", http.StatusBadRequest)
		return
	}
	var body struct {
		Src    string          `json:"src"`
		Dst    string          `json:"dst"`
		Policy *core.ACLPolicy `json:"policy"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
		return
	}
	got, err := h.coord.CheckAccess(r.Context(), core.MeshnetID(id), body.Src, body.Dst, body.Policy)
	if errors.Is(err, core.ErrNodeNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "check access: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, got)
}

// setDisabled returns a handler that flips the kill switch to `disabled`. On
// success it bumps the node's meshnet so peers (and the node itself) re-pull
// their netmap right away.
func (h *handler) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad node id", http.StatusBadRequest)
			return
		}
		// Load first so we know the meshnet to notify (and to 404 cleanly).
		node, err := h.nodes.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, core.ErrNodeNotFound) {
				http.Error(w, "node not found", http.StatusNotFound)
				return
			}
			http.Error(w, "get node: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := h.nodes.SetDisabled(r.Context(), id, disabled); err != nil {
			http.Error(w, "set disabled: "+err.Error(), http.StatusInternalServerError)
			return
		}
		h.notif.Bump(node.Meshnet)
		h.logger.Info("admin set node disabled", "node_id", id, "meshnet", node.Meshnet, "disabled", disabled)
		node.Disabled = disabled
		writeJSON(w, http.StatusOK, toView(node, h.coord.Presence.IsOnline(node.ID)))
	}
}

func toView(n *core.Node, online bool) nodeView {
	v := nodeView{
		ID:                n.ID,
		Meshnet:           int64(n.Meshnet),
		Name:              n.Name,
		HostName:          n.HostName,
		NamePinned:        n.NamePinned,
		TagsPinned:        n.TagsPinned,
		OwnerUserID:       n.OwnerUserID,
		DeviceFingerprint: n.DeviceFingerprint,
		Approved:          n.Approved,
		Online:            online,
		Disabled:          n.Disabled,
		Tags:              n.Tags,
		DERPHome:          n.DERPHome,
	}
	if n.Overlay.IsValid() {
		v.Overlay = n.Overlay.String()
	}
	if !n.LastSeen.IsZero() {
		v.LastSeen = n.LastSeen.Format("2006-01-02T15:04:05Z07:00")
	}
	for _, rt := range n.AdvertisedRoutes {
		v.AdvertisedRoutes = append(v.AdvertisedRoutes, rt.String())
	}
	for _, rt := range n.ApprovedRoutes {
		v.ApprovedRoutes = append(v.ApprovedRoutes, rt.String())
	}
	if v.ApprovedRoutes == nil {
		v.ApprovedRoutes = []string{}
	}
	v.RoutesReviewed = n.RoutesReviewed
	if v.Services == nil {
		v.Services = []serviceView{}
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
