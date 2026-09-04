// Package store is the PLATFORM (SaaS) NodeStore: an ent/DB-backed
// implementation of core.NodeStore over a calabi-coord-owned mesh_nodes table
// (MESH.8c). It lives under internal/platform so the edition-agnostic core and
// the community coordinator never link ent — community keeps the in-memory
// NodeStore. The DB is the durable registry behind admin visibility, seat
// billing, and console (MESH.8b/8d/8e).
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshacl"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshaclrevision"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshnode"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshservice"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshsetting"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Store implements core.NodeStore over ent.
type Store struct{ client *ent.Client }

// New wraps an ent client.
func New(c *ent.Client) *Store { return &Store{client: c} }

// Close releases the underlying DB.
func (s *Store) Close() error { return s.client.Close() }

// Migrate runs the ent-managed schema migration (idempotent — safe every boot).
func (s *Store) Migrate(ctx context.Context) error {
	if err := s.client.Schema.Create(ctx); err != nil {
		return fmt.Errorf("coord store: migrate: %w", err)
	}
	return nil
}

// Upsert inserts (ID==0) or updates a node. On insert the store assigns the ID.
func (s *Store) Upsert(ctx context.Context, n *core.Node) (*core.Node, error) {
	eps, err := marshalStrings(addrPortsToStrings(n.Endpoints))
	if err != nil {
		return nil, err
	}
	approved, err := marshalStrings(prefixesToStrings(n.ApprovedRoutes))
	if err != nil {
		return nil, err
	}
	routes, err := marshalStrings(prefixesToStrings(n.AdvertisedRoutes))
	if err != nil {
		return nil, err
	}
	tags, err := marshalStrings(n.Tags)
	if err != nil {
		return nil, err
	}

	if n.ID == 0 {
		row, err := s.client.MeshNode.Create().
			SetMeshnetID(int64(n.Meshnet)).
			SetNodeKey(n.NodeKey.String()).
			SetName(n.Name).
			SetHostName(n.HostName).
			SetNamePinned(n.NamePinned).
			SetDiscoKey(discoText(n.DiscoKey)).
			SetOverlay(addrText(n.Overlay)).
			SetDerpHome(n.DERPHome).
			SetEndpointsJSON(eps).
			SetAdvertisedRoutesJSON(routes).
			SetApprovedRoutesJSON(approved).
			SetRoutesReviewed(n.RoutesReviewed).
			SetOwnerUserID(n.OwnerUserID).
			SetDeviceFingerprint(n.DeviceFingerprint).
			SetTagsPinned(n.TagsPinned).
			SetApproved(n.Approved).
			SetTagsJSON(tags).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("coord store: create node: %w", err)
		}
		return toNode(row)
	}

	// Deliberately NOT written here: disabled, approved, tags_pinned. Those are
	// admin DECISIONS about the node, each with its own setter (SetDisabled /
	// SetApproved / SetTags), and a node's own re-enrolment must not be able to
	// undo them. Everything else on this call is node-reported state.
	row, err := s.client.MeshNode.UpdateOneID(int(n.ID)).
		SetName(n.Name).
		SetHostName(n.HostName).
		SetNamePinned(n.NamePinned).
		SetDiscoKey(discoText(n.DiscoKey)).
		SetOverlay(addrText(n.Overlay)).
		SetDerpHome(n.DERPHome).
		SetEndpointsJSON(eps).
		SetAdvertisedRoutesJSON(routes).
		SetApprovedRoutesJSON(approved).
		SetRoutesReviewed(n.RoutesReviewed).
		SetOwnerUserID(n.OwnerUserID).
		// The node re-reports this on every enrolment, and core.Register decides
		// whether it changes (non-empty only). Leaving it out of the UPDATE meant
		// a node created before it ever had a fingerprint could NEVER acquire
		// one: the value arrived, core merged it, and this dropped it on the
		// floor — silently, since Upsert returns the row it just wrote.
		SetDeviceFingerprint(n.DeviceFingerprint).
		SetTagsJSON(tags).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, core.ErrNodeNotFound
		}
		return nil, fmt.Errorf("coord store: update node %d: %w", n.ID, err)
	}
	return toNode(row)
}

// Get returns a node by id, or core.ErrNodeNotFound.
func (s *Store) Get(ctx context.Context, id int64) (*core.Node, error) {
	row, err := s.client.MeshNode.Get(ctx, int(id))
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, core.ErrNodeNotFound
		}
		return nil, err
	}
	return toNode(row)
}

// FindByKey returns the node in meshnet t with the given key, or
// core.ErrNodeNotFound (drives idempotent re-enrollment).
// ResolveNodeKey implements core.NodeKeyResolver: find a node by key across
// every meshnet. Used ONLY to attribute relay usage — a relay reports opaque
// keys and cannot say whose they are. ent's Only() rejects a multi-row match,
// which is what we want: two nodes sharing a key would mean guessing an owner,
// and guessing bills the wrong org.
func (s *Store) ResolveNodeKey(ctx context.Context, key meshproto.NodeKey) (*core.Node, error) {
	row, err := s.client.MeshNode.Query().
		Where(meshnode.NodeKey(key.String())).
		Only(ctx)
	if err != nil {
		switch {
		case ent.IsNotFound(err):
			return nil, core.ErrNodeNotFound
		case ent.IsNotSingular(err):
			return nil, core.ErrAmbiguousNodeKey
		}
		return nil, err
	}
	return toNode(row)
}

func (s *Store) FindByKey(ctx context.Context, t core.MeshnetID, key meshproto.NodeKey) (*core.Node, error) {
	row, err := s.client.MeshNode.Query().
		Where(meshnode.MeshnetID(int64(t)), meshnode.NodeKey(key.String())).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, core.ErrNodeNotFound
		}
		return nil, err
	}
	return toNode(row)
}

// ListMeshnet returns every node in a meshnet (caller applies ACL).
func (s *Store) ListMeshnet(ctx context.Context, t core.MeshnetID) ([]*core.Node, error) {
	rows, err := s.client.MeshNode.Query().
		Where(meshnode.MeshnetID(int64(t))).
		Order(ent.Asc(meshnode.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*core.Node, 0, len(rows))
	for _, r := range rows {
		n, err := toNode(r)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// SetDisabled flips a node's admin kill switch (MESH.8b).
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	err := s.client.MeshNode.UpdateOneID(int(id)).SetDisabled(disabled).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// AllOverlays returns every allocated overlay address across all meshnets, so
// startup can warm the in-memory IPAM past them and avoid re-handing a live
// address to a fresh node (MESH.8c). Invalid/empty overlays are skipped.
func (s *Store) AllOverlays(ctx context.Context) ([]netip.Addr, error) {
	rows, err := s.client.MeshNode.Query().Select(meshnode.FieldOverlay).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(rows))
	for _, r := range rows {
		if r.Overlay == "" {
			continue
		}
		if a, err := netip.ParseAddr(r.Overlay); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// GetACL returns the meshnet's stored ACL doc, or (zero,false,nil) if none is
// stored (MESH.8e-2). A malformed stored blob is an error (it should never
// happen — SetACL only ever writes marshalled docs).
func (s *Store) GetACL(ctx context.Context, t core.MeshnetID) (core.ACLPolicy, bool, error) {
	row, err := s.client.MeshACL.Query().Where(meshacl.MeshnetID(int64(t))).Only(ctx)
	if ent.IsNotFound(err) {
		return core.ACLPolicy{}, false, nil
	}
	if err != nil {
		return core.ACLPolicy{}, false, err
	}
	var p core.ACLPolicy
	if row.PolicyJSON != "" {
		if err := json.Unmarshal([]byte(row.PolicyJSON), &p); err != nil {
			return core.ACLPolicy{}, false, fmt.Errorf("coord store: acl doc for meshnet %d: %w", t, err)
		}
	}
	return p, true, nil
}

// SetACL upserts the meshnet's ACL doc (one row per meshnet). Callers validate
// the doc (core.ValidateACLPolicy) before persisting.
func (s *Store) SetACL(ctx context.Context, t core.MeshnetID, p core.ACLPolicy) error {
	blob, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("coord store: marshal acl doc: %w", err)
	}
	existing, err := s.client.MeshACL.Query().Where(meshacl.MeshnetID(int64(t))).Only(ctx)
	if ent.IsNotFound(err) {
		return s.client.MeshACL.Create().
			SetMeshnetID(int64(t)).
			SetPolicyJSON(string(blob)).
			Exec(ctx)
	}
	if err != nil {
		return err
	}
	return s.client.MeshACL.UpdateOneID(existing.ID).SetPolicyJSON(string(blob)).Exec(ctx)
}

// UpdateEndpoints replaces a node's discovered endpoints (MESH.4).
func (s *Store) UpdateEndpoints(ctx context.Context, id int64, eps []netip.AddrPort) error {
	blob, err := marshalStrings(addrPortsToStrings(eps))
	if err != nil {
		return err
	}
	err = s.client.MeshNode.UpdateOneID(int(id)).SetEndpointsJSON(blob).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// ---- declared services (MESH.8e-4) ----

// ListServices returns every service declared in the meshnet, oldest first.
func (s *Store) ListServices(ctx context.Context, t core.MeshnetID) ([]core.Service, error) {
	rows, err := s.client.MeshService.Query().
		Where(meshservice.MeshnetID(int64(t))).
		Order(ent.Asc(meshservice.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Service, 0, len(rows))
	for _, r := range rows {
		out = append(out, toService(r))
	}
	return out, nil
}

// CreateService stores a declaration. A duplicate (node, name) is refused by the
// unique index; surface it as the domain error so the API answers 409/400
// instead of leaking a constraint message.
func (s *Store) CreateService(ctx context.Context, in core.Service) (*core.Service, error) {
	row, err := s.client.MeshService.Create().
		SetMeshnetID(int64(in.Meshnet)).
		SetNodeID(in.NodeID).
		SetName(in.Name).
		SetProto(in.Proto).
		SetPort(in.Port).
		SetTarget(in.Target).
		SetNote(in.Note).
		SetApproved(in.Approved).
		SetSource(sourceOrNode(in.Source)).
		Save(ctx)
	if ent.IsConstraintError(err) {
		return nil, core.ErrServiceExists
	}
	if err != nil {
		return nil, err
	}
	out := toService(row)
	return &out, nil
}

// UpdateService rewrites the mutable fields of a declaration (proto/port/note/
// approved). Name, node and meshnet are identity and never change here.
func (s *Store) UpdateService(ctx context.Context, in core.Service) error {
	err := s.client.MeshService.UpdateOneID(int(in.ID)).
		SetProto(in.Proto).
		SetPort(in.Port).
		SetTarget(in.Target).
		SetNote(in.Note).
		SetApproved(in.Approved).
		Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrServiceNotFound
	}
	return err
}

// DeleteService removes one declaration by id.
func (s *Store) DeleteService(ctx context.Context, id int64) error {
	err := s.client.MeshService.DeleteOneID(int(id)).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrServiceNotFound
	}
	return err
}

func toService(m *ent.MeshService) core.Service {
	return core.Service{
		ID:        int64(m.ID),
		Meshnet:   core.MeshnetID(m.MeshnetID),
		NodeID:    m.NodeID,
		Name:      m.Name,
		Proto:     m.Proto,
		Port:      m.Port,
		Target:    m.Target,
		Note:      m.Note,
		Source:    sourceOrNode(m.Source),
		Approved:  m.Approved,
		CreatedAt: m.CreatedAt,
	}
}

// sourceOrNode normalizes an empty source to "node". Rows written before the
// column existed came from devices, and reading them as console-authored would
// strand them outside reconciliation — their device could never withdraw or
// correct them again.
func sourceOrNode(s string) string {
	if s == core.ServiceSourceConsole {
		return core.ServiceSourceConsole
	}
	return core.ServiceSourceNode
}

// AppendRevision records one saved ACL document (append-only history).
func (s *Store) AppendRevision(ctx context.Context, t core.MeshnetID, p core.ACLPolicy, actor string) error {
	blob, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("coord store: marshal acl revision: %w", err)
	}
	return s.client.MeshACLRevision.Create().
		SetMeshnetID(int64(t)).
		SetPolicyJSON(string(blob)).
		SetActor(actor).
		Exec(ctx)
}

// ListRevisions returns a meshnet's saved ACL documents, newest first. A
// malformed stored blob is SKIPPED rather than failing the whole listing — one
// bad row must not cost the admin access to the rest of their history.
func (s *Store) ListRevisions(ctx context.Context, t core.MeshnetID, limit int) ([]core.ACLRevision, error) {
	q := s.client.MeshACLRevision.Query().
		Where(meshaclrevision.MeshnetID(int64(t))).
		Order(ent.Desc(meshaclrevision.FieldCreatedAt), ent.Desc(meshaclrevision.FieldID))
	if limit > 0 {
		q = q.Limit(limit)
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.ACLRevision, 0, len(rows))
	for _, row := range rows {
		var p core.ACLPolicy
		if row.PolicyJSON != "" {
			if err := json.Unmarshal([]byte(row.PolicyJSON), &p); err != nil {
				continue
			}
		}
		out = append(out, core.ACLRevision{
			ID:        int64(row.ID),
			Policy:    p,
			Actor:     row.Actor,
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// Delete removes a node row permanently (MESH.8e-8).
func (s *Store) Delete(ctx context.Context, id int64) error {
	err := s.client.MeshNode.DeleteOneID(int(id)).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// SetTags replaces a node's ACL tags and pins them.
func (s *Store) SetTags(ctx context.Context, id int64, tags []string) error {
	raw, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	err = s.client.MeshNode.UpdateOneID(int(id)).
		SetTagsJSON(string(raw)).
		SetTagsPinned(true).
		Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// SetApproved flips device approval (MESH.8e-5).
func (s *Store) SetApproved(ctx context.Context, id int64, approved bool) error {
	err := s.client.MeshNode.UpdateOneID(int(id)).SetApproved(approved).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// GetSettings returns a meshnet's switches; an absent row means all defaults.
func (s *Store) GetSettings(ctx context.Context, t core.MeshnetID) (core.MeshnetSettings, error) {
	row, err := s.client.MeshSetting.Query().Where(meshsetting.MeshnetID(int64(t))).Only(ctx)
	if ent.IsNotFound(err) {
		return core.MeshnetSettings{}, nil
	}
	if err != nil {
		return core.MeshnetSettings{}, err
	}
	return core.MeshnetSettings{RequireDeviceApproval: row.RequireDeviceApproval}, nil
}

// SetSettings upserts a meshnet's switches (one row per meshnet).
func (s *Store) SetSettings(ctx context.Context, t core.MeshnetID, in core.MeshnetSettings) error {
	existing, err := s.client.MeshSetting.Query().Where(meshsetting.MeshnetID(int64(t))).Only(ctx)
	if ent.IsNotFound(err) {
		return s.client.MeshSetting.Create().
			SetMeshnetID(int64(t)).
			SetRequireDeviceApproval(in.RequireDeviceApproval).
			Exec(ctx)
	}
	if err != nil {
		return err
	}
	return s.client.MeshSetting.UpdateOneID(existing.ID).
		SetRequireDeviceApproval(in.RequireDeviceApproval).
		Exec(ctx)
}

// UpdateApprovedRoutes records the admin's route decision and marks the node
// reviewed, so its later claims no longer route automatically.
func (s *Store) UpdateApprovedRoutes(ctx context.Context, id int64, routes []netip.Prefix) error {
	blob, err := marshalStrings(prefixesToStrings(routes))
	if err != nil {
		return err
	}
	err = s.client.MeshNode.UpdateOneID(int(id)).
		SetApprovedRoutesJSON(blob).
		SetRoutesReviewed(true).
		Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// UpdateName sets an admin-chosen node name and pins it, so the node's next
// re-registration stops following its hostname (core.RenameNode validated it).
func (s *Store) UpdateName(ctx context.Context, id int64, name string) error {
	err := s.client.MeshNode.UpdateOneID(int(id)).SetName(name).SetNamePinned(true).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// UpdateDERPHome records the node's measured home relay region (MESH.4 B2b).
func (s *Store) UpdateDERPHome(ctx context.Context, id int64, region string) error {
	err := s.client.MeshNode.UpdateOneID(int(id)).SetDerpHome(region).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrNodeNotFound
	}
	return err
}

// ---- conversion helpers ----

func toNode(m *ent.MeshNode) (*core.Node, error) {
	nk, err := meshproto.ParseNodeKey(m.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("coord store: node_key %q: %w", m.NodeKey, err)
	}
	n := &core.Node{
		ID:         int64(m.ID),
		Meshnet:    core.MeshnetID(m.MeshnetID),
		Name:       m.Name,
		HostName:   m.HostName,
		NamePinned: m.NamePinned,
		NodeKey:    nk,
		DERPHome:   m.DerpHome,
		Disabled:   m.Disabled,
		CreatedAt:  m.CreatedAt,
		LastSeen:   m.LastSeen,
	}
	if m.DiscoKey != "" {
		if dk, err := meshproto.ParseDiscoKey(m.DiscoKey); err == nil {
			n.DiscoKey = dk
		}
	}
	if m.Overlay != "" {
		if a, err := netip.ParseAddr(m.Overlay); err == nil {
			n.Overlay = a
		}
	}
	if n.Endpoints, err = parseAddrPorts(m.EndpointsJSON); err != nil {
		return nil, fmt.Errorf("coord store: endpoints: %w", err)
	}
	if n.AdvertisedRoutes, err = parsePrefixes(m.AdvertisedRoutesJSON); err != nil {
		return nil, fmt.Errorf("coord store: advertised_routes: %w", err)
	}
	if n.ApprovedRoutes, err = parsePrefixes(m.ApprovedRoutesJSON); err != nil {
		return nil, fmt.Errorf("coord store: approved_routes: %w", err)
	}
	n.RoutesReviewed = m.RoutesReviewed
	n.OwnerUserID = m.OwnerUserID
	n.DeviceFingerprint = m.DeviceFingerprint
	n.TagsPinned = m.TagsPinned
	n.Approved = m.Approved
	if n.Tags, err = unmarshalStrings(m.TagsJSON); err != nil {
		return nil, fmt.Errorf("coord store: tags: %w", err)
	}
	return n, nil
}

func discoText(k meshproto.DiscoKey) string {
	if k.IsZero() {
		return ""
	}
	return k.String()
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func addrPortsToStrings(eps []netip.AddrPort) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.String())
	}
	return out
}

func prefixesToStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func parseAddrPorts(blob string) ([]netip.AddrPort, error) {
	ss, err := unmarshalStrings(blob)
	if err != nil {
		return nil, err
	}
	out := make([]netip.AddrPort, 0, len(ss))
	for _, s := range ss {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, nil
}

func parsePrefixes(blob string) ([]netip.Prefix, error) {
	ss, err := unmarshalStrings(blob)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func marshalStrings(ss []string) (string, error) {
	if len(ss) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(ss)
	return string(b), err
}

func unmarshalStrings(blob string) ([]string, error) {
	if blob == "" {
		return nil, nil
	}
	var ss []string
	if err := json.Unmarshal([]byte(blob), &ss); err != nil {
		return nil, err
	}
	return ss, nil
}
