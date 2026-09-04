package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Services are what a node OFFERS on the mesh: "this machine serves postgres on
// 5432". They are DECLARED by a person, never discovered by scanning the node — (a rejected proposal to report a
// node's listening ports) and the rule it distilled: declaration over discovery.
//
// A service is also the unit access will be granted against (an ACL "svc:<name>"
// selector), which is why the name is validated like a label and why a node's
// declaration is only a CLAIM: a node that could name its own services could
// name one that is granted access, i.e. self-assert its way into traffic meant
// for someone else. Same reasoning as Identity.Tags. So the node DECLARES and an
// admin APPROVES — those are the only two steps, and the console cannot invent a
// service the machine never claimed.
//
// Names are NOT unique in a meshnet on purpose: three nodes serving "web" are
// one logical service with three instances, and one rule should cover them.
// Within a single node a name is unique (a node has one "web").

// Service is one declared endpoint on a node.
type Service struct {
	ID      int64     `json:"id"`
	Meshnet MeshnetID `json:"meshnet"`
	NodeID  int64     `json:"node_id"`
	Name    string    `json:"name"`
	Proto   string    `json:"proto"` // "tcp" or "udp"
	// Port is what MESH PEERS dial on this node's overlay address. It is not
	// necessarily where the application listens — see Target.
	Port int `json:"port"`
	// Target is what the DEVICE ITSELF dials to reach the application, e.g.
	// "127.0.0.1:5432" or a box on its LAN. Empty means 127.0.0.1:<port>.
	//
	// The two are separate because they answer different questions, and the gap
	// between them is the single most confusing thing about a service: the
	// packet filter opening Port does nothing if the application is bound to
	// loopback only, because a peer's packet arrives on the tun interface with
	// the overlay address as its destination and finds no socket there.
	//
	// It is also what makes a service and a tunnel the same shape: a tunnel's
	// local_addr IS this address, which is why publishing one needs no second
	// piece of information.
	Target string `json:"target"`
	Note   string `json:"note"`
	// Source says who authored this row: ServiceSourceNode (the machine's config
	// declared it — a claim) or ServiceSourceConsole (an admin entered it — an
	// authorization). Empty reads as node, so rows that predate the field keep
	// being reconciled against their device exactly as before.
	Source string `json:"source"`
	// Approved gates ACL visibility. A declaration is a CLAIM: until an admin
	// confirms it, no "svc:" rule matches it. Defaults TRUE in storage so
	// services that predate the pending state never silently stop matching.
	Approved  bool      `json:"approved"`
	CreatedAt time.Time `json:"created_at"`
}

// Service sources. A row's source decides who may change it: a device's
// declaration can never modify — or shadow — one an admin entered.
const (
	ServiceSourceNode    = "node"
	ServiceSourceConsole = "console"
)

// FromConsole reports whether an admin authored this row. Written as a helper
// because the zero value must read as "node": rows stored before the field
// existed came from devices, and treating them as console-authored would strand
// them outside reconciliation forever.
func (s Service) FromConsole() bool { return s.Source == ServiceSourceConsole }

// maxDeclaredServicesPerNode caps what one node may propose in a registration.
// A claim costs a row and a line in the console's pending list, so it needs a
// ceiling; nothing legitimate declares dozens of services on one machine.
const maxDeclaredServicesPerNode = 32

var (
	// ErrInvalidService is returned for a service that isn't usable (bad label,
	// unknown protocol, out-of-range port).
	ErrInvalidService = errors.New("core: invalid service")
	// ErrServiceExists is returned when a node already has that service name.
	// The (node, name) index still enforces it, so a concurrent re-registration
	// of the same node can trip it even though reconcile checks first.
	ErrServiceExists = errors.New("core: node already declares this service")
	// ErrServiceNotFound is returned for an unknown service id.
	ErrServiceNotFound = errors.New("core: service not found")
)

// ServiceStore persists declared services. Optional: a coordinator without one
// simply has no service registry (ACL selectors then match nothing).
type ServiceStore interface {
	// ListServices returns every service in the meshnet.
	ListServices(ctx context.Context, t MeshnetID) ([]Service, error)
	// CreateService stores a new one and returns it with its id.
	CreateService(ctx context.Context, s Service) (*Service, error)
	// DeleteService removes one by id; ErrServiceNotFound if unknown.
	DeleteService(ctx context.Context, id int64) error
	// UpdateService rewrites a service's mutable fields (proto/port/note/approved)
	// by id; ErrServiceNotFound if unknown.
	UpdateService(ctx context.Context, s Service) error
}

// ValidateService checks a declaration before it is stored. The name is a label
// (same alphabet as a node name) because it will be an ACL selector; the
// protocol is tcp/udp; the port is a real port. Pure — expects a normalized name.
func ValidateService(name, proto string, port int) error {
	if err := ValidateNodeName(name); err != nil {
		return fmt.Errorf("%w: name: %s", ErrInvalidService, strings.TrimPrefix(err.Error(), "core: invalid node name: "))
	}
	switch proto {
	case "tcp", "udp":
	default:
		return fmt.Errorf("%w: protocol %q (use tcp or udp)", ErrInvalidService, proto)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d out of range (1-65535)", ErrInvalidService, port)
	}
	return nil
}

// TargetAddr is the address the device dials for this service, defaulting to
// loopback on the declared port.
func (s Service) TargetAddr() string {
	if t := strings.TrimSpace(s.Target); t != "" {
		return t
	}
	return "127.0.0.1:" + strconv.Itoa(s.Port)
}

// ValidateServiceTarget checks an explicit target. Empty is always fine (it
// means loopback on the service's own port). Pure.
func ValidateServiceTarget(target string) error {
	// Shared with the client so the two cannot drift — a target this side
	// rejects is skipped, not reported (see meshproto.ValidateHostPort).
	if err := meshproto.ValidateHostPort(target); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidService,
			strings.TrimPrefix(err.Error(), "invalid label: "))
	}
	return nil
}

// SetServiceApproved confirms (or un-confirms) a service a NODE declared. This
// is the authorization step: until it happens, no "svc:" rule matches the entry,
// so a machine cannot pull authorized traffic to itself by naming a service it
// does not own.
func (c *Coordinator) SetServiceApproved(ctx context.Context, t MeshnetID, id int64, approved bool) (*Service, error) {
	if c.Services == nil {
		return nil, fmt.Errorf("core: service registry not supported")
	}
	svcs, err := c.Services.ListServices(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list services: %w", err)
	}
	for _, s := range svcs {
		if s.ID != id {
			continue
		}
		s.Approved = approved
		if err := c.Services.UpdateService(ctx, s); err != nil {
			return nil, fmt.Errorf("core: update service: %w", err)
		}
		if c.Logger != nil {
			c.Logger.Info("service approval changed", "meshnet", t, "service_id", id, "name", s.Name, "approved", approved)
		}
		return &s, nil
	}
	// ListServices is meshnet-scoped, so an id from another tenant lands here.
	return nil, ErrServiceNotFound
}

// reconcileDeclaredServices brings the node-sourced entries in line with what the
// node declares right now. It mirrors the subnet-route model exactly:
//
//   - a NEW declaration is stored PENDING (a claim, not a fact);
//   - an unchanged declaration keeps whatever the admin decided about it;
//   - a declaration whose proto/port CHANGED goes back to pending, because the
//     admin approved a specific endpoint and this is a different one;
//   - a declaration the node STOPPED making is removed — a machine that no longer
//     offers a service must stop being a valid target for rules about it.
//
// This is the ONLY way a service enters the registry: the console approves and
// un-approves, it never invents one. So an entry that is here but undeclared is
// necessarily stale, and removing it is always right.
//
// Best-effort by design: this runs inside registration, and a service-registry
// hiccup must not keep a machine off the mesh. Errors are returned for the
// caller to log, never to fail the enrollment.
func (c *Coordinator) reconcileDeclaredServices(ctx context.Context, node *Node, declared []Service) error {
	if c.Services == nil {
		return nil
	}
	if len(declared) > maxDeclaredServicesPerNode {
		declared = declared[:maxDeclaredServicesPerNode]
	}
	// Normalize + drop anything unusable. A typo in a config file costs that one
	// line, not the machine's enrollment.
	want := make(map[string]Service, len(declared))
	for _, d := range declared {
		name := NormalizeNodeName(d.Name)
		proto := strings.ToLower(strings.TrimSpace(d.Proto))
		if err := ValidateService(name, proto, d.Port); err != nil {
			if c.Logger != nil {
				c.Logger.Warn("ignoring unusable service declaration", "node_id", node.ID, "name", d.Name, "err", err)
			}
			continue
		}
		if _, dup := want[name]; dup {
			continue // a node has one service per name; first wins
		}
		target := strings.TrimSpace(d.Target)
		if err := ValidateServiceTarget(target); err != nil {
			// Same posture as an unusable name or port: a typo costs that one
			// line, not the machine's enrollment.
			if c.Logger != nil {
				c.Logger.Warn("ignoring service declaration with an unusable target", "node_id", node.ID, "name", name, "err", err)
			}
			continue
		}
		want[name] = Service{
			Meshnet: node.Meshnet, NodeID: node.ID, Name: name, Proto: proto,
			Port: d.Port, Target: target, Note: strings.TrimSpace(d.Note),
		}
	}

	existing, err := c.Services.ListServices(ctx, node.Meshnet)
	if err != nil {
		return fmt.Errorf("core: list services: %w", err)
	}
	seen := map[string]bool{}
	for _, cur := range existing {
		if cur.NodeID != node.ID {
			continue
		}
		seen[cur.Name] = true
		if cur.FromConsole() {
			// An admin authored this row. A device's declaration must not modify
			// it, withdraw it, or push it back to pending — and marking the name
			// seen above is what stops a same-named declaration creating a SHADOW
			// row beside it, which would leave two entries claiming one name and
			// only one of them carrying the authorization.
			continue
		}
		d, still := want[cur.Name]
		if !still {
			if err := c.Services.DeleteService(ctx, cur.ID); err != nil && !errors.Is(err, ErrServiceNotFound) {
				return fmt.Errorf("core: withdraw service %d: %w", cur.ID, err)
			}
			if c.Logger != nil {
				c.Logger.Info("service declaration withdrawn", "node_id", node.ID, "service", cur.Name)
			}
			continue
		}
		if cur.Proto == d.Proto && cur.Port == d.Port && cur.Target == d.Target && cur.Note == d.Note {
			continue // unchanged; keep the admin's decision
		}
		// The admin approved a specific ENDPOINT, and where the traffic actually
		// ends up is part of it: protocol, the port peers dial, and the address
		// behind them. A note is prose and changes nothing.
		endpointChanged := cur.Proto != d.Proto || cur.Port != d.Port || cur.Target != d.Target
		upd := cur
		upd.Proto, upd.Port, upd.Target, upd.Note = d.Proto, d.Port, d.Target, d.Note
		if endpointChanged {
			upd.Approved = false
		}
		if err := c.Services.UpdateService(ctx, upd); err != nil {
			return fmt.Errorf("core: update service %d: %w", cur.ID, err)
		}
		if c.Logger != nil {
			c.Logger.Info("service declaration changed", "node_id", node.ID, "service", cur.Name,
				"proto", d.Proto, "port", d.Port, "re_pending", endpointChanged)
		}
	}
	for name, d := range want {
		if seen[name] {
			continue
		}
		if _, err := c.Services.CreateService(ctx, d); err != nil {
			return fmt.Errorf("core: record declaration %q: %w", name, err)
		}
		if c.Logger != nil {
			c.Logger.Info("service declared by node (pending confirmation)", "node_id", node.ID,
				"service", name, "proto", d.Proto, "port", d.Port)
		}
	}
	return nil
}

// CreateConsoleService records a service an ADMIN entered, rather than one a
// device declared.
//
// It starts confirmed: creating it here IS the authorization, and asking someone
// to confirm what they just typed would be theatre. That also marks the line
// this method sits on — a device's claim needs a second human step, an admin's
// entry is already that step.
//
// Why this is safe now and wasn't before: a service name used to decide WHICH
// MACHINES a rule covered, so inventing one here would have been inventing
// group membership. demoted "svc:" to naming ports on the declaring
// device only, so a console entry now says no more than "this machine offers
// this port" — a statement an admin is entitled to make.
func (c *Coordinator) CreateConsoleService(ctx context.Context, t MeshnetID, nodeID int64, name, proto string, port int, target, note string) (*Service, error) {
	if c.Services == nil {
		return nil, fmt.Errorf("core: service registry not supported")
	}
	name = NormalizeNodeName(name)
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = "tcp"
	}
	if err := ValidateService(name, proto, port); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	if err := ValidateServiceTarget(target); err != nil {
		return nil, err
	}
	// The node must be in the CALLER's meshnet. Without this the id in a request
	// would be enough to attach a service to a stranger's machine.
	node, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if node.Meshnet != t {
		return nil, ErrNodeNotFound
	}
	existing, err := c.Services.ListServices(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list services: %w", err)
	}
	for _, s := range existing {
		if s.NodeID == nodeID && s.Name == name {
			return nil, ErrServiceExists
		}
	}
	out, err := c.Services.CreateService(ctx, Service{
		Meshnet: t, NodeID: nodeID, Name: name, Proto: proto, Port: port, Target: target,
		Note: strings.TrimSpace(note), Source: ServiceSourceConsole, Approved: true,
	})
	if err != nil {
		return nil, fmt.Errorf("core: create service: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("service created in console", "meshnet", t, "node_id", nodeID,
			"service", name, "proto", proto, "port", port)
	}
	return out, nil
}

// DeleteConsoleService removes an admin-authored service.
//
// Only console rows. A device-declared row would simply come back — pending —
// on that machine's next registration, so deleting one looks like it failed;
// un-confirming it is the action that actually means something.
func (c *Coordinator) DeleteConsoleService(ctx context.Context, t MeshnetID, id int64) error {
	if c.Services == nil {
		return fmt.Errorf("core: service registry not supported")
	}
	svcs, err := c.Services.ListServices(ctx, t)
	if err != nil {
		return fmt.Errorf("core: list services: %w", err)
	}
	for _, s := range svcs {
		if s.ID != id {
			continue
		}
		if !s.FromConsole() {
			return fmt.Errorf("%w: this service is declared by the device's own config; un-confirm it instead of deleting (it would be recreated on the machine's next registration)", ErrInvalidService)
		}
		if err := c.Services.DeleteService(ctx, id); err != nil {
			return fmt.Errorf("core: delete service: %w", err)
		}
		if c.Logger != nil {
			c.Logger.Info("console service deleted", "meshnet", t, "service_id", id, "name", s.Name)
		}
		return nil
	}
	// ListServices is meshnet-scoped, so an id from another tenant lands here.
	return ErrServiceNotFound
}

// ServicesFor returns the meshnet's declared services (empty when the build has
// no registry).
func (c *Coordinator) ServicesFor(ctx context.Context, t MeshnetID) ([]Service, error) {
	if c.Services == nil {
		return nil, nil
	}
	return c.Services.ListServices(ctx, t)
}

// MemServiceStore is an in-memory ServiceStore (dev / tests / community).
type MemServiceStore struct {
	mu   sync.Mutex
	next int64
	m    map[int64]Service
}

func NewMemServiceStore() *MemServiceStore {
	return &MemServiceStore{m: map[int64]Service{}}
}

func (s *MemServiceStore) ListServices(_ context.Context, t MeshnetID) ([]Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Service, 0, len(s.m))
	for _, v := range s.m {
		if v.Meshnet == t {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemServiceStore) CreateService(_ context.Context, in Service) (*Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	in.ID = s.next
	in.CreatedAt = time.Now()
	s.m[in.ID] = in
	out := in
	return &out, nil
}

func (s *MemServiceStore) UpdateService(_ context.Context, in Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[in.ID]
	if !ok {
		return ErrServiceNotFound
	}
	cur.Proto, cur.Port, cur.Target, cur.Note, cur.Approved = in.Proto, in.Port, in.Target, in.Note, in.Approved
	s.m[in.ID] = cur
	return nil
}

func (s *MemServiceStore) DeleteService(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return ErrServiceNotFound
	}
	delete(s.m, id)
	return nil
}

// MeshnetSettings are a meshnet's org-level switches (MESH.8e-5). The zero value
// is what every meshnet runs on until an admin changes something.
type MeshnetSettings struct {
	RequireDeviceApproval bool `json:"require_device_approval"`
}

// SettingsStore persists per-meshnet settings. Optional: without one every
// meshnet runs on defaults and the switches aren't available.
type SettingsStore interface {
	GetSettings(ctx context.Context, t MeshnetID) (MeshnetSettings, error)
	SetSettings(ctx context.Context, t MeshnetID, s MeshnetSettings) error
}

// MemSettingsStore is an in-memory SettingsStore (dev / tests / community).
type MemSettingsStore struct {
	mu sync.Mutex
	m  map[MeshnetID]MeshnetSettings
}

func NewMemSettingsStore() *MemSettingsStore {
	return &MemSettingsStore{m: map[MeshnetID]MeshnetSettings{}}
}

func (s *MemSettingsStore) GetSettings(_ context.Context, t MeshnetID) (MeshnetSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[t], nil
}

func (s *MemSettingsStore) SetSettings(_ context.Context, t MeshnetID, in MeshnetSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[t] = in
	return nil
}
