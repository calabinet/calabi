// Package filecontrol is the machine service's METADATA-ONLY bridge to an
// ordinary user's file agent. No path, private key, file name or body crosses
// this boundary. OS-authenticated IPC is mandatory; loopback tokens cannot
// identify the desktop user who is allowed to own the receiving session.
package filecontrol

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type Peer struct {
	Grant       filetransfer.Grant `json:"grant"`
	Name        string             `json:"name"`
	Incoming    bool               `json:"incoming"`
	ExpiresUnix int64              `json:"expires_unix"`
}
type Snapshot struct {
	OwnsLease bool     `json:"owns_lease"`
	Members   []Member `json:"members"`
	Ready     bool     `json:"ready"`
	Scope     string   `json:"scope"`
	NodeKey   string   `json:"node_key"`
	Overlay   string   `json:"overlay"`
	RelayKbps uint32   `json:"relay_kbps"`
	Peers     []Peer   `json:"peers"`
}
type Source struct {
	View    func() (Snapshot, error)
	Publish func(context.Context, string, *meshpb.FileTransferInfo) error
	// Receiving adjusts only the installer's fixed file-port firewall rule.
	// No caller-supplied address, executable or port is passed to it.
	Receiving func(context.Context, bool) error
}

type Member struct {
	IP        string `json:"ip"`
	DeviceKey string `json:"device_key"`
	Incoming  bool   `json:"incoming"`
}
type Request struct {
	Op    string                   `json:"op"`
	Scope string                   `json:"scope,omitempty"`
	Lease string                   `json:"lease,omitempty"`
	Info  *meshpb.FileTransferInfo `json:"info,omitempty"`
}
type Response struct {
	Snapshot Snapshot `json:"snapshot"`
	Error    string   `json:"error,omitempty"`
}
type Control struct {
	Source    Source
	mu        sync.Mutex
	owner     string
	lease     string
	scope     string
	expires   time.Time
	receiving bool
}

// ReconcileReception closes the host exception after an agent lease expires or
// the mesh session changes, even if no further IPC requests arrive.
func (c *Control) ReconcileReception(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.receiving {
		return c.setReceiving(ctx, false)
	}
	view, err := c.Source.View()
	if c.receiving && (err != nil || !view.Ready || c.scope != view.Scope || !time.Now().Before(c.expires)) {
		return c.setReceiving(ctx, false)
	}
	return nil
}

func (c *Control) setReceiving(ctx context.Context, receiving bool) error {
	if c.Source.Receiving != nil {
		if err := c.Source.Receiving(ctx, receiving); err != nil {
			return err
		}
	}
	c.receiving = receiving
	return nil
}

// StopReception is also called on startup to close a rule left by a crashed
// daemon, and on shutdown without relying on a desktop agent's cleanup.
func (c *Control) StopReception(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setReceiving(ctx, false)
}

// Bind metadata IPC to the exact supervised daemon, including dev/fallback
// ports. A global pipe could accidentally attach a preview UI to another
// daemon's organization when both instances run on the same machine.
func EndpointForConsole(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("exact local daemon console URL required")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("local console port required")
	}
	return fmt.Sprintf(`\\.\pipe\Calabi.FileControl.v1.%d`, port), nil
}

// Handle is called ONLY after the transport resolves the kernel's peer identity.
// A different SID/UID, or a second process without the random lease, cannot
// replace an active receiver. First claim is explicit local opt-in; a dead
// agent's ownership expires along with its coordinator declaration.
func (c *Control) Handle(ctx context.Context, principal string, req Request) Response {
	fail := func(err error) Response { return Response{Error: err.Error()} }
	if principal == "" {
		return fail(errors.New("OS user identity unavailable"))
	}
	view, err := c.Source.View()
	if err != nil {
		return fail(err)
	}
	if req.Op == "snapshot" {
		c.mu.Lock()
		view.OwnsLease = c.owner == principal && c.scope == view.Scope && time.Now().Before(c.expires) && subtle.ConstantTimeCompare([]byte(c.lease), []byte(req.Lease)) == 1
		c.mu.Unlock()
		return Response{Snapshot: view}
	}
	if req.Op != "publish" || !view.Ready || req.Scope != view.Scope {
		return fail(errors.New("mesh session changed or unavailable"))
	}
	token, err := hex.DecodeString(req.Lease)
	if err != nil || len(token) != 32 {
		return fail(errors.New("invalid local agent lease"))
	}
	key, err := meshproto.ParseNodeKey(view.NodeKey)
	if err != nil {
		return fail(err)
	}
	if req.Info != nil {
		if req.Info.Port != 17401 {
			return fail(errors.New("unsupported file listener port"))
		}
		if _, err := meshproto.VerifyFileTransfer(key, req.Info, time.Now()); err != nil {
			return fail(err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	owned := c.scope == view.Scope && time.Now().Before(c.expires)
	if owned && (c.owner != principal || subtle.ConstantTimeCompare([]byte(c.lease), []byte(req.Lease)) != 1) {
		return fail(errors.New("another local user session owns file transfers"))
	}
	if req.Info == nil && !owned {
		return Response{Snapshot: view}
	}
	// Reserve ownership before the RPC: a lost response cannot unlock a
	// declaration that may already have reached the coordinator.
	if req.Info != nil {
		c.owner = principal
		c.lease = req.Lease
		c.scope = view.Scope
		c.expires = time.Unix(req.Info.ExpiresUnix, 0)
	}
	if err := c.setReceiving(ctx, req.Info != nil && req.Info.Receiving); err != nil {
		return fail(err)
	}
	if err := c.Source.Publish(ctx, view.Scope, req.Info); err != nil {
		return fail(err)
	}
	if req.Info == nil {
		c.owner = ""
		c.lease = ""
		c.scope = ""
		c.expires = time.Time{}
	} else {
		c.owner = principal
		c.lease = req.Lease
		c.scope = view.Scope
		c.expires = time.Unix(req.Info.ExpiresUnix, 0)
	}
	view.OwnsLease = req.Info != nil
	return Response{Snapshot: view}
}
