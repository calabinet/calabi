package selfhosted

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/platform/meshenroll"
	"github.com/calabinet/calabi/apps/client/internal/trust"
)

// What a self-hosted server lists — its devices, the tunnels its daemons serve,
// its traffic. Connected, a
// device reads over its live session. Not connected, it proves its node key for
// a read-only view session (OpenViewSession), which neither connects it nor ends
// a session it holds.

// ErrCannotView: the device is not connected and cannot open a view session —
// a coordinator from before node_reauth, which is also before view sessions.
var ErrCannotView = errors.New("connect to see this")

// Node is who this device is on a self-hosted server: enough to open a view
// session.
type Node struct {
	Server string
	Trust  trust.Config
	NodeID int64
	// Reauth: the coordinator takes this node back by proof alone, which is also
	// what a view session needs.
	Reauth bool
	Key    mesh.PrivateKey
}

// Viewer reads a self-hosted server's lists, keeping one view session until
// shortly before it expires. The zero value is ready to use.
type Viewer struct {
	mu   sync.Mutex
	view *viewConn
}

type viewConn struct {
	key  string // the server and node it was opened for
	conn *grpc.ClientConn
	cc   *mesh.CoordClient
	exp  time.Time
}

// Read runs read over live when there is a live session, else over a view
// session for the node node returns (called only when one has to be opened). A
// refused view session — the server restarted and forgot it — is reopened once.
func (v *Viewer) Read(ctx context.Context, live *mesh.CoordClient, node func() (Node, error), read func(*mesh.CoordClient) error) error {
	cc, err := v.reader(ctx, live, node)
	if err != nil {
		return err
	}
	err = read(cc)
	if status.Code(err) == codes.Unauthenticated && cc != live {
		v.Drop()
		if cc, err = v.reader(ctx, nil, node); err != nil {
			return err
		}
		err = read(cc)
	}
	return err
}

func (v *Viewer) reader(ctx context.Context, live *mesh.CoordClient, node func() (Node, error)) (*mesh.CoordClient, error) {
	if live != nil {
		return live, nil
	}
	n, err := node()
	if err != nil {
		return nil, err
	}
	if n.NodeID == 0 || !n.Reauth {
		return nil, ErrCannotView
	}
	key := fmt.Sprintf("%s|%d", n.Server, n.NodeID)
	v.mu.Lock()
	defer v.mu.Unlock()
	if cur := v.view; cur != nil && cur.key == key && time.Until(cur.exp) > 30*time.Second {
		return cur.cc, nil
	}
	v.closeLocked()
	tlsCfg, err := n.Trust.TLS(n.Server)
	if err != nil {
		return nil, err
	}
	conn, err := meshenroll.DialCoord(n.Server, tlsCfg)
	if err != nil {
		return nil, err
	}
	cc := mesh.NewCoordClient(conn)
	exp, err := cc.OpenViewSession(ctx, n.NodeID, n.Key.Public(), n.Key)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	v.view = &viewConn{key: key, conn: conn, cc: cc, exp: exp}
	return cc, nil
}

// Drop forgets the view session: the device left or changed servers, or its
// trust in the server changed.
func (v *Viewer) Drop() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closeLocked()
}

func (v *Viewer) closeLocked() {
	if v.view != nil {
		_ = v.view.conn.Close()
		v.view = nil
	}
}

// ReadFailure is how a failed read is explained to a person: a stable code and
// the HTTP status to answer with.
func ReadFailure(err error) (httpStatus int, code string) {
	switch {
	case errors.Is(err, ErrCannotView):
		return 409, "not_connected"
	case status.Code(err) == codes.NotFound, status.Code(err) == codes.FailedPrecondition:
		return 409, "needs_invite"
	case status.Code(err) == codes.PermissionDenied:
		return 403, "disabled"
	}
	return 502, "unreachable"
}
