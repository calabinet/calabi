package rpc

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

type inviteRig struct {
	c    meshpb.CoordinatorClient
	keys *core.MemAuthKeyStore
	auth *core.KeyAuth
	now  *time.Time
}

// startInviteServer runs a self-hosted coordinator: a key file with one entry,
// plus minted keys. quota caps its devices (0 = none).
func startInviteServer(t *testing.T, quota int) inviteRig {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	keys := core.NewMemAuthKeyStore()
	now := time.Now()
	coord := &core.Coordinator{
		Nodes:    core.NewMemNodeStore(),
		Policy:   core.AllowAllPolicy{},
		IPAM:     core.NewMemIPAM(),
		DERP:     core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
		AuthKeys: keys,
	}
	if quota > 0 {
		coord.Quota = core.StaticNodeQuota{Limit: quota}
	}
	rig := inviteRig{keys: keys, now: &now}
	rig.auth = &core.KeyAuth{
		Static: core.StaticAuth{Keys: map[string]core.Identity{"file-key": {Meshnet: 1}}},
		Keys:   keys,
		Now:    func() time.Time { return *rig.now },
	}
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, New(coord, rig.auth, core.NewNotifier(), slog.Default()))
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); gs.Stop(); _ = lis.Close() })
	rig.c = meshpb.NewCoordinatorClient(conn)
	return rig
}

func (r inviteRig) mint(t *testing.T, edit func(*core.AuthKey)) (string, *core.AuthKey) {
	t.Helper()
	secret, k, err := core.NewAuthKey(1)
	if err != nil {
		t.Fatal(err)
	}
	k.MaxUses = 1
	if edit != nil {
		edit(k)
	}
	saved, err := r.keys.CreateAuthKey(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	return secret, saved
}

func (r inviteRig) uses(t *testing.T, secret string) int {
	t.Helper()
	k, err := r.keys.AuthKeyByHash(context.Background(), core.HashAuthKey(secret))
	if err != nil {
		t.Fatal(err)
	}
	return k.Uses
}

// A one-time key admits one device. That device may present it again — a
// desktop with it in its config file does after every restart — without
// spending anything; a second device is refused.
func TestOneTimeKeyAdmitsOneDevice(t *testing.T) {
	r := startInviteServer(t, 0)
	ctx := context.Background()
	secret, _ := r.mint(t, func(k *core.AuthKey) { k.Tags = []string{"tag:phone"} })

	phone := enroll(t, r.c, secret, "phone")
	if got := r.uses(t, secret); got != 1 {
		t.Fatalf("uses after the first device = %d, want 1", got)
	}
	again, err := enrollAs(ctx, r.c, secret, "phone", phone.key, phone.priv, nil)
	if err != nil || again.GetNodeId() != phone.id {
		t.Fatalf("the admitted device presenting the key again: %v (node %d, want %d)", err, again.GetNodeId(), phone.id)
	}
	if got := r.uses(t, secret); got != 1 {
		t.Fatalf("uses after the same device came back = %d, want still 1", got)
	}
	key, priv := newKeyPair(t)
	if _, err := enrollAs(ctx, r.c, secret, "laptop", key, priv, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a second device with a one-time key: err = %v, want Unauthenticated", err)
	}
	// The key-file entry is unaffected and unlimited.
	enroll(t, r.c, "file-key", "server-1")
	enroll(t, r.c, "file-key", "server-2")
}

// Expiry stops NEW devices; the device the key already admitted is not locked
// out by it.
func TestExpiredKeyStillLetsItsDeviceBack(t *testing.T) {
	r := startInviteServer(t, 0)
	ctx := context.Background()
	secret, _ := r.mint(t, func(k *core.AuthKey) { k.MaxUses, k.ExpiresAt = 0, time.Now().Add(time.Hour) })
	laptop := enroll(t, r.c, secret, "laptop")

	*r.now = time.Now().Add(2 * time.Hour)
	if _, err := enrollAs(ctx, r.c, secret, "laptop", laptop.key, laptop.priv, nil); err != nil {
		t.Fatalf("the admitted device after expiry: %v", err)
	}
	key, priv := newKeyPair(t)
	if _, err := enrollAs(ctx, r.c, secret, "late", key, priv, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a new device after expiry: err = %v, want Unauthenticated", err)
	}
}

// Revoking refuses the key outright — at the challenge, for anyone — while a
// device it admitted keeps coming back by proof alone.
func TestRevokedKeyIsRefusedButItsDevicesStay(t *testing.T) {
	r := startInviteServer(t, 0)
	ctx := context.Background()
	secret, k := r.mint(t, func(k *core.AuthKey) { k.MaxUses = 0 })
	phone := enroll(t, r.c, secret, "phone")

	if err := r.keys.RevokeAuthKey(ctx, 1, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: secret}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("challenge with a revoked key: err = %v, want Unauthenticated", err)
	}
	if _, err := reauth(ctx, r.c, phone, "phone"); err != nil {
		t.Fatalf("the admitted device by proof alone after its key was revoked: %v", err)
	}
}

// An enrollment that fails after the key was spent gives the use back.
func TestFailedEnrollmentGivesTheUseBack(t *testing.T) {
	r := startInviteServer(t, 1) // one device fits
	ctx := context.Background()
	enroll(t, r.c, "file-key", "first")
	secret, _ := r.mint(t, nil)

	key, priv := newKeyPair(t)
	if _, err := enrollAs(ctx, r.c, secret, "second", key, priv, nil); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over quota: err = %v, want ResourceExhausted", err)
	}
	if got := r.uses(t, secret); got != 0 {
		t.Fatalf("uses after a refused enrollment = %d, want 0 (given back)", got)
	}
}

// A self-hosted coordinator lists the caller's whole meshnet — reachable or
// not, disabled included — to its own devices; an identity-backed one refuses,
// since there the platform's API decides who sees which device.
func TestListNodesIsForSelfHostedCoordinators(t *testing.T) {
	r := startInviteServer(t, 0)
	ctx := context.Background()
	phone := enroll(t, r.c, "file-key", "phone")
	laptop := enroll(t, r.c, "file-key", "laptop")
	resp, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: phone.token})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, n := range resp.GetNodes() {
		names[n.GetName()] = true
		if n.GetId() == laptop.id && n.GetOverlayAddr() != laptop.overlay {
			t.Errorf("laptop overlay %q, want %q", n.GetOverlayAddr(), laptop.overlay)
		}
	}
	if !names["phone"] || !names["laptop"] {
		t.Fatalf("listed %v, want both devices", names)
	}
	if _, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: "made-up"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("without a session: %v", err)
	}

	platform := startReauthServer(t)
	n, _ := enrollWithCaps(t, platform.c, "alice-token", "laptop")
	if _, err := platform.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: n.token}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("identity-backed coordinator: err = %v, want PermissionDenied", err)
	}
}
