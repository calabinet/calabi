package core

import (
	"context"
	"errors"
	"testing"
)

// memberQuotaFake implements both halves so the coordinator picks the
// member-aware one, and records what it was asked.
type memberQuotaFake struct {
	orgCalls         int
	memberCalls      int
	lastCurrent      int
	lastOwnerCurrent int
	lastOwner        int64
	deny             bool
}

func (f *memberQuotaFake) Admit(_ context.Context, _ MeshnetID, current int) (bool, int, string, error) {
	f.orgCalls++
	f.lastCurrent = current
	return true, -1, "", nil
}

func (f *memberQuotaFake) AdmitMember(_ context.Context, _ MeshnetID, owner int64, current, ownerCurrent int) (bool, int, string, error) {
	f.memberCalls++
	f.lastCurrent, f.lastOwnerCurrent, f.lastOwner = current, ownerCurrent, owner
	if f.deny {
		return false, 1, "member limit 1 reached for mesh_node", nil
	}
	return true, -1, "", nil
}

// orgOnlyQuota is the older contract — what a self-hosted coordinator plugs in.
type orgOnlyQuota struct{ calls int }

func (q *orgOnlyQuota) Admit(context.Context, MeshnetID, int) (bool, int, string, error) {
	q.calls++
	return true, -1, "", nil
}

// The member seat count is the enrolling person's own active nodes, while the
// org count stays the whole meshnet.
func TestRegisterAsksForTheOwnersOwnSeatCount(t *testing.T) {
	c := newTestCoord()
	fake := &memberQuotaFake{}
	c.Quota = fake
	ctx := context.Background()

	for i, in := range []RegisterInput{
		{Meshnet: 1, Name: "a", NodeKey: key(1), OwnerUserID: 7},
		{Meshnet: 1, Name: "b", NodeKey: key(2), OwnerUserID: 7},
		{Meshnet: 1, Name: "c", NodeKey: key(3), OwnerUserID: 8},
	} {
		if _, err := c.Register(ctx, in); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "d", NodeKey: key(4), OwnerUserID: 7}); err != nil {
		t.Fatalf("register d: %v", err)
	}
	if fake.lastOwner != 7 {
		t.Fatalf("owner = %d, want 7", fake.lastOwner)
	}
	if fake.lastOwnerCurrent != 2 {
		t.Fatalf("ownerCurrent = %d, want 2 (user 7's own nodes, not user 8's)", fake.lastOwnerCurrent)
	}
	if fake.lastCurrent != 3 {
		t.Fatalf("current = %d, want 3 (every active node in the meshnet)", fake.lastCurrent)
	}
}

// No owner (self-hosted StaticAuth, legacy api-keys) → the org-only question,
// exactly as before member quotas existed.
func TestRegisterWithoutOwnerUsesOrgOnlyAdmit(t *testing.T) {
	c := newTestCoord()
	fake := &memberQuotaFake{}
	c.Quota = fake
	ctx := context.Background()

	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if fake.memberCalls != 0 {
		t.Fatalf("an unattributed enrolment must not ask the member question, got %d calls", fake.memberCalls)
	}
	if fake.orgCalls != 1 {
		t.Fatalf("orgCalls = %d, want 1", fake.orgCalls)
	}
}

// A backend that only implements the published NodeQuota contract keeps
// working — that interface is what outside self-hosters implement.
func TestOrgOnlyBackendStillWorks(t *testing.T) {
	c := newTestCoord()
	q := &orgOnlyQuota{}
	c.Quota = q
	ctx := context.Background()

	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1), OwnerUserID: 7}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if q.calls != 1 {
		t.Fatalf("the org-only backend should have been asked once, got %d", q.calls)
	}
}

// A member-scoped refusal comes back as the same quota error the org-level one
// does, so the RPC layer keeps mapping it to ResourceExhausted.
func TestMemberQuotaRefusalIsANodeQuotaError(t *testing.T) {
	c := newTestCoord()
	c.Quota = &memberQuotaFake{deny: true}

	_, err := c.Register(context.Background(), RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1), OwnerUserID: 7})
	if !errors.Is(err, ErrNodeQuotaExceeded) {
		t.Fatalf("err = %v, want ErrNodeQuotaExceeded", err)
	}
}

// A disabled node frees its owner's seat exactly as it frees the org's. If the
// two layers disagreed, an admin disabling a device would fix the org total and
// leave its owner still locked out.
func TestOwnerSeatCountSkipsDisabledAndOtherOwners(t *testing.T) {
	nodes := []*Node{
		{OwnerUserID: 7},
		{OwnerUserID: 7, Disabled: true},
		{OwnerUserID: 8},
		{}, // unattributed
	}
	if got := ownerSeatCount(nodes, 7); got != 1 {
		t.Fatalf("ownerSeatCount(7) = %d, want 1", got)
	}
	if got := ownerSeatCount(nodes, 0); got != 0 {
		t.Fatalf("ownerSeatCount(0) = %d, want 0 — nobody owns the unattributed nodes", got)
	}
}
