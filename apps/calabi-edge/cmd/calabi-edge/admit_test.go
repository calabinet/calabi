package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type fakeIdentity struct {
	count int32
	err   error
}

func (f *fakeIdentity) GetOrgOnlineCount(ctx context.Context, orgID int64) (int32, error) {
	return f.count, f.err
}

type fakeQuota struct {
	limit int64
	err   error
}

func (f *fakeQuota) OnlineClientLimit(ctx context.Context, orgID int64) (int64, error) {
	return f.limit, f.err
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Under-cap orgs admit.
func TestOnlineCapAdapter_UnderCapAdmits(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{count: 1},
		quotaCli:    &fakeQuota{limit: 5},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if !d.Allowed {
		t.Fatalf("want allowed, got %+v", d)
	}
	if d.Current != 1 || d.Limit != 5 {
		t.Errorf("decision counters = (%d/%d), want (1/5)", d.Current, d.Limit)
	}
}

// At-cap orgs refuse — current=limit means the +1 would tip over.
func TestOnlineCapAdapter_AtCapRefuses(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{count: 1},
		quotaCli:    &fakeQuota{limit: 1},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if d.Allowed {
		t.Fatalf("want refused at cap, got %+v", d)
	}
	if d.Reason == "" {
		t.Errorf("want non-empty refusal reason")
	}
}

// Unlimited plan (limit=-1) always admits, even with huge counts.
func TestOnlineCapAdapter_UnlimitedAdmits(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{count: 99999},
		quotaCli:    &fakeQuota{limit: -1},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if !d.Allowed {
		t.Fatalf("want allowed for unlimited, got %+v", d)
	}
	if d.Limit != -1 {
		t.Errorf("limit = %d, want -1 (unlimited)", d.Limit)
	}
}

// Non-numeric tenant_id bypasses the
// gate — those clients have no org row to count against.
func TestOnlineCapAdapter_NonNumericTenantAdmits(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{count: 99},
		quotaCli:    &fakeQuota{limit: 0}, // would refuse if it got this far
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "dev")
	if !d.Allowed {
		t.Fatalf("want allowed for dev tenant, got %+v", d)
	}
}

// Quota-svc unreachable ⇒ refuse. Admitting on error silently breaks
// the cap.
func TestOnlineCapAdapter_QuotaErrorRefuses(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{count: 1},
		quotaCli:    &fakeQuota{err: errors.New("quota down")},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if d.Allowed {
		t.Fatalf("want refused on quota error, got %+v", d)
	}
}

// Identity-svc unreachable ⇒ refuse. Same fail-closed policy.
func TestOnlineCapAdapter_IdentityErrorRefuses(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: &fakeIdentity{err: errors.New("identity down")},
		quotaCli:    &fakeQuota{limit: 5},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if d.Allowed {
		t.Fatalf("want refused on identity error, got %+v", d)
	}
}

// Adapter with either dep nil short-circuits to admit (dev edge mode).
func TestOnlineCapAdapter_MissingDepsAdmit(t *testing.T) {
	a := &onlineCapAdapter{
		identityCli: nil,
		quotaCli:    &fakeQuota{limit: 1},
		logger:      silentLogger(),
	}
	d := a.AdmitNewSession(context.Background(), "42")
	if !d.Allowed {
		t.Fatalf("want allowed when identity nil, got %+v", d)
	}
}
