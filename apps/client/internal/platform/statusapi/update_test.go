package statusapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/selfupdate"
)

// fakeUpdate is a hand-written UpdateSource so the handler tests do not need a
// manifest host.
type fakeUpdate struct {
	snap      selfupdate.Snapshot
	policy    selfupdate.Policy
	checkErr  error
	applyErr  error
	applied   int
	policySet int
}

func (f *fakeUpdate) Snapshot() selfupdate.Snapshot { return f.snap }
func (f *fakeUpdate) Check(context.Context) (selfupdate.Snapshot, error) {
	return f.snap, f.checkErr
}
func (f *fakeUpdate) Apply(context.Context) error {
	f.applied++
	return f.applyErr
}
func (f *fakeUpdate) Policy() selfupdate.Policy { return f.policy }
func (f *fakeUpdate) SetPolicy(p selfupdate.Policy) (selfupdate.Snapshot, error) {
	if err := p.Validate(); err != nil {
		return f.snap, err
	}
	f.policy, f.policySet = p, f.policySet+1
	f.snap.Policy = p
	return f.snap, nil
}

func updateTestServer(t *testing.T, up UpdateSource) http.Handler {
	t.Helper()
	s := New(nil, Config{BFFConsoleURL: "http://127.0.0.1:0", Update: up})
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

// A daemon with no update agent — a dev build, updates disabled, or any client
// shipped before this change — must 404, and the SPA must read that as "no
// information" rather than an error. If this ever became a 500 the console would
// show a red card on every developer machine.
func TestUpdateEndpointsAreAbsentWhenNotConfigured(t *testing.T) {
	h := updateTestServer(t, nil)
	req := httptest.NewRequest("GET", "/v1/update", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /v1/update with no agent: got %d, want 404", rr.Code)
	}
}

func TestUpdateGetRendersTheSnapshot(t *testing.T) {
	f := &fakeUpdate{snap: selfupdate.Snapshot{
		Status: selfupdate.Status{Current: "1.10.0", Latest: "1.11.0", Available: true,
			HasArtifact: false, CanApply: false, Reason: selfupdate.ReasonNoArtifact},
		Auto:  false,
		State: selfupdate.StateIdle,
	}}
	h := updateTestServer(t, f)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/update", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	// available and can_apply must BOTH reach the SPA. Dropping either one is how
	// "there is a newer version, install it by hand" becomes unrenderable.
	for k, want := range map[string]any{
		"current": "1.10.0", "latest": "1.11.0",
		"available": true, "can_apply": false, "reason": selfupdate.ReasonNoArtifact,
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

// The writes carry the local token like every other write on this surface.
func TestUpdateWritesRequireTheLocalToken(t *testing.T) {
	f := &fakeUpdate{}
	h := updateTestServer(t, f)
	for _, w := range []struct{ method, path string }{
		{"POST", "/v1/update/check"},
		{"POST", "/v1/update/apply"},
		{"PUT", "/v1/update/policy"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(w.method, w.path, nil)) // no X-Local-Token
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: got %d, want 401", w.method, w.path, rr.Code)
		}
	}
	if f.applied != 0 || f.policySet != 0 {
		t.Errorf("a write ran without a token (applied=%d policySet=%d)", f.applied, f.policySet)
	}
}

// "This machine cannot install updates itself" is a 409 carrying the snapshot —
// a fact about the install, which the console turns into "请手动更新". A 500 here
// would make an ordinary, expected state look like a malfunction.
func TestUpdateApplyCannotApplyIs409WithTheSnapshot(t *testing.T) {
	tok := isolateCreds(t)
	f := &fakeUpdate{
		applyErr: selfupdate.ErrCannotApply,
		snap: selfupdate.Snapshot{
			Status: selfupdate.Status{Current: "1.10.0", Latest: "1.11.0", Available: true,
				Reason: selfupdate.ReasonNotPrivileged},
			State: selfupdate.StateIdle,
		},
	}
	h := updateTestServer(t, f)
	req := httptest.NewRequest("POST", "/v1/update/apply", nil)
	req.Header.Set("X-Local-Token", tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409 (body %s)", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["reason"] != selfupdate.ReasonNotPrivileged {
		t.Errorf("reason = %v, want %q — the console needs it to pick its message",
			got["reason"], selfupdate.ReasonNotPrivileged)
	}
}

// A failed check reports 502 but still returns the snapshot, so the console can
// keep showing the last known version instead of blanking the card.
func TestUpdateCheckFailureStillReturnsTheSnapshot(t *testing.T) {
	tok := isolateCreds(t)
	f := &fakeUpdate{
		checkErr: errors.New("dial tcp: no route to host"),
		snap: selfupdate.Snapshot{
			Status: selfupdate.Status{Current: "1.10.0", Latest: "1.11.0", Available: true},
			State:  selfupdate.StateFailed, Error: "dial tcp: no route to host",
		},
	}
	h := updateTestServer(t, f)
	req := httptest.NewRequest("POST", "/v1/update/check", nil)
	req.Header.Set("X-Local-Token", tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["latest"] != "1.11.0" || got["error"] == "" {
		t.Errorf("want the last good status AND the error, got %v", got)
	}
}

// The policy PUT MERGES. A body naming only the mode must not also wipe the
// maintenance window to "any time" and the defer cap to "never wait" — the two
// settings someone switching to notify-only cares about most.
func TestUpdatePolicyPutMergesInsteadOfReplacing(t *testing.T) {
	tok := isolateCreds(t)
	f := &fakeUpdate{policy: selfupdate.Policy{
		Mode: selfupdate.ModeAuto, WindowStartHour: 23, WindowEndHour: 5, MaxDeferDays: 3,
	}}
	h := updateTestServer(t, f)

	req := httptest.NewRequest("PUT", "/v1/update/policy", strings.NewReader(`{"mode":"notify"}`))
	req.Header.Set("X-Local-Token", tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	want := selfupdate.Policy{Mode: selfupdate.ModeNotify, WindowStartHour: 23, WindowEndHour: 5, MaxDeferDays: 3}
	if f.policy != want {
		t.Errorf("stored %+v, want %+v", f.policy, want)
	}
}

// An impossible setting is rejected with a 400 that names the problem, not
// quietly repaired into something the caller did not ask for.
func TestUpdatePolicyPutRejectsNonsense(t *testing.T) {
	tok := isolateCreds(t)
	f := &fakeUpdate{policy: selfupdate.DefaultPolicy()}
	h := updateTestServer(t, f)

	for _, body := range []string{`{"mode":"off"}`, `{"window_start_hour":25}`, `{"max_defer_days":-1}`} {
		req := httptest.NewRequest("PUT", "/v1/update/policy", strings.NewReader(body))
		req.Header.Set("X-Local-Token", tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: got %d, want 400", body, rr.Code)
		}
	}
	if f.policy != selfupdate.DefaultPolicy() {
		t.Errorf("a rejected body still changed the stored policy: %+v", f.policy)
	}
}
