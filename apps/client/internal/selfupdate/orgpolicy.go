package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// OrgPolicy is the organisation's requirement on how eagerly its machines update: at least this mode, and at most
// this long holding a routine update back.
//
// It only TIGHTENS. The machine keeps its own setting, the daemon acts on the
// stricter of the two, and removing the org policy gives the machine back
// exactly what it had chosen. It cannot mark a release critical, pick a version
// or roll one back — those stay in the signed manifest — so it is safe to take
// from the control plane: the most a forged one can do is make a verified
// release install sooner.
type OrgPolicy struct {
	OrgID        int64  `json:"org_id"`
	MinMode      string `json:"min_mode,omitempty"`
	MaxDeferDays *int   `json:"max_defer_days,omitempty"`
}

// ErrNoOrg is what an OrgPolicy source returns when this daemon belongs to no
// org (nobody logged in, no API key). The cached policy is dropped: the machine
// has left whatever org set it.
var ErrNoOrg = errors.New("selfupdate: not in an org")

func (o *OrgPolicy) empty() bool {
	return o == nil || (modeRank(o.MinMode) == 0 && o.MaxDeferDays == nil)
}

// modeRank orders modes from loosest to strictest. Unknown = loosest, so a mode
// this build does not know can never tighten anything by accident.
func modeRank(m string) int {
	switch m {
	case ModeAuto:
		return 2
	case ModeSecurity:
		return 1
	}
	return 0
}

// Tighten returns the policy the daemon acts on: the machine's setting, made
// at least as strict as the org requires. The window is the machine's alone —
// "restart at a different hour" is neither tighter nor looser.
func (p Policy) Tighten(o *OrgPolicy) Policy {
	if o == nil {
		return p
	}
	if modeRank(o.MinMode) > modeRank(p.Mode) {
		p.Mode = o.MinMode
	}
	if o.MaxDeferDays != nil && *o.MaxDeferDays < p.MaxDeferDays {
		p.MaxDeferDays = *o.MaxDeferDays
	}
	return p
}

const orgPolicyFile = "org-policy.json"

type orgPolicyCache struct {
	OrgPolicy
	FetchedAt time.Time `json:"fetched_at"`
}

// loadOrgPolicy reads the last policy fetched, so an offline machine still keeps
// its org's rules and a restart does not forget them until the next fetch.
func loadOrgPolicy(dir string) *OrgPolicy {
	b, err := os.ReadFile(filepath.Join(dir, orgPolicyFile))
	if err != nil {
		return nil
	}
	var c orgPolicyCache
	if json.Unmarshal(b, &c) != nil || c.OrgPolicy.empty() {
		return nil
	}
	o := c.OrgPolicy
	return &o
}

func saveOrgPolicy(dir string, o *OrgPolicy, now time.Time) error {
	if o.empty() {
		err := os.Remove(filepath.Join(dir, orgPolicyFile))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, err := json.Marshal(orgPolicyCache{OrgPolicy: *o, FetchedAt: now.UTC()})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, orgPolicyFile), b)
}

// orgPolicyTimeout bounds one fetch. It runs in front of every manifest check.
const orgPolicyTimeout = 10 * time.Second

// refreshOrgPolicy fetches the org policy and adopts it. A failure keeps the
// cached one: an unreachable control plane must not loosen an org's rules.
func (a *Agent) refreshOrgPolicy(ctx context.Context) {
	if a.u.OrgPolicy == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, orgPolicyTimeout)
	o, err := a.u.OrgPolicy(ctx)
	cancel()
	switch {
	case errors.Is(err, ErrNoOrg):
		o = nil
	case err != nil:
		a.logf("selfupdate: could not read the org update policy (keeping the last one): %v", err)
		return
	}
	if o.empty() {
		o = nil
	}
	if err := saveOrgPolicy(a.u.DownloadDir, o, a.now()); err != nil {
		a.logf("selfupdate: could not cache the org update policy: %v", err)
	}

	a.mu.Lock()
	changed := !sameOrgPolicy(a.org, o)
	a.org = o
	a.snap.OrgPolicy = o
	a.snap.Auto = a.policy.Tighten(o).Mode == ModeAuto && a.u.Privileged
	a.mu.Unlock()
	if changed {
		if o == nil {
			a.logf("selfupdate: no org update policy applies")
		} else {
			a.logf("selfupdate: org update policy: min mode %q, max defer %v", o.MinMode, deferText(o.MaxDeferDays))
		}
	}
}

// RefreshOrgPolicy re-reads the org policy now and re-decides a pending update
// against it — for a login or an org switch, which change which org's rules
// apply. Like SetPolicy it never installs by itself; the next evaluation does.
func (a *Agent) RefreshOrgPolicy(ctx context.Context) {
	if a == nil {
		return
	}
	a.refreshOrgPolicy(ctx)
	a.mu.Lock()
	st := a.snap.Status
	a.mu.Unlock()
	a.evaluate(st, false)
}

func sameOrgPolicy(a, b *OrgPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.OrgID != b.OrgID || a.MinMode != b.MinMode {
		return false
	}
	if a.MaxDeferDays == nil || b.MaxDeferDays == nil {
		return a.MaxDeferDays == b.MaxDeferDays
	}
	return *a.MaxDeferDays == *b.MaxDeferDays
}

func deferText(n *int) any {
	if n == nil {
		return "none"
	}
	return *n
}
