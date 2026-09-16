package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Policy is the machine's update setting — U2 of
//
// It is a MACHINE setting, not a user or org one: the daemon is shared by every
// OS user on the box, the logged-in account can change or log out, the machine
// cannot. It lives next to the version floor in the update directory, which for
// a privileged system service is the machine-wide SystemDataDir.
type Policy struct {
	Mode string `json:"mode"`
	// WindowStartHour/WindowEndHour are hours on the MACHINE's local clock,
	// half-open [start, end). Equal values mean "no window, any time".
	// A window that wraps midnight (23 → 5) is fine.
	//
	// The machine's clock, not the viewer's: the restart happens here. A console
	// opened from another timezone must say whose 3am it means.
	WindowStartHour int `json:"window_start_hour"`
	WindowEndHour   int `json:"window_end_hour"`
	// MaxDeferDays caps how long the window and the busy check may hold a
	// routine update back. 0 = they may not hold it at all (install as soon as
	// it is found).
	//
	// Without a cap, "install at 3am when idle" means "never" for a laptop that
	// is closed every night and a server that is busy every night — the two
	// machines that most need the fix. The cap is what keeps a preference from
	// silently becoming a permanent opt-out.
	MaxDeferDays int `json:"max_defer_days"`
}

// Update modes. Stable strings: they are persisted and the SPA switches on them.
const (
	// ModeAuto installs whatever the check finds, subject to the window/busy
	// rules and their MaxDeferDays backstop.
	ModeAuto = "auto"
	// ModeSecurity installs only releases the signed manifest marks critical.
	// Routine versions are reported and wait for a human.
	ModeSecurity = "security"
	// ModeNotify installs nothing on its own — including critical ones. It keeps
	// saying so; it is not an off switch. Turning the CHECK off is an ops
	// decision (CALABI_UPDATE_MANIFEST=), deliberately not one click away.
	ModeNotify = "notify"
)

// Why an available update is being held. Stable strings; the SPA renders them.
const (
	HoldNotifyOnly    = "notify-only"    // mode=notify, and this is not critical
	HoldSecurityOnly  = "security-only"  // mode=security, and this is not critical
	HoldOutsideWindow = "outside-window" // waiting for the maintenance window
	HoldBusy          = "busy"           // traffic is moving through this client
)

// DefaultPolicy: install automatically, but at night, and never hold anything
// longer than a week.
func DefaultPolicy() Policy {
	return Policy{Mode: defaultMode(), WindowStartHour: 3, WindowEndHour: 5, MaxDeferDays: 7}
}

// defaultMode differs by platform because the cost of an unattended restart
// does.
//
// A Linux system-service install is, in practice, a server: the restart drops
// live tunnels and flaps mesh routes for something nobody asked for at that
// moment. So Linux starts at "security only" — critical releases still land on
// their own, routine ones wait for a person. Desktops start at "automatic",
// where a few seconds of reconnect costs nothing.
//
// This is a DEFAULT, not a rule: either platform can be set to any mode, and
// the choice is stored per machine.
func defaultMode() string {
	if runtime.GOOS == "linux" {
		return ModeSecurity
	}
	return ModeAuto
}

// Validate rejects a policy rather than silently repairing it — this arrives
// from a REST body, and a 400 telling the caller what is wrong beats quietly
// storing something they did not ask for.
func (p Policy) Validate() error {
	switch p.Mode {
	case ModeAuto, ModeSecurity, ModeNotify:
	default:
		return fmt.Errorf("selfupdate: unknown mode %q", p.Mode)
	}
	for _, h := range []int{p.WindowStartHour, p.WindowEndHour} {
		if h < 0 || h > 23 {
			return fmt.Errorf("selfupdate: window hours must be 0-23, got %d", h)
		}
	}
	if p.MaxDeferDays < 0 || p.MaxDeferDays > 90 {
		return fmt.Errorf("selfupdate: max_defer_days must be 0-90, got %d", p.MaxDeferDays)
	}
	return nil
}

// InWindow reports whether now falls in the maintenance window, on the clock the
// time carries.
func (p Policy) InWindow(now time.Time) bool {
	if p.WindowStartHour == p.WindowEndHour {
		return true // no window configured: any time is fine
	}
	h := now.Hour()
	if p.WindowStartHour < p.WindowEndHour {
		return h >= p.WindowStartHour && h < p.WindowEndHour
	}
	return h >= p.WindowStartHour || h < p.WindowEndHour // wraps midnight
}

// Decision is what the policy says to do about one check result.
type Decision struct {
	Install bool
	// Hold is why not, when Install is false and an update IS available. Empty
	// when there is nothing to install or when installing.
	Hold string
}

// Decide applies the policy.
//
// Two escalation tiers, and they are not the same thing:
//
//   - critical (in the signed manifest): overrides ModeSecurity and every
//     waiting rule — window included. A window exists to keep a ROUTINE restart
//     out of the working day; making a remotely-exploitable fix wait until 3am
//     would be using it for something it was not for. It does NOT override
//     ModeNotify: a person who said "never install without me" gets a louder
//     notice, not a surprise restart.
//   - min_supported: the floor. Overrides ModeNotify as well — the one case
//     where an explicit "never without me" is not honoured, because leaving the
//     machine where it is has become worse than restarting it unasked.
//
// waitingSince is when this same version was first held back; zero means it has
// not been held yet.
func (p Policy) Decide(st Status, now time.Time, busy bool, waitingSince time.Time) Decision {
	if !st.Available || !st.CanApply {
		return Decision{} // nothing installable: not a policy question
	}
	// The floor. Nothing here is a preference any more: the running version is
	// below what the publisher still supports, so every mode installs and no
	// waiting rule applies.
	if st.Mandatory {
		return Decision{Install: true}
	}
	if st.Critical {
		if p.Mode == ModeNotify {
			return Decision{Hold: HoldNotifyOnly}
		}
		return Decision{Install: true}
	}
	switch p.Mode {
	case ModeNotify:
		return Decision{Hold: HoldNotifyOnly}
	case ModeSecurity:
		return Decision{Hold: HoldSecurityOnly}
	}
	// The backstop is checked BEFORE the reasons to wait, so that a machine
	// which is never idle inside its window still lands the update.
	if p.MaxDeferDays <= 0 {
		return Decision{Install: true}
	}
	if !waitingSince.IsZero() && now.Sub(waitingSince) >= time.Duration(p.MaxDeferDays)*24*time.Hour {
		return Decision{Install: true}
	}
	if !p.InWindow(now) {
		return Decision{Hold: HoldOutsideWindow}
	}
	if busy {
		return Decision{Hold: HoldBusy}
	}
	return Decision{Install: true}
}

// ---- persistence -----------------------------------------------------------

const policyFile = "policy.json"

// LoadPolicy reads the stored policy, falling back to the default for a missing
// or unreadable file. A corrupt settings file must not wedge updates off — that
// would turn a bad write into a permanent, silent opt-out.
func LoadPolicy(dir string) Policy {
	b, err := os.ReadFile(filepath.Join(dir, policyFile))
	if err != nil {
		return DefaultPolicy()
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return DefaultPolicy()
	}
	if err := p.Validate(); err != nil {
		return DefaultPolicy()
	}
	return p
}

// SavePolicy persists it. 0600 under a directory the service owns.
func SavePolicy(dir string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, policyFile), append(b, '\n'), 0o600)
}

// deferState remembers when a specific version was first held back, so the
// MaxDeferDays backstop survives restarts. Without it, a daemon that restarts
// daily would reset its own deadline and defer forever.
//
// A separate file from the policy on purpose: the user writes the policy, the
// agent writes this. One file with both would let a settings save clobber the
// clock — or the clock clobber a setting.
type deferState struct {
	Version string    `json:"version"`
	Since   time.Time `json:"since"`
}

const deferStateFile = "defer-state.json"

func readDeferState(dir string) deferState {
	b, err := os.ReadFile(filepath.Join(dir, deferStateFile))
	if err != nil {
		return deferState{}
	}
	var s deferState
	if err := json.Unmarshal(b, &s); err != nil {
		return deferState{}
	}
	return s
}

// waitingSince returns how long THIS version has been held, or zero when it is
// a different version than the one we were holding (a new release restarts the
// clock — it has not been waiting, it just arrived).
func waitingSince(dir, version string) time.Time {
	s := readDeferState(dir)
	if s.Version != version {
		return time.Time{}
	}
	return s.Since
}

// noteDeferred starts the clock for version, if it is not already running.
// Best-effort: failing to record it only means the deadline restarts later.
func noteDeferred(dir, version string, now time.Time) {
	if s := readDeferState(dir); s.Version == version && !s.Since.IsZero() {
		return
	}
	b, err := json.MarshalIndent(deferState{Version: version, Since: now}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, deferStateFile), append(b, '\n'), 0o600)
}

// clearDeferState forgets the clock — nothing is being held any more.
func clearDeferState(dir string) {
	_ = os.Remove(filepath.Join(dir, deferStateFile))
}
