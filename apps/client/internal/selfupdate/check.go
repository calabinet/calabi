package selfupdate

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Status is one check's outcome: what the signed manifest names, and whether
// THIS machine could act on it.
//
// Available and CanApply are deliberately TWO fields. Folding them into one
// ("is there an update for me?") is how the Linux/agent population ended up
// unable to learn it was out of date at all: CheckAndApply treated "the manifest
// has no artifact for linux-x86_64" as an error, so those daemons logged a
// failure every 6 hours and never told anyone a newer version existed. Knowing
// you are old is useful even where you cannot fix it yourself — that is what the
// console's "有新版本，请手动更新" state is made of. and
type Status struct {
	Current string `json:"current"`
	// Latest is the manifest's version. Empty only when the check failed.
	Latest string `json:"latest,omitempty"`
	// Available: the manifest names something other than what is running and we
	// should move to it (newer, or a signed deliberate rollback).
	Available bool `json:"available"`
	// HasArtifact: the manifest carries a fully-signed installer for this
	// platform key. False on Linux today — latest.json is desktop-only.
	HasArtifact bool `json:"has_artifact"`
	// CanApply: HasArtifact AND this process is allowed to install it (supported
	// platform, running as the privileged system service).
	CanApply bool `json:"can_apply"`
	// Rollback marks a manifest that deliberately points BACKWARDS (ops undoing a
	// bad release). Inside the signature, so it cannot be added or stripped.
	Rollback bool `json:"rollback,omitempty"`
	// Critical marks a security release the policy treats differently: it
	// installs under "security updates only" and skips the maintenance window.
	Critical bool `json:"critical,omitempty"`
	// Mandatory: the running version is below the manifest's min_supported, so
	// this update installs whatever the machine's mode says. The console has to
	// say so plainly — an unavoidable restart deserves a sentence, not a
	// surprise.
	Mandatory bool `json:"mandatory,omitempty"`
	// Rollout is the release's staged-rollout schedule and this machine's place
	// in it; nil when the release goes to every machine at once.
	Rollout *RolloutState `json:"rollout,omitempty"`
	// Reason says why CanApply is false while Available is true, so the console
	// can tell "you must update by hand" apart from "something is wrong".
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Reasons CanApply is false. Stable strings — the SPA switches on them.
const (
	ReasonNoArtifact    = "no-artifact"          // manifest has nothing for this platform key
	ReasonUnsigned      = "artifact-unsigned"    // entry exists but lacks sha256/signature
	ReasonForeignOrigin = "artifact-foreign"     // installer URL is not the manifest's own origin
	ReasonUnsupportedOS = "unsupported-platform" // no OS-installer path on this GOOS
	ReasonNotPrivileged = "not-privileged"       // not the machine-wide system service
	// ReasonManagedElsewhere: this binary was not installed by the artifact the
	// manifest carries for its platform (scoop, Homebrew, a hand-extracted
	// archive), so running that artifact would install something ELSE rather
	// than update this. See installerManagedFrom.
	ReasonManagedElsewhere = "managed-elsewhere"
)

// Check runs the read-only half of a cycle: fetch the manifest, verify its
// signature, and decide what it means for this machine. It NEVER downloads an
// installer and never touches the running install.
func (u *Updater) Check(ctx context.Context) (Status, error) {
	st, _, err := u.check(ctx)
	return st, err
}

// manifestFetchTimeout bounds the two small GETs one check is made of.
//
// http.DefaultClient has NO timeout of its own. A manifest host that accepts the
// connection and then never answers — a hung server, a half-open NAT entry, a
// captive portal — parks the check for as long as the OS is willing to wait,
// which on some paths is forever. That is worse than slow: a check holds the
// agent's single-operation claim, so the snapshot stays state="checking" (the
// console's button spins with nothing left to stop it), every later check
// answers 409, and the 6-hourly loop never runs again. A bounded failure is
// recoverable and says so in the log; a hang takes updates off this machine
// silently and permanently.
const manifestFetchTimeout = 20 * time.Second

// check is the single verification path both Check and CheckAndApply run
// through — deliberately not two of them. Two paths means one of them quietly
// loses a gate; a root service applying a downloaded file cannot afford that.
// It returns the chosen artifact alongside the status so the apply half does not
// re-parse (and thus re-decide) anything.
func (u *Updater) check(ctx context.Context) (Status, PlatformArtifact, error) {
	st := Status{Current: u.CurrentVersion, CheckedAt: time.Now().UTC()}

	// One budget for both documents, because what has to be bounded is the whole
	// check — that is what the caller is waiting on. Scoped to this function on
	// purpose: CheckAndApply downloads an installer AFTER this returns, on the
	// caller's own context, and a download is allowed to take minutes.
	ctx, cancel := context.WithTimeout(ctx, u.fetchTimeout())
	defer cancel()

	m, raw, err := FetchManifest(ctx, u.ManifestURL)
	if err != nil {
		return st, PlatformArtifact{}, err
	}
	// NOTHING from the manifest is trusted before its own signature checks out
	// (audit finding UPD-1). Fail closed: a service that cannot establish where
	// an instruction came from must not follow it.
	sig, err := FetchManifestSignature(ctx, u.ManifestURL)
	if err != nil {
		return st, PlatformArtifact{}, err
	}
	if err := VerifyManifestSignature(raw, sig, u.PubKey); err != nil {
		return st, PlatformArtifact{}, err
	}
	// The version reached the filesystem path verbatim before this check.
	if err := ValidateVersion(m.Version); err != nil {
		return st, PlatformArtifact{}, err
	}
	if err := os.MkdirAll(u.DownloadDir, 0o700); err != nil {
		return st, PlatformArtifact{}, err
	}
	// Anti-rollback. A valid signature proves we published this manifest, not
	// that we published it LAST: replaying a genuine older one is the same
	// downgrade by another route, and the attacker needs no key for it.
	//
	// This lives in the CHECK half on purpose. The floor is a ledger of what this
	// machine has been offered, not a side effect of installing something — a
	// daemon that only ever checks still has to remember, or the first machine to
	// gain the ability to apply would start from an open floor.
	floor := readVersionFloor(u.DownloadDir)
	if floor != "" && IsNewer(m.Version, floor) && !m.Rollback {
		return st, PlatformArtifact{}, fmt.Errorf("selfupdate: manifest offers %s but %s was already seen — refusing "+
			"(a deliberate rollback must carry \"rollback\": true inside the signed manifest)", m.Version, floor)
	}
	if !m.Rollback {
		writeVersionFloor(u.DownloadDir, m.Version)
	}

	st.Latest, st.Rollback, st.Critical = m.Version, m.Rollback, m.Critical
	// A floor newer than the release it ships with is nonsense — it would demand
	// a version nobody published. Treat it as a malformed manifest rather than
	// letting it force an install nothing can satisfy.
	if m.MinSupported != "" {
		if err := ValidateVersion(m.MinSupported); err != nil {
			return st, PlatformArtifact{}, fmt.Errorf("selfupdate: manifest min_supported is malformed")
		}
		if IsNewer(m.Version, m.MinSupported) {
			return st, PlatformArtifact{}, fmt.Errorf(
				"selfupdate: manifest requires at least %s but only publishes %s — refusing", m.MinSupported, m.Version)
		}
		st.Mandatory = IsNewer(u.CurrentVersion, m.MinSupported)
	}
	if m.Rollout != nil {
		// Malformed = refused, like min_supported: a schedule nothing can follow
		// must not quietly become "everyone now".
		if err := m.Rollout.validate(); err != nil {
			return st, PlatformArtifact{}, err
		}
		st.Rollout = newRolloutState(m.Rollout, rolloutBucket(u.installID(), m.Version))
	}
	switch {
	case m.Rollback:
		// A rollback manifest means "get onto exactly this version", in either
		// direction — but we are already there often enough to say so.
		st.Available = u.CurrentVersion != m.Version
	default:
		st.Available = IsNewer(u.CurrentVersion, m.Version)
	}
	if !st.Available {
		return st, PlatformArtifact{}, nil
	}

	// Two different kinds of "cannot apply", and they must not be conflated:
	//
	//   nothing published for me   → a STATE. Every Linux/agent daemon lives here
	//                                (latest.json is desktop-only) and should say
	//                                "1.11.0 is out, update by hand", not fail.
	//   published but wrong        → an ERROR. Unsigned, or pointing at someone
	//                                else's host, means the manifest is malformed
	//                                or hostile; that deserves to be loud.
	art, ok := m.ArtifactForThisPlatform()
	if !ok {
		st.Reason = ReasonNoArtifact
		return st, PlatformArtifact{}, nil
	}
	// A service auto-applying an UNSIGNED download would be a gift to an attacker
	// who can spoof the manifest host — refuse rather than trust TLS alone.
	if art.SHA256 == "" || art.Signature == "" {
		st.Reason = ReasonUnsigned
		return st, PlatformArtifact{}, fmt.Errorf("selfupdate: artifact for %s is missing sha256/signature — refusing", PlatformKey())
	}
	// The installer must come from the same host as the manifest, over the same
	// or a stronger scheme: a spoofed manifest should not be able to redirect a
	// privileged download to an arbitrary origin.
	if err := sameOriginArtifact(u.ManifestURL, art.URL); err != nil {
		st.Reason = ReasonForeignOrigin
		return st, PlatformArtifact{}, err
	}
	st.HasArtifact = true

	// Everything above is about the manifest; what follows is about US.
	switch {
	case !u.applierAvailable():
		st.Reason = ReasonUnsupportedOS
	// BEFORE the privilege question, on purpose. For a scoop or Homebrew
	// install the not-privileged advice ("reinstall it as a system service")
	// leads nowhere: done, the install would still be one the desktop artifact
	// cannot replace. The actionable answer is "update it the way you installed
	// it", so that is the one to give.
	case !u.installerManaged():
		st.Reason = ReasonManagedElsewhere
	case !u.Privileged:
		st.Reason = ReasonNotPrivileged
	default:
		st.CanApply = true
	}
	return st, art, nil
}

// applierAvailable reports whether there is anything that could install an
// installer here. applySupported describes the DEFAULT applier (the OS
// installer); a caller that injects its own Apply has answered the question
// itself. Production never injects one — only tests do.
func (u *Updater) applierAvailable() bool { return applySupported || u.Apply != nil }
