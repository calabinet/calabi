package selfupdate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Rollout staggers one release across machines over time: starting at Start, the share of
// machines allowed to install grows linearly to CapPercent over Hours.
//
// It lives INSIDE the signed manifest like every other field that changes what
// a daemon does. Pausing a rollout is publishing a re-signed manifest with the
// cap at the current percentage; there is no other lever.
//
// It only ever holds an update back. It cannot make anything install sooner
// than the machine's own policy allows, and a release below min_supported
// ignores it — the floor is the floor.
type Rollout struct {
	Start time.Time `json:"start"`
	// Hours to go from 0% to the cap. 0 = the cap applies from Start.
	Hours int `json:"hours"`
	// CapPercent bounds the share of machines, 0-100. Absent = 100. A pointer
	// because 0 is a real value — "paused before anyone got it".
	CapPercent *int `json:"cap_percent,omitempty"`
}

// maxRolloutHours: a month. Anything longer is a typo for a pause.
const maxRolloutHours = 720

func (r *Rollout) validate() error {
	if r.Start.IsZero() {
		return fmt.Errorf("selfupdate: manifest rollout has no start")
	}
	if r.Hours < 0 || r.Hours > maxRolloutHours {
		return fmt.Errorf("selfupdate: manifest rollout hours must be 0-%d, got %d", maxRolloutHours, r.Hours)
	}
	if r.CapPercent != nil && (*r.CapPercent < 0 || *r.CapPercent > 100) {
		return fmt.Errorf("selfupdate: manifest rollout cap_percent must be 0-100, got %d", *r.CapPercent)
	}
	return nil
}

// RolloutState is the published schedule plus where this machine sits in it.
// The check computes it once; whether the machine is included is re-derived at
// every evaluation, so a held update notices the ramp reaching it within one
// pendingEvalInterval rather than at the next six-hourly fetch.
type RolloutState struct {
	Start      time.Time `json:"start"`
	Hours      int       `json:"hours"`
	CapPercent int       `json:"cap_percent"`
	// Bucket is this machine's position, 0-99. Included once Percent > Bucket.
	Bucket int `json:"bucket"`
}

func newRolloutState(r *Rollout, bucket int) *RolloutState {
	capPct := 100
	if r.CapPercent != nil {
		capPct = *r.CapPercent
	}
	return &RolloutState{Start: r.Start.UTC(), Hours: r.Hours, CapPercent: capPct, Bucket: bucket}
}

// Percent is the share of machines allowed to install at now.
func (r *RolloutState) Percent(now time.Time) int {
	if r == nil {
		return 100
	}
	if now.Before(r.Start) {
		return 0
	}
	if r.Hours == 0 {
		return r.CapPercent
	}
	pct := int(100 * now.Sub(r.Start) / (time.Duration(r.Hours) * time.Hour))
	if pct > r.CapPercent {
		pct = r.CapPercent
	}
	return pct
}

// Included reports whether this machine's turn has come. No rollout = yes.
func (r *RolloutState) Included(now time.Time) bool {
	return r == nil || r.Bucket < r.Percent(now)
}

// ETA is when this machine's turn comes on the published schedule, or false
// when the cap stops short of it — then nothing on the schedule will ever
// include it, and the console must not promise a date.
func (r *RolloutState) ETA() (time.Time, bool) {
	if r == nil || r.Bucket >= r.CapPercent {
		return time.Time{}, false
	}
	// Percent reaches Bucket+1 once (Bucket+1)% of Hours has elapsed.
	return r.Start.Add(time.Duration(r.Hours) * time.Hour * time.Duration(r.Bucket+1) / 100), true
}

// rolloutBucket places a machine in 0-99 for one version. The version is part of
// the input so each release reaches a different first slice of the fleet: the
// same machines should not be every release's canaries.
func rolloutBucket(installID, version string) int {
	sum := sha256.Sum256([]byte(installID + ":" + strings.TrimSpace(version)))
	return int(binary.BigEndian.Uint16(sum[:2]) % 100)
}

const installIDFile = "install-id"

// loadInstallID returns this install's random id, minting it on first use. It is
// not an identity anyone else sees — it only decides the rollout bucket — so it
// is not the registration fingerprint, which a machine nobody logged into does
// not have. Upgrades keep it (the data directory survives them); a reinstall
// draws a new bucket, which is harmless.
//
// If it cannot be persisted, a per-process id still gives a valid bucket; it
// just may change on restart.
func loadInstallID(dir string) string {
	p := filepath.Join(dir, installIDFile)
	if b, err := os.ReadFile(p); err == nil {
		if id := strings.TrimSpace(string(b)); len(id) >= 16 {
			return id
		}
	}
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	id := hex.EncodeToString(buf[:])
	_ = writeFileAtomic(p, []byte(id+"\n"))
	return id
}
