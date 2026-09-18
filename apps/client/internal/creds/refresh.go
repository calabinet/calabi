package creds

import (
	"context"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// ExchangeFunc spends refreshToken at the control plane (bff-console's
// /v1/auth/refresh) and returns the new pair. RefreshSession only calls it with
// the exchange lock held.
type ExchangeFunc func(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)

var (
	// refreshMu serialises every refresh-token exchange in the process. A
	// refresh token is good for ONE exchange — identity-svc rotates it on use and
	// refuses a replay — so two exchanges that overlap spend the same token and
	// the second comes back refused. There used to be two locks: the local
	// console's proxy (statusapi) and the daemon's edge/mesh recovery each had
	// their own, and they collided.
	//
	// It only covers this process. Two PROCESSES sharing one creds file collide
	// the same way — the CLI beside a running daemon, and on a phone the app
	// beside its VPN extension, which run separately by design — so an exchange
	// also holds a file lock next to the creds file (lockExchange).
	refreshMu sync.Mutex

	// failKey / failAt back off after a failed exchange, so a dead session
	// doesn't hit identity-svc on every proxied request. Keyed by the creds file
	// and the refresh token that failed: a new sign-in is never held back by the
	// old session's failure. Only failures start it — a success must never make
	// the next caller give up, which is how one expired access token used to
	// bounce the local console to its login screen.
	failKey string
	failAt  time.Time

	// failCooldown is a var so tests can shorten it.
	failCooldown = 30 * time.Second
)

// RefreshSession returns an access token newer than refused — the one the
// caller's request was just rejected with — or "" when there is none to be had.
//
//   - If the token on disk already differs from refused, someone refreshed (or
//     signed in, or switched org) while this caller waited: return that without
//     spending the refresh token again. This is what turns N simultaneous 401s
//     into one exchange and N successful retries.
//   - Otherwise exchange once, re-read the file, and save the new pair on top of
//     whatever the rest of the daemon wrote during the round trip (a region
//     switch, the edge the session landed on). If the session itself was
//     replaced meanwhile — the refresh token on disk is no longer the one spent —
//     the newer session wins and is what the caller gets.
func RefreshSession(ctx context.Context, refused string, exchange ExchangeFunc) string {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	unlock, ok := lockExchange(ctx)
	if !ok {
		return "" // gave up waiting while another process refreshed
	}
	defer unlock()

	cfg, err := Load()
	if err != nil || cfg == nil {
		return ""
	}
	if cfg.AccessToken != "" && cfg.AccessToken != refused {
		return cfg.AccessToken
	}
	if cfg.RefreshToken == "" {
		return ""
	}
	spent := cfg.RefreshToken
	key := spent
	if p, err := Path(); err == nil {
		key = p + "\x00" + spent
	}
	if key == failKey && time.Since(failAt) < failCooldown {
		return ""
	}

	access, next, err := exchange(ctx, spent)
	if err != nil || access == "" || access == cfg.AccessToken {
		// A caller that went away (the browser dropped the request) says
		// nothing about the session; don't make everyone else wait for it.
		if ctx.Err() == nil {
			failKey, failAt = key, time.Now()
		}
		return ""
	}
	failKey = ""

	cur, err := Load()
	if err != nil || cur == nil {
		cur = cfg
	}
	if cur.RefreshToken != spent {
		if cur.AccessToken != "" && cur.AccessToken != refused {
			return cur.AccessToken
		}
		return ""
	}
	cur.AccessToken = access
	if next != "" {
		cur.RefreshToken = next
	}
	// A failed save still leaves the caller with a working token for its
	// retry; the next refusal simply refreshes again.
	_ = Save(cur)
	return access
}

// exchangeLockPoll is how often a waiting process retries the file lock.
const exchangeLockPoll = 20 * time.Millisecond

// lockExchange takes the cross-process half of the exchange lock: a file lock
// beside the creds file, held across read, exchange and write. ok=false only
// when ctx ended while another process held it.
//
// A lock file that cannot be opened at all — no data dir yet, or a directory
// this user may not write, such as a service's — does not stop the refresh:
// this process's own lock still holds, which is all there was before, and
// refusing would turn a missing directory into a sign-out.
//
// On iOS the lock sits in the app group container the app shares with its
// extension; the app must not be suspended while holding it (the system kills
// a process suspended holding a lock in a shared container), so it takes it
// inside a background task.
func lockExchange(ctx context.Context) (unlock func(), ok bool) {
	p, err := Path()
	if err != nil {
		return func() {}, true
	}
	fl := flock.New(p + ".lock")
	locked, err := fl.TryLock()
	if err != nil {
		return func() {}, true // the lock file is unusable here; see above
	}
	if !locked {
		// Another process is mid-exchange. Wait for it: what it saves is most
		// likely the very token this caller is after.
		if locked, err = fl.TryLockContext(ctx, exchangeLockPoll); !locked {
			if err != nil && ctx.Err() == nil {
				return func() {}, true
			}
			return nil, false
		}
	}
	return func() { _ = fl.Unlock() }, true
}
