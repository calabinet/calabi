package creds

import (
	"context"
	"sync"
	"time"
)

// ExchangeFunc spends refreshToken at the control plane (bff-console's
// /v1/auth/refresh) and returns the new pair. RefreshSession only calls it with
// the process-wide exchange lock held.
type ExchangeFunc func(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)

var (
	// refreshMu serialises every refresh-token exchange in the process. A
	// refresh token is good for ONE exchange — identity-svc rotates it on use and
	// refuses a replay — so two exchanges that overlap spend the same token and
	// the second comes back refused. There used to be two locks: the local
	// console's proxy (statusapi) and the daemon's edge/mesh recovery each had
	// their own, and they collided.
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
