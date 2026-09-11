package status

// The unlock secret: what lets a visitor from another machine use the console.
//
// The console trusts whoever can load it — it hands the page its write token —
// and has always made that safe by binding loopback. People bind it wider anyway
// (the Docker image documents 0.0.0.0), and the loopback-only guard that came
// with MESH-9 would have taken that away from them. This keeps it, on one
// condition: a visitor who is not on this machine first proves they know the
// secret, and holds a session cookie from then on.
//
// Why a cookie is enough against DNS rebinding, which is what the loopback-only
// guard was for: a rebinding page reaches the console under ITS OWN name, and a
// browser keeps cookies per name. The session a real visitor holds for
// 192.0.2.5:7400 is never sent to evil.example:7400, and the page does not know
// the secret to get one of its own.
//
// What it does not do: the console is plain HTTP, so on a network someone else
// can watch, the secret and the session cross it in the clear. That is a
// transport problem (SSH forward, HTTPS proxy), and the daemon says so when it
// is bound beyond loopback.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	consoleStatePath  = "/v1/console/state"
	consoleUnlockPath = "/v1/console/unlock"

	// consoleSessionTTL is how long one unlock lasts. Absolute, not sliding: the
	// session is a bearer credential on a plain-HTTP connection, and a bound on
	// how long a stolen one works is worth one extra prompt a day.
	consoleSessionTTL  = 12 * time.Hour
	maxConsoleSessions = 256

	// The guessing budget. Per peer, 5 wrong answers per 5 minutes; across all
	// peers, 30 a minute, so spreading guesses over many addresses buys nothing.
	// A generated secret is 120 bits and needs neither. A chosen one might.
	unlockFailWindow   = 5 * time.Minute
	unlockFailsPerPeer = 5
	unlockGlobalWindow = time.Minute
	unlockGlobalFails  = 30
	maxTrackedPeers    = 4096
)

type consoleLock struct {
	logger *slog.Logger
	digest [32]byte // SHA-256 of the secret: what is compared, in constant time
	now    func() time.Time

	mu       sync.Mutex
	sessions map[string]time.Time   // session token -> expiry
	fails    map[string][]time.Time // peer -> recent wrong answers, oldest first
	global   []time.Time            // every recent wrong answer, oldest first
}

func newConsoleLock(logger *slog.Logger, secret string) *consoleLock {
	return &consoleLock{
		logger:   logger,
		digest:   sha256.Sum256([]byte(secret)),
		now:      time.Now,
		sessions: map[string]time.Time{},
		fails:    map[string][]time.Time{},
	}
}

// serveState answers GET /v1/console/state: whether the page should show the
// console or the unlock form. A nil lock means no secret is configured.
func (l *consoleLock) serveState(w http.ResponseWriter, r *http.Request, local bool) {
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"locked":           !local && !l.unlocked(r),
		"remote":           !local,
		"unlock_available": l != nil,
	})
}

// serveUnlock answers POST /v1/console/unlock {"secret": "..."}.
func (l *consoleLock) serveUnlock(w http.ResponseWriter, r *http.Request, local bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeConsoleJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if local {
		// Nothing to unlock: this machine is the console's owner.
		writeConsoleJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if l == nil {
		writeConsoleJSON(w, http.StatusMisdirectedRequest, map[string]any{"error": "console_unlock_unavailable"})
		return
	}
	peer := peerKey(r)
	if wait := l.throttled(peer); wait > 0 {
		secs := int(math.Ceil(wait.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeConsoleJSON(w, http.StatusTooManyRequests,
			map[string]any{"error": "console_unlock_throttled", "retry_after_sec": secs})
		return
	}
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeConsoleJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(body.Secret)))
	if subtle.ConstantTimeCompare(got[:], l.digest[:]) != 1 {
		n := l.recordFailure(peer)
		l.logger.Warn("console unlock refused: wrong secret", "peer", peer, "recent_failures", n)
		writeConsoleJSON(w, http.StatusUnauthorized, map[string]any{"error": "console_unlock_failed"})
		return
	}
	tok, err := l.newSession()
	if err != nil {
		writeConsoleJSON(w, http.StatusInternalServerError, map[string]any{"error": "session_unavailable"})
		return
	}
	l.clearFailures(peer)
	http.SetCookie(w, &http.Cookie{
		Name:     consoleCookieName(r.Host),
		Value:    tok,
		Path:     "/",
		MaxAge:   int(consoleSessionTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	l.logger.Info("console unlocked for a visitor from another machine", "peer", peer)
	writeConsoleJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// unlocked reports whether r carries a live session. False on a nil lock.
func (l *consoleLock) unlocked(r *http.Request) bool {
	if l == nil {
		return false
	}
	c, err := r.Cookie(consoleCookieName(r.Host))
	if err != nil || c.Value == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	exp, ok := l.sessions[c.Value]
	if !ok {
		return false
	}
	if !l.now().Before(exp) {
		delete(l.sessions, c.Value)
		return false
	}
	return true
}

func (l *consoleLock) newSession() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for t, exp := range l.sessions {
		if !now.Before(exp) {
			delete(l.sessions, t)
		}
	}
	if len(l.sessions) >= maxConsoleSessions {
		// Full of live sessions: the one closest to expiring goes.
		var victim string
		var soonest time.Time
		for t, exp := range l.sessions {
			if victim == "" || exp.Before(soonest) {
				victim, soonest = t, exp
			}
		}
		delete(l.sessions, victim)
	}
	l.sessions[tok] = now.Add(consoleSessionTTL)
	return tok, nil
}

// throttled returns how long peer must wait before its next guess; 0 = go on.
func (l *consoleLock) throttled(peer string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	l.global = keepSince(l.global, now.Add(-unlockGlobalWindow))
	if len(l.global) >= unlockGlobalFails {
		wait = l.global[len(l.global)-unlockGlobalFails].Add(unlockGlobalWindow).Sub(now)
	}
	f := keepSince(l.fails[peer], now.Add(-unlockFailWindow))
	if len(f) == 0 {
		delete(l.fails, peer)
	} else {
		l.fails[peer] = f
	}
	if len(f) >= unlockFailsPerPeer {
		if w := f[len(f)-unlockFailsPerPeer].Add(unlockFailWindow).Sub(now); w > wait {
			wait = w
		}
	}
	return wait
}

// recordFailure notes a wrong answer and returns peer's recent count.
func (l *consoleLock) recordFailure(peer string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.global = append(l.global, now)
	if _, tracked := l.fails[peer]; !tracked && len(l.fails) >= maxTrackedPeers {
		for p, ts := range l.fails {
			if ts = keepSince(ts, now.Add(-unlockFailWindow)); len(ts) == 0 {
				delete(l.fails, p)
			}
		}
		if len(l.fails) >= maxTrackedPeers {
			// Cannot track one more peer; the global budget still counted it.
			return 1
		}
	}
	l.fails[peer] = append(l.fails[peer], now)
	return len(l.fails[peer])
}

func (l *consoleLock) clearFailures(peer string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, peer)
}

// keepSince drops the entries of ts (oldest first) at or before cutoff.
func keepSince(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

// peerKey identifies the guesser for the rate limit: the TCP peer, never a
// forwarding header a client could vary. Behind a reverse proxy every visitor
// shares one key, which errs on the side of fewer guesses.
func peerKey(r *http.Request) string {
	if ip, ok := peerAddr(r); ok {
		return ip.String()
	}
	return r.RemoteAddr
}

// consoleCookieName is per port. Browsers keep cookies per host NAME, not per
// port, so two consoles on one machine (7400, 7401 — see listenWithFallback)
// would otherwise overwrite each other's session.
func consoleCookieName(host string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, port)
		if digits != "" {
			return "calabi_console_" + digits
		}
	}
	return "calabi_console"
}

func writeConsoleJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
