package main

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// meshRefreshCooldown bounds how often a refused registration may spend a
	// token refresh. From here a refusal also looks like an expired SESSION, a
	// revoked key, or a coordinator that cannot reach identity-svc, and no
	// refresh fixes any of those; the loop retries every 30s at worst, so without
	// a cooldown a dead session would cost a refresh round trip every 30s forever.
	meshRefreshCooldown = time.Minute
	// meshRefreshTimeout caps one refresh, so a control plane that is slow to
	// answer holds the retry loop up by seconds rather than by bffclient's 30s.
	meshRefreshTimeout = 10 * time.Second
)

// refreshAfterDenial is the mesh's half of keeping a login session usable. It
// reports whether it came back with a new credential, so the loop can retry at
// once instead of waiting out its backoff.
//
// Why the mesh has to do this itself: an access token lives 15 minutes, and the
// only things that refresh one are edge discovery on a 401 — which runs when the
// edge session RECONNECTS — and the local console on a proxied call. A machine
// whose edge session stays up and whose console nobody opens refreshes nothing,
// so the first time the mesh has to re-register after the token expires (any
// coordinator blip will do), it is refused — and every retry then sends the same
// expired token again. The symptom is `mesh: register: ... auth key denied`
// every 30s with nothing that would ever change it.
//
// Unauthenticated is the only code worth acting on: it is what coord answers
// for a credential it will not accept, from GetRegisterChallenge and
// RegisterNode alike. Anything else is a network or server problem that a new
// token does not change.
func (r *meshRunner) refreshAfterDenial(ctx context.Context, err error) bool {
	if r.refreshFn == nil || status.Code(err) != codes.Unauthenticated {
		return false
	}
	if !r.lastRefresh.IsZero() && time.Since(r.lastRefresh) < meshRefreshCooldown {
		return false
	}
	r.lastRefresh = time.Now()
	rctx, cancel := context.WithTimeout(ctx, meshRefreshTimeout)
	defer cancel()
	if r.refreshFn(rctx) == "" {
		return false
	}
	r.logger.Info("mesh: the coordinator refused the credential; refreshed it, retrying now")
	return true
}

// meshRefreshForLogin is the platform daemon's refreshFn. Only a sign-in has
// anything to refresh: an API key the coordinator refuses is revoked or wrong,
// and the remedy for that is a new key, not another round trip. It also keeps a
// service's leftover sign-in in its creds file from being rotated on its behalf.
func meshRefreshForLogin(ctx context.Context) string {
	if _, kind := resolveCredential(); kind != credLogin {
		return ""
	}
	return refreshBearer(ctx)
}
