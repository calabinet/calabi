package main

import "context"

// refreshAfterDenial renews the daemon's credential after the coordinator
// refused it, at most once per meshenroll.RefreshCooldown
// meshenroll.RefreshGate for why the mesh cannot wait for anything else to). It
// reports whether it came back with a new credential, so the loop can retry at
// once instead of waiting out its backoff.
func (r *meshRunner) refreshAfterDenial(ctx context.Context, err error) bool {
	if !r.refreshGate.AfterDenial(ctx, err, r.refreshFn) {
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
