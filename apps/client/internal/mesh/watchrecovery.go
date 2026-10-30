package mesh

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type watchRecovery struct {
	refresh        func(context.Context) error
	interrupted    func()
	wake           <-chan struct{}
	initialTimeout time.Duration // zero uses the production bound; tests shorten it
	onTimeout      func()
}

// watchReauthenticated repairs a superseded subscription within the SAME live
// discovery transport. refresh must perform full registration, including proof
// and membership reauthorization, replacing the old token before subscribing.
// Network/auth/decoder failures still end the transport session. Each Watch
// starts a fresh decoder, so no delta baseline crosses RPCs.
func (c *CoordClient) watchReauthenticated(ctx context.Context, nodeID int64, recovery watchRecovery, onMap func(NetMap), onGrant func([]byte)) error {
	backoff := time.Second
	for {
		// A new RPC must deliver its first authoritative map. Quiet established
		// subscriptions have no such deadline. Never leave one client waiting
		// forever for a first frame after the rest of its group has recovered.
		timeout := recovery.initialTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		attempt, cancel := context.WithCancel(ctx)
		var expired atomic.Bool
		first := time.AfterFunc(timeout, func() { expired.Store(true); cancel() })
		err := c.watchUpdates(attempt, nodeID, func(m NetMap) { first.Stop(); onMap(m) }, onGrant)
		first.Stop()
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stalled := expired.Load() && status.Code(err) == codes.Canceled
		if !stalled && status.Code(err) != codes.Aborted {
			return err
		}
		if stalled && recovery.onTimeout != nil {
			recovery.onTimeout()
		}
		if recovery.interrupted != nil {
			recovery.interrupted()
		}
		timer := time.NewTimer(ReconnectDelay(backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		case <-recovery.wake:
			timer.Stop()
			backoff = time.Second
		}
		// Recheck authorization AFTER waiting, including a network-change wakeup.
		refreshCtx, release := context.WithTimeout(ctx, 30*time.Second)
		err = recovery.refresh(refreshCtx)
		release()
		if err != nil {
			return err
		}
		backoff = min(backoff*2, time.Minute)
	}
}
