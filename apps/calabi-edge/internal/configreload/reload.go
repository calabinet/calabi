// Package configreload watches the calabi-edge YAML for changes and
// applies a whitelisted subset of fields without a process restart.
//
// What's hot-reloadable:
//   - accepted_tokens — the static fallback token table
//   - http.base_domain — the subdomain suffix for new tunnels
//
// Everything else (listener addresses, TLS material, upstream gRPC
// dials) requires a restart. Editor-saved files often appear as
// RENAME / WRITE / CREATE depending on platform + tool, so we coalesce
// any of those into a re-read of the canonical path.
//
// Design:
//   - One fsnotify.Watcher per process; watches the *directory* of the
//     YAML and filters to the file's basename. This survives editors
//     (vim, VSCode) that rename-over-write the original inode.
//   - Debounce: 250ms after the latest event so a multi-write save
//     reads once at the end.
//   - On parse / whitelist-violation error: log + KEEP the old config.
//     Never panic, never half-apply.
package configreload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
)

// Hot-reload debounce window.
const debounceWindow = 250 * time.Millisecond

// Applier installs the new whitelisted values. Each method is called on
// every reload regardless of whether the value changed; implementations
// should be idempotent + cheap.
type Applier interface {
	ApplyAcceptedTokens(tokens []config.TokenEntry)
	ApplyBaseDomain(base string)
}

// Reloader watches the YAML path and dispatches changes to an Applier.
type Reloader struct {
	path    string
	logger  *slog.Logger
	applier Applier

	mu      sync.Mutex
	current config.Config
}

// New returns an unstarted reloader. initial MUST be the config that
// was loaded at boot — we use it as the baseline for whitelist diffing
// (so on the first reload we don't accidentally treat "field present
// in file" as "field changed").
func New(path string, initial config.Config, applier Applier, logger *slog.Logger) *Reloader {
	return &Reloader{
		path:    path,
		logger:  logger.With("component", "configreload"),
		applier: applier,
		current: initial,
	}
}

// Run blocks until ctx is cancelled. Errors during a single reload are
// logged and swallowed; Run only returns an error if the watcher cannot
// be set up at all.
func (r *Reloader) Run(ctx context.Context) error {
	if r.path == "" {
		r.logger.Info("config path empty; hot-reload disabled")
		<-ctx.Done()
		return nil
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	defer w.Close()

	dir := filepath.Dir(r.path)
	target := filepath.Base(r.path)
	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	r.logger.Info("hot-reload watching", "path", r.path)

	var (
		timer *time.Timer
		fireC <-chan time.Time
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if filepath.Base(ev.Name) != target {
				continue
			}
			// Coalesce bursts of events into a single reload.
			if timer == nil {
				timer = time.NewTimer(debounceWindow)
				fireC = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounceWindow)
			}
		case <-fireC:
			timer = nil
			fireC = nil
			if err := r.reload(); err != nil {
				r.logger.Warn("reload rejected; keeping previous config", "err", err)
			}
		case werr, ok := <-w.Errors:
			if !ok {
				return nil
			}
			r.logger.Warn("fsnotify error", "err", werr)
		}
	}
}

// reload re-reads the file and applies whitelisted changes. Returns an
// error iff the file couldn't be parsed OR a non-whitelisted field
// changed (in which case we refuse the whole reload to avoid silently
// ignoring an admin's intended change).
func (r *Reloader) reload() error {
	next, err := config.Load(r.path)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	r.mu.Lock()
	prev := r.current
	r.mu.Unlock()

	if err := requireOnlyWhitelisted(prev, next); err != nil {
		return err
	}

	// Apply each whitelisted field. The applier is responsible for
	// being idempotent — we don't gate on "did the value change" because
	// computing that for slices means deep-equality.
	r.applier.ApplyAcceptedTokens(next.AcceptedTokens)
	r.applier.ApplyBaseDomain(next.HTTP.BaseDomain)

	r.mu.Lock()
	r.current = next
	r.mu.Unlock()
	r.logger.Info("hot-reload applied",
		"accepted_tokens", len(next.AcceptedTokens),
		"base_domain", next.HTTP.BaseDomain)
	return nil
}

// requireOnlyWhitelisted compares prev vs. next and returns an error if
// any non-whitelisted field differs. The whitelist is intentionally
// hard-coded here (not data-driven) so it's grep-able + auditable.
//
// Whitelisted (allowed to change on reload):
//   - HTTP.BaseDomain
//   - AcceptedTokens
//
// Everything else (NodeLabel, Region, all listener addrs, all upstream
// addrs, log config) is a restart-only field.
func requireOnlyWhitelisted(prev, next config.Config) error {
	type comparable struct {
		NodeLabel string
		Region    string
		Control   config.ControlListener
		// note: HTTP.BaseDomain is whitelisted; we only compare HTTP.Addr
		HTTPAddr string
		HTTPS    config.HTTPSListener
		SNI      config.SNIListener
		Admin    config.AdminListener
		Identity config.IdentityClient
		Tunnel   config.TunnelClient
		Cert     config.CertClient
		Config   config.ConfigClient
		Quota    config.QuotaClient
		Log      config.LogConfig
	}
	cmp := func(c config.Config) comparable {
		return comparable{
			NodeLabel: c.NodeLabel,
			Region:    c.Region,
			Control:   c.Control,
			HTTPAddr:  c.HTTP.Addr,
			HTTPS:     c.HTTPS,
			SNI:       c.SNI,
			Admin:     c.Admin,
			Identity:  c.Identity,
			Tunnel:    c.Tunnel,
			Cert:      c.Cert,
			Config:    c.Config,
			Quota:     c.Quota,
			Log:       c.Log,
		}
	}
	if !reflect.DeepEqual(cmp(prev), cmp(next)) {
		return errors.New("non-whitelisted field changed (allowed: http.base_domain, accepted_tokens); restart calabi-edge to apply")
	}
	return nil
}
