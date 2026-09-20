// Package configreload watches the calabi-edge YAML for changes and
// applies a whitelisted subset of fields without a process restart.
//
// What's hot-reloadable:
//   - base_domain (either spelling) — the subdomain suffix for new tunnels
//
// Everything else requires a restart, including every field added to
// config.Config after this was written: the check zeroes the hot fields
// and compares the rest whole, so there is no list of restart-only fields
// to forget to extend. Editor-saved files often appear as
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
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
)

// Hot-reload debounce window.
const debounceWindow = 250 * time.Millisecond

// Applier installs the new whitelisted values. Each method is called on
// every reload regardless of whether the value changed; implementations
// should be idempotent + cheap.
type Applier interface {
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
// error iff the file couldn't be loaded or validated OR a non-whitelisted
// field changed (in which case we refuse the whole reload to avoid
// silently ignoring an admin's intended change).
//
// The file goes through config.LoadEffective, the same pipeline boot used
// to build r.current — env overrides, mode normalization, the production
// posture check. Load alone would make every env-overridden field read as
// "changed" and let a reload install what boot would have refused.
func (r *Reloader) reload() error {
	next, _, err := config.LoadEffective(r.path)
	if err != nil {
		return err
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
	r.applier.ApplyBaseDomain(next.HTTP.BaseDomain)

	r.mu.Lock()
	r.current = next
	r.mu.Unlock()
	r.logger.Info("hot-reload applied", "base_domain", next.HTTP.BaseDomain)
	return nil
}

// requireOnlyWhitelisted returns an error if prev and next differ in
// anything but the hot-reloadable fields.
//
// Inverted on purpose: it zeroes the fields a reload MAY change and
// compares everything else whole. It used to hand-pick the fields to
// compare, so every field added to config.Config after that list was
// written — mode, role, relay.*, multi_region, public, state, mesh,
// edge_class — could be edited and reloaded, the log said "hot-reload
// applied", and nothing took effect: an operator who set
// relay.require_auth: true kept an open relay until the next restart.
func requireOnlyWhitelisted(prev, next config.Config) error {
	a, b := withoutHotFields(prev), withoutHotFields(next)
	if reflect.DeepEqual(a, b) {
		return nil
	}
	changed := changedFields(reflect.ValueOf(a), reflect.ValueOf(b), "")
	if len(changed) == 0 {
		// DeepEqual found a difference no exported field accounts for.
		// The names are for the log; the gate is DeepEqual, so still refuse.
		changed = []string{"(unexported)"}
	}
	return fmt.Errorf("restart-only field(s) changed: %s (hot-reloadable: base_domain); restart calabi-edge to apply",
		strings.Join(changed, ", "))
}

// withoutHotFields zeroes the fields a reload may change. This IS the
// whitelist: whatever it doesn't zero is restart-only.
func withoutHotFields(c config.Config) config.Config {
	// Two spellings of one setting, kept equal by config.Load — changing
	// either changes both, so both are hot.
	c.BaseDomain = ""
	c.HTTP.BaseDomain = ""
	return c
}

// changedFields lists the YAML paths (e.g. relay.require_auth) of the
// fields that differ between a and b, two values of the same struct type.
// Names only, never values: the config carries credentials.
func changedFields(a, b reflect.Value, prefix string) []string {
	var out []string
	t := a.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := yamlName(f)
		if prefix != "" {
			name = prefix + "." + name
		}
		fa, fb := a.Field(i), b.Field(i)
		if f.Type.Kind() == reflect.Struct {
			if sub := changedFields(fa, fb, name); len(sub) > 0 {
				out = append(out, sub...)
				continue
			}
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			out = append(out, name)
		}
	}
	return out
}

func yamlName(f reflect.StructField) string {
	if tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); tag != "" && tag != "-" {
		return tag
	}
	return f.Name
}
