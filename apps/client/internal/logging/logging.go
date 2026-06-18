// Package logging owns the calabi client's structured-logging pipeline.
//
// Before the client logged to stderr only — fine for foreground
// `calabi http <port>` runs, fatal for `calabi daemon` once we register
// the binary as a Windows Service / systemd unit: the service manager
// detaches stderr and the user has nothing to grep when something breaks.
//
// What this package does:
//
//  1. Sets up a slog.Logger that fans out to:
//     - stderr (so foreground runs still look the same)
//     - a rotating log file under <config-dir>/logs/calabi.log
//     (rotated by lumberjack at 10MB, 5-file retention, ~5MB gzipped)
//     - an in-process ring buffer + pub/sub hub so the status server's
//     /logs and /logs/stream endpoints can serve "last N lines" and
//     "tail -f" without re-opening the rotated file
//
//  2. Exposes Tail(n) and Subscribe() so internal/status can serve the
//     HTTP endpoints without importing slog internals.
//
// Why a hub instead of just tailing the file? Two reasons: (a) it works
// across rotation boundaries without resetting the read position, and
// (b) it keeps log bytes from hitting disk twice on the hot path —
// stdout/file get the formatted text once, subscribers get the same
// bytes via the multi-writer fan-out.
package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Options controls how the logger is constructed. Zero value is valid
// (file logging disabled, debug off, stderr only).
type Options struct {
	// FilePath overrides the default rotated-log location. Empty =
	// derive from configDir() + "logs/calabi.log".
	FilePath string
	// Debug, when true, sets the slog level to Debug instead of Info.
	// Honors $CALABI_DEBUG=1 when left at the default false.
	Debug bool
	// MaxSizeMB is the lumberjack rotation threshold; 0 → 10 MB.
	MaxSizeMB int
	// MaxBackups is the number of rotated files kept; 0 → 5.
	MaxBackups int
	// MaxAgeDays bounds how long rotated files stick around; 0 = forever.
	MaxAgeDays int
	// DisableFile is a kill switch for the file sink — used by the
	// foreground single-tunnel CLIs (`calabi http <port>`) so test runs
	// and short-lived demos don't litter the disk.
	DisableFile bool
	// RingCapacity bounds the in-memory tail buffer (line count); 0 → 2000.
	// Tradeoff: bigger = more memory + more useful /logs?tail=N, smaller =
	// truncate sooner if the UI is slow to subscribe.
	RingCapacity int
}

// Hub is the package-level singleton holding the rotator, ring buffer,
// and subscriber set. It implements io.Writer (used by slog's text
// handler) and is goroutine-safe.
type Hub struct {
	mu          sync.RWMutex
	ring        []string
	ringCap     int
	subscribers map[chan string]struct{}
	rotator     io.WriteCloser
	filePath    string
}

var (
	hubMu sync.Mutex
	hub   *Hub
)

// Setup initializes the package and returns the configured slog.Logger.
//
// Idempotent: subsequent calls return the same logger and ignore opts.
// This matches main.go's pattern of calling setupLogger() from each
// subcommand without coordinating.
func Setup(opts Options) *slog.Logger {
	hubMu.Lock()
	defer hubMu.Unlock()
	if hub != nil {
		return slog.Default()
	}

	if opts.Debug || os.Getenv("CALABI_DEBUG") == "1" {
		opts.Debug = true
	}
	if opts.MaxSizeMB == 0 {
		opts.MaxSizeMB = 10
	}
	if opts.MaxBackups == 0 {
		opts.MaxBackups = 5
	}
	if opts.RingCapacity == 0 {
		opts.RingCapacity = 2000
	}
	if opts.FilePath == "" {
		opts.FilePath = defaultFilePath()
	}

	h := &Hub{
		ringCap:     opts.RingCapacity,
		ring:        make([]string, 0, opts.RingCapacity),
		subscribers: make(map[chan string]struct{}),
		filePath:    opts.FilePath,
	}

	// File sink. Best-effort: a failure here (read-only home dir on a
	// CI machine, locked-down kiosk) must NOT crash the client — we
	// still want stderr logging to come up.
	if !opts.DisableFile && opts.FilePath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.FilePath), 0o700); err == nil {
			h.rotator = &lumberjack.Logger{
				Filename:   opts.FilePath,
				MaxSize:    opts.MaxSizeMB,
				MaxBackups: opts.MaxBackups,
				MaxAge:     opts.MaxAgeDays,
				Compress:   true,
			}
		}
	}

	// Sink order: file (durable) → stderr (visibility) → hub (tail/SSE).
	// The hub is io.Writer-side fanning into the ring + per-sub channels.
	//
	// NOT io.MultiWriter: it stops at the first erroring sink, which starves the
	// rest. A Windows SERVICE has no console, so writing os.Stderr fails with
	// "handle is invalid" — io.MultiWriter would then never reach the hub, and
	// the dashboard's /logs page stays blank even though the file has every
	// line. bestEffortWriter feeds every healthy sink regardless of a broken one.
	var sinks []io.Writer
	if h.rotator != nil {
		sinks = append(sinks, h.rotator)
	}
	sinks = append(sinks, os.Stderr, h)
	w := bestEffortWriter(sinks)

	lvl := slog.LevelInfo
	if opts.Debug {
		lvl = slog.LevelDebug
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	hub = h
	return logger
}

// bestEffortWriter fans each write out to every sink, ignoring per-sink errors
// (unlike io.MultiWriter, which returns at the first erroring sink and skips the
// rest). Correct for a log fan-out: one broken sink — e.g. a service's detached
// os.Stderr — must not stop the others (the durable file and the dashboard hub)
// from getting the line.
type bestEffortWriter []io.Writer

func (m bestEffortWriter) Write(p []byte) (int, error) {
	for _, s := range m {
		_, _ = s.Write(p)
	}
	return len(p), nil
}

// GetHub returns the package singleton; nil if Setup has not been called.
// Callers (the status server) tolerate nil by serving empty results.
func GetHub() *Hub {
	hubMu.Lock()
	defer hubMu.Unlock()
	return hub
}

// FilePath returns the resolved file-sink path (may be empty if file
// logging was disabled). Used by the /logs/download endpoint.
func (h *Hub) FilePath() string {
	if h == nil {
		return ""
	}
	return h.filePath
}

// Write implements io.Writer. slog's text handler emits one record per
// call ending with '\n'; we may also receive multi-line writes if a
// caller hand-formats. Split on '\n' so the ring stays one-line-per-slot.
func (h *Hub) Write(p []byte) (int, error) {
	if h == nil || len(p) == 0 {
		return len(p), nil
	}
	// We don't own p — copy any retained slices before unlocking.
	lines := splitLines(p)
	if len(lines) == 0 {
		return len(p), nil
	}
	h.mu.Lock()
	for _, ln := range lines {
		if len(h.ring) >= h.ringCap {
			// drop the oldest line (O(n) shift acceptable: ringCap is
			// in the low thousands, this happens at most a few times/sec).
			copy(h.ring, h.ring[1:])
			h.ring = h.ring[:len(h.ring)-1]
		}
		h.ring = append(h.ring, ln)
	}
	subs := make([]chan string, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	// Push to subscribers OUTSIDE the lock so a stuck UI doesn't block
	// logging. Drop on full channel — better lose tail bytes than stall
	// the calling goroutine.
	for _, ch := range subs {
		for _, ln := range lines {
			select {
			case ch <- ln:
			default:
				// subscriber is too slow; skip
			}
		}
	}
	return len(p), nil
}

// Tail returns up to n most-recent lines from the ring buffer, oldest
// first. n <= 0 returns the whole ring.
func (h *Hub) Tail(n int) []string {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if n <= 0 || n > len(h.ring) {
		out := make([]string, len(h.ring))
		copy(out, h.ring)
		return out
	}
	out := make([]string, n)
	copy(out, h.ring[len(h.ring)-n:])
	return out
}

// Subscribe returns a channel that receives every new line until ctx
// cancels. Buffer is sized for ~one burst (256 lines); slow subscribers
// drop bytes rather than block writers.
func (h *Hub) Subscribe(ctx context.Context) <-chan string {
	if h == nil {
		// Closed channel — callers read zero values and exit cleanly.
		ch := make(chan string)
		close(ch)
		return ch
	}
	ch := make(chan string, 256)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
		close(ch)
	}()
	return ch
}

// Close flushes the file sink. Called from main's defer; ignored if Setup
// was never called.
func (h *Hub) Close() error {
	if h == nil || h.rotator == nil {
		return nil
	}
	return h.rotator.Close()
}

// splitLines splits b on '\n', dropping the trailing empty slot if b
// ends with '\n'. Each returned line excludes the newline.
func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	// Fast path: usually exactly one line ending in '\n'.
	if bytes.Count(b, []byte{'\n'}) == 1 && b[len(b)-1] == '\n' {
		return []string{string(b[:len(b)-1])}
	}
	raw := strings.Split(string(b), "\n")
	out := make([]string, 0, len(raw))
	for i, s := range raw {
		if i == len(raw)-1 && s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// defaultFilePath resolves the per-OS log location. Mirrors creds.configDir
// without importing the creds package (avoid a cycle: creds → logging in
// future would block this).
//
//	Windows: %LOCALAPPDATA%\calabi\logs\calabi.log
//	Linux:   $XDG_CONFIG_HOME/calabi/logs/calabi.log  (or ~/.config/...)
//	macOS:   ~/Library/Logs/calabi/calabi.log
func defaultFilePath() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "calabi", "logs", "calabi.log")
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Logs", "calabi", "calabi.log")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "calabi", "logs", "calabi.log")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "calabi", "logs", "calabi.log")
	}
	// Last-ditch: write into the temp dir so we never lose logs entirely.
	return filepath.Join(os.TempDir(), fmt.Sprintf("calabi-%d.log", time.Now().Unix()))
}
