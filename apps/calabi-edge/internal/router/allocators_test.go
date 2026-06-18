package router

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// TestSubdomainAllocator_InMemory checks the no-persistence default: a
// fresh allocator hands out u000001, u000002, ... and Seed jumps the
// counter forward. This is the path tests + ephemeral edges use.
func TestSubdomainAllocator_InMemory(t *testing.T) {
	a := NewSubdomainAllocator("example.com")
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000001.example.com" {
		t.Fatalf("first Allocate = %q, want u000001.example.com", got)
	}
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000002.example.com" {
		t.Fatalf("second Allocate = %q, want u000002.example.com", got)
	}
	a.Seed(99)
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000100.example.com" {
		t.Fatalf("post-Seed Allocate = %q, want u000100.example.com", got)
	}
}

// TestSubdomainAllocator_PersistsAcrossRestart is the core fix for
// task #71: after UsePersistentSeq, the seq value survives a fresh
// allocator instance built from the same path.
func TestSubdomainAllocator_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdomain.seq")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	a1 := NewSubdomainAllocator("example.com")
	if err := a1.UsePersistentSeq(path, logger); err != nil {
		t.Fatalf("UsePersistentSeq: %v", err)
	}
	for i := 0; i < 5; i++ {
		_ = a1.Allocate(proto.ProxyKindHTTP)
	}
	// File should now hold "5\n".
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seq file: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "5" {
		t.Fatalf("seq file = %q, want 5", got)
	}

	// Simulate restart: brand-new allocator, same path. First Allocate
	// must return u000006 (not u000001), proving persistence took.
	a2 := NewSubdomainAllocator("example.com")
	if err := a2.UsePersistentSeq(path, logger); err != nil {
		t.Fatalf("UsePersistentSeq (post-restart): %v", err)
	}
	if got := a2.Allocate(proto.ProxyKindHTTP); got != "u000006.example.com" {
		t.Fatalf("post-restart Allocate = %q, want u000006.example.com", got)
	}
}

// TestSubdomainAllocator_PersistMissingFileStartsAtZero covers the
// happy first-boot case: no file exists, allocator starts at 1.
func TestSubdomainAllocator_PersistMissingFileStartsAtZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdomain.seq") // also tests MkdirAll
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	a := NewSubdomainAllocator("example.com")
	if err := a.UsePersistentSeq(path, logger); err != nil {
		t.Fatalf("UsePersistentSeq: %v", err)
	}
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000001.example.com" {
		t.Fatalf("first Allocate on fresh path = %q, want u000001.example.com", got)
	}
}

// SeedIfBehind only moves seq forward — calling with a lower value is
// a no-op, calling with a higher value advances and persists. The
// edge boot uses this to layer DB-max on top of the file-backed value
// without ever rewinding the counter.
func TestSubdomainAllocator_SeedIfBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdomain.seq")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := NewSubdomainAllocator("example.com")
	if err := a.UsePersistentSeq(path, logger); err != nil {
		t.Fatalf("UsePersistentSeq: %v", err)
	}
	a.Seed(10)

	// Behind — no-op.
	a.SeedIfBehind(5)
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000011.example.com" {
		t.Fatalf("after SeedIfBehind(5) low → Allocate = %q, want u000011.example.com", got)
	}
	// Ahead — bumps + persists.
	a.SeedIfBehind(100)
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000101.example.com" {
		t.Fatalf("after SeedIfBehind(100) → Allocate = %q, want u000101.example.com", got)
	}
	data, _ := os.ReadFile(path)
	if got := strings.TrimSpace(string(data)); got != "101" {
		t.Fatalf("seq file = %q, want 101 (SeedIfBehind should persist)", got)
	}
}

// TestSubdomainAllocator_CorruptFileResetsToZero — operator nukes the
// file or writes garbage to it; allocator boots at 0 and the next
// Allocate overwrites the bad contents with a valid number.
func TestSubdomainAllocator_CorruptFileResetsToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdomain.seq")
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	a := NewSubdomainAllocator("example.com")
	if err := a.UsePersistentSeq(path, logger); err != nil {
		t.Fatalf("UsePersistentSeq with corrupt file: %v", err)
	}
	if got := a.Allocate(proto.ProxyKindHTTP); got != "u000001.example.com" {
		t.Fatalf("Allocate after corrupt-reset = %q, want u000001.example.com", got)
	}
	// And the corrupt content should now be replaced by "1\n".
	data, _ := os.ReadFile(path)
	if got := strings.TrimSpace(string(data)); got != "1" {
		t.Fatalf("seq file after recovery = %q, want 1", got)
	}
	// Sanity: subsequent value still parseable.
	if _, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err != nil {
		t.Fatalf("seq file not a number after recovery: %v", err)
	}
}
