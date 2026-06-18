#!/usr/bin/env bash
# verify-community.sh — guard that the Community Edition build links NONE of the
# control-plane code. The OSS split (docs/oss-split-and-local-mode.md) keeps every
# platform package under internal/platform/* behind //go:build !community; this
# script proves the `-tags community` build excludes all of it. Run from the repo
# root: `make verify-community` (or `bash scripts/verify-community.sh`).
set -uo pipefail

fail=0

check() {
  local dir="$1" pkg="$2"
  local hits
  hits=$(cd "$dir" && go list -tags community -deps "$pkg" 2>/dev/null | grep "internal/platform" || true)
  if [ -n "$hits" ]; then
    echo "FAIL: $dir $pkg links control-plane packages:"
    echo "$hits" | sed 's/^/    /'
    fail=1
  else
    echo "ok:   $dir $pkg — 0 internal/platform deps"
  fi
}

check apps/calabi-edge ./cmd/calabi-edge
check apps/client    ./cmd/calabi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Community build leaks control-plane code — a platform package is reachable"
  echo "without //go:build !community. See docs/oss-split-and-local-mode.md §四."
  exit 1
fi
echo "community build is clean (no control-plane code linked)"
