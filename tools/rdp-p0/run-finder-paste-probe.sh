#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Run on macOS.' >&2; exit 1; }
source_dir="$(cd "$(dirname "$0")" && pwd)"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/calabi-finder-probe.XXXXXX")
trap 'rm -f "$build_dir/finder-paste-probe"; rmdir "$build_dir"' EXIT
xcrun clang -fobjc-arc -Wall -Wextra "$source_dir/finder-paste-probe.m" \
  -framework Cocoa -framework ApplicationServices -o "$build_dir/finder-paste-probe"
"$build_dir/finder-paste-probe" 2>&1 | tee "$source_dir/finder-paste-probe.log"
