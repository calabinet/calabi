#!/usr/bin/env bash
# verify-reproducible-build.sh - rebuild the official calabi binaries from
# published source and check they are byte-for-byte what was shipped.
#
# You do not have to trust that the binary you downloaded came from this
# repository. Check it:
#
#   curl -fsSLO https://download.calabi.net/latest/build-manifest.json
#   bash scripts/verify-reproducible-build.sh build-manifest.json
#
# The manifest names the source commit, the Go toolchain, the exact build flags,
# and the one input that is NOT in this repo (the platform's edge-CA root, a
# public certificate, carried in the manifest verbatim). This script checks the
# commit out, applies that input, rebuilds every artifact and compares hashes.
#
# WHAT IS COMPARED, AND WHY IT IS NOT THE DOWNLOAD
#
# The .zip / .tar.gz you downloaded is NOT reproducible and cannot be: tar+gzip
# and zip both record modification times, so packaging the same bytes a second
# later yields a different archive. What IS stable is the BINARY inside. So this
# unpacks nothing and compares the binary it builds against binary_sha256. To
# check the archive you actually downloaded, use SHA256SUMS - that is a
# different question (did I get the file intact) from this one (was the file
# built from this source).
#
# WHAT THIS DOES NOT COVER
#
# The manifest's not_reproducible_yet list, honestly enumerated: the Windows
# desktop installer, the macOS .pkg, the docker images, and two inputs that ship
# as committed blobs rather than being built here (the console SPA bundle and
# the third-party wintun.dll). Those are byte-identical for anyone building this
# commit, but this script does not derive them from their own sources.
#
# Requirements: go (the version the manifest names), git, and one of
# python3 / python / jq.
#
# Usage:
#   verify-reproducible-build.sh <manifest.json> [--tree <dir>] [--keep]
#     --tree   verify against an existing checkout instead of cloning
#     --keep   leave the work tree in place for inspection
set -uo pipefail

MANIFEST="${1:?usage: verify-reproducible-build.sh <build-manifest.json> [--tree <dir>] [--keep]}"
shift
TREE=""
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tree) TREE="${2:?--tree needs a directory}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done
[ -f "$MANIFEST" ] || { echo "no such manifest: $MANIFEST" >&2; exit 2; }
MANIFEST="$(cd "$(dirname "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"

if   command -v sha256sum >/dev/null 2>&1; then SHA() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum    >/dev/null 2>&1; then SHA() { shasum -a 256 "$1" | awk '{print $1}'; }
else echo "need sha256sum or shasum" >&2; exit 2; fi

# --- read the manifest ------------------------------------------------------
# Two readers for one job is not elegant, but requiring a specific JSON tool
# would turn "anyone can check this" into "anyone with jq can check this".
# Both open the file as UTF-8 explicitly: the default encoding is the console's
# on Windows, and a manifest is exactly the kind of file that gets verified on
# whatever machine the user happens to have.
PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
if [ -n "$PY" ]; then
  read_field() { "$PY" -c 'import io,json,sys
d=json.load(io.open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2].split("."): d=d[k]
sys.stdout.write(str(d))' "$MANIFEST" "$1"; }
  read_ca()   { "$PY" -c 'import io,json,sys
d=json.load(io.open(sys.argv[1], encoding="utf-8"))
sys.stdout.write("\n".join(d["inputs"]["edge_ca"]["pem"]) + "\n")' "$MANIFEST"; }
  read_jobs() { "$PY" -c 'import io,json,sys
d=json.load(io.open(sys.argv[1], encoding="utf-8"))
for group, items in d["artifacts"].items():
    for a in items or []:
        sys.stdout.write("\t".join([group, a["platform"], a["binary"], a["binary_sha256"], a["ldflags"], a["archive"]]) + "\n")' "$MANIFEST"; }
elif command -v jq >/dev/null 2>&1; then
  read_field() { jq -r ".$1" "$MANIFEST"; }
  read_ca()    { jq -r '.inputs.edge_ca.pem[]' "$MANIFEST"; }
  read_jobs()  { jq -r '.artifacts | to_entries[] | .key as $g | (.value // [])[] | [$g,.platform,.binary,.binary_sha256,.ldflags,.archive] | @tsv' "$MANIFEST"; }
else
  echo "need python3, python, or jq to read the manifest" >&2; exit 2
fi

REPO="$(read_field source.repo)"
COMMIT="$(read_field source.commit)"
WANT_GO="$(read_field toolchain.go)"
VERSION="$(read_field version)"

echo "manifest:  calabi $VERSION"
echo "source:    $REPO @ $COMMIT"
echo "toolchain: $WANT_GO"

# --- toolchain ---------------------------------------------------------------
command -v go >/dev/null 2>&1 || { echo "go is not installed" >&2; exit 2; }
HAVE_GO="$(go version | awk '{print $3}')"
if [ "$HAVE_GO" != "$WANT_GO" ]; then
  # Not fatal, but say it FIRST rather than letting it surface as a mysterious
  # hash mismatch. A different Go version is the single most common reason a
  # reproduction fails, and it is not evidence of tampering.
  echo
  echo "WARNING: your Go is $HAVE_GO, the release was built with $WANT_GO."
  echo "         Hashes will almost certainly differ. Install $WANT_GO to compare."
  echo
fi

# --- get the sources ---------------------------------------------------------
WORK=""
if [ -n "$TREE" ]; then
  TREE="$(cd "$TREE" && pwd)"
  echo "using existing tree: $TREE"
  if [ -d "$TREE/.git" ]; then
    at="$(cd "$TREE" && git rev-parse HEAD)"
    [ "$at" = "$COMMIT" ] || echo "WARNING: tree is at $at, manifest names $COMMIT"
  fi
else
  command -v git >/dev/null 2>&1 || { echo "git is not installed" >&2; exit 2; }
  WORK="$(mktemp -d)"
  TREE="$WORK/src"
  echo
  echo "cloning $REPO ..."
  git clone --quiet "$REPO" "$TREE" || { echo "clone failed" >&2; exit 2; }
  ( cd "$TREE" && git checkout --quiet "$COMMIT" ) || { echo "commit $COMMIT not found in $REPO" >&2; exit 2; }
fi
CA_BACKUP=""
CA_FILE=""
# Put the tree back the way it was found. With --tree the user pointed us at
# THEIR checkout, and writing the platform's CA into it and walking away would
# leave a clone that quietly builds a client trusting calabi.net - and, if they
# happen to publish from that tree, ships it.
cleanup() {
  if [ -n "$CA_BACKUP" ] && [ -f "$CA_BACKUP" ]; then
    cp "$CA_BACKUP" "$CA_FILE" 2>/dev/null || true
    rm -f "$CA_BACKUP"
  fi
  if [ "$KEEP" = 0 ] && [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

# --- apply the one input that is not in the repo ----------------------------
CA_PATH="$(read_field inputs.edge_ca.path)"
if [ -f "$TREE/$CA_PATH" ]; then
  CA_FILE="$TREE/$CA_PATH"
  CA_BACKUP="$(mktemp)"
  cp "$CA_FILE" "$CA_BACKUP"
  read_ca > "$CA_FILE"
  echo "applied edge-CA from the manifest -> $CA_PATH (restored on exit)"
fi

# --- rebuild and compare -----------------------------------------------------
# GOWORK is explicitly cleared from the environment, NOT set to "off": the build
# must use the tree's own go.work, and workspace mode and GOWORK=off produce
# different bytes. An inherited GOWORK pointing elsewhere would silently change
# the result.
unset GOWORK

ERRLOG="$(mktemp)"
pass=0; fail=0; skip=0
echo
while IFS="$(printf '\t')" read -r group platform binary want ldflags archive; do
  [ -n "${group:-}" ] || continue
  case "$group" in
    client) src="$TREE/apps/client";      cmd="./cmd/calabi" ;;
    edge)   src="$TREE/apps/calabi-edge"; cmd="./cmd/calabi-edge" ;;
    *)      echo "  SKIP $archive - unknown component '$group'"; skip=$((skip+1)); continue ;;
  esac
  if [ ! -d "$src" ]; then
    echo "  SKIP $archive - $group is not in this tree"
    skip=$((skip+1)); continue
  fi
  goos="${platform%%/*}"; goarch="${platform##*/}"
  goarm=""
  # armv7 is GOARCH=arm plus GOARM=7; the manifest records the pair as linux/arm.
  case "$archive" in *armv7*) goarm=7 ;; esac
  outbin="${WORK:-${TMPDIR:-/tmp}}/rebuild-$group-$goos-$goarch${goarm:+v$goarm}"
  printf '  building %-34s ' "$archive"
  # -buildvcs=false must match the release build: with VCS stamping on, the bytes
  # depend on which git repository the source happens to sit in, so your clone
  # could never match ours no matter how correct everything else was.
  if ! ( cd "$src" && env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" ${goarm:+GOARM="$goarm"} \
           go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "$outbin" "$cmd" ) 2>"$ERRLOG"; then
    echo "BUILD FAILED"
    sed 's/^/      /' "$ERRLOG"
    fail=$((fail+1)); continue
  fi
  got="$(SHA "$outbin")"
  if [ "$got" = "$want" ]; then
    echo "MATCH"
    pass=$((pass+1))
  else
    echo "MISMATCH"
    echo "      built    $got"
    echo "      released $want"
    fail=$((fail+1))
  fi
  rm -f "$outbin"
done <<EOF
$(read_jobs)
EOF
rm -f "$ERRLOG"

echo
echo "match: $pass   mismatch: $fail   skipped: $skip"
if [ "$fail" -ne 0 ]; then
  echo
  echo "A mismatch is not proof of tampering. Check, in this order:"
  echo "  1. your Go is exactly $WANT_GO (see the warning above, if any)"
  echo "  2. you did not set GOWORK, GOFLAGS, GOEXPERIMENT or GOAMD64"
  echo "  3. the tree is at $COMMIT with no local edits (git status)"
  echo "If all three hold and it still differs, that IS worth reporting."
  exit 1
fi
if [ "$pass" -eq 0 ]; then
  echo "nothing was verified"
  exit 1
fi
echo "every rebuilt binary matches what was released."
