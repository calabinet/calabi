#!/usr/bin/env bash
# verify-public-tree.sh — guard that the components destined for the PUBLIC
# repository link NO closed control-plane contract.
#
# Supersedes verify-community.sh. That script asked "does the -tags community
# build avoid internal/platform/*?", which was the right question while the
# community edition existed. It is the WRONG question now (full-oss-plan F1):
# the client no longer has editions, and its internal/platform/* packages —
# bffclient / clientreg / edgepicker / statusapi — are published on purpose.
# They speak bff-console's public HTTP REST API, which anyone can already read
# in browser devtools; they import no generated contract at all.
#
# The question that actually protects the商业 boundary is narrower and harder:
#
#   does this binary link pkg/api (the MONOLITHIC generated control-plane
#   package, ~150 internal RPCs across 11 services incl. every Admin* one),
#   pkg/eventbus, or any control-plane service?
#
# That is what must never reach the public tree — see full-oss-plan §3.2.
set -uo pipefail

fail=0

# Packages that must never appear in a public binary's dependency graph.
# pkg/api          — the control-plane contract monolith (the whole reason the
#                    platform edge/coord are not published yet). Note the edge
#                    CONTRACT is no longer in there: F3 moved it to its own
#                    module, pkg/edge-proto, precisely so it can be exported.
# pkg/eventbus     — internal NATS subjects + payload shapes.
# apps/*-svc, bff-* — control-plane services themselves.
# Listed explicitly rather than as `apps/.*-svc`: calabi-coord IS a publish target
# (full-oss-plan D4), so a blanket suffix rule would flag the very component we
# are trying to open.
CLOSED_SVCS='audit|billing|cert|config|domain|identity|metering|notify|quota|support|tenant|tunnel'
FORBIDDEN="calabi/pkg/api|calabi/pkg/eventbus|calabi/apps/($CLOSED_SVCS)-svc|calabi/apps/bff-"

# report_only <dir> <pkg> — same scan, but prints what is left instead of
# failing. For a component that is deliberately not published yet.
report_only() {
  local dir="$1" pkg="$2" hits
  hits=$(cd "$dir" && go list -deps "$pkg" 2>/dev/null | grep -E "$FORBIDDEN" || true)
  if [ -n "$hits" ]; then
    echo "todo: $dir $pkg — not publishable yet, still links:"
    echo "$hits" | sed 's/^/    /'
  else
    echo "ok:   $dir $pkg — no closed contract linked (ready to publish)"
  fi
}

# check <dir> <pkg> [build tags]
check() {
  local dir="$1" pkg="$2" tags="${3:-}"
  local hits label
  label="$dir $pkg${tags:+ (-tags $tags)}"
  if [ -n "$tags" ]; then
    hits=$(cd "$dir" && go list -tags "$tags" -deps "$pkg" 2>/dev/null | grep -E "$FORBIDDEN" || true)
  else
    hits=$(cd "$dir" && go list -deps "$pkg" 2>/dev/null | grep -E "$FORBIDDEN" || true)
  fi
  if [ -n "$hits" ]; then
    echo "FAIL: $label links closed control-plane packages:"
    echo "$hits" | sed 's/^/    /'
    fail=1
  else
    echo "ok:   $label — no closed contract linked"
  fi
}

# The client ships as ONE binary now: no tags, and the DEFAULT build must be
# clean. This is the F1 deliverable — if this line fails, the client cannot be
# published as-is.
check apps/client ./cmd/calabi

# The edge ships whole since F3: one build, no edition split, and it reaches the
# control plane only through bff-edge whose contract lives in its own module.
check apps/calabi-edge ./cmd/calabi-edge

# coord became publishable when F4 landed: the nodehooks contract took its
# pkg/api dependency to zero, and BillingHooks.ReportRelayUsage replaced the
# direct publish to the cluster's NATS that was the last thing linking
# pkg/eventbus. This line was report_only while that was outstanding; it is
# ENFORCED now, which is the point of having written it early.
check apps/calabi-coord ./cmd/calabi-coord

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "A component destined for the public repo links the closed control-plane"
  echo "contract. See docs/runbook/full-oss-plan.md §3.2 / §7.2."
  exit 1
fi
echo ""
echo "public tree is clean (no closed control-plane contract linked)"
