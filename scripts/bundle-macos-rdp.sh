#!/usr/bin/env bash
# Complete the app bundle before packaging or notarizing it.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
app="${1:?Pass the freshly built Calabi.app}"
archs=()
case "${2:-}" in
  universal-apple-darwin) archs=(arm64 x86_64); finder_target=--universal ;;
  aarch64-apple-darwin) archs=(arm64); finder_target=--arm64 ;;
  x86_64-apple-darwin) archs=(x86_64); finder_target=--x86_64 ;;
  "") archs=("$(uname -m)"); finder_target="--${archs[0]}" ;;
  *) echo "Unsupported macOS target: $2" >&2; exit 2 ;;
esac
for tool in cmake pkg-config python3; do
  command -v "$tool" >/dev/null || { echo "Missing Mac RDP build tool: $tool" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for arch in "${archs[@]}"; do
  bash "$root/tools/rdp-p0/build-macos-sdk.sh" "$arch" "$work/$arch"
  helper="$(bash "$root/tools/rdp-p0/build-helper.sh" --release-sdk "$arch" "$work/$arch/sdk")"
  cp "$helper" "$work/$arch/calabi-rdp"
done

sign=(--force --sign "${APPLE_SIGNING_IDENTITY:--}")
if [[ -n "${APPLE_SIGNING_IDENTITY:-}" && "$APPLE_SIGNING_IDENTITY" != - ]]; then
  sign+=(--options runtime --timestamp)
fi
frameworks="$app/Contents/Frameworks"
resources="$app/Contents/Resources"
mkdir -p "$frameworks" "$resources/rdp-licenses"
for name in libfreerdp3.3.dylib libfreerdp-client3.3.dylib libwinpr3.3.dylib \
            libcrypto.3.dylib libssl.3.dylib; do
  slices=()
  for arch in "${archs[@]}"; do slices+=("$work/$arch/sdk/lib/$name"); done
  lipo -create "${slices[@]}" -output "$frameworks/$name"
  codesign "${sign[@]}" "$frameworks/$name"
done
cp "$work/${archs[0]}"/sdk/licenses/*.txt "$resources/rdp-licenses/"

slices=()
for arch in "${archs[@]}"; do slices+=("$work/$arch/calabi-rdp"); done
rdp="$app/Contents/MacOS/calabi-rdp"
lipo -create "${slices[@]}" -output "$rdp"
chmod 755 "$rdp"
codesign "${sign[@]}" "$rdp"

bash "$root/tools/rdp-finder-menu/build.sh" "$app/Contents/MacOS/CalabiRemoteFiles.app" "$finder_target" "${APPLE_SIGNING_IDENTITY:--}"
codesign "${sign[@]}" --preserve-metadata=entitlements "$app"
bash "$root/scripts/verify-macos-rdp-bundle.sh" "$app" "${archs[@]}"
