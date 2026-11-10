#!/usr/bin/env bash
# Build the native session executable on the target Mac. stdout is its path.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
src="$root/tools/rdp-p0"
tmp=$(mktemp -d)
trap 'rm -f "$tmp/session.o" "$tmp/clipboard.o" "$tmp/window.o" "$tmp/clipboard-test" "$tmp/display-layout-test" "$tmp/display-channel-test" "$tmp/gfx-channel-test" "$tmp/macos-clipboard-test" "$tmp/macos-mesh-test" "$tmp/macos-fileprovider-test" "$tmp/build.json"; rmdir "$tmp"' EXIT
cc=(xcrun clang)
cargo_args=()
link_paths=()
run_tests=1
if [[ $# -ne 0 ]]; then
  [[ $# -eq 3 && "$1" == --release-sdk ]] || {
    echo "Usage: $0 [--release-sdk ARCH SDK_DIR]" >&2; exit 2;
  }
  case "$2" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) echo "Unsupported architecture: $2" >&2; exit 2 ;;
  esac
  unset PKG_CONFIG_PATH
  export PKG_CONFIG_LIBDIR="$3/lib/pkgconfig"
  export MACOSX_DEPLOYMENT_TARGET=11.0
  cc+=(-arch "$2")
  cargo_args=(--release --target "$target")
  link_paths=(-Wl,-rpath,@executable_path/../Frameworks)
  # Run the channel, display and clipboard fixtures on the native slice.
  if [[ "$2" == "$(uname -m)" ]]; then
    export DYLD_LIBRARY_PATH="$3/lib"
  else
    run_tests=0
  fi
fi
if ! pkg-config --atleast-version=3.32.2 freerdp3; then
  echo "Mac RDP requires FreeRDP 3.32.2 or newer." >&2
  exit 1
fi
pkg-config --modversion freerdp3 winpr3 >&2
cflags_text="$(pkg-config --cflags freerdp3 freerdp-client3 winpr3)"
libs_text="$(pkg-config --libs freerdp3 freerdp-client3 winpr3)"
read -ra cflags <<< "$cflags_text"
read -ra libs <<< "$libs_text"
if [[ $run_tests -eq 1 ]]; then
  "${cc[@]}" -std=c11 -Wall -Wextra "$src/display_layout_test.c" -o "$tmp/display-layout-test"
  "$tmp/display-layout-test" >&2
  "${cc[@]}" -std=c11 "${cflags[@]}" "$src/display_channel_test.c" "${libs[@]}" -o "$tmp/display-channel-test"
  WLOG_LEVEL=OFF "$tmp/display-channel-test" >&2
  "${cc[@]}" -std=c11 "${cflags[@]}" "$src/gfx_channel_test.c" "${libs[@]}" -o "$tmp/gfx-channel-test"
  if [[ $# -eq 0 ]]; then
    WLOG_LEVEL=OFF "$tmp/gfx-channel-test" >&2
  else
    gfx="$(WLOG_LEVEL=OFF "$tmp/gfx-channel-test" --require-gfx)"
    printf '%s\n' "$gfx" >&2
    grep -q 'AVC available=1' <<<"$gfx" || { echo 'Missing RDPGFX H.264 support' >&2; exit 1; }
  fi
  # Use the installed SDK to exercise channel recreation; no real connection or clipboard access.
  "${cc[@]}" -std=c11 "${cflags[@]}" "$src/clipboard_test.c" "${libs[@]}" -o "$tmp/clipboard-test"
  WLOG_LEVEL=OFF "$tmp/clipboard-test" >&2
  printf '%s\n' 'RDP clipboard lifecycle tests passed.' >&2
  "${cc[@]}" -fobjc-arc "$src/macos_clipboard_test.m" -framework AppKit -framework ImageIO -framework CoreGraphics -o "$tmp/macos-clipboard-test"
  "$tmp/macos-clipboard-test" >&2
  "${cc[@]}" -fobjc-arc "$src/macos_mesh_copy_test.m" -framework AppKit -framework ImageIO -framework CoreGraphics -o "$tmp/macos-mesh-test"
  "$tmp/macos-mesh-test" >&2
  "${cc[@]}" -fobjc-arc "$src/macos_fileprovider_bridge_test.m" -framework AppKit -framework ImageIO -framework CoreGraphics -o "$tmp/macos-fileprovider-test"
  "$tmp/macos-fileprovider-test" >&2
fi
"${cc[@]}" -std=c11 -Werror=incompatible-pointer-types -DCALABI_REMOTE_WORKSPACE -DCALABI_RDP_GFX "${cflags[@]}" -c "$src/session.c" -o "$tmp/session.o"
"${cc[@]}" -std=c11 "${cflags[@]}" -c "$src/clipboard.c" -o "$tmp/clipboard.o"
"${cc[@]}" -fobjc-arc -DCALABI_REMOTE_WORKSPACE -c "$src/window.m" -o "$tmp/window.o"
args=(-C "link-arg=$tmp/session.o" -C "link-arg=$tmp/clipboard.o" -C "link-arg=$tmp/window.o" -C link-arg=-framework -C link-arg=AppKit -C link-arg=-framework -C link-arg=ImageIO -C link-arg=-framework -C link-arg=CoreGraphics -C link-arg=-framework -C link-arg=Security -C link-arg=-framework -C link-arg=FinderSync)
for flag in "${libs[@]}" ${link_paths[@]+"${link_paths[@]}"}; do args+=(-C "link-arg=$flag"); done
cd "$root/apps/client-desktop/src-tauri"
cargo rustc ${cargo_args[@]+"${cargo_args[@]}"} --example rdp-p0 --features rdp-p0 --message-format=json-render-diagnostics -- "${args[@]}" > "$tmp/build.json"
exe=$(python3 - "$tmp/build.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        artifact = json.loads(line)
        if artifact.get("target", {}).get("name") == "rdp-p0" and artifact.get("executable"):
            print(artifact["executable"])
            break
    else:
        sys.exit("Missing probe binary in Cargo output")
PY
)
printf '%s\n' "$exe"
