#!/usr/bin/env bash
# Verify the app itself or the copy extracted from a release .pkg.
set -euo pipefail
app="${1:?Pass the Calabi.app path}"
shift
[[ $# -gt 0 ]] || set -- arm64 x86_64
app_dir="$app/Contents"
rdp="$app_dir/MacOS/calabi-rdp"
host="$app_dir/MacOS/CalabiRemoteFiles.app/Contents"
extension="$host/PlugIns/RemoteMenu.appex/Contents"
frameworks="$app_dir/Frameworks"
main="$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$app_dir/Info.plist")"

for path in "$app_dir/MacOS/$main" "$rdp" "$host/MacOS/RemoteFiles" "$extension/MacOS/RemoteFiles"; do
  [[ -x "$path" ]] || { echo "Missing executable: $path" >&2; exit 1; }
  for arch in "$@"; do lipo "$path" -verify_arch "$arch"; done
done
[[ -x "$host/Resources/activate-menu.sh" ]]
[[ "$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$extension/Info.plist")" == net.calabi.rdp-finder-menu.extension ]]
[[ "$(/usr/libexec/PlistBuddy -c 'Print NSExtension:NSExtensionPointIdentifier' "$extension/Info.plist")" == com.apple.FinderSync ]]

libs=(libfreerdp3.3.dylib libfreerdp-client3.3.dylib libwinpr3.3.dylib
      libcrypto.3.dylib libssl.3.dylib)
for name in "${libs[@]}"; do
  for arch in "$@"; do lipo "$frameworks/$name" -verify_arch "$arch"; done
done
for license in FreeRDP OpenSSL; do
  [[ -s "$app_dir/Resources/rdp-licenses/$license.txt" ]]
done

openh264_files="$(find "$app" -iname '*openh264*' -print)"
if [[ -n "$openh264_files" ]]; then
  echo "Unexpected OpenH264 file in $app" >&2; exit 1
fi

# Every non-system dylib load must resolve inside this app, on both slices.
for path in "$rdp" "${libs[@]/#/$frameworks/}"; do
  for arch in "$@"; do
    commands="$(otool -arch "$arch" -l "$path")"
    rpaths="$(awk '$1=="cmd" && $2=="LC_RPATH" {getline; getline; print $2}' <<<"$commands")"
    expected_rpath=
    if [[ "$path" == "$rdp" ]]; then expected_rpath='@executable_path/../Frameworks'; fi
    [[ "$rpaths" == "$expected_rpath" ]] || {
      echo "Unexpected runtime search path in $path ($arch): $rpaths" >&2; exit 1;
    }
    linked="$(otool -arch "$arch" -L "$path")"
    if [[ "$path" == "$frameworks/libfreerdp3.3.dylib" ]] &&
       ! grep -q '/VideoToolbox\.framework/' <<<"$linked"; then
      echo "Missing system VideoToolbox dependency in $path ($arch)" >&2; exit 1
    fi
    while read -r lib; do
      case "$lib" in
        /usr/lib/*|/System/Library/*) ;;
        @rpath/*)
          [[ "$lib" == "@rpath/${lib##*/}" && -f "$frameworks/${lib##*/}" ]] || {
            echo "Missing bundled dependency $lib in $path ($arch)" >&2; exit 1;
          }
          ;;
        *) echo "External dependency $lib in $path ($arch)" >&2; exit 1 ;;
      esac
    done < <(awk '$2 == "(compatibility" {print $1}' <<<"$linked")
  done
done
codesign --verify --all-architectures --deep --strict "$app"
echo "Verified Mac RDP bundle ($*) with VideoToolbox and Finder Sync extension: $app"
