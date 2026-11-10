#!/usr/bin/env bash
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)"
app="${1:?Pass output CalabiRemoteFiles.app path}"
arch_flags=()
case "${2:-}" in
  "") ;;
  --universal) arch_flags=(-arch arm64 -arch x86_64) ;;
  --arm64) arch_flags=(-arch arm64) ;;
  --x86_64) arch_flags=(-arch x86_64) ;;
  *) echo "Unknown Finder extension target: $2" >&2; exit 2 ;;
esac
test_dir=$(mktemp -d)
trap 'rm -f "$test_dir/host-test" "$test_dir/extension.entitlements"; rmdir "$test_dir"' EXIT
xcrun clang -fobjc-arc -Wall -Wextra -mmacosx-version-min=11.0 "$src/HostTest.m" -framework Cocoa -framework FinderSync -o "$test_dir/host-test"
"$test_dir/host-test" >&2
ext="$app/Contents/PlugIns/RemoteMenu.appex"
# Build in a fresh staging app; never leave the previous File Provider extension inside.
[[ ! -e "$app/Contents/PlugIns/RemoteFiles.appex" ]] || {
  echo 'Stale File Provider bundle exists; remove only that old bundle before building.' >&2; exit 1;
}
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$ext/Contents/MacOS" "$ext/Contents/Resources"
install -m 755 "$src/activate.sh" "$app/Contents/Resources/activate-menu.sh"
key=$(uuidgen)
for file in "$app/Contents/Info.plist" "$ext/Contents/Info.plist"; do
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>' > "$file"
  plutil -insert CFBundleVersion -string 98 "$file"
  plutil -insert CFBundleShortVersionString -string 0.7 "$file"
  plutil -insert CFBundleExecutable -string RemoteFiles "$file"
  plutil -insert CFBundleName -string 'Calabi 远程文件菜单' "$file"
  plutil -insert LSMinimumSystemVersion -string 11.0 "$file"
  plutil -insert MenuBuildKey -string "$key" "$file"
done
info="$app/Contents/Info.plist"
plutil -insert CFBundleIdentifier -string net.calabi.rdp-finder-menu "$info"
plutil -insert CFBundlePackageType -string APPL "$info"
plutil -insert NSPrincipalClass -string NSApplication "$info"
plutil -insert LSUIElement -bool YES "$info"
plutil -insert CFBundleURLTypes -json '[{"CFBundleURLName":"Calabi Remote Paste","CFBundleURLSchemes":["calabi-remote-paste"]}]' "$info"
info="$ext/Contents/Info.plist"
plutil -insert CFBundleIdentifier -string net.calabi.rdp-finder-menu.extension "$info"
plutil -insert CFBundlePackageType -string 'XPC!' "$info"
plutil -insert NSExtension -json '{"NSExtensionPointIdentifier":"com.apple.FinderSync","NSExtensionPrincipalClass":"CalabiRemoteMenu"}' "$info"
cp "$src/../../apps/client-desktop/src-tauri/icons/32x32.png" "$ext/Contents/Resources/calabi-menu.png"
xcrun clang -fobjc-arc -Wall -Wextra -mmacosx-version-min=11.0 ${arch_flags[@]+"${arch_flags[@]}"} "$src/Host.m" -framework Cocoa -framework FinderSync -o "$app/Contents/MacOS/RemoteFiles"
xcrun clang -fobjc-arc -Wall -Wextra -mmacosx-version-min=11.0 ${arch_flags[@]+"${arch_flags[@]}"} -fapplication-extension "$src/Extension.m" -framework Cocoa -framework FinderSync -Wl,-e,_NSExtensionMain -o "$ext/Contents/MacOS/RemoteFiles"
identity="${3:--}"
sign=(--force --sign "$identity")
if [[ "$identity" != - ]]; then
  sign+=(--options runtime --timestamp)
fi
# codesign requires standard XML with LF line endings and no BOM.
entitlements="$test_dir/extension.entitlements"
plutil -convert xml1 -o "$entitlements" "$src/extension.entitlements"
codesign "${sign[@]}" --entitlements "$entitlements" "$ext"
codesign "${sign[@]}" "$app"
codesign --verify --deep --strict "$app"
