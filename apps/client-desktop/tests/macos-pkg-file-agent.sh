#!/usr/bin/env bash
# Run as root in a disposable Linux container with bash and su available.
# macOS pkgbuild is stopped after capturing the real payload and postinstall;
# the actual Unix permission boundary is then exercised as an ordinary user.
set -euo pipefail
if [[ ! -f /.dockerenv || "$(uname -s)" != Linux || "$(id -u)" != 0 ]]; then
    echo 'Run only as root inside a disposable Docker Linux container.' >&2
    exit 2
fi
PACKAGE_SCRIPT="${1:?pass package-macos-pkg.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/repo/scripts" "$WORK/repo/fixture.app/Contents/MacOS" "$WORK/tools" "$WORK/capture"
cp "$PACKAGE_SCRIPT" "$WORK/repo/scripts/package-macos-pkg.sh"
printf '2.4.0\n' > "$WORK/repo/VERSION"
printf '#!/bin/sh\nprintf "helper works\\n"\n' > "$WORK/repo/calabi"
chmod 755 "$WORK/repo/calabi"
printf 'signed-app-fixture\n' > "$WORK/repo/fixture.app/Contents/MacOS/calabi-desktop"
export CAPTURE="$WORK/capture"
cat > "$WORK/tools/uname" <<'SH'
#!/bin/sh
echo Darwin
SH
cat > "$WORK/tools/pkgbuild" <<'SH'
#!/bin/sh
test "$1" = --analyze || exit 1
cp -R "$3" "$CAPTURE/payload"
cp -R "$(dirname "$3")/scripts" "$CAPTURE/scripts"
exit 73
SH
cat > "$WORK/tools/launchctl" <<'SH'
#!/bin/sh
case "$1" in print) exit 1 ;; enable|bootstrap) exit 0 ;; *) exit 1 ;; esac
SH
chmod 755 "$WORK/tools/"*
export PATH="$WORK/tools:$PATH"
unset CALABI_UPDATE_PRIVKEY CALABI_DOWNLOAD_BASE
set +e
bash "$WORK/repo/scripts/package-macos-pkg.sh" --app fixture.app --daemon calabi --out fixture.pkg > "$WORK/build.log" 2>&1
status=$?
set -e
if [[ "$status" != 73 ]]; then cat "$WORK/build.log"; exit 1; fi

PUBLIC="/Library/Calabi/bin/calabi"
PRIVATE="/Library/Application Support/Calabi"
test -f "$CAPTURE/payload$PUBLIC"
cmp "$CAPTURE/payload$PUBLIC" "$CAPTURE/payload$PRIVATE/bin/calabi"
cmp "$WORK/repo/fixture.app/Contents/MacOS/calabi-desktop" "$CAPTURE/payload/Applications/fixture.app/Contents/MacOS/calabi-desktop"
test ! -e "$CAPTURE/payload/Applications/fixture.app/Contents/MacOS/calabi"
cp -R "$CAPTURE/payload/Library" /
printf 'existing-private-state\n' > "$PRIVATE/config.json"
chmod 600 "$PRIVATE/config.json"
chmod 700 "$PRIVATE" /Library/Calabi /Library/Calabi/bin
# The original layout reproduces the ordinary-user execution failure.
if su nobody -s /bin/sh -c "\"$PRIVATE/bin/calabi\"" >/dev/null 2>&1; then
    echo 'private service binary was executable by an ordinary user' >&2; exit 1
fi
grep -q '^wheel:' /etc/group || addgroup -S wheel
bash "$CAPTURE/scripts/postinstall"
test "$(stat -c %a "$PRIVATE")" = 700
test "$(stat -c %a "$PRIVATE/config.json")" = 600
test "$(cat "$PRIVATE/config.json")" = existing-private-state
for path in /Library/Calabi /Library/Calabi/bin "$PUBLIC"; do
    test "$(stat -c %a "$path")" = 755
    test "$(stat -c %u "$path")" = 0
done
test "$(su nobody -s /bin/sh -c "$PUBLIC")" = 'helper works'
if su nobody -s /bin/sh -c "cat \"$PRIVATE/config.json\"" >/dev/null 2>&1; then
    echo 'ordinary user could read service credentials' >&2; exit 1
fi
echo 'PASS: ordinary-user helper executes; root service state stays private'
