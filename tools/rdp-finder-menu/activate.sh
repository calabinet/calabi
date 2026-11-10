#!/bin/bash
# Run in the logged-in user's GUI session, never root's plugin registry.
set -eu
app="${1:-/Applications/Calabi.app/Contents/MacOS/CalabiRemoteFiles.app}"
extension="$app/Contents/PlugIns/RemoteMenu.appex"
identifier=net.calabi.rdp-finder-menu.extension
if [[ ! -d "$extension" ]]; then
  [[ "${2:-}" != --refresh ]] || exit 3
  exit 0
fi
if [[ "$(/usr/bin/id -u)" = 0 ]]; then
  echo 'FINDER_MENU_ACTIVATE refused=root' >&2
  exit 1
fi
if [[ "${2:-}" = --refresh ]]; then
  # Refresh only this installed, explicitly enabled copy. Leave elections alone.
  registrations=$(/usr/bin/pluginkit -m -v -i "$identifier")
  if ! printf '%s\n' "$registrations" | /usr/bin/awk -F '\t' -v path="$extension" \
      '$0 ~ /^[[:space:]]*\+/ && $NF == path { enabled=1 } END { exit !enabled }'; then
    exit 3
  fi
  /usr/bin/pluginkit -r "$extension" || :
  # A temporary registry error must not strand the extension after removal.
  if /usr/bin/pluginkit -a "$extension"; then exit 0; fi
  /bin/sleep 0.5
  /usr/bin/pluginkit -a "$extension"
  exit 0
fi
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$app"
/usr/bin/pluginkit -a "$extension"
for attempt in 1 2 3 4; do
  if /usr/bin/pluginkit -e use -i "$identifier"; then
    if /usr/bin/pluginkit -m -i "$identifier" | /usr/bin/grep -Eq '^[[:space:]]*\+'; then
      echo 'FINDER_MENU_ACTIVATE enabled=1'
      exit 0
    fi
  fi
  /bin/sleep 0.5
done
echo 'FINDER_MENU_ACTIVATE enabled=0' >&2
exit 1
