# Source before any build. Native Linux/macOS retain their existing behavior.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    _calabi_guard_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    _calabi_powershell="$(command -v pwsh.exe || command -v powershell.exe)"
    export CALABI_GUARD_SCRIPT="$(cygpath -w "$_calabi_guard_root/scripts/dev/build-cache.ps1")"
    if [[ -z "${CALABI_BUILD_LEASE:-}" ]] || ! "$_calabi_powershell" -NoProfile -Command '. $env:CALABI_GUARD_SCRIPT; if (Test-CalabiBuildLease) { exit 0 }; exit 1'; then
      exec "$_calabi_powershell" -NoProfile -File "$(cygpath -w "$_calabi_guard_root/scripts/dev/build.ps1")" git-bash "$0" "$@"
    fi
    ;;
esac
