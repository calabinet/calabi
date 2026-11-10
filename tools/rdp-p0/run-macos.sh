#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'Requires macOS.' >&2; exit 1; }
if [[ $# != 3 ]]; then
  echo "Usage: bash $0 <Calabi peer IPv4> <Calabi utun device> <Windows RDP leaf SHA256 hex>" >&2
  exit 2
fi
export CALABI_P0_PEER="$1" CALABI_P0_SHA256="$3"
python3 - "$1" "$3" <<'PY'
import ipaddress, re, sys
if ipaddress.ip_address(sys.argv[1]) not in ipaddress.ip_network("100.64.0.0/10"):
    sys.exit("P0 accepts only a numeric Calabi overlay IPv4 address")
if not re.fullmatch(r"[0-9a-fA-F]{64}", sys.argv[2]):
    sys.exit("Expected the independently verified SHA-256 of the RDP leaf certificate")
PY
check_route() {
  local selected
  selected=$(/sbin/route -n get "$1" | awk '/interface:/{print $2}')
  [[ "$2" =~ ^utun[0-9]+$ && "$selected" == "$2" ]] || {
    echo 'Peer route does not match the specified Calabi utun device.' >&2; exit 1;
  }
}
check_route "$1" "$2"
root=$(cd "$(dirname "$0")/../.." && pwd)
src="$root/tools/rdp-p0"
exe=$(bash "$src/build-helper.sh")
check_route "$1" "$2"
"$exe"
