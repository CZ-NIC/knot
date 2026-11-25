#!/usr/bin/env bash
set -euo pipefail

: "${CAPS:=+sys_admin,+net_admin,+net_raw,+bpf,+sys_resource}"
SETPRIV="${XDP_SETPRIV:-./xdp_setpriv}"

check_setpriv() {
  if [[ ! -e "$SETPRIV" ]]; then
    echo "error: $SETPRIV not found (see README, XDP section)" >&2
    return 1
  fi
  if [[ ! -x "$SETPRIV" ]]; then
    echo "error: $SETPRIV is not executable" >&2
    return 1
  fi

  # Run it for real: a missing setcap, a nosuid mount or a stripped xattr
  # only shows up here as an EPERM or an empty CapAmb.
  local amb
  if ! amb=$("$SETPRIV" --inh-caps="$CAPS" --ambient-caps="$CAPS" \
                 grep '^CapAmb:' /proc/self/status 2>&1); then
    echo "error: $SETPRIV cannot grant capabilities:" >&2
    echo "  $amb" >&2
    echo "  Check: getcap $SETPRIV (file caps present?)" >&2
    return 1
  fi

  if [[ "$amb" =~ ^CapAmb:[[:space:]]+0+$ ]]; then
    echo "error: $SETPRIV ran but granted no ambient capabilities" >&2
    return 1
  fi
}

use_caps=0
for arg in "$@"; do
  case "$arg" in
    -x|--xdp|--xdp=*)
      use_caps=1
      break
      ;;
  esac
done

if (( use_caps )); then
  check_setpriv
  echo "Running with extra capabilities."
  exec "$SETPRIV" --inh-caps="$CAPS" --ambient-caps="$CAPS" ./runtests.py "$@"
else
  echo "Running with no extra capabilities."
  exec ./runtests.py "$@"
fi