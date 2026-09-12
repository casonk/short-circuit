#!/usr/bin/env bash
# hub_activation_guard.sh — reconcile the shared dual-hub WireGuard identity to
# the ACID fencing lease.
#
# The v4 dual-hub mesh shares one virtual hub identity across a primary and one
# or more standbys. Exactly one host may run that identity at a time; the one
# allowed to is the current fence holder. This guard is the reconciler that makes
# that true on each host, run periodically by a systemd timer (Linux) or a
# launchd job (macOS):
#
#   fence held    -> ensure the interface is up, then refresh the client DNS;
#   fence NOT held -> ensure the interface is down.
#
# It is idempotent (safe to run every tick) and FAIL-CLOSED: the lease check
# exits 0 only when this host unambiguously holds a healthy, fenced lease; any
# other result -- not the holder, unhealthy quorum, provider error, or a config
# problem -- is treated as "not held", so the host tears its interface down. A
# shared hub identity therefore never runs on two hosts at once.
#
# The guard never elects anything: election is the quorum-backed lease's job.
set -euo pipefail

INTERFACE="${HUB_INTERFACE:-wg0}"
WG="${WG_BINARY:-wg}"
WG_QUICK="${WG_QUICK_BINARY:-wg-quick}"
# The lease check (required) and DDNS update (optional) are supplied as command
# strings so the guard is path-agnostic and testable. LEASE_CHECK_COMMAND must
# exit 0 iff this host holds the fence (see check_active_lease.py).
LEASE_CHECK_COMMAND="${LEASE_CHECK_COMMAND:?set LEASE_CHECK_COMMAND to the acid-lease check command}"
DDNS_UPDATE_COMMAND="${DDNS_UPDATE_COMMAND:-}"

log() { printf '[hub-activation-guard] %s\n' "$*"; }

interface_is_up() { "$WG" show "$INTERFACE" >/dev/null 2>&1; }

fence_is_held() { /bin/sh -c "$LEASE_CHECK_COMMAND" >/dev/null 2>&1; }

ensure_active() {
  if ! interface_is_up; then
    log "fence held; bringing up ${INTERFACE}"
    "$WG_QUICK" up "$INTERFACE"
  fi
  if [[ -n "${DDNS_UPDATE_COMMAND}" ]]; then
    if ! /bin/sh -c "$DDNS_UPDATE_COMMAND" >/dev/null 2>&1; then
      log "warning: DDNS update failed; will retry next tick"
    fi
  fi
}

ensure_inactive() {
  if interface_is_up; then
    log "fence not held; bringing down ${INTERFACE}"
    "$WG_QUICK" down "$INTERFACE"
  fi
}

main() {
  if fence_is_held; then
    ensure_active
  else
    ensure_inactive
  fi
}

main "$@"
