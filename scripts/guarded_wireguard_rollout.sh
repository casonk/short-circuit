#!/usr/bin/env bash
set -euo pipefail

MODE="status"
INTERFACE="wg0"
CONFIG_PATH="/etc/wireguard/wg0.conf"
STATE_ROOT="/var/lib/short-circuit/wireguard-rollout"
TIMEOUT_SECONDS="1800"
POLL_SECONDS="15"
WAIT_INLINE=0
SCHEDULE_ROLLBACK=1
REQUIRE_ALL_PEERS=0
REQUIRED_PEERS=()
CANDIDATE_PATH=""
APPLY_EPOCH=""
STATUS=""

usage() {
  cat <<'USAGE'
Usage: guarded_wireguard_rollout.sh MODE [OPTIONS]

Apply a WireGuard server config with an automatic rollback guard. If no
required peer completes a fresh handshake before the deadline, the prior config
is restored and wg-quick is restarted.

Modes:
  --apply                 Snapshot current config, apply candidate, and arm guard.
  --verify                Check whether the pending rollout has succeeded.
  --verify-or-rollback    Check the pending rollout and roll back on timeout.
  --rollback              Restore the prior config immediately.
  --status                Report pending rollout status (default).

Options:
  --candidate PATH        Candidate WireGuard config for --apply.
  --interface NAME        WireGuard interface (default: wg0).
  --config PATH           Active config path (default: /etc/wireguard/wg0.conf).
  --state-root PATH       Rollback state root.
  --timeout-seconds N     Rollback deadline after apply (default: 1800).
  --poll-seconds N        Inline wait poll interval (default: 15).
  --required-peer KEY     Public key that must handshake; repeatable.
  --require-all-peers     Require every selected peer instead of any one peer.
  --wait-inline           Wait in this process instead of only arming systemd.
  --no-schedule           Do not arm the systemd transient rollback check.
  --help                  Show this help.

Default --apply behavior arms a root systemd transient check. Use
--wait-inline only when a supervising terminal or service will remain alive.
USAGE
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_root() {
  if [[ "${SHORT_CIRCUIT_TEST_ALLOW_NONROOT:-0}" == "1" ]]; then
    return
  fi
  (( EUID == 0 )) || fail "run this mode with sudo"
}

require_option_value() {
  local option="$1"
  local value="${2:-}"

  [[ -n "${value}" && "${value}" != --* ]] || fail "${option} requires a value"
}

validate_name() {
  [[ "$1" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail "invalid interface name: $1"
}

validate_positive_int() {
  local label="$1"
  local value="$2"

  [[ "${value}" =~ ^[0-9]+$ ]] || fail "${label} must be a positive integer"
  (( 10#${value} > 0 )) || fail "${label} must be a positive integer"
}

validate_public_key() {
  [[ "$1" =~ ^[A-Za-z0-9+/]{42,44}=*$ ]] || fail "invalid WireGuard peer public key: $1"
}

state_dir() {
  printf '%s/%s\n' "${STATE_ROOT}" "${INTERFACE}"
}

metadata_path() {
  printf '%s/rollout.env\n' "$(state_dir)"
}

metadata_status() {
  local metadata
  local owner
  local mode

  metadata="$(metadata_path)"
  [[ -f "${metadata}" ]] || return 1
  owner="$(stat -c '%u' "${metadata}")"
  mode="$(stat -c '%a' "${metadata}")"
  if [[ "${owner}" != "0" ]]; then
    [[ "${SHORT_CIRCUIT_TEST_ALLOW_USER_STATE:-0}" == "1" ]] ||
      fail "metadata must be owned by root: ${metadata}"
  fi
  (( (8#${mode} & 8#022) == 0 )) || fail "metadata must not be group- or world-writable"
  bash -c 'source "$1"; printf "%s" "${STATUS:-pending}"' bash "${metadata}"
}

archive_rollout_state() {
  local archive_dir
  local item
  local stamp
  local status

  status="$(metadata_status)"
  stamp="$(date +%Y%m%dT%H%M%S)"
  archive_dir="$(state_dir)/archive/${stamp}-${status}"
  install -d -m 0700 "${archive_dir}"
  for item in rollout.env previous.conf candidate.conf; do
    if [[ -e "$(state_dir)/${item}" ]]; then
      mv -f "$(state_dir)/${item}" "${archive_dir}/${item}"
    fi
  done
  log "archived prior ${status} rollout state: ${archive_dir}"
}

previous_config_path() {
  printf '%s/previous.conf\n' "$(state_dir)"
}

candidate_config_path() {
  printf '%s/candidate.conf\n' "$(state_dir)"
}

unit_name() {
  local safe="${INTERFACE//[^A-Za-z0-9_.-]/_}"
  printf 'short-circuit-%s-rollback-guard\n' "${safe}"
}

script_path() {
  readlink -f "$0"
}

extract_candidate_peers() {
  local source_path="$1"
  awk '
    BEGIN { in_peer = 0 }
    /^[[:space:]]*\[Peer\][[:space:]]*$/ { in_peer = 1; next }
    /^[[:space:]]*\[/ { in_peer = 0; next }
    in_peer && /^[[:space:]]*PublicKey[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      sub(/[[:space:]]*(#.*)?$/, "", $0)
      if ($0 != "") print $0
    }
  ' "${source_path}"
}

join_peers_for_state() {
  local peer
  local existing_status
  local joined=""

  for peer in "${REQUIRED_PEERS[@]}"; do
    if [[ -z "${joined}" ]]; then
      joined="${peer}"
    else
      joined="${joined} ${peer}"
    fi
  done
  printf '%s\n' "${joined}"
}

write_metadata() {
  local state
  local temp_file

  state="$(state_dir)"
  install -d -m 0700 "${state}"
  temp_file="$(mktemp "${state}/rollout.XXXXXX")"
  {
    printf 'STATE_VERSION=1\n'
    printf 'INTERFACE=%q\n' "${INTERFACE}"
    printf 'CONFIG_PATH=%q\n' "${CONFIG_PATH}"
    printf 'STATE_ROOT=%q\n' "${STATE_ROOT}"
    APPLY_EPOCH="$(date +%s)"
    printf 'APPLY_EPOCH=%q\n' "${APPLY_EPOCH}"
    printf 'TIMEOUT_SECONDS=%q\n' "${TIMEOUT_SECONDS}"
    printf 'REQUIRE_ALL_PEERS=%q\n' "${REQUIRE_ALL_PEERS}"
    printf 'REQUIRED_PEERS=%q\n' "$(join_peers_for_state)"
    printf 'STATUS=%q\n' "pending"
  } > "${temp_file}"
  chmod 0600 "${temp_file}"
  mv -f "${temp_file}" "$(metadata_path)"
}

load_metadata() {
  local metadata
  local owner
  local mode
  local peer
  local saved_required_peers

  metadata="$(metadata_path)"
  [[ -f "${metadata}" ]] || fail "no pending rollout metadata: ${metadata}"
  owner="$(stat -c '%u' "${metadata}")"
  mode="$(stat -c '%a' "${metadata}")"
  if [[ "${owner}" != "0" ]]; then
    [[ "${SHORT_CIRCUIT_TEST_ALLOW_USER_STATE:-0}" == "1" ]] ||
      fail "metadata must be owned by root: ${metadata}"
  fi
  (( (8#${mode} & 8#022) == 0 )) || fail "metadata must not be group- or world-writable"
  # shellcheck source=/dev/null
  source "${metadata}"
  [[ "${STATE_VERSION:-}" == "1" ]] || fail "unsupported metadata version"
  validate_name "${INTERFACE}"
  validate_positive_int "timeout seconds" "${TIMEOUT_SECONDS}"
  [[ "${REQUIRE_ALL_PEERS}" == "0" || "${REQUIRE_ALL_PEERS}" == "1" ]] ||
    fail "invalid REQUIRE_ALL_PEERS in metadata"
  saved_required_peers="${REQUIRED_PEERS:-}"
  REQUIRED_PEERS=()
  for peer in ${saved_required_peers}; do
    validate_public_key "${peer}"
    REQUIRED_PEERS+=("${peer}")
  done
  ((${#REQUIRED_PEERS[@]} > 0)) || fail "metadata does not name any required peers"
}

write_status() {
  local status="$1"
  local metadata
  local temp_file

  load_metadata
  metadata="$(metadata_path)"
  temp_file="$(mktemp "$(state_dir)/rollout.XXXXXX")"
  {
    printf 'STATE_VERSION=1\n'
    printf 'INTERFACE=%q\n' "${INTERFACE}"
    printf 'CONFIG_PATH=%q\n' "${CONFIG_PATH}"
    printf 'STATE_ROOT=%q\n' "${STATE_ROOT}"
    printf 'APPLY_EPOCH=%q\n' "${APPLY_EPOCH}"
    printf 'TIMEOUT_SECONDS=%q\n' "${TIMEOUT_SECONDS}"
    printf 'REQUIRE_ALL_PEERS=%q\n' "${REQUIRE_ALL_PEERS}"
    printf 'REQUIRED_PEERS=%q\n' "$(join_peers_for_state)"
    printf 'STATUS=%q\n' "${status}"
  } > "${temp_file}"
  chmod 0600 "${temp_file}"
  mv -f "${temp_file}" "${metadata}"
}

latest_handshakes() {
  wg show "${INTERFACE}" latest-handshakes
}

peer_has_fresh_handshake() {
  local wanted="$1"
  local line_peer
  local line_epoch

  while read -r line_peer line_epoch; do
    [[ "${line_peer}" == "${wanted}" ]] || continue
    [[ "${line_epoch}" =~ ^[0-9]+$ ]] || return 1
    (( 10#${line_epoch} > 10#${APPLY_EPOCH} )) && return 0
    return 1
  done < <(latest_handshakes)
  return 1
}

handshake_requirement_satisfied() {
  local peer

  if (( REQUIRE_ALL_PEERS == 1 )); then
    for peer in "${REQUIRED_PEERS[@]}"; do
      peer_has_fresh_handshake "${peer}" || return 1
    done
    return 0
  fi

  for peer in "${REQUIRED_PEERS[@]}"; do
    peer_has_fresh_handshake "${peer}" && return 0
  done
  return 1
}

deadline_reached() {
  local now
  now="$(date +%s)"
  (( 10#${now} >= 10#${APPLY_EPOCH} + 10#${TIMEOUT_SECONDS} ))
}

restart_wireguard() {
  systemctl restart "wg-quick@${INTERFACE}.service"
}

restore_previous_config() {
  [[ -f "$(previous_config_path)" ]] || fail "previous config missing: $(previous_config_path)"
  install -m 0600 "$(previous_config_path)" "${CONFIG_PATH}"
}

schedule_systemd_guard() {
  local unit

  require_command systemd-run
  unit="$(unit_name)"
  systemd-run \
    --unit="${unit}" \
    --description="short-circuit WireGuard rollback guard for ${INTERFACE}" \
    --on-active="${TIMEOUT_SECONDS}s" \
    --collect \
    /usr/bin/env bash "$(script_path)" \
      --verify-or-rollback \
      --interface "${INTERFACE}" \
      --state-root "${STATE_ROOT}" >/dev/null
  log "armed rollback guard: ${unit} in ${TIMEOUT_SECONDS}s"
}

apply_rollout() {
  local state
  local peer

  require_root
  require_command install
  require_command wg
  require_command systemctl
  [[ -n "${CANDIDATE_PATH}" ]] || fail "--candidate is required with --apply"
  [[ -f "${CANDIDATE_PATH}" ]] || fail "candidate config not found: ${CANDIDATE_PATH}"
  [[ -f "${CONFIG_PATH}" ]] || fail "active config not found: ${CONFIG_PATH}"

  if ((${#REQUIRED_PEERS[@]} == 0)); then
    while read -r peer; do
      validate_public_key "${peer}"
      REQUIRED_PEERS+=("${peer}")
    done < <(extract_candidate_peers "${CANDIDATE_PATH}")
  fi
  ((${#REQUIRED_PEERS[@]} > 0)) || fail "no required peers found; pass --required-peer"

  if (( SCHEDULE_ROLLBACK == 1 )); then
    require_command systemd-run
  fi

  state="$(state_dir)"
  install -d -m 0700 "${state}"
  if [[ -f "$(metadata_path)" ]]; then
    existing_status="$(metadata_status)"
    if [[ "${existing_status}" == "pending" ]]; then
      fail "pending rollout already exists for ${INTERFACE}; verify or roll it back first"
    fi
    archive_rollout_state
  fi
  cp -p "${CONFIG_PATH}" "$(previous_config_path)"
  cp -p "${CANDIDATE_PATH}" "$(candidate_config_path)"
  chmod 0600 "$(previous_config_path)" "$(candidate_config_path)"
  write_metadata

  install -m 0600 "$(candidate_config_path)" "${CONFIG_PATH}"
  if ! restart_wireguard; then
    log "candidate restart failed; restoring previous config"
    restore_previous_config
    restart_wireguard
    write_status "failed-rolled-back"
    fail "candidate config failed to restart wg-quick@${INTERFACE}.service; previous config restored"
  fi
  log "applied candidate config to ${CONFIG_PATH}; waiting for fresh peer handshake after ${APPLY_EPOCH}"

  if (( SCHEDULE_ROLLBACK == 1 )); then
    schedule_systemd_guard
  fi
  if (( WAIT_INLINE == 1 )); then
    wait_for_success_or_rollback
  fi
}

mark_success() {
  write_status "succeeded"
  log "rollout succeeded: fresh required peer handshake observed"
}

verify_rollout() {
  load_metadata
  if handshake_requirement_satisfied; then
    mark_success
    return 0
  fi
  if deadline_reached; then
    return 2
  fi
  log "rollout still pending: no fresh required peer handshake yet"
  return 1
}

rollback_rollout() {
  require_root
  require_command install
  require_command systemctl
  load_metadata
  restore_previous_config
  restart_wireguard
  write_status "rolled-back"
  log "rollback applied: restored ${CONFIG_PATH} and restarted wg-quick@${INTERFACE}.service"
}

verify_or_rollback() {
  local status

  if verify_rollout; then
    return 0
  else
    status=$?
  fi
  case "${status}" in
    1)
      log "rollout deadline has not elapsed; leaving pending"
      return 1
      ;;
    2)
      log "rollout deadline elapsed without required peer handshake"
      rollback_rollout
      ;;
    *) return "${status}" ;;
  esac
}

wait_for_success_or_rollback() {
  load_metadata
  while true; do
    if handshake_requirement_satisfied; then
      mark_success
      return 0
    fi
    if deadline_reached; then
      log "rollout deadline elapsed without required peer handshake"
      rollback_rollout
      return 2
    fi
    sleep "${POLL_SECONDS}"
  done
}

status_rollout() {
  load_metadata
  log "interface: ${INTERFACE}"
  log "config: ${CONFIG_PATH}"
  log "status: ${STATUS}"
  log "applied_at_epoch: ${APPLY_EPOCH}"
  log "timeout_seconds: ${TIMEOUT_SECONDS}"
  log "require_all_peers: ${REQUIRE_ALL_PEERS}"
  log "required_peers: $(join_peers_for_state)"
  if handshake_requirement_satisfied; then
    log "handshake_state: satisfied"
  elif deadline_reached; then
    log "handshake_state: expired"
  else
    log "handshake_state: pending"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) MODE="apply"; shift ;;
    --verify) MODE="verify"; shift ;;
    --verify-or-rollback) MODE="verify-or-rollback"; shift ;;
    --rollback) MODE="rollback"; shift ;;
    --status) MODE="status"; shift ;;
    --candidate) require_option_value "$1" "${2:-}"; CANDIDATE_PATH="$2"; shift 2 ;;
    --interface) require_option_value "$1" "${2:-}"; INTERFACE="$2"; shift 2 ;;
    --config) require_option_value "$1" "${2:-}"; CONFIG_PATH="$2"; shift 2 ;;
    --state-root) require_option_value "$1" "${2:-}"; STATE_ROOT="$2"; shift 2 ;;
    --timeout-seconds) require_option_value "$1" "${2:-}"; TIMEOUT_SECONDS="$2"; shift 2 ;;
    --poll-seconds) require_option_value "$1" "${2:-}"; POLL_SECONDS="$2"; shift 2 ;;
    --required-peer) require_option_value "$1" "${2:-}"; REQUIRED_PEERS+=("$2"); shift 2 ;;
    --require-all-peers) REQUIRE_ALL_PEERS=1; shift ;;
    --wait-inline) WAIT_INLINE=1; shift ;;
    --no-schedule) SCHEDULE_ROLLBACK=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

validate_name "${INTERFACE}"
validate_positive_int "timeout seconds" "${TIMEOUT_SECONDS}"
validate_positive_int "poll seconds" "${POLL_SECONDS}"
for peer in "${REQUIRED_PEERS[@]}"; do
  validate_public_key "${peer}"
done

case "${MODE}" in
  apply) apply_rollout ;;
  verify) verify_rollout ;;
  verify-or-rollback) verify_or_rollback ;;
  rollback) rollback_rollout ;;
  status) status_rollout ;;
  *) fail "unsupported mode: ${MODE}" ;;
esac
