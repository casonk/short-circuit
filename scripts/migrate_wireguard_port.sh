#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODE="check"
NEW_PORT="41194"
ENDPOINT_HOST=""
INTERFACE="wg0"
PUBLIC_ZONE=""
SERVER_DEST="/etc/wireguard/wg0.conf"
CONFIG_DIR="${REPO_ROOT}/config/wireguard"
EXPORT_DIR="${REPO_ROOT}/artifacts/wireguard-port-migration"
STATE_FILE="/var/lib/short-circuit/wireguard-port-migration.env"

usage() {
  cat <<'EOF'
Usage: migrate_wireguard_port.sh MODE [OPTIONS]

Modes:
  --check      Report local and live port state.
  --prepare    Back up and update ignored local configs and export clients.
  --apply      Update the live config, firewalld, and WireGuard listener.
  --verify     Verify config, listener, firewall, and handshake state.
  --rollback   Restore the host and local configs from migration backups.

Options:
  --new-port PORT       New fixed UDP port (default: 41194).
  --endpoint-host HOST  Replace the client Endpoint host while preparing.
  --interface NAME      WireGuard interface (default: wg0).
  --public-zone ZONE    WAN firewalld zone; auto-detected by default.
  --server-dest PATH    Live config (default: /etc/wireguard/wg0.conf).
  --config-dir PATH     Local config directory.
  --export-dir PATH     Prepared client export directory.
  --state-file PATH     Root-owned live rollback state.
  --help                Show this help.

Safe order:
  1. --prepare
  2. Forward BOTH old and new UDP ports on the router.
  3. --apply
  4. Import a prepared client profile, reconnect, and --verify.
  5. Remove the old router forward only after a new handshake succeeds.
EOF
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
  (( EUID == 0 )) || fail "run this mode with sudo"
}

validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] || fail "invalid port: $1"
  (( 10#$1 >= 1024 && 10#$1 <= 65535 )) || fail "port must be between 1024 and 65535"
  [[ "$1" != "51820" ]] || fail "choose a non-default port instead of 51820"
}

extract_value() {
  local path="$1"
  local key="$2"

  awk -F '=' -v key="${key}" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      value = $2
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "${path}"
}

replace_value() {
  local path="$1"
  local key="$2"
  local value="$3"
  sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${value}|" "${path}"
}

replace_endpoint_port() {
  local path="$1"
  local endpoint
  local host

  endpoint="$(extract_value "${path}" "Endpoint")"
  [[ -n "${endpoint}" ]] || fail "missing Endpoint in ${path}"
  host="${endpoint%:*}"
  [[ -n "${host}" && "${host}" != "${endpoint}" ]] ||
    fail "invalid Endpoint in ${path}: ${endpoint}"
  if [[ -n "${ENDPOINT_HOST}" ]]; then
    host="${ENDPOINT_HOST}"
  fi
  replace_value "${path}" "Endpoint" "${host}:${NEW_PORT}"
}

load_local_configs() {
  mapfile -t SERVER_CONFIGS < <(
    find "${CONFIG_DIR}" -maxdepth 1 -type f -name 'wg0-server*.local.conf' -print | sort
  )
  mapfile -t CLIENT_CONFIGS < <(
    find "${CONFIG_DIR}" -maxdepth 1 -type f -name '*peer*.local.conf' -print | sort
  )
  (( ${#SERVER_CONFIGS[@]} > 0 )) || fail "no local server configs found in ${CONFIG_DIR}"
  (( ${#CLIENT_CONFIGS[@]} > 0 )) || fail "no local client configs found in ${CONFIG_DIR}"
}

detect_public_zone() {
  local interface
  local zone

  if [[ -n "${PUBLIC_ZONE}" ]]; then
    printf '%s\n' "${PUBLIC_ZONE}"
    return
  fi
  interface="$(ip route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  [[ -n "${interface}" ]] || fail "unable to detect default-route interface"
  zone="$(firewall-cmd --get-zone-of-interface="${interface}" 2>/dev/null || true)"
  [[ -n "${zone}" ]] || zone="$(firewall-cmd --get-default-zone)"
  printf '%s\n' "${zone}"
}

firewall_has_exact_port() {
  local zone="$1"
  local wanted="$2"
  local listed

  for listed in $(firewall-cmd --permanent --zone="${zone}" --list-ports); do
    [[ "${listed}" == "${wanted}" ]] && return 0
  done
  return 1
}

show_local_state() {
  local path
  local endpoint

  load_local_configs
  for path in "${SERVER_CONFIGS[@]}"; do
    log "server $(basename "${path}"): $(extract_value "${path}" "ListenPort")"
  done
  for path in "${CLIENT_CONFIGS[@]}"; do
    endpoint="$(extract_value "${path}" "Endpoint")"
    log "client $(basename "${path}"): ${endpoint##*:}"
  done
}

check_state() {
  show_local_state
  if (( EUID == 0 )); then
    local zone
    zone="$(detect_public_zone)"
    log "live config port: $(extract_value "${SERVER_DEST}" "ListenPort")"
    log "live listener: $(wg show "${INTERFACE}" listen-port)"
    log "public zone: ${zone}"
    log "public ports: $(firewall-cmd --permanent --zone="${zone}" --list-ports)"
  else
    log "live root-owned state: unavailable without sudo"
  fi
}

prepare_configs() {
  local backup_dir
  local backup_marker
  local path
  local current_port

  load_local_configs
  backup_marker="${CONFIG_DIR}/.wireguard-port-migration-backup"
  if [[ -f "${backup_marker}" ]]; then
    backup_dir="$(cat "${backup_marker}")"
    [[ -d "${backup_dir}" ]] || fail "recorded backup directory is missing: ${backup_dir}"
    log "preserving existing local backup: ${backup_dir}"
  else
    backup_dir="${CONFIG_DIR}/port-migration-backup-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "${backup_dir}"
    chmod 0700 "${backup_dir}"
    for path in "${SERVER_CONFIGS[@]}" "${CLIENT_CONFIGS[@]}"; do
      cp -a "${path}" "${backup_dir}/"
    done
    printf '%s\n' "${backup_dir}" > "${backup_marker}"
  fi
  mkdir -p "${EXPORT_DIR}"
  chmod 0700 "${EXPORT_DIR}"
  for path in "${SERVER_CONFIGS[@]}"; do
    current_port="$(extract_value "${path}" "ListenPort")"
    [[ -n "${current_port}" ]] || fail "missing ListenPort in ${path}"
    replace_value "${path}" "ListenPort" "${NEW_PORT}"
  done
  for path in "${CLIENT_CONFIGS[@]}"; do
    replace_endpoint_port "${path}"
    install -m 0600 "${path}" "${EXPORT_DIR}/$(basename "${path}")"
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t png -o "${EXPORT_DIR}/$(basename "${path}" .conf).png" < "${path}"
      chmod 0600 "${EXPORT_DIR}/$(basename "${path}" .conf).png"
    fi
  done
  log "updated local configs to UDP ${NEW_PORT}"
  log "saved local backup: ${backup_dir}"
  log "exported client profiles: ${EXPORT_DIR}"
  if command -v qrencode >/dev/null 2>&1; then
    log "generated QR PNGs beside the exported client profiles"
  fi
  log "next: forward both old and new UDP ports on the router before --apply"
}

write_live_state() {
  local old_port="$1"
  local zone="$2"
  local state_dir
  local temp_file

  if [[ -f "${STATE_FILE}" ]]; then
    log "preserving existing live rollback state: ${STATE_FILE}"
    return
  fi
  state_dir="$(dirname "${STATE_FILE}")"
  install -d -m 0700 "${state_dir}"
  temp_file="$(mktemp "${state_dir}/wireguard-port-migration.XXXXXX")"
  {
    printf 'STATE_VERSION=1\n'
    printf 'INTERFACE=%q\n' "${INTERFACE}"
    printf 'PUBLIC_ZONE=%q\n' "${zone}"
    printf 'SERVER_DEST=%q\n' "${SERVER_DEST}"
    printf 'OLD_PORT=%q\n' "${old_port}"
    printf 'NEW_PORT=%q\n' "${NEW_PORT}"
    printf 'APPLIED_AT=0\n'
  } > "${temp_file}"
  chmod 0600 "${temp_file}"
  cp -a "${SERVER_DEST}" "${state_dir}/wg0.conf.before-port-migration"
  mv -f "${temp_file}" "${STATE_FILE}"
  log "saved live rollback state: ${STATE_FILE}"
}

verify_live() {
  local require_fresh_handshake="${1:-false}"
  local zone
  local handshake
  local applied_at=0

  require_root
  zone="$(detect_public_zone)"
  [[ "$(extract_value "${SERVER_DEST}" "ListenPort")" == "${NEW_PORT}" ]] ||
    fail "live config does not use ${NEW_PORT}"
  [[ "$(wg show "${INTERFACE}" listen-port)" == "${NEW_PORT}" ]] ||
    fail "live listener does not use ${NEW_PORT}"
  firewall_has_exact_port "${zone}" "${NEW_PORT}/udp" ||
    fail "${zone} does not explicitly allow ${NEW_PORT}/udp"
  handshake="$(wg show "${INTERFACE}" latest-handshakes | awk 'NF >= 2 { if ($2 > newest) newest = $2 } END { print newest + 0 }')"
  log "live config and firewall verification passed for UDP ${NEW_PORT}"
  if [[ -f "${STATE_FILE}" ]]; then
    applied_at="$(awk -F= '$1 == "APPLIED_AT" { print $2; exit }' "${STATE_FILE}")"
    [[ "${applied_at}" =~ ^[0-9]+$ ]] || applied_at=0
  fi
  if [[ "${require_fresh_handshake}" == "true" ]]; then
    (( handshake >= applied_at && applied_at > 0 )) ||
      fail "no handshake has completed since the port switch; reconnect a prepared client before removing the old router forward"
    log "fresh post-migration handshake verified: ${handshake}"
  elif (( handshake > 0 )); then
    log "latest historical peer handshake epoch: ${handshake}"
    log "run --verify after reconnecting to require a post-migration handshake"
  else
    log "no peer handshake recorded; reconnect and run --verify"
  fi
}

apply_live() {
  local old_port
  local zone

  require_root
  load_local_configs
  [[ "$(extract_value "${SERVER_CONFIGS[0]}" "ListenPort")" == "${NEW_PORT}" ]] ||
    fail "run --prepare first"
  old_port="$(extract_value "${SERVER_DEST}" "ListenPort")"
  zone="$(detect_public_zone)"
  write_live_state "${old_port}" "${zone}"

  if ! firewall_has_exact_port "${zone}" "${NEW_PORT}/udp"; then
    firewall-cmd --permanent --zone="${zone}" --add-port="${NEW_PORT}/udp" >/dev/null
    log "allowed new public port: ${NEW_PORT}/udp"
  fi
  firewall-cmd --reload >/dev/null
  replace_value "${SERVER_DEST}" "ListenPort" "${NEW_PORT}"
  chmod 0600 "${SERVER_DEST}"
  wg set "${INTERFACE}" listen-port "${NEW_PORT}"
  sed -i "s/^APPLIED_AT=.*/APPLIED_AT=$(date +%s)/" "${STATE_FILE}"
  log "switched ${INTERFACE} to UDP ${NEW_PORT}"

  if firewall_has_exact_port "${zone}" "${old_port}/udp"; then
    firewall-cmd --permanent --zone="${zone}" --remove-port="${old_port}/udp" >/dev/null
    firewall-cmd --reload >/dev/null
    log "removed old host firewall port: ${old_port}/udp"
  fi
  verify_live false
  log "keep both router forwards until a client using UDP ${NEW_PORT} completes a fresh handshake"
}

load_live_state() {
  local owner
  local mode

  [[ -f "${STATE_FILE}" ]] || fail "rollback state not found: ${STATE_FILE}"
  owner="$(stat -c '%u' "${STATE_FILE}")"
  mode="$(stat -c '%a' "${STATE_FILE}")"
  [[ "${owner}" == "0" ]] || fail "rollback state must be root-owned"
  (( (8#${mode} & 8#022) == 0 )) ||
    fail "rollback state must not be group- or world-writable"
  # shellcheck source=/dev/null
  source "${STATE_FILE}"
  [[ "${STATE_VERSION:-}" == "1" ]] || fail "unsupported rollback state version"
}

rollback_migration() {
  local state_dir
  local backup_marker
  local backup_dir
  local path

  require_root
  load_live_state
  state_dir="$(dirname "${STATE_FILE}")"
  install -m 0600 "${state_dir}/wg0.conf.before-port-migration" "${SERVER_DEST}"
  wg set "${INTERFACE}" listen-port "${OLD_PORT}"
  if ! firewall_has_exact_port "${PUBLIC_ZONE}" "${OLD_PORT}/udp"; then
    firewall-cmd --permanent --zone="${PUBLIC_ZONE}" --add-port="${OLD_PORT}/udp" >/dev/null
  fi
  if firewall_has_exact_port "${PUBLIC_ZONE}" "${NEW_PORT}/udp"; then
    firewall-cmd --permanent --zone="${PUBLIC_ZONE}" --remove-port="${NEW_PORT}/udp" >/dev/null
  fi
  firewall-cmd --reload >/dev/null

  backup_marker="${CONFIG_DIR}/.wireguard-port-migration-backup"
  if [[ -f "${backup_marker}" ]]; then
    backup_dir="$(cat "${backup_marker}")"
    if [[ -d "${backup_dir}" ]]; then
      for path in "${backup_dir}"/*.local.conf; do
        [[ -f "${path}" ]] || continue
        cp -a "${path}" "${CONFIG_DIR}/"
      done
      log "restored local configs from ${backup_dir}"
    fi
  fi
  log "rolled back ${INTERFACE} to UDP ${OLD_PORT}"
  log "restore the router's old UDP forward before reconnecting remotely"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --prepare) MODE="prepare"; shift ;;
    --apply) MODE="apply"; shift ;;
    --verify) MODE="verify"; shift ;;
    --rollback) MODE="rollback"; shift ;;
    --new-port) NEW_PORT="$2"; shift 2 ;;
    --endpoint-host) ENDPOINT_HOST="$2"; shift 2 ;;
    --interface) INTERFACE="$2"; shift 2 ;;
    --public-zone) PUBLIC_ZONE="$2"; shift 2 ;;
    --server-dest) SERVER_DEST="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --export-dir) EXPORT_DIR="$2"; shift 2 ;;
    --state-file) STATE_FILE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_command awk
require_command find
require_command sed
validate_port "${NEW_PORT}"

case "${MODE}" in
  check) check_state ;;
  prepare) prepare_configs ;;
  apply)
    require_command firewall-cmd
    require_command ip
    require_command wg
    apply_live
    ;;
  verify)
    require_command firewall-cmd
    require_command ip
    require_command wg
    verify_live true
    ;;
  rollback)
    require_command firewall-cmd
    require_command wg
    rollback_migration
    ;;
  *) fail "unsupported mode: ${MODE}" ;;
esac
