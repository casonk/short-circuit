#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVER_EXAMPLE="${REPO_ROOT}/config/wireguard/wg0-server.example.conf"
SERVER_LAN_EXAMPLE="${REPO_ROOT}/config/wireguard/wg0-server.lan-vpn.example.conf"
SERVER_PUBLIC_LOCAL_DEFAULT="${REPO_ROOT}/config/wireguard/wg0-server.public-vpn.local.conf"
SERVER_LAN_LOCAL_DEFAULT="${REPO_ROOT}/config/wireguard/wg0-server.lan-vpn.local.conf"
CLIENT_EXAMPLE="${REPO_ROOT}/config/wireguard/client-peer.example.conf"
CLIENT_LAN_EXAMPLE="${REPO_ROOT}/config/wireguard/client-peer.lan-vpn.example.conf"
CLIENT_PUBLIC_LOCAL_DEFAULT="${REPO_ROOT}/config/wireguard/client-peer.public-vpn.local.conf"
CLIENT_LAN_LOCAL_DEFAULT="${REPO_ROOT}/config/wireguard/client-peer.lan-vpn.local.conf"
SERVER_DEST_DEFAULT="/etc/wireguard/wg0.conf"
IP_FORWARD_SYSCTL="/etc/sysctl.d/99-short-circuit-wireguard.conf"
WIREGUARD_DNS_DEST_DEFAULT="/etc/dnsmasq.d/short-circuit-wireguard.conf"
WIREGUARD_DNS_DROPIN_DEFAULT="/etc/systemd/system/dnsmasq.service.d/short-circuit-wireguard.conf"
WIREGUARD_DNS_HOSTNAME_DEFAULT="host.vpn.internal"

SERVER_CONFIG=""
CLIENT_CONFIG=""
SERVER_DEST="${SERVER_DEST_DEFAULT}"
WIREGUARD_DNS_DEST="${WIREGUARD_DNS_DEST_DEFAULT}"
WIREGUARD_DNS_DROPIN="${WIREGUARD_DNS_DROPIN_DEFAULT}"
INIT_LOCAL_CONFIGS=0
ENABLE_IP_FORWARD=0
SKIP_START=0
PRINT_CLIENT_QR=0
QR_OUTPUT=""
GENERATE_MISSING_KEYS=0
SKIP_DNS=0
WIREGUARD_DNS_HOSTNAME=""
SKIP_FIREWALL=0
WIREGUARD_FIREWALL_ZONE="trusted"
WIREGUARD_PROFILE="wireguard-public-vpn"
LAN_SUBNET=""
SERVER_CONFIG_EXPLICIT=0
CLIENT_CONFIG_EXPLICIT=0

usage() {
  cat <<'EOF'
Usage: setup_wireguard.sh [options]

Set up a WireGuard server from local-only config files.

Options:
  --init-local-configs     Copy the example configs to local-only .local files.
  --profile NAME           WireGuard profile to initialize or validate. Supported:
                           wireguard-public-vpn, wireguard-lan-vpn.
  --server-config PATH     Local server config to install.
  --client-config PATH     Local client peer config for QR rendering.
  --server-dest PATH       Destination server config path. Default: /etc/wireguard/wg0.conf
  --dns-dest PATH          Destination dnsmasq config path.
                           Default: /etc/dnsmasq.d/short-circuit-wireguard.conf
  --dns-hostname HOST      Private hostname to publish to WireGuard clients.
                           Default: host.vpn.internal
  --lan-subnet CIDR        LAN subnet to route for wireguard-lan-vpn, for example 192.168.0.0/24.
                           Replaces <lan-subnet-cidr> in the client config when present.
  --generate-missing-keys  Generate and write missing server/client key pairs when the
                           paired placeholders are still present.
  --enable-ip-forward      Write a sysctl drop-in enabling IPv4 and IPv6 forwarding.
  --skip-dns               Do not install or restart the dnsmasq split-DNS helper.
  --skip-firewall          Do not update firewalld for the WireGuard interface.
  --firewall-zone ZONE     firewalld zone to assign to the WireGuard interface. Default: trusted
  --skip-start             Do not enable or restart wg-quick@wg0 after installing config.
  --print-client-qr        Print an ANSI QR code for the client peer config.
  --qr-output PATH         Write a PNG QR code for the client peer config.
  --help                   Show this help text.

This installer will install missing runtime packages automatically when a
supported package manager is available. Currently supported: dnf, apt-get, yum.

Typical flow:
  ./scripts/setup_wireguard.sh --init-local-configs --profile wireguard-public-vpn
  # edit config/wireguard/*.public-vpn.local.conf
  sudo ./scripts/setup_wireguard.sh --profile wireguard-public-vpn --print-client-qr

  ./scripts/setup_wireguard.sh --init-local-configs --profile wireguard-lan-vpn --lan-subnet 192.168.0.0/24
  # edit config/wireguard/*.lan-vpn.local.conf
  sudo ./scripts/setup_wireguard.sh --profile wireguard-lan-vpn --lan-subnet 192.168.0.0/24 --enable-ip-forward --print-client-qr
EOF
}

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

ensure_profile() {
  case "${WIREGUARD_PROFILE}" in
    wireguard-public-vpn|wireguard-lan-vpn) ;;
    *)
      fail "invalid WireGuard profile: ${WIREGUARD_PROFILE}"
      ;;
  esac
}

selected_server_example() {
  case "${WIREGUARD_PROFILE}" in
    wireguard-lan-vpn)
      printf '%s\n' "${SERVER_LAN_EXAMPLE}"
      ;;
    *)
      printf '%s\n' "${SERVER_EXAMPLE}"
      ;;
  esac
}

selected_server_local_default() {
  case "${WIREGUARD_PROFILE}" in
    wireguard-lan-vpn)
      printf '%s\n' "${SERVER_LAN_LOCAL_DEFAULT}"
      ;;
    *)
      printf '%s\n' "${SERVER_PUBLIC_LOCAL_DEFAULT}"
      ;;
  esac
}

selected_client_example() {
  case "${WIREGUARD_PROFILE}" in
    wireguard-lan-vpn)
      printf '%s\n' "${CLIENT_LAN_EXAMPLE}"
      ;;
    *)
      printf '%s\n' "${CLIENT_EXAMPLE}"
      ;;
  esac
}

selected_client_local_default() {
  case "${WIREGUARD_PROFILE}" in
    wireguard-lan-vpn)
      printf '%s\n' "${CLIENT_LAN_LOCAL_DEFAULT}"
      ;;
    *)
      printf '%s\n' "${CLIENT_PUBLIC_LOCAL_DEFAULT}"
      ;;
  esac
}

apply_profile_local_defaults() {
  if (( SERVER_CONFIG_EXPLICIT == 0 )); then
    SERVER_CONFIG="$(selected_server_local_default)"
  fi

  if (( CLIENT_CONFIG_EXPLICIT == 0 )); then
    CLIENT_CONFIG="$(selected_client_local_default)"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

find_package_manager() {
  if command -v dnf >/dev/null 2>&1; then
    printf 'dnf\n'
    return
  fi
  if command -v apt-get >/dev/null 2>&1; then
    printf 'apt-get\n'
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    printf 'yum\n'
    return
  fi
  fail "missing runtime packages and no supported package manager found (supported: dnf, apt-get, yum)"
}

install_os_packages() {
  local package_manager
  package_manager="$(find_package_manager)"

  case "${package_manager}" in
    dnf)
      log "install missing packages with dnf: $*"
      dnf install -y "$@"
      ;;
    apt-get)
      log "refresh apt package metadata"
      apt-get update
      log "install missing packages with apt-get: $*"
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    yum)
      log "install missing packages with yum: $*"
      yum install -y "$@"
      ;;
    *)
      fail "unsupported package manager: ${package_manager}"
      ;;
  esac
}

install_runtime_packages_if_needed() {
  local missing_packages=()

  if ! command -v wg-quick >/dev/null 2>&1; then
    missing_packages+=(wireguard-tools)
  fi

  if (( SKIP_DNS == 0 )) && ! command -v dnsmasq >/dev/null 2>&1; then
    missing_packages+=(dnsmasq)
  fi

  if (( PRINT_CLIENT_QR == 1 )) || [[ -n "${QR_OUTPUT}" ]]; then
    if ! command -v qrencode >/dev/null 2>&1; then
      missing_packages+=(qrencode)
    fi
  fi

  if [[ -f "${CLIENT_CONFIG}" ]] && endpoint_needs_autofill; then
    if ! command -v curl >/dev/null 2>&1; then
      missing_packages+=(curl)
    fi
  fi

  if (( ${#missing_packages[@]} == 0 )); then
    return
  fi

  install_os_packages "${missing_packages[@]}"

  command -v wg-quick >/dev/null 2>&1 || fail "wg-quick still missing after package install"
  if (( SKIP_DNS == 0 )); then
    command -v dnsmasq >/dev/null 2>&1 || fail "dnsmasq still missing after package install"
  fi
  if (( PRINT_CLIENT_QR == 1 )) || [[ -n "${QR_OUTPUT}" ]]; then
    command -v qrencode >/dev/null 2>&1 || fail "qrencode still missing after package install"
  fi
  if [[ -f "${CLIENT_CONFIG}" ]] && endpoint_needs_autofill; then
    command -v curl >/dev/null 2>&1 || fail "curl still missing after package install"
  fi
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run as root for installation steps"
}

copy_if_missing() {
  local source="$1"
  local target="$2"
  if [[ -e "${target}" ]]; then
    log "keep existing ${target}"
    return
  fi
  install -D -m 600 "${source}" "${target}"
  log "created ${target}"
}

copy_seeded_local_if_missing() {
  local example_source="$1"
  local target="$2"

  if [[ -e "${target}" ]]; then
    log "keep existing ${target}"
    return
  fi

  install -D -m 600 "${example_source}" "${target}"
  log "created ${target}"
}

apply_profile_overrides_if_needed() {
  ensure_profile

  case "${WIREGUARD_PROFILE}" in
    wireguard-public-vpn)
      [[ -n "${LAN_SUBNET}" ]] && warn "--lan-subnet is ignored for ${WIREGUARD_PROFILE}"
      replace_config_value "${CLIENT_CONFIG}" "AllowedIPs" "10.99.0.1/32"
      log "set WireGuard host-only AllowedIPs to 10.99.0.1/32 in ${CLIENT_CONFIG}"
      ;;
    wireguard-lan-vpn)
      if [[ -n "${LAN_SUBNET}" ]]; then
        replace_placeholder_in_file "${CLIENT_CONFIG}" "<lan-subnet-cidr>" "${LAN_SUBNET}"
        replace_config_value "${CLIENT_CONFIG}" "AllowedIPs" "10.99.0.0/24, ${LAN_SUBNET}"
        log "set WireGuard LAN AllowedIPs to 10.99.0.0/24, ${LAN_SUBNET} in ${CLIENT_CONFIG}"
        return
      fi

      if grep -q '<lan-subnet-cidr>' "${CLIENT_CONFIG}" 2>/dev/null; then
        warn "wireguard-lan-vpn still needs a real LAN subnet in ${CLIENT_CONFIG}; set it manually or rerun with --lan-subnet"
      elif ! grep -Eq '^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*10\.99\.0\.0/24,' "${CLIENT_CONFIG}" 2>/dev/null; then
        warn "wireguard-lan-vpn expects client AllowedIPs to include the full tunnel subnet and a LAN subnet; rerun with --lan-subnet or update ${CLIENT_CONFIG} manually"
      fi
      ;;
  esac
}

contains_placeholders() {
  grep -Eq '<[^>]+>' "$1"
}

check_local_config() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" ]] || fail "${label} not found: ${path}"
  if contains_placeholders "${path}"; then
    fail "${label} still contains placeholder values: ${path}"
  fi
}

endpoint_needs_autofill() {
  local endpoint

  endpoint="$(extract_first_config_value "${CLIENT_CONFIG}" "Endpoint")"

  [[ -z "${endpoint}" ]] && return 0
  [[ "${endpoint}" == "<wireguard-endpoint-hostname-or-ip>:51820" ]] && return 0
  [[ "${endpoint}" =~ ^vpn\.example\.com(:[0-9]+)?$ ]] && return 0

  return 1
}

format_endpoint_host() {
  local host="$1"

  if [[ "${host}" == *:* ]] && [[ ! "${host}" =~ ^\[.*\]$ ]]; then
    printf '[%s]\n' "${host}"
    return
  fi

  printf '%s\n' "${host}"
}

detect_public_ip() {
  local url
  local ip_candidate

  require_command curl

  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://icanhazip.com"
  do
    ip_candidate="$(curl -fsS --max-time 10 "${url}" 2>/dev/null | tr -d '[:space:]')" || continue
    [[ -z "${ip_candidate}" ]] && continue
    if [[ "${ip_candidate}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf '%s\n' "${ip_candidate}"
      return
    fi
    if [[ "${ip_candidate}" =~ ^[0-9A-Fa-f:]+$ ]] && [[ "${ip_candidate}" == *:* ]]; then
      printf '%s\n' "${ip_candidate}"
      return
    fi
  done

  fail "unable to detect the current public IP automatically; set Endpoint manually in ${CLIENT_CONFIG}"
}

autofill_client_endpoint_if_needed() {
  local public_ip
  local listen_port
  local endpoint

  [[ -f "${CLIENT_CONFIG}" ]] || fail "client peer config not found: ${CLIENT_CONFIG}"

  if ! endpoint_needs_autofill; then
    return
  fi

  public_ip="$(detect_public_ip)"
  listen_port="$(extract_first_config_value "${SERVER_CONFIG}" "ListenPort")"
  [[ -n "${listen_port}" ]] || listen_port="51820"
  endpoint="$(format_endpoint_host "${public_ip}"):${listen_port}"

  sed -i "s|^[[:space:]]*Endpoint[[:space:]]*=.*$|Endpoint = ${endpoint}|" "${CLIENT_CONFIG}"
  warn "auto-set the client peer Endpoint to the current public IP (${public_ip}) in ${CLIENT_CONFIG}; replace it with a stable DNS name or other stable public endpoint if this WAN address can change"
}

check_client_export_config() {
  local endpoint

  check_local_config "${CLIENT_CONFIG}" "client peer config"
  endpoint="$(extract_first_config_value "${CLIENT_CONFIG}" "Endpoint")"
  [[ -n "${endpoint}" ]] || fail "client peer config is missing Endpoint: ${CLIENT_CONFIG}"

  if endpoint_needs_autofill; then
    fail "client peer config still has an incomplete Endpoint (${endpoint}); replace it with the real VPN hostname or public IP or let the installer auto-fill it before QR export: ${CLIENT_CONFIG}"
  fi
}

replace_placeholder_in_file() {
  local path="$1"
  local placeholder="$2"
  local value="$3"
  sed -i "s|${placeholder}|${value}|g" "${path}"
}

replace_config_value() {
  local path="$1"
  local key_name="$2"
  local value="$3"
  sed -i "s|^[[:space:]]*${key_name}[[:space:]]*=.*$|${key_name} = ${value}|" "${path}"
}

extract_first_config_value() {
  local path="$1"
  local key_name="$2"
  awk -F '=' -v key_name="${key_name}" '
    $1 ~ "^[[:space:]]*" key_name "[[:space:]]*$" {
      value = $2
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "${path}"
}

resolve_wireguard_dns_hostname() {
  if [[ -n "${WIREGUARD_DNS_HOSTNAME}" ]]; then
    printf '%s\n' "${WIREGUARD_DNS_HOSTNAME}"
    return
  fi
  printf '%s\n' "${WIREGUARD_DNS_HOSTNAME_DEFAULT}"
}

extract_first_address_from_list() {
  local raw_value="$1"
  local first_address

  first_address="${raw_value%%,*}"
  first_address="${first_address%% *}"
  first_address="${first_address#${first_address%%[![:space:]]*}}"
  first_address="${first_address%${first_address##*[![:space:]]}}"
  printf '%s\n' "${first_address}"
}

extract_wireguard_server_ip() {
  local address_value
  local primary_address

  address_value="$(extract_first_config_value "${SERVER_CONFIG}" "Address")"
  [[ -n "${address_value}" ]] || fail "server config is missing Address: ${SERVER_CONFIG}"

  primary_address="$(extract_first_address_from_list "${address_value}")"
  [[ -n "${primary_address}" ]] || fail "server config Address is empty: ${SERVER_CONFIG}"
  printf '%s\n' "${primary_address%%/*}"
}

install_wireguard_dns() {
  local dns_hostname
  local dns_ip
  local client_dns
  local dropin_dir

  (( SKIP_DNS == 1 )) && return

  dns_hostname="$(resolve_wireguard_dns_hostname)"
  [[ -n "${dns_hostname}" ]] || fail "unable to determine WireGuard DNS hostname"
  dns_ip="$(extract_wireguard_server_ip)"
  client_dns="$(extract_first_config_value "${CLIENT_CONFIG}" "DNS")"

  if [[ -z "${client_dns}" ]]; then
    warn "client peer config has no DNS setting; add DNS = ${dns_ip} to ${CLIENT_CONFIG} so WireGuard clients resolve ${dns_hostname}"
  elif [[ "${client_dns}" != "${dns_ip}" ]]; then
    warn "client peer config DNS (${client_dns}) does not match the server WireGuard IP (${dns_ip}); clients must use a DNS server that resolves ${dns_hostname}"
  fi

  install -d "$(dirname "${WIREGUARD_DNS_DEST}")"
  cat > "${WIREGUARD_DNS_DEST}" <<EOF
# managed by short-circuit setup_wireguard.sh
interface=${INTERFACE_NAME}
listen-address=${dns_ip}
bind-interfaces
no-hosts
host-record=${dns_hostname},${dns_ip}
EOF
  log "installed ${WIREGUARD_DNS_DEST}"

  dropin_dir="$(dirname "${WIREGUARD_DNS_DROPIN}")"
  install -d "${dropin_dir}"
  cat > "${WIREGUARD_DNS_DROPIN}" <<EOF
[Unit]
After=wg-quick@${INTERFACE_NAME}.service
Wants=wg-quick@${INTERFACE_NAME}.service
EOF
  systemctl daemon-reload
  log "installed ${WIREGUARD_DNS_DROPIN}"

  if (( SKIP_START == 0 )); then
    systemctl enable --now dnsmasq.service
    systemctl restart dnsmasq.service
    log "enabled and restarted dnsmasq.service for ${dns_hostname} -> ${dns_ip}"
  else
    systemctl enable dnsmasq.service
    log "enabled dnsmasq.service; start it after ${INTERFACE_NAME} is up to serve ${dns_hostname} -> ${dns_ip}"
  fi
}

install_wireguard_firewall() {
  (( SKIP_FIREWALL == 1 )) && return

  if ! command -v firewall-cmd >/dev/null 2>&1; then
    warn "firewall-cmd not found; skipping firewalld integration for ${INTERFACE_NAME}"
    return
  fi

  if ! systemctl is-active --quiet firewalld.service; then
    warn "firewalld.service is not active; skipping firewalld integration for ${INTERFACE_NAME}"
    return
  fi

  if firewall-cmd --permanent --zone="${WIREGUARD_FIREWALL_ZONE}" --query-interface="${INTERFACE_NAME}" >/dev/null 2>&1; then
    firewall-cmd --zone="${WIREGUARD_FIREWALL_ZONE}" --add-interface="${INTERFACE_NAME}" >/dev/null 2>&1 || true
    log "firewalld already maps ${INTERFACE_NAME} to zone ${WIREGUARD_FIREWALL_ZONE}"
  else
    firewall-cmd --permanent --zone="${WIREGUARD_FIREWALL_ZONE}" --add-interface="${INTERFACE_NAME}" >/dev/null
    firewall-cmd --zone="${WIREGUARD_FIREWALL_ZONE}" --add-interface="${INTERFACE_NAME}" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null
    log "assigned ${INTERFACE_NAME} to firewalld zone ${WIREGUARD_FIREWALL_ZONE}"
  fi
}

derive_public_key() {
  local private_key="$1"
  printf '%s' "${private_key}" | wg pubkey
}

generate_key_pair() {
  local private_key
  local public_key
  private_key="$(wg genkey)"
  public_key="$(derive_public_key "${private_key}")"
  printf '%s\n%s\n' "${private_key}" "${public_key}"
}

sync_server_key_pair() {
  local server_private_key
  local server_public_key
  local generated_pair

  server_private_key="$(extract_first_config_value "${SERVER_CONFIG}" "PrivateKey")"
  server_public_key="$(extract_first_config_value "${CLIENT_CONFIG}" "PublicKey")"

  if [[ "${server_private_key}" == "<server-private-key>" ]]; then
    if [[ "${server_public_key}" == "<server-public-key>" ]]; then
      generated_pair="$(generate_key_pair)"
      server_private_key="$(printf '%s\n' "${generated_pair}" | sed -n '1p')"
      server_public_key="$(printf '%s\n' "${generated_pair}" | sed -n '2p')"
      replace_placeholder_in_file "${SERVER_CONFIG}" "<server-private-key>" "${server_private_key}"
      replace_placeholder_in_file "${CLIENT_CONFIG}" "<server-public-key>" "${server_public_key}"
      log "generated server WireGuard key pair"
      return
    fi
    fail "server private key is still a placeholder while client config already has a server public key; set the matching private key manually or restore <server-public-key> so the script can generate a fresh pair"
  fi

  if [[ "${server_public_key}" == "<server-public-key>" ]]; then
    server_public_key="$(derive_public_key "${server_private_key}")"
    replace_placeholder_in_file "${CLIENT_CONFIG}" "<server-public-key>" "${server_public_key}"
    log "derived server public key from existing server private key"
  fi
}

sync_client_key_pair() {
  local client_private_key
  local client_public_key
  local generated_pair

  client_private_key="$(extract_first_config_value "${CLIENT_CONFIG}" "PrivateKey")"
  client_public_key="$(extract_first_config_value "${SERVER_CONFIG}" "PublicKey")"

  if [[ "${client_private_key}" == "<client-private-key>" ]]; then
    if [[ "${client_public_key}" == "<client-public-key>" ]]; then
      generated_pair="$(generate_key_pair)"
      client_private_key="$(printf '%s\n' "${generated_pair}" | sed -n '1p')"
      client_public_key="$(printf '%s\n' "${generated_pair}" | sed -n '2p')"
      replace_placeholder_in_file "${CLIENT_CONFIG}" "<client-private-key>" "${client_private_key}"
      replace_placeholder_in_file "${SERVER_CONFIG}" "<client-public-key>" "${client_public_key}"
      log "generated client WireGuard key pair"
      return
    fi
    fail "client private key is still a placeholder while server config already has a client public key; set the matching private key manually or restore <client-public-key> so the script can generate a fresh pair"
  fi

  if [[ "${client_public_key}" == "<client-public-key>" ]]; then
    client_public_key="$(derive_public_key "${client_private_key}")"
    replace_placeholder_in_file "${SERVER_CONFIG}" "<client-public-key>" "${client_public_key}"
    log "derived client public key from existing client private key"
  fi
}

generate_missing_keys_if_needed() {
  [[ -f "${SERVER_CONFIG}" ]] || fail "server config not found: ${SERVER_CONFIG}"
  [[ -f "${CLIENT_CONFIG}" ]] || fail "client peer config not found: ${CLIENT_CONFIG}"

  if ! grep -Eq '<(server-private-key|server-public-key|client-private-key|client-public-key)>' "${SERVER_CONFIG}" "${CLIENT_CONFIG}"; then
    return
  fi

  require_command wg
  sync_server_key_pair
  sync_client_key_pair
}

render_client_qr() {
  (( PRINT_CLIENT_QR == 0 )) && [[ -z "${QR_OUTPUT}" ]] && return

  require_command qrencode
  check_client_export_config

  if (( PRINT_CLIENT_QR == 1 )); then
    log "ANSI QR for ${CLIENT_CONFIG}:"
    qrencode -t ANSIUTF8 < "${CLIENT_CONFIG}"
  fi

  if [[ -n "${QR_OUTPUT}" ]]; then
    install -d "$(dirname "${QR_OUTPUT}")"
    qrencode -o "${QR_OUTPUT}" < "${CLIENT_CONFIG}"
    log "wrote ${QR_OUTPUT}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --init-local-configs)
      INIT_LOCAL_CONFIGS=1
      shift
      ;;
    --profile)
      WIREGUARD_PROFILE="$2"
      shift 2
      ;;
    --server-config)
      SERVER_CONFIG="$2"
      SERVER_CONFIG_EXPLICIT=1
      shift 2
      ;;
    --client-config)
      CLIENT_CONFIG="$2"
      CLIENT_CONFIG_EXPLICIT=1
      shift 2
      ;;
    --server-dest)
      SERVER_DEST="$2"
      shift 2
      ;;
    --dns-dest)
      WIREGUARD_DNS_DEST="$2"
      shift 2
      ;;
    --dns-hostname)
      WIREGUARD_DNS_HOSTNAME="$2"
      shift 2
      ;;
    --lan-subnet)
      LAN_SUBNET="$2"
      shift 2
      ;;
    --generate-missing-keys)
      GENERATE_MISSING_KEYS=1
      shift
      ;;
    --enable-ip-forward)
      ENABLE_IP_FORWARD=1
      shift
      ;;
    --skip-dns)
      SKIP_DNS=1
      shift
      ;;
    --skip-firewall)
      SKIP_FIREWALL=1
      shift
      ;;
    --firewall-zone)
      WIREGUARD_FIREWALL_ZONE="$2"
      shift 2
      ;;
    --skip-start)
      SKIP_START=1
      shift
      ;;
    --print-client-qr)
      PRINT_CLIENT_QR=1
      shift
      ;;
    --qr-output)
      QR_OUTPUT="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

ensure_profile
apply_profile_local_defaults

if (( INIT_LOCAL_CONFIGS == 1 )); then
  copy_seeded_local_if_missing "$(selected_server_example)" "${SERVER_CONFIG}"
  copy_seeded_local_if_missing "$(selected_client_example)" "${CLIENT_CONFIG}"
  apply_profile_overrides_if_needed
  if (( GENERATE_MISSING_KEYS == 1 )); then
    require_command wg
    generate_missing_keys_if_needed
  fi
  log "edit the local configs, then rerun with sudo to install them"
  exit 0
fi

require_root
require_command install
require_command systemctl
install_runtime_packages_if_needed
apply_profile_overrides_if_needed
generate_missing_keys_if_needed
autofill_client_endpoint_if_needed

check_local_config "${SERVER_CONFIG}" "server config"
if (( PRINT_CLIENT_QR == 1 )) || [[ -n "${QR_OUTPUT}" ]]; then
  check_client_export_config
fi
INTERFACE_NAME="$(basename "${SERVER_DEST}" .conf)"

install -d /etc/wireguard
install -m 600 "${SERVER_CONFIG}" "${SERVER_DEST}"
log "installed ${SERVER_DEST}"

if (( ENABLE_IP_FORWARD == 1 )); then
  printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' > "${IP_FORWARD_SYSCTL}"
  sysctl -p "${IP_FORWARD_SYSCTL}" >/dev/null
  log "updated ${IP_FORWARD_SYSCTL}"
fi

render_client_qr

if (( SKIP_START == 0 )); then
  systemctl enable --now "wg-quick@${INTERFACE_NAME}.service"
  systemctl restart "wg-quick@${INTERFACE_NAME}.service"
  log "enabled and restarted wg-quick@${INTERFACE_NAME}.service"
fi

install_wireguard_dns
install_wireguard_firewall

log "next checks:"
log "  sudo wg show ${INTERFACE_NAME}"
log "  sudo systemctl status wg-quick@${INTERFACE_NAME}.service"
if (( SKIP_DNS == 0 )); then
  log "  sudo systemctl status dnsmasq.service"
fi
if (( SKIP_FIREWALL == 0 )); then
  log "  sudo firewall-cmd --zone=${WIREGUARD_FIREWALL_ZONE} --list-all"
fi
