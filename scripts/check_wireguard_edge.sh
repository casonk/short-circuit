#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTERFACE="wg0"
SERVER_CONFIG="${REPO_ROOT}/config/wireguard/wg0-server.public-vpn.local.conf"
CLIENT_CONFIG="${REPO_ROOT}/config/wireguard/client-peer.public-vpn.local.conf"
ROUTE_PROBE="1.1.1.1"
LAN_INTERFACE=""
EXPECTED_ROUTER_TARGET=""
SKIP_PUBLIC_IP=0

usage() {
  cat <<'USAGE'
Usage: check_wireguard_edge.sh [OPTIONS]

Summarize the public WireGuard edge values that must agree with router/NAT
state. The script does not change router, firewall, WireGuard, or system state.

Options:
  --interface NAME              WireGuard interface to report (default: wg0).
  --server-config PATH          Server config to inspect.
  --client-config PATH          Client config to inspect for Endpoint.
  --route-probe IP              IP used for local egress route detection.
  --lan-interface NAME          Interface whose IPv4 should receive router forwards.
  --expected-router-target IP   Fail if the current host LAN IP differs.
  --skip-public-ip              Do not query the current public IPv4.
  --help                        Show this help.
USAGE
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_option_value() {
  local option="$1"
  local value="${2:-}"

  [[ -n "${value}" && "${value}" != --* ]] || fail "${option} requires a value"
}

extract_first_config_value() {
  local path="$1"
  local key="$2"

  awk -F '=' -v key="${key}" '
    /^[[:space:]]*#/ { next }
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      value = $2
      sub(/^[[:space:]]*/, "", value)
      sub(/[[:space:]]*(#.*)?$/, "", value)
      print value
      exit
    }
  ' "${path}"
}

parse_endpoint_host() {
  local endpoint="$1"

  if [[ "${endpoint}" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  else
    printf '%s\n' "${endpoint%:*}"
  fi
}

parse_endpoint_port() {
  local endpoint="$1"

  if [[ "${endpoint}" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[2]}"
  else
    printf '%s\n' "${endpoint##*:}"
  fi
}

detect_lan_ipv4() {
  if [[ -n "${SHORT_CIRCUIT_TEST_LAN_IPV4:-}" ]]; then
    printf '%s\n' "${SHORT_CIRCUIT_TEST_LAN_IPV4}"
    return
  fi

  if [[ -n "${LAN_INTERFACE}" ]]; then
    ip -4 -o addr show dev "${LAN_INTERFACE}" scope global | awk '
      NR == 1 {
        sub(/\/.*/, "", $4)
        print $4
        exit
      }
    '
    return
  fi

  ip -4 route get "${ROUTE_PROBE}" | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "src" && (i + 1) <= NF) {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

detect_public_ipv4() {
  if [[ -n "${SHORT_CIRCUIT_TEST_PUBLIC_IPV4:-}" ]]; then
    printf '%s\n' "${SHORT_CIRCUIT_TEST_PUBLIC_IPV4}"
    return
  fi

  curl -4 -fsS https://ifconfig.me
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) require_option_value "$1" "${2:-}"; INTERFACE="$2"; shift 2 ;;
    --server-config) require_option_value "$1" "${2:-}"; SERVER_CONFIG="$2"; shift 2 ;;
    --client-config) require_option_value "$1" "${2:-}"; CLIENT_CONFIG="$2"; shift 2 ;;
    --route-probe) require_option_value "$1" "${2:-}"; ROUTE_PROBE="$2"; shift 2 ;;
    --lan-interface) require_option_value "$1" "${2:-}"; LAN_INTERFACE="$2"; shift 2 ;;
    --expected-router-target) require_option_value "$1" "${2:-}"; EXPECTED_ROUTER_TARGET="$2"; shift 2 ;;
    --skip-public-ip) SKIP_PUBLIC_IP=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -f "${SERVER_CONFIG}" ]] || fail "server config not found: ${SERVER_CONFIG}"
[[ -f "${CLIENT_CONFIG}" ]] || fail "client config not found: ${CLIENT_CONFIG}"

listen_port="$(extract_first_config_value "${SERVER_CONFIG}" "ListenPort")"
endpoint="$(extract_first_config_value "${CLIENT_CONFIG}" "Endpoint")"
[[ -n "${listen_port}" ]] || fail "server config is missing ListenPort: ${SERVER_CONFIG}"
[[ -n "${endpoint}" ]] || fail "client config is missing Endpoint: ${CLIENT_CONFIG}"
endpoint_host="$(parse_endpoint_host "${endpoint}")"
endpoint_port="$(parse_endpoint_port "${endpoint}")"
lan_ipv4="$(detect_lan_ipv4)"
[[ -n "${lan_ipv4}" ]] || fail "could not determine current host LAN IPv4"

printf 'interface: %s\n' "${INTERFACE}"
printf 'server_config: %s\n' "${SERVER_CONFIG}"
printf 'client_config: %s\n' "${CLIENT_CONFIG}"
printf 'listen_port: %s\n' "${listen_port}"
printf 'client_endpoint: %s\n' "${endpoint}"
if [[ -n "${LAN_INTERFACE}" ]]; then
  printf 'lan_interface: %s\n' "${LAN_INTERFACE}"
fi
printf 'current_host_lan_ipv4: %s\n' "${lan_ipv4}"
printf 'required_router_forward: UDP %s -> %s:%s\n' "${endpoint_port}" "${lan_ipv4}" "${listen_port}"

if [[ "${endpoint_port}" != "${listen_port}" ]]; then
  printf 'warning: client endpoint port differs from server ListenPort; verify intentional NAT/relay mapping\n'
fi

if (( SKIP_PUBLIC_IP == 0 )); then
  public_ipv4="$(detect_public_ipv4)"
  printf 'current_public_ipv4: %s\n' "${public_ipv4}"
  if [[ "${endpoint_host}" == "${public_ipv4}" ]]; then
    printf 'public_endpoint_state: matches current public IPv4\n'
  else
    printf 'public_endpoint_state: endpoint host differs from current public IPv4; verify DNS/NAT intentionally resolves this way\n'
  fi
fi

if [[ -n "${EXPECTED_ROUTER_TARGET}" ]]; then
  if [[ "${EXPECTED_ROUTER_TARGET}" == "${lan_ipv4}" ]]; then
    printf 'router_target_state: matches expected target\n'
  else
    fail "expected router target ${EXPECTED_ROUTER_TARGET}, but current host LAN IPv4 is ${lan_ipv4}"
  fi
fi
