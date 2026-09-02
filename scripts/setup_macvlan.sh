#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

EXAMPLE_CONF="${REPO_ROOT}/config/macvlan/macvlan.example.conf"
LOCAL_CONF="${REPO_ROOT}/config/macvlan/macvlan.local.conf"
NM_CON_DIR="/etc/NetworkManager/system-connections"

INIT_LOCAL_CONFIG=0
TEARDOWN=0
STATUS=0

usage() {
  cat <<'EOF'
Usage: setup_macvlan.sh [options]

Create a persistent macvlan interface via NetworkManager so this host
presents a second MAC address on the LAN, obtaining its own DHCP lease
alongside the hardware MAC.

Options:
  --init-local-config   Copy macvlan.example.conf to macvlan.local.conf for editing.
  --teardown            Bring down and delete the macvlan NM connection.
  --status              Print current macvlan interface and connection state.
  -h, --help            Show this help.

Config (macvlan.local.conf):
  MACVLAN_PARENT   Parent physical interface  (default: enp5s0)
  MACVLAN_IFACE    macvlan interface name      (default: macvlan0)
  MACVLAN_MAC      Spoofed MAC address         (required; no default)
  MACVLAN_CON_NAME NetworkManager connection name (default: spoof-mac)

The macvlan.local.conf file is gitignored. Copy the example and edit it
before running this script without --init-local-config.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --init-local-config) INIT_LOCAL_CONFIG=1 ;;
    --teardown)          TEARDOWN=1 ;;
    --status)            STATUS=1 ;;
    -h|--help)           usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

if [[ "${INIT_LOCAL_CONFIG}" -eq 1 ]]; then
  if [[ -f "${LOCAL_CONF}" ]]; then
    echo "macvlan.local.conf already exists — edit it directly."
  else
    cp "${EXAMPLE_CONF}" "${LOCAL_CONF}"
    echo "Created ${LOCAL_CONF} — set MACVLAN_MAC before running setup."
  fi
  exit 0
fi

# Load local config if present, else set defaults
MACVLAN_PARENT=enp5s0
MACVLAN_IFACE=macvlan0
MACVLAN_MAC=""
MACVLAN_CON_NAME=spoof-mac

if [[ -f "${LOCAL_CONF}" ]]; then
  # shellcheck source=/dev/null
  source "${LOCAL_CONF}"
else
  echo "No macvlan.local.conf found. Run with --init-local-config first." >&2
  exit 1
fi

if [[ "${STATUS}" -eq 1 ]]; then
  echo "=== NetworkManager connection ==="
  nmcli con show "${MACVLAN_CON_NAME}" 2>/dev/null \
    | grep -E "^connection\.(id|uuid|type)|^GENERAL\.(STATE|IP-IFACE)|cloned-mac|macvlan\." \
    || echo "(connection '${MACVLAN_CON_NAME}' not found)"
  echo "=== Interface ==="
  ip addr show "${MACVLAN_IFACE}" 2>/dev/null || echo "(interface '${MACVLAN_IFACE}' not found)"
  exit 0
fi

if [[ "${TEARDOWN}" -eq 1 ]]; then
  echo "Bringing down and deleting connection '${MACVLAN_CON_NAME}'..."
  sudo nmcli con down "${MACVLAN_CON_NAME}" 2>/dev/null || true
  sudo nmcli con delete "${MACVLAN_CON_NAME}"
  echo "Done."
  exit 0
fi

# Validate MAC before touching the system
if [[ -z "${MACVLAN_MAC}" || "${MACVLAN_MAC}" == "02:XX:XX:XX:XX:XX" ]]; then
  echo "MACVLAN_MAC is not set in ${LOCAL_CONF}." >&2
  echo "Generate one with:" >&2
  echo "  printf '02:%02x:%02x:%02x:%02x:%02x\n' \$(od -An -N5 -tu1 /dev/urandom | tr -s ' ' '\\n' | grep -v '^\$' | head -5)" >&2
  exit 1
fi

# Validate locally-administered bit (bit 1 of first octet must be set)
first_octet=$(printf '%d' "0x${MACVLAN_MAC%%:*}")
if (( (first_octet & 0x02) == 0 )); then
  echo "MACVLAN_MAC '${MACVLAN_MAC}' is not locally-administered (bit 1 of first octet must be set)." >&2
  echo "Use a MAC starting with 02:, 06:, 0a:, 0e:, etc." >&2
  exit 1
fi

# Bail if connection already exists
if nmcli con show "${MACVLAN_CON_NAME}" &>/dev/null; then
  echo "Connection '${MACVLAN_CON_NAME}' already exists."
  echo "Run --status to inspect it or --teardown to remove it first."
  exit 1
fi

echo "Creating macvlan connection '${MACVLAN_CON_NAME}'..."
echo "  parent:    ${MACVLAN_PARENT}"
echo "  interface: ${MACVLAN_IFACE}"
echo "  MAC:       ${MACVLAN_MAC}"

sudo nmcli con add \
  type macvlan \
  con-name "${MACVLAN_CON_NAME}" \
  ifname "${MACVLAN_IFACE}" \
  macvlan.parent "${MACVLAN_PARENT}" \
  macvlan.mode bridge \
  802-3-ethernet.cloned-mac-address "${MACVLAN_MAC}" \
  ipv4.method auto \
  ipv6.method auto

# NM does not always rename the on-disk file when the connection id differs
# from the filename it chose at creation time — rename it explicitly.
expected_file="${NM_CON_DIR}/${MACVLAN_CON_NAME}.nmconnection"
actual_file=$(sudo find "${NM_CON_DIR}" -name "*.nmconnection" -newer "${NM_CON_DIR}" 2>/dev/null \
  | head -1)
if [[ -n "${actual_file}" && "${actual_file}" != "${expected_file}" ]]; then
  sudo mv "${actual_file}" "${expected_file}"
  sudo nmcli con reload
fi

echo "Bringing up '${MACVLAN_CON_NAME}'..."
sudo nmcli con up "${MACVLAN_CON_NAME}"

echo ""
echo "=== Result ==="
ip addr show "${MACVLAN_IFACE}" | grep -E "link/ether|inet "
