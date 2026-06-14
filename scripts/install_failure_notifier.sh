#!/usr/bin/env bash
# Install the systemd OnFailure notification infrastructure for dnsmasq.
# Requires root. Run: sudo bash scripts/install_failure_notifier.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NOTIFY_SCRIPT="${REPO_ROOT}/config/service-failure-notify"
NOTIFY_ENV="/etc/service-failure-notify.env"
INSTALL_BIN="/usr/local/bin/service-failure-notify"
UNIT_FILE="/etc/systemd/system/service-failure-notify@.service"
DROPIN_DIR="/etc/systemd/system/dnsmasq.service.d"
DROPIN_FILE="${DROPIN_DIR}/on-failure-notify.conf"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (sudo bash $0)" >&2
  exit 1
fi

# Prompt for notification email if env file doesn't exist
if [[ ! -f "${NOTIFY_ENV}" ]]; then
  read -rp "Notification email address (e.g. casonkonzer@gmail.com): " NOTIFY_EMAIL
  cat > "${NOTIFY_ENV}" <<EOF
# Written by short-circuit/scripts/install_failure_notifier.sh
NOTIFY_EMAIL=${NOTIFY_EMAIL}
SHOCK_RELAY_DIR=/mnt/4tb-m2/git/util-repos/shock-relay
EOF
  chmod 644 "${NOTIFY_ENV}"
  echo "Wrote ${NOTIFY_ENV}"
else
  echo "Reusing existing ${NOTIFY_ENV}"
fi

# Install the notify script
install -m 755 "${NOTIFY_SCRIPT}" "${INSTALL_BIN}"
echo "Installed ${INSTALL_BIN}"

# Install the template service unit
cat > "${UNIT_FILE}" <<'EOF'
[Unit]
Description=Notify on failure of %i
After=network-online.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/local/bin/service-failure-notify %i
EOF
echo "Installed ${UNIT_FILE}"

# Install the dnsmasq OnFailure drop-in
install -d "${DROPIN_DIR}"
cat > "${DROPIN_FILE}" <<'EOF'
[Unit]
OnFailure=service-failure-notify@dnsmasq.service
EOF
echo "Installed ${DROPIN_FILE}"

systemctl daemon-reload
echo "Reloaded systemd daemon"
echo ""
echo "Done. dnsmasq will now email on failure."
echo "Test with: sudo systemctl start service-failure-notify@dnsmasq.service"
