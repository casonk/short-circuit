#!/bin/sh

set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

TOKEN_PATH=/run/secrets/nordvpn-token
INGRESS_INTERFACE=eth0
NORD_INTERFACE=nordlynx
FILTER_TABLE=short_circuit_egress

fail() {
    printf '%s\n' "nord-egress: $1" >&2
    exit 1
}

disable_forwarding() {
    sysctl -q -w net.ipv4.ip_forward=0 >/dev/null 2>&1
}

remove_policy() {
    nft delete table inet "$FILTER_TABLE" >/dev/null 2>&1 || true
}

cleanup() {
    if disable_forwarding; then
        remove_policy
    else
        printf '%s\n' \
            "nord-egress: keeping the nftables policy because forwarding could not be disabled" \
            >&2
    fi
    nordvpn disconnect >/dev/null 2>&1 || true
}

install_bootstrap_policy() {
    nft -f - <<EOF
table inet $FILTER_TABLE {
    chain forward {
        type filter hook forward priority -10; policy drop;
    }
}
EOF
}

nord_connected() {
    status=$(timeout 5 nordvpn status 2>/dev/null) || return 1
    printf '%s\n' "$status" | grep -Fx 'Status: Connected' >/dev/null
}

healthcheck() {
    test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 || exit 1
    test "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1 || exit 1
    test "$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)" = 1 || exit 1
    ip link show "$NORD_INTERFACE" >/dev/null 2>&1 || exit 1
    nord_connected || exit 1
    ip -4 route show table all | grep -Eq "(^|[[:space:]])dev $NORD_INTERFACE([[:space:]]|$)" \
        || exit 1
    nft list chain inet "$FILTER_TABLE" forward 2>/dev/null | grep -F 'policy drop' \
        >/dev/null || exit 1
}

validate_authorized_sources() {
    awk -v subnet="$mesh_source" -v sources="$authorized_sources" '
        function ip_to_int(ip, parts, count, index, octet, value) {
            count = split(ip, parts, ".")
            if (count != 4) {
                return -1
            }
            value = 0
            for (index = 1; index <= 4; index++) {
                if (parts[index] !~ /^[0-9]+$/ || length(parts[index]) > 3) {
                    return -1
                }
                octet = parts[index] + 0
                if (octet > 255 || (length(parts[index]) > 1 &&
                        substr(parts[index], 1, 1) == "0")) {
                    return -1
                }
                value = (value * 256) + octet
            }
            return value
        }

        BEGIN {
            if (split(subnet, subnet_parts, "/") != 2) {
                exit 1
            }
            subnet_base = ip_to_int(subnet_parts[1])
            prefix = subnet_parts[2] + 0
            if (subnet_base < 0 || subnet_parts[2] !~ /^[0-9]+$/ ||
                    (length(subnet_parts[2]) > 1 && substr(subnet_parts[2], 1, 1) == "0") ||
                    prefix < 16 || prefix > 30) {
                exit 1
            }
            block_size = 2 ^ (32 - prefix)
            first_address = int(subnet_base / block_size) * block_size
            last_address = first_address + block_size - 1

            source_count = split(sources, source_list, ",")
            if (source_count < 1 || sources == "") {
                exit 1
            }
            previous_address = -1
            for (source_index = 1; source_index <= source_count; source_index++) {
                if (split(source_list[source_index], source_parts, "/") != 2 ||
                        source_parts[2] != "32") {
                    exit 1
                }
                source_address = ip_to_int(source_parts[1])
                if (source_address <= first_address || source_address >= last_address ||
                        source_address <= previous_address) {
                    exit 1
                }
                previous_address = source_address
            }
        }
    ' </dev/null
}

if [ "${1:-}" = "--healthcheck" ]; then
    healthcheck
    exit 0
fi

test "$(uname -s)" = Linux || fail "Linux is required"
test "$(id -u)" = 0 || fail "container UID 0 is required"
test -c /dev/net/tun || fail "/dev/net/tun is required"
test "${TC_EGRESS_FAIL_CLOSED:-}" = true || fail "fail-closed policy is required"
test "${TC_IPV6_POLICY:-}" = disabled-drop || fail "IPv6 must be disabled and dropped"
test "${TC_CRUD_LEADERSHIP:-}" = none || fail "the egress gateway cannot hold CRUD leadership"
test "${TC_INGRESS_INTERFACE:-}" = "$INGRESS_INTERFACE" || fail "unexpected ingress interface"
test "${TC_NORD_INTERFACE:-}" = "$NORD_INTERFACE" || fail "unexpected NordLynx interface"
test "${TC_NORD_TOKEN_FILE:-}" = "$TOKEN_PATH" || fail "token must use the fixed secret path"

mesh_source=${TC_MESH_SOURCE_SUBNET:-}
test -n "$mesh_source" || fail "the mesh source subnet is required"
printf '%s\n' "$mesh_source" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' \
    || fail "the mesh source subnet must be an IPv4 CIDR"
authorized_sources=${TC_AUTHORIZED_SOURCE_ADDRESSES:-}
test -n "$authorized_sources" || fail "at least one authorized source /32 is required"
validate_authorized_sources \
    || fail "authorized sources must be sorted, unique IPv4 /32s inside the mesh subnet"
authorized_nft_elements=$(printf '%s\n' "$authorized_sources" | sed 's/,/, /g')

case "${TC_NORD_CONNECT:-fastest}" in
    fastest)
        nord_connect=
        ;;
    [!A-Za-z0-9]*|*[!A-Za-z0-9_-]*|'')
        fail "the NordVPN connection selector is invalid"
        ;;
    *)
        nord_connect=$TC_NORD_CONNECT
        ;;
esac

# Prove CAP_NET_ADMIN inside this namespace without touching a host interface.
probe_interface=tc-cap-probe
ip link add name "$probe_interface" type dummy >/dev/null 2>&1 \
    || fail "CAP_NET_ADMIN is required"
ip link delete "$probe_interface" >/dev/null 2>&1 \
    || fail "could not clean up the capability probe"

disable_forwarding || fail "could not establish disabled IPv4 forwarding"
remove_policy
install_bootstrap_policy || fail "could not establish the bootstrap drop policy"
trap cleanup EXIT
trap 'exit 0' INT TERM HUP

test -f "$TOKEN_PATH" || fail "the Podman token secret is not mounted"
token_size=$(wc -c < "$TOKEN_PATH" | tr -d ' ')
test "$token_size" -ge 1 2>/dev/null || fail "the token secret is empty or malformed"
test "$token_size" -le 1026 2>/dev/null || fail "the token secret is too large"

/etc/init.d/nordvpn start >/dev/null 2>&1 || fail "the NordVPN daemon did not start"

daemon_ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
    if timeout 3 nordvpn status >/dev/null 2>&1; then
        daemon_ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$daemon_ready" = true || fail "the NordVPN CLI could not reach its daemon"

# Version 5.2 can return a nonzero ALREADY_SET result for idempotent settings.
# Verify the pinned CLI's source-defined settings output instead of trusting the
# setter status. Consent must be disabled before login so the headless token
# flow cannot fall into an interactive consent loop.
nordvpn set analytics off >/dev/null 2>&1 || true
settings=$(timeout 10 nordvpn settings 2>/dev/null) \
    || fail "could not read NordVPN settings before login"
printf '%s\n' "$settings" | grep -Fx 'User Consent: disabled' >/dev/null \
    || fail "NordVPN user consent is not disabled"
unset settings

# The pinned CLI supports a no-positional-token terminal prompt. The fixed
# broker starts that prompt in a PTY, waits until terminal echo is disabled,
# and only then reads and forwards the secret. No process argv or environment
# contains the token, and all child output remains suppressed.
timeout 90 /usr/local/sbin/nord-token-login >/dev/null 2>&1 \
    || fail "NordVPN token login failed or timed out"

nordvpn set meshnet off >/dev/null 2>&1 || true
nordvpn set lan-discovery disable >/dev/null 2>&1 || true
saved_ifs=$IFS
IFS=,
set -- $authorized_sources
IFS=$saved_ifs
for authorized_source do
    if nordvpn allowlist add subnet "$authorized_source" >/dev/null 2>&1; then
        :
    elif nordvpn whitelist add subnet "$authorized_source" >/dev/null 2>&1; then
        :
    else
        # An existing rule is reported as a nonzero result in the pinned CLI.
        # The complete settings output is checked below before any connection.
        :
    fi
done
nordvpn set technology NordLynx >/dev/null 2>&1 || true
nordvpn set killswitch on >/dev/null 2>&1 || true

settings=$(timeout 10 nordvpn settings 2>/dev/null) \
    || fail "could not verify NordVPN settings"
printf '%s\n' "$settings" | grep -Fx 'Technology: NORDLYNX' >/dev/null \
    || fail "NordLynx is not selected"
printf '%s\n' "$settings" | grep -Fx 'User Consent: disabled' >/dev/null \
    || fail "NordVPN user consent is not disabled"
printf '%s\n' "$settings" | grep -Fx 'Kill Switch: enabled' >/dev/null \
    || fail "the NordVPN kill switch is not enabled"
printf '%s\n' "$settings" | grep -Fx 'LAN Discovery: disabled' >/dev/null \
    || fail "LAN discovery is not disabled"
if printf '%s\n' "$settings" | grep -q '^Meshnet:'; then
    printf '%s\n' "$settings" | grep -Fx 'Meshnet: disabled' >/dev/null \
        || fail "container Meshnet is not disabled"
fi
saved_ifs=$IFS
IFS=,
set -- $authorized_sources
IFS=$saved_ifs
for authorized_source do
    printf '%s\n' "$settings" | grep -Fqx "$(printf '\t%s' "$authorized_source")" \
        || fail "an authorized WireGuard source is absent from the NordVPN allowlist"
done
unset settings

if [ -n "$nord_connect" ]; then
    nordvpn connect "$nord_connect" >/dev/null 2>&1 || fail "NordVPN connection failed"
else
    nordvpn connect >/dev/null 2>&1 || fail "NordVPN connection failed"
fi

tunnel_ready=false
attempt=0
while [ "$attempt" -lt 60 ]; do
    if ip link show "$NORD_INTERFACE" >/dev/null 2>&1 && nord_connected; then
        tunnel_ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$tunnel_ready" = true || fail "the NordLynx interface was not created"

# A dedicated interval set accepts only the configured peer /32s and only when
# the packet leaves over NordLynx. If NordLynx disappears, the ordinary eth0
# default route cannot become a fallback because the policy remains drop.
nft -f - <<EOF
delete table inet $FILTER_TABLE
table inet $FILTER_TABLE {
    set authorized_sources {
        type ipv4_addr
        flags interval
        elements = { $authorized_nft_elements }
    }
    chain forward {
        type filter hook forward priority -10; policy drop;
        meta nfproto ipv6 drop
        iifname "$INGRESS_INTERFACE" ip saddr @authorized_sources oifname "$NORD_INTERFACE" ct state new,established,related accept
        iifname "$NORD_INTERFACE" oifname "$INGRESS_INTERFACE" ip daddr @authorized_sources ct state established,related accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr @authorized_sources oifname "$NORD_INTERFACE" masquerade
    }
}
EOF

sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null \
    || fail "could not disable IPv6"
sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null \
    || fail "could not disable default IPv6"
sysctl -q -w net.ipv4.ip_forward=1 >/dev/null \
    || fail "could not enable namespace-local IPv4 forwarding"

while sleep 5; do
    ip link show "$NORD_INTERFACE" >/dev/null 2>&1 \
        || fail "NordLynx disappeared; forwarding was stopped"
done
