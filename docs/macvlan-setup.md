# macvlan Setup

`short-circuit` includes a script for creating a persistent macvlan interface
that gives this host a second MAC address and a separate DHCP lease on the LAN —
running in parallel with the hardware MAC, not replacing it.

## Why

A macvlan interface lets you reserve two DHCP leases in your router:

- hardware MAC → stable primary IP (e.g. `192.168.0.6`)
- spoofed MAC   → separate IP for privacy or role separation (e.g. `192.168.0.7`)

Both are live simultaneously. NetworkManager manages the macvlan connection so
it comes back automatically after a reboot.

## Quick Start

```bash
# 1. Seed your local config
bash scripts/setup_macvlan.sh --init-local-config

# 2. Edit config/macvlan/macvlan.local.conf — set MACVLAN_MAC at minimum.
#    Generate a locally-administered MAC if you need one:
printf '02:%02x:%02x:%02x:%02x:%02x\n' \
  $(od -An -N5 -tu1 /dev/urandom | tr -s ' ' '\n' | grep -v '^$' | head -5)

# 3. Add a DHCP reservation in your router for the spoofed MAC → desired IP.

# 4. Apply
bash scripts/setup_macvlan.sh
```

## Config Reference (`macvlan.local.conf`)

| Key | Default | Description |
|---|---|---|
| `MACVLAN_PARENT` | `enp5s0` | Physical parent interface |
| `MACVLAN_IFACE` | `macvlan0` | macvlan interface name |
| `MACVLAN_MAC` | *(required)* | Spoofed MAC — must be locally-administered (`02:xx:…`) |
| `MACVLAN_CON_NAME` | `spoof-mac` | NetworkManager connection name |

`macvlan.local.conf` is gitignored. Never commit a real MAC or IP.

## Operations

```bash
# Check current state
bash scripts/setup_macvlan.sh --status

# Remove the macvlan connection
bash scripts/setup_macvlan.sh --teardown
```

## Persistence

The connection is stored in `/etc/NetworkManager/system-connections/spoof-mac.nmconnection`
and activated automatically on boot by NetworkManager.

## Relation to WireGuard

WireGuard (`wg0`) is a separate interface managed by `short-circuit`'s
`setup_wireguard.sh`. The macvlan interface operates independently on the LAN
and does not affect WireGuard routing.

## DHCP Reservation Note

If you want the spoofed MAC to always receive the same IP, add a DHCP
reservation in your router for `MACVLAN_MAC → desired-IP` before running the
script. Without a reservation, the router assigns a lease from its pool, which
may drift across reboots.
