# Access Modes

This document describes how to reach common services on the host through a
`short-circuit` WireGuard tunnel after the client is connected.

All examples use `10.99.0.1` as the server tunnel IP (the default) and
`host.vpn.internal` as the example private hostname. Replace these with your
actual values.

## SMB (File Sharing)

WireGuard routes TCP 445 to the server through the tunnel. From a connected
client:

- **iOS**: open Files, tap `Browse`, then `...`, then `Connect to Server`, and
  enter `smb://10.99.0.1` or `smb://host.vpn.internal`.
- **macOS**: in Finder, press `Cmd+K` and enter `smb://10.99.0.1`.
- **Windows**: in File Explorer, use `\\10.99.0.1\<share-name>`.
- **Linux**: use `smb://10.99.0.1/<share-name>` in a file manager or
  `smbclient //10.99.0.1/<share-name> -U <username>`.

The `wireguard-public-vpn` profile routes only the host tunnel IP. The
`wireguard-lan-vpn` profile routes the full LAN, allowing access to SMB
servers on other LAN devices by LAN IP.

## HTTPS (Web Access)

Private HTTPS services on the server (e.g. a reverse proxy or web UI) are
accessible via the tunnel IP or a private hostname if DNS is configured.

The `setup_wireguard.sh` installer configures a `dnsmasq` split-DNS helper on
the server that resolves the private hostname to the server tunnel IP:

```bash
sudo ./scripts/setup_wireguard.sh \
  --profile wireguard-public-vpn \
  --dns-hostname files.example.internal
```

After connecting, the client can reach:

- `https://10.99.0.1:<port>` (by tunnel IP)
- `https://files.example.internal:<port>` (by private hostname, if DNS is set)

For the private hostname to work, the client WireGuard config must set:

```
DNS = 10.99.0.1
```

This routes DNS queries through the tunnel to the split-DNS helper on the host.

### TLS Certificates

For private HTTPS with a self-signed or locally issued certificate, the client
device must trust the CA. Options:

- Install a trusted CA certificate profile on the client (recommended for iOS).
- Use a public ACME certificate if the hostname is publicly resolvable.
- Accept the self-signed cert manually for internal testing.

## SSH

SSH access through the tunnel works without any additional WireGuard
configuration. The `trusted` firewalld zone (the default for the WireGuard
interface) allows SSH.

From a connected client:

```bash
ssh user@10.99.0.1
```

Or with a private hostname if DNS is configured:

```bash
ssh user@host.vpn.internal
```

### SSH Configuration Tip

Add a `~/.ssh/config` entry on the client for convenience:

```
Host wg-host
    HostName 10.99.0.1
    User your-username
    IdentityFile ~/.ssh/id_ed25519
```

Then connect with `ssh wg-host`.

### LAN-VPN SSH Access

With the `wireguard-lan-vpn` profile and a suitable `AllowedIPs` including your
home LAN subnet (e.g. `192.168.0.0/24`), SSH to any LAN host is available by
LAN IP:

```bash
ssh user@192.168.0.50
```

## Firewall Defaults

The installer assigns the WireGuard interface to the `trusted` firewalld zone
by default. This zone allows:

- Inbound connections from connected clients on any port.
- SMB, HTTPS, and SSH without additional firewall rules.

To use a more restrictive zone, pass `--firewall-zone <zone>` and manually add
the required services to that zone.

These defaults describe `setup_wireguard.sh` and its conventional Linux
profiles. They do not implement the schema-v2 NordVPN egress boundary. A
full-tunnel egress gateway must not rely on the broad `trusted` zone as proof
of source authorization, NAT, a kill switch, or WAN fallback prevention.

## Accessing LAN Devices (wireguard-lan-vpn Only)

With the `wireguard-lan-vpn` profile and `--enable-ip-forward`:

- The host forwards traffic from the WireGuard tunnel to the home LAN.
- The client's `AllowedIPs` includes both the tunnel subnet and the LAN subnet.
- LAN devices do not need WireGuard installed; traffic is forwarded by the host.

LAN devices must have a route back to the client's WireGuard IP (10.99.0.2) via
the host. The simplest approach is to set the host as the default gateway for
LAN devices, or to add a static route on each device:

```
Destination: 10.99.0.0/24   Gateway: <host LAN IP>
```

## Recovery-Mesh Routing Scope

Schema-v2 recovery profiles keep endpoint transport separate from routing
scope. A leaf can reach the same WireGuard hub through a direct endpoint, an
opaque UDP relay, or Nord Meshnet; that choice does not grant additional
routes.

| Leaf policy | Rendered `AllowedIPs` | Intended reach |
|---|---|---|
| Egress unauthorized, `peer_transit: false` | Hub `/32` | Services on the hub only |
| Egress unauthorized, `peer_transit: true` | Recovery `/28` | Hub and temporary peers, after separately enabling hub forwarding |
| Named in NordVPN egress allowlist | `0.0.0.0/0, ::/0` | Full tunnel to a reviewed Linux egress gateway |

The last two rows are alternative policies, not composable capabilities.
`mesh.peer_transit: true` and `egress.mode: nord-vpn` are rejected together in
the current schema because a broad peer route would conflict with the exact-
source, outbound-only egress boundary.

The hub always retains one `/32` per leaf. It never assigns a default route to
a leaf peer entry, and it never learns a leaf endpoint from the declaration.
WireGuard learns the roaming leaf endpoint from authenticated traffic.

`peer_transit: true` is only render-time intent. The manifest reports that the
hub requires forwarding, while `activation_performed`, `routing_changed`, and
`forwarding_enabled` remain false. The temporary macOS procedure leaves peer
transit disabled.

### Roaming across isolated and off-site networks

WireGuard can learn a leaf's changing source address after authenticated
traffic, but a phone still needs one reachable hub endpoint. Guest client
isolation prevents an RFC 1918 `lan-direct` endpoint even when the guest shares
the router's public address. Cellular and arbitrary external Wi-Fi have the
same private-endpoint limitation.

Use `scripts/render_roaming_policy.py` to classify `trusted-wlan`,
`isolated-wlan`, and `offsite`. A complete declared `stable-primary` policy
requires one public/direct listener or opaque UDP relay across all three and
alignment with every mesh leaf's declared transport. It is still unverified:
the renderer produces only a key-free decision plan and never changes DNS,
router, WireGuard, firewall, or iOS On-Demand state. Public ingress must be
default-deny except for the reviewed WireGuard UDP port. See
`docs/roaming-policy.md`.

With an aligned `opaque-udp-relay` mesh transport, the one imported iPhone
profile keeps the same stable endpoint while its source network changes. The
relay may expose UDP `443` while Air still listens locally on UDP `51821`, but
Air needs a separately supervised outbound relay client and the relay must be
provisioned before this can work. This covers Internet paths that allow the
chosen outbound UDP port, not captive/no-Internet or all-UDP-blocked networks.

## NordVPN Internet Egress

Nord Meshnet and NordVPN egress solve different problems:

- `hub_transport.mode: nord-meshnet` is an optional outer path for the
  WireGuard UDP exchange.
- `egress.mode: nord-vpn` requests that Internet traffic from specifically
  authorized leaves leave a Linux gateway through NordLynx.

For an authorized leaf, the mesh renderer emits the mesh declaration's reviewed
public IPv4 DNS servers. The same list is supplied to the Podman container as
its public bootstrap DNS; the egress config cannot substitute a second DNS
source. `ipv6_policy` is fixed to `block`; `::/0` is captured so native IPv6
cannot bypass the requested privacy boundary. Routed IPv6 is not yet supported.

The egress container contract accepts only its explicit
`authorized_source_addresses`, each a WireGuard leaf `/32`, masquerades those
sources only on `nordlynx`, and keeps forwarding default-deny if NordLynx
disappears. Those addresses must match the mesh nodes named in
`egress.authorized_leaf_ids` exactly.

An active egress render requires `--mesh-config`. One canonical mesh binding
records the generation, cutover epoch, expiry, normalized-document SHA-256,
Linux gateway address and public key, WireGuard interface, public DNS,
authorized leaf IDs, their exact sorted `/32`s, and the complete expected leaf
public-key→exact-`/32` peer map. The egress declaration must match its
generation, subnet, interface, and address set; peer transit must be false. This
prevents two independently edited declarations from silently authorizing
different traffic.

The output contains 15 artifacts: three Quadlets; host-guard and route-lifecycle
scripts/services; a managed `wg-quick` drop-in; an expiry-stop service and
persistent expiry timer; the mesh binding; a staged `Containerfile`,
entrypoint, and C token helper; plus the manifest. Its install map points only
to future root-owned locations. Before the preferred route can be added, hard
checks require native Linux, rootful Podman 5.8 or newer, `/dev/net/tun`, host
IPv4 forwarding, `rp_filter` set to `0` or `2` for the relevant paths, and exact
equality between the full runtime WireGuard peer map and every bound leaf public
key and `/32`.

On the hub, those WireGuard `AllowedIPs` provide the first cryptokey-routing
anti-spoof boundary. The persistent host guard preserves it with source rules
bound to the WireGuard input interface, an IPv4 terminal prohibit route, and
interface-wide IPv4 and IPv6 prohibit rules. Those policy rules survive an
nftables flush and retain the no-ordinary-WAN terminal path. The nftables layer
adds peer-transit, private/LAN, unknown-source, bridge-to-host, and bridge-escape
denials.

A separate service adds the preferred container route only while both Podman
reports the Nord egress container healthy and the systemd `wg-quick@` unit is
active; it is `BindsTo`/`After` both. The fixed managed `wg-quick` drop-in
requires and verifies the guard, wants the route service, and checks the bound
gateway public key, listen port, exact single IPv4 address, lack of global IPv6,
and full public-key→exact-`/32` runtime map in `ExecStartPost`. Its
`ExecStopPost` forces cleanup after a failed start. Raw `wg-quick up`,
`wg setconf`, and post-start peer mutation are unsupported because they bypass
that ordering and verification.

The bound UTC expiry is enforced twice. Guard installation and verification
reject an already expired generation, while the drop-in hard-requires and orders
itself after a persistent systemd timer scheduled for the exact `expires_at`.
The timer is `BindsTo`/`PartOf` WireGuard without reverse ordering back to that
unit; at the deadline its dedicated stop service stops WireGuard. The
WireGuard-bound preferred route is then removed, but the terminal prohibit guard
remains. Expiry is therefore runtime policy once these artifacts are installed,
not only a render-time warning.

Generation cutover atomically replaces the one fixed
`50-short-circuit-nord-egress.conf` drop-in. The previous WireGuard and egress
units must be masked and stopped before its guard is explicitly decommissioned;
cleanup refuses to proceed while the WireGuard unit is unmasked/active, its
interface exists, or a preferred route remains.

NordVPN 5.2.0 is content-pinned with fixed amd64/arm64 `.deb` SHA-256 values.
The staged C broker runs its no-positional-token login in a PTY, waits for the
exact prompt and disabled `ECHO`/`ECHONL`, and only then disables dumps, opens
the root-owned Podman secret, forwards/wipes it, and suppresses child output.
No credential is present in `argv`, the environment, or a rendered artifact,
and prompt drift fails before the secret is opened. Nord state is ephemeral and
container replacement requires a fresh login.

Rendering does not install those files, create or expose a token, build the
image, log into Nord, start a unit, change live routing, or prove traffic. Until
native-Linux tests cover Quadlet generation, unauthorized and spoofed sources,
Nord connection and outage, public DNS, observed external IP, and return paths,
a rendered profile is not an operational egress gateway.

This gateway policy also cannot stop a leaf from falling back locally. If an
authorized leaf's WireGuard interface is torn down, the WireGuard default route
is removed and its ordinary WAN path can return. A persistent leaf-side kill
switch has not been implemented, so end-to-end no-fallback remains a separate
leaf integration gate.

macOS cannot be selected as the schema-v2 egress gateway. The temporary Mac
hub remains host-only because the repository does not install PF, forwarding,
NAT, or an isolated Nord namespace there.

## Future: SSH In Depth

`./util-repos/pit-box` will provide deeper SSH-specific functionality layered
on top of the WireGuard tunnel established by this repo, including SSH key
management, bastion patterns, and host certificate workflows.
