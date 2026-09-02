# Setup Guide

This guide walks through deploying a WireGuard VPN server using `short-circuit`
so that mobile or remote clients can reach private services on the host.

## Prerequisites

- Linux host (Fedora, Debian, or Ubuntu) with internet access.
- A supported package manager: `dnf`, `apt-get`, or `yum`.
- Root access for installation steps.
- UDP port 51820 accessible inbound on the host (router port-forward or firewall
  rule).
- A stable public endpoint: either a hostname (`vpn.example.com`) or a known
  public IP. The installer can auto-fill the current public IP when none is set,
  but a stable DNS name is preferred.

## Choose a Profile

| Profile | Client Reach | When To Use |
|---|---|---|
| `wireguard-public-vpn` | Host tunnel IP only | Access services on the server host |
| `wireguard-lan-vpn` | Host + full home LAN | Access any LAN device through the tunnel |

The declarative recovery mesh is not a third installer profile. Its schema-v2
renderer is transport-independent: every leaf chooses a `direct` WireGuard
endpoint or an optional `nord-meshnet` carrier, while peer transit and
`disabled`/`nord-vpn` Internet egress remain separate policy decisions.
Rendering never activates forwarding, NAT, firewall rules, Podman, Nord, or a
tunnel. See [`temporary-macos-hub.md`](temporary-macos-hub.md); the normal Linux
procedure below remains the canonical deployment path.

## 1. Initialize Local Config Files

```bash
./scripts/setup_wireguard.sh --init-local-configs --profile wireguard-public-vpn
```

This creates gitignored `*.local.conf` files under `config/wireguard/` from the
example templates:

- `config/wireguard/wg0-server.public-vpn.local.conf`
- `config/wireguard/client-peer.public-vpn.local.conf`

## 2. Edit Local Configs

Open each local file and replace every `<placeholder>`. At minimum:

**Server config** (`wg0-server.public-vpn.local.conf`):

- `PrivateKey`: the server's WireGuard private key
- The client `[Peer]` section's `PublicKey`: the client's WireGuard public key

**Client config** (`client-peer.public-vpn.local.conf`):

- `PrivateKey`: the client device's WireGuard private key
- `Endpoint`: the server's public hostname or IP with port, e.g.
  `vpn.example.com:51820`
- `PublicKey` under `[Peer]`: the server's WireGuard public key

### Auto-Generate Missing Keys

If you have not created WireGuard key pairs yet, the installer can generate them:

```bash
./scripts/setup_wireguard.sh \
  --init-local-configs \
  --profile wireguard-public-vpn \
  --generate-missing-keys
```

This writes coherent key pairs into both local config files. Keep the resulting
private keys out of git — these files are already gitignored.

## 3. Install as Root

```bash
sudo ./scripts/setup_wireguard.sh \
  --profile wireguard-public-vpn \
  --dns-hostname host.vpn.internal \
  --print-client-qr
```

The installer will:

1. Install `wireguard-tools` and `dnsmasq` if missing.
2. Write the server config to `/etc/wireguard/wg0.conf`.
3. Configure a split-DNS helper under `/etc/dnsmasq.d/` so connected clients
   resolve the private hostname to the server tunnel IP.
4. Open the WireGuard UDP listen port on the WAN-facing firewalld zone
   (default: `public`).
5. Configure a `systemd` drop-in so `dnsmasq` waits for the WireGuard interface.
6. Assign the WireGuard interface to the explicit-service `wireguard` firewalld
   zone (if `firewalld` is active).
7. Enable and start `wg-quick@wg0`.
8. Print an ANSI QR code for the client peer config.

### Key Installer Flags

| Flag | Purpose |
|---|---|
| `--dns-hostname HOST` | Private hostname the DNS helper resolves to the server tunnel IP |
| `--generate-missing-keys` | Auto-fill placeholder key pairs before installing |
| `--enable-ip-forward` | Write a sysctl drop-in enabling IPv4/IPv6 forwarding (required for `wireguard-lan-vpn`) |
| `--skip-dns` | Do not install the dnsmasq split-DNS helper |
| `--skip-firewall` | Do not update firewalld |
| `--skip-start` | Install config without enabling or starting WireGuard |
| `--public-zone ZONE` | firewalld zone that should allow inbound UDP for the WireGuard listen port |
| `--print-client-qr` | Print ANSI QR for client peer config |
| `--qr-output PATH` | Write PNG QR for client peer config |

`setup_wireguard.sh` installs these conventional Linux profiles only. In
particular, `--enable-ip-forward` writes sysctl settings; it does not create the
source-restricted NAT, NordLynx namespace, host policy route, IPv6 block, or
kill-switch verification required for `nord-vpn` egress in a schema-v2 mesh.
Do not treat it as an egress installer.

## LAN-VPN Profile

```bash
./scripts/setup_wireguard.sh \
  --init-local-configs \
  --profile wireguard-lan-vpn \
  --lan-subnet 192.168.0.0/24

sudo ./scripts/setup_wireguard.sh \
  --profile wireguard-lan-vpn \
  --lan-subnet 192.168.0.0/24 \
  --enable-ip-forward \
  --dns-hostname host.vpn.internal \
  --print-client-qr
```

The `--lan-subnet` flag updates the client `AllowedIPs` to include both the
WireGuard tunnel subnet and the home LAN range. The `--enable-ip-forward` flag
writes a `sysctl` drop-in enabling IPv4 and IPv6 forwarding on the host.

## 4. Export and Import the Client Config

For desktop clients such as a MacBook Air, export a validated WireGuard config
to a handoff path:

```bash
./scripts/setup_wireguard.sh \
  --profile wireguard-public-vpn \
  --export-client-config /srv/snowbridge/share/tmp/macbook-air-wireguard.conf
```

After the installer prints the QR code, import it on the client device:

- **iOS/Android**: open the WireGuard app and tap the `+` to scan the QR code.
- **macOS/Windows**: use the WireGuard desktop app to import the `.conf` file.
- Or transfer `config/wireguard/client-peer.public-vpn.local.conf` securely.

If the same MacBook also needs private HTTPS or admin-site access protected by
the shared mTLS CA, export the Apple trust profile from `wiring-harness`:

```bash
sudo python3 ../wiring-harness/scripts/export_mtls_profile.py \
  --device-name macbook-air \
  --type mobile \
  --platform macos
```

That stages a signed Apple `mobileconfig` and PKCS#12 identity for macOS
import alongside the WireGuard tunnel config.

## 5. Verify the Connection

On the server:

```bash
sudo wg show wg0
sudo systemctl status wg-quick@wg0.service
sudo systemctl status dnsmasq.service
sudo firewall-cmd --zone=wireguard --list-all
```

From the connected client, try:

- **Ping**: `ping 10.99.0.1`
- **SMB**: mount `smb://10.99.0.1` or `smb://<private-hostname>`
- **SSH**: `ssh user@10.99.0.1`

See `docs/access-modes.md` for service-specific connection details.

## Declarative Recovery Mesh

Start the recovery workflow from the inert tracked example through the
gitignored local declaration:

```bash
python3 scripts/render_wireguard_mesh.py init
python3 scripts/render_wireguard_mesh.py generate-key --node-id temp-mac-hub
```

An active schema-v2 declaration adds a required `platform` to every node. The
hub has no endpoint field. Each leaf declares exactly one path to that hub:

```json
{
  "id": "leaf-direct",
  "role": "leaf",
  "platform": "linux",
  "address": "10.99.0.241/32",
  "public_key": "<leaf-public-key>",
  "hub_transport": {
    "mode": "direct",
    "endpoint": "vpn.example.com:51821"
  }
}
```

Use `direct` for a routable LAN, public IPv4/IPv6, or canonical DNS endpoint.
A private LAN endpoint must retain the mesh listener port; a reviewed public
NAT mapping may expose a different canonical UDP port. Use `nord-meshnet` only
for a literal RFC6598 address supplied by Nord Meshnet and retain the mesh
listener port.

Use `opaque-udp-relay` when the leaf should keep one stable public endpoint and
the relay forwards encrypted datagrams without terminating WireGuard:

```json
{
  "hub_transport": {
    "mode": "opaque-udp-relay",
    "endpoint": "relay.mesh.example.com:443"
  }
}
```

The external relay can accept UDP `443` while Air continues listening locally
on UDP `51821`. Air must separately initiate and maintain the outbound relay
client; the mesh renderer neither installs that client nor provisions DNS,
public compute, firewall policy, or the relay service. All three modes still
carry an ordinary end-to-end WireGuard tunnel; an opaque relay never owns the
WireGuard peer identity.

The mesh policy defaults are deliberately inert:

```json
{
  "peer_transit": false,
  "egress": {
    "mode": "disabled",
    "gateway_node_id": null
  }
}
```

With `peer_transit: false`, a non-egress leaf receives only the hub `/32`.
Enabling it renders the recovery `/28` route for non-egress leaves and marks
the hub manifest as requiring forwarding, but does not enable that forwarding.
`peer_transit: true` cannot coexist with `egress.mode: nord-vpn` in the current
schema; the egress boundary deliberately accepts named leaf `/32`s rather than
a transit-capable overlay.

### Build a multi-service mobile access bundle

When a phone must reach both the temporary Air hub and a canonical home server,
render one replacement profile rather than enabling peer transit or treating a
reachable service as an application-writer failover decision. The owner-only
bundle declaration binds its client identity and temporary Air peer exactly to
the active mesh declaration. It then adds one or more canonical peers, each on
its own non-overlapping `/32` outside the temporary mesh subnet.

```bash
python3 scripts/render_wireguard_access_bundle.py init
# Fill config/wireguard/access-bundle.local.json from the active mesh and
# canonical server's reviewed public key, /32, and endpoint.
python3 scripts/render_wireguard_access_bundle.py validate \
  --mesh-config config/wireguard/mesh.local.json
python3 scripts/render_wireguard_access_bundle.py render \
  --mesh-config config/wireguard/mesh.local.json \
  --private-key-file config/wireguard/mesh.local.d/keys/mini.key
```

The bundle expires with the temporary mesh and refuses to render if its client,
Air peer, endpoint, generation, or expiry differs from that declaration. It
contains only exact peer `/32` `AllowedIPs`; it never renders a recovery subnet,
default route, forwarding rule, or application writer selection. Importing the
replacement iOS profile and adding the same client public key to every server
remain explicit operator actions. By default, each output is created once under
an owner-only generation/client directory, preserving the reviewed prior bundle.

### Classify roaming networks before activation

A private `direct` endpoint is not automatically usable from an isolated guest
WLAN or an off-site network. Bind a separate roaming declaration to the current
mesh and keep it in `audit-only` until one stable public/direct or opaque relay
path covers all three required classes:

```bash
python3 scripts/render_roaming_policy.py init
python3 scripts/render_roaming_policy.py validate \
  --policy config/wireguard/roaming-policy.local.json \
  --mesh-config config/wireguard/mesh.local.json
```

The first strategy is deliberately `stable-primary`: one endpoint remains
usable as the phone changes Wi-Fi or moves to cellular. The policy does not put
multiple endpoints behind one WireGuard peer or claim automatic failover. Once
the mesh declaration and policy are aligned, the same ordinary iPhone profile
and QR remain in use; switching networks does not require a second tunnel
profile.
`lan-direct` is limited to trusted Wi-Fi, and Nord is fixed to egress-only.
`required` additionally demands that every mesh leaf's transport mode and
endpoint already match the selected policy path, but the renderer does not
update or import those profiles and always reports reachability unverified.
It also cannot make a captive portal, an offline network, or a network that
blocks every usable outbound UDP port carry WireGuard. Keep public
listener/relay ingress default-deny with only the reviewed UDP port exposed and
management separately protected. See `docs/roaming-policy.md` for relay and
external-validation gates.

NordVPN Internet egress is a separate Linux-only declaration:

```json
{
  "mode": "nord-vpn",
  "gateway_node_id": "hub-linux",
  "authorized_leaf_ids": ["leaf-direct"],
  "dns_servers": ["<reviewed-public-ipv4-dns>"],
  "ipv6_policy": "block"
}
```

Only named leaves receive `0.0.0.0/0, ::/0` and the declared DNS servers.
Unauthorized leaves retain the hub-only route because peer transit must be off.
The gateway must be the sole hub, declared with `platform: linux`; a macOS
gateway is rejected. The generated manifests say that forwarding, NAT, and
fail-closed egress are required, but report that none was activated.

The isolated image contract under `containers/nord-egress/` is intended for a
rootful Linux Podman namespace. Its separate credential-free declaration lists
the exact authorized WireGuard source `/32`s. That list must equal the node
addresses selected by mesh `egress.authorized_leaf_ids`; authorizing the whole
recovery `/28` would silently widen egress to other leaves. Entries must be
canonical, unique, and sorted by address. `mesh_source_subnet` remains only the
containing validation/routing context; it is not an acceptance or NAT rule.

Initialize the contract separately, then bind every active validation and
render to the authoritative private mesh declaration:

```bash
python3 scripts/render_nord_egress_container.py init
# Edit runtime/nord-egress-container/config.json:
# generation > 0, enabled: true, and reviewed authorized_source_addresses.
python3 scripts/render_nord_egress_container.py validate \
  --mesh-config config/wireguard/mesh.local.json
python3 scripts/render_nord_egress_container.py render \
  --mesh-config config/wireguard/mesh.local.json
```

Enabled validation fails without `--mesh-config`. The binding captures one
canonical active mesh generation, cutover epoch, expiry, normalized-document
SHA-256, Linux gateway address and public key, WireGuard interface, public DNS,
authorized leaf IDs, exact sorted source `/32`s, and every leaf's expected
WireGuard public-key→exact-`/32` binding. The egress declaration's generation,
mesh subnet, interface, and source list must match. Public bootstrap DNS for the
container is supplied from this mesh binding; there is no second egress-specific
DNS list.

The renderer accepts only owner-only ignored state under `runtime/` and emits
the following generation-scoped staging set:

- three Quadlets: image build, isolated network, and container;
- a persistent fail-closed host-guard script and service;
- a preferred-route lifecycle script and service;
- a `wg-quick` dependency drop-in;
- an expiry-stop service and persistent expiry timer;
- `mesh-binding.json`;
- a staged `Containerfile`, entrypoint, and `nord-token-login.c` helper; and
- a manifest with the exact future install map.

That is 15 rendered artifacts. The manifest itself is the review record; its
other 14 artifacts have fixed future destinations.

The mapped destinations are root-owned locations below
`/etc/containers/systemd`, `/etc/systemd/system`, and
`/etc/short-circuit/nord-egress/<gateway>-g<generation>/`. A privileged unit
never refers to the user-writable clone or ignored output directory. The three
Quadlets have no `[Install]` section, and the renderer copies nothing to those
destinations.

The Quadlets require native Linux, rootful Podman 5.8 or newer, an isolated
bridge, `/dev/net/tun`, `NET_ADMIN`, and a fixed file-mounted Podman secret. The
build pins NordVPN package version 5.2.0 and verifies architecture-specific
`.deb` SHA-256 values for amd64 and arm64 before installation. The Nord package
is therefore pinned by content as well as version. The Ubuntu base image has a
syntactically pinned digest, but the operator still must review its provenance.

The pinned NordVPN 5.2 Linux CLI supports a no-positional-token prompt. The
staged C broker contains no credential: it opens the validated CLI, launches
`nordvpn login --token` in a PTY with a sanitized environment, matches the exact
prompt, and verifies `ECHO`/`ECHONL` are disabled. Only then does it disable
core dumps/process dumpability, open the fixed root-owned secret, forward and
wipe the token, and discard all child output. It never falls back to a
credential-bearing `argv`; privileged host inspection remains outside this
boundary. No Nord state volume is retained, so replacement means a fresh login.

The persistent host guard is ordered before both `wg-quick` and the container.
For only the exact authorized `/32`s arriving on the WireGuard interface, it
installs source lookup/prohibit pairs and an IPv4 terminal prohibit route. It
also installs interface-wide IPv4 and IPv6 terminal prohibit rules before its
nftables isolation. The policy-routing prohibits are independent of nftables
and survive an nftables flush, so a lost nft table does not turn WireGuard input
into ordinary-WAN fallback. The nft rules additionally block peer transit,
private/LAN and reserved destinations, unknown WireGuard sources, bridge-to-host
input, and bridge escape. Stopping the container does not remove the guard.

A separate service adds the preferred route through the container only after
Podman reports it healthy and the systemd `wg-quick@<interface>.service` is
active. The route unit is `BindsTo` and `After` both services, so either one
stopping removes only the preferred bridge route. The `wg-quick` dependency
drop-in requires and verifies the persistent guard, wants the route service,
and runs an `ExecStartPost` verifier against the complete runtime identity.

The verifier first requires the bound gateway public key, listen port, exactly
one matching global IPv4 address, and no global IPv6 address. It then requires
exact equality between the mesh-bound set of leaf public keys and `/32`s and
`wg show <interface> allowed-ips`. A broad route, wrong key, wrong `/32`,
missing peer, or extra peer fails startup. Hard preflight also checks host IPv4
forwarding and `rp_filter` set to `0` or `2` on the relevant paths. Neither
renderer silently changes forwarding or reverse-path-filtering sysctls. A
failed start runs `ExecStopPost=-/usr/bin/wg-quick down %i`, ensuring the
partially configured interface is removed before retry.

This ordering is enforced only through systemd. Do not use raw `wg-quick up`,
`wg setconf`, or post-start `wg` peer mutation on an egress gateway: those paths
bypass the managed dependency and post-start verification. Start, stop, and
replace the WireGuard configuration only through the bound
`wg-quick@<interface>.service` generation.

The mesh-bound `expires_at` is also enforced by that lifecycle. Host-guard
install and every guard verification compare the current UTC epoch to the bound
deadline and reject startup when the generation is expired. The `wg-quick`
drop-in requires and orders itself after a generation-specific expiry timer
whose `OnCalendar` is the canonical UTC deadline. The persistent timer is
`BindsTo`/`PartOf` the WireGuard unit and deliberately has no reverse
`After=wg-quick@` ordering, avoiding a dependency cycle. When it fires, a
`RefuseManualStart` stop service requests that systemd stop WireGuard. Because
the preferred route is bound to WireGuard, it is removed while the persistent
terminal guard remains. An expiry missed during downtime is caught both by the
persistent timer and the independent startup gate.

Inside the namespace, forwarded IPv4 is accepted only from the same `/32` set
and only through `nordlynx`; IPv6 is disabled/dropped and the forward policy
stays default-deny if Nord disappears. WireGuard cryptokey routing remains the
first anti-spoof boundary.

Rendering does not create a token or Podman secret, install any staged file,
build an image, log into Nord, start a unit, change a live route, or exercise
traffic. Creating the rootful Podman secret and installing/starting the reviewed
artifacts remain explicit privileged steps, followed by native-Linux Quadlet,
external-IP, DNS, return-path, unauthorized-leaf, spoofed-source, and deliberate
Nord-outage tests.

### Privileged generation cutover contract

The renderer deliberately does not install or execute this sequence. A reviewed
native-Linux installation must preserve these invariants:

1. Stage every new generation at its generation-specific root-owned paths.
2. Before decommissioning the previous guard, mask and stop the WireGuard unit,
   stop and mask the previous generation's egress units, and verify that the
   WireGuard interface and preferred route are absent.
3. Run the previous generation's host-guard `decommission` action. It fails
   closed unless the WireGuard unit is masked and inactive and the interface
   and preferred routes are gone.
4. Install the new generation-scoped artifacts. Atomically replace the one
   managed WireGuard dependency drop-in at
   `wg-quick@<interface>.service.d/50-short-circuit-nord-egress.conf`; never
   leave old and new generation dependencies side by side.
5. Run `systemctl daemon-reload`, then unmask and start WireGuard only through
   its systemd unit. The new guard and runtime public-key→`/32` verification
   must succeed before the preferred route appears.

Do not decommission the old terminal rules while WireGuard can race back into
existence, and do not overwrite a generation-specific directory in place.

The authorized leaf still needs its own persistent no-fallback policy. If its
WireGuard interface is torn down, the default routes installed by `wg-quick`
disappear and the leaf's ordinary WAN may return. Until that leaf-side gate and
the native-Linux gateway tests pass, the rendered system is not an end-to-end
fail-closed deployment.

Legacy schema-v1 local declarations remain readable. The renderer validates
them first, normalizes them to v2 in memory with transit and egress disabled,
prints a warning, and leaves the source file unchanged. Migrate deliberately
to a new generation and cutover epoch rather than overwriting reviewed output.
