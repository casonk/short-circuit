# short-circuit

WireGuard VPN setup and configuration utility for private remote access.

This repo lives under:

- `./util-repos/short-circuit`

## Purpose

- Provide a scriptable WireGuard installer that works across Fedora, Debian,
  and Ubuntu hosts.
- Maintain profile-based configuration templates for two common access patterns:
  host-only VPN and wider home-LAN routing.
- Render a supervised recovery topology whose WireGuard transport is
  independent from Nord: each leaf selects a direct endpoint, an opaque UDP
  relay, or Nord Meshnet as an optional carrier.
- Classify trusted, isolated, and off-site networks with a render-only roaming
  policy that fails closed until one stable public/direct or opaque relay path
  covers every required network class.
- Keep peer transit and Internet egress explicit. The temporary macOS hub stays
  host-only; fail-closed NordVPN egress is a separate Linux/rootful-Podman
  policy and is never inferred from tunnel reachability.
- Enable authenticated SMB, HTTPS, and SSH access from mobile or remote clients
  through a private WireGuard tunnel.
- Keep all real keys, endpoints, and host-specific values outside git.
- Consent reference: [`../../doc-repos/my-consent/remote-access-and-private-files.md`](../../doc-repos/my-consent/remote-access-and-private-files.md) documents the explicit consent covering personal remote-access, device, and access-control data handled by this repo.

## Supported Profiles

| Profile | Client Reach | Use Case |
|---|---|---|
| `wireguard-public-vpn` | Host tunnel IP only | Reach SMB, HTTPS, SSH on the server host |
| `wireguard-lan-vpn` | Host + full home LAN | Reach any LAN device through the tunnel |

## Repository Layout

- `scripts/setup_wireguard.sh`: installer for either profile
- `scripts/guarded_wireguard_rollout.sh`: root-run config apply helper
  that snapshots the active config and rolls back automatically if no selected
  peer reconnects
- `scripts/render_wireguard_mesh.py`: fail-closed schema-v2 recovery-mesh
  renderer with schema-v1 in-memory compatibility
- `scripts/render_roaming_policy.py`: mesh-bound, key-free roaming coverage
  validator and decision-plan renderer; it performs no endpoint switching
- `scripts/render_wireguard_access_bundle.py`: renders one replacement mobile
  profile with an existing temporary-mesh peer plus disjoint canonical service
  peers; it never enables transit or selects an application writer
- `scripts/render_nord_egress_container.py`: owner-only, mesh-bound renderer for
  15 inactive rootful-Linux artifacts: three Quadlets, guard/route/expiry
  lifecycle, managed `wg-quick` dependency, binding, build inputs, and manifest
- `config/wireguard/wg0-server.example.conf`: server config template (public-vpn)
- `config/wireguard/wg0-server.lan-vpn.example.conf`: server config template (lan-vpn)
- `config/wireguard/client-peer.example.conf`: client peer template (public-vpn)
- `config/wireguard/client-peer.lan-vpn.example.conf`: client peer template (lan-vpn)
- `config/wireguard/mesh.example.json`: synthetic temporary-mesh declaration
- `config/wireguard/roaming-policy.example.json`: inert roaming-policy
  declaration with Nord restricted to outbound egress
- `config/wireguard/access-bundle.example.json`: inert multi-service mobile
  access-bundle declaration
- `config/wireguard/nord-egress-container.example.json`: inert, credential-free
  rootful-Podman egress declaration
- `containers/nord-egress/`: isolated Linux NordLynx egress image contract;
  the image itself does not host the WireGuard mesh or install host routes
- `docs/setup-guide.md`: step-by-step setup walkthrough
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the tunnel
- `docs/temporary-macos-hub.md`: fenced temporary laptop-hub runbook
- `docs/roaming-policy.md`: trusted/isolated/off-site path policy and relay gate
- `docs/contributor-architecture-blueprint.md`: contributor-facing architecture
- `docs/diagrams/repo-architecture.puml`: PlantUML architecture source
- `docs/diagrams/repo-architecture.drawio`: draw.io architecture source

## Quick Start

### 1. Initialize local config files

```bash
./scripts/setup_wireguard.sh --init-local-configs --profile wireguard-public-vpn
```

This copies the example templates to gitignored `*.local.conf` files.

### 2. Edit the local configs

Replace every `<placeholder>` in the generated local configs. At minimum:

- `config/wireguard/wg0-server.public-vpn.local.conf`: server private key,
  client public key
- `config/wireguard/client-peer.public-vpn.local.conf`: client private key,
  server public key, `Endpoint` hostname or IP

Or let the script generate missing key pairs automatically:

```bash
./scripts/setup_wireguard.sh \
  --init-local-configs \
  --profile wireguard-public-vpn \
  --generate-missing-keys
```

### 3. Install as root

```bash
sudo ./scripts/setup_wireguard.sh \
  --profile wireguard-public-vpn \
  --print-client-qr
```

The installer will:

- Install `wireguard-tools` and `dnsmasq` if missing.
- Write the server config to `/etc/wireguard/wg0.conf`.
- Configure a split-DNS helper so clients resolve private hostnames.
- Open the WireGuard UDP listen port on the WAN-facing firewalld zone.
- Assign the WireGuard interface to the explicit-service `wireguard` firewalld zone.
- Enable and start `wg-quick@wg0`.

### Guarded Config Rollout

For remote changes, apply a reviewed candidate config through the
rollback guard instead of overwriting `/etc/wireguard/wg0.conf` directly:

```bash
sudo ./scripts/guarded_wireguard_rollout.sh \
  --apply \
  --candidate /path/to/wg0.candidate.conf \
  --interface wg0 \
  --config /etc/wireguard/wg0.conf
```

`--apply` snapshots the current config, installs the candidate, restarts
`wg-quick@wg0`, and arms a root `systemd-run` check for 30 minutes later. If no
selected peer has a fresh handshake after the apply time, `--verify-or-rollback`
restores the prior config and restarts WireGuard. Pass `--required-peer
<public-key>` to monitor a specific device; otherwise the guard derives peers
from the candidate config and accepts any one fresh handshake.

### Export a Desktop Client Config

For a MacBook or other desktop client, export the validated client config to a
share or handoff path and import it into the WireGuard app:

```bash
./scripts/setup_wireguard.sh \
  --profile wireguard-public-vpn \
  --export-client-config /srv/snowbridge/share/tmp/macbook-air-wireguard.conf
```

If the device also needs private HTTPS client-certificate access, pair that
with `wiring-harness`:

```bash
sudo python3 ../wiring-harness/scripts/export_mtls_profile.py \
  --device-name macbook-air \
  --type mobile \
  --platform macos
```

### LAN-VPN Profile

```bash
./scripts/setup_wireguard.sh \
  --init-local-configs \
  --profile wireguard-lan-vpn \
  --lan-subnet 192.168.0.0/24

sudo ./scripts/setup_wireguard.sh \
  --profile wireguard-lan-vpn \
  --lan-subnet 192.168.0.0/24 \
  --enable-ip-forward \
  --print-client-qr
```

### Temporary macOS Hub

When the canonical home server is offline, a MacBook can temporarily listen as
a **host-only** WireGuard hub under manual supervision. Use a fresh identity
and the reserved temporary range (`10.99.0.241`–`10.99.0.254`); never reuse the
home server's key or `10.99.0.1` address.

Schema v2 separates three concerns:

- `hub_transport` is selected per leaf: `direct` reaches the WireGuard UDP
  listener or a reviewed public NAT mapping, `opaque-udp-relay` names a stable
  public datagram forwarder that does not terminate WireGuard, and
  `nord-meshnet` carries the same WireGuard protocol over an authenticated
  RFC6598 Meshnet path.
- `mesh.peer_transit` decides whether leaves receive the recovery overlay route.
  It defaults to `false` and still needs an explicitly activated forwarding
  policy on the hub. It cannot coexist with `egress.mode: nord-vpn` in the
  current fail-closed design.
- `egress.mode` is either `disabled` or `nord-vpn`. NordVPN egress is restricted
  to named leaves, renders full-tunnel routes plus explicit DNS, and requires a
  Linux gateway with an isolated, fail-closed forwarding/NAT policy. macOS is
  rejected as an egress gateway.

Rendering changes no interface, route, firewall, forwarding, NAT, systemd,
Podman, or Nord state. The temporary Mac procedure therefore keeps
`peer_transit: false` and egress disabled. See
[docs/temporary-macos-hub.md](docs/temporary-macos-hub.md) for endpoint modes,
external validation, expiry, and handback.

### Roaming policy

Guest isolation and cellular networks cannot reach an RFC 1918 laptop endpoint.
The roaming-policy renderer binds a separate key-free decision plan to the
validated mesh generation. A `lan-direct` path is valid only on trusted Wi-Fi;
`isolated-wlan` and `offsite` require one stable public/direct listener or an
opaque UDP relay that preserves WireGuard end-to-end encryption. Nord remains
egress-only and is rejected as a roaming carrier.

Start from the inert ignored declaration and validate it alongside the mesh:

```bash
python3 scripts/render_roaming_policy.py init
python3 scripts/render_roaming_policy.py validate \
  --policy config/wireguard/roaming-policy.local.json \
  --mesh-config config/wireguard/mesh.local.json
```

`audit-only` reports missing coverage without claiming automatic failover;
`required` refuses any policy whose stable primary path does not cover trusted,
isolated, and off-site networks or whose kind and endpoint do not match every
mesh leaf's declared transport. With one aligned stable endpoint, the ordinary
rendered iPhone profile is imported once and remains unchanged across Wi-Fi and
cellular transitions. An external relay may accept UDP `443` while Air keeps
its generation-bound local listener on UDP `51821`; Air must maintain the
separate outbound relay client that connects those two sides. Rendering neither
provisions that relay nor proves reachability.

This promise covers Internet-connected networks that permit outbound UDP to
the selected port. No WireGuard profile can work before captive-portal login,
without Internet access, or through a network that blocks all usable outbound
UDP. Any public listener or relay must remain default-deny and expose only its
reviewed WireGuard UDP port, with management protected separately. See
[docs/roaming-policy.md](docs/roaming-policy.md).

Start from an inert, gitignored declaration; rendering does not activate it:

```bash
python3 scripts/render_wireguard_mesh.py init
python3 scripts/render_wireguard_mesh.py generate-key --node-id temp-mac-hub
```

The renderer can still read a private schema-v1 declaration. It validates and
normalizes that document to v2 in memory, warns the operator, assumes no peer
transit or egress, and never rewrites the source file.

The Linux NordVPN namespace has a separate inert initialization/render path:

```bash
python3 scripts/render_nord_egress_container.py init
# Review the ignored runtime config, advance its generation, and set enabled.
python3 scripts/render_nord_egress_container.py validate \
  --mesh-config config/wireguard/mesh.local.json
python3 scripts/render_nord_egress_container.py render \
  --mesh-config config/wireguard/mesh.local.json
```

An active validate or render is refused without `--mesh-config`. The renderer
binds the egress generation to one validated active mesh generation, cutover
epoch, expiry, canonical-document SHA-256, Linux gateway identity and public
key, WireGuard interface, explicit DNS list, exact authorized leaf IDs and
addresses, and the complete expected WireGuard leaf public-key→`/32` map. The
egress declaration's generation, mesh subnet, interface, and sorted leaf `/32`
list must agree with that binding; `peer_transit` must remain false. Public
bootstrap DNS is taken from the mesh declaration rather than a second
egress-specific source of truth.

The ignored owner-only output contains 15 artifacts: three Quadlets (`.build`,
`.network`, and `.container`); host-guard and preferred-route scripts plus
their services; a `wg-quick` dependency drop-in; an expiry-stop service and
expiry timer; `mesh-binding.json`; a staged `Containerfile`, entrypoint, and C
token-login helper; and the manifest. The manifest maps the 14 installable
inputs to future root-owned paths below
`/etc/containers/systemd`, `/etc/systemd/system`, and
`/etc/short-circuit/nord-egress/<gateway>-g<generation>/`; no root unit refers
back to the user-writable clone or ignored runtime tree.

The guard installs exact source rules tied to the WireGuard input interface,
an IPv4 terminal prohibit route, interface-wide IPv4 and IPv6 prohibit rules,
and bridge/WireGuard nftables drops before the tunnel or egress container. The
policy-routing prohibits survive an nftables flush, so forwarded WireGuard
traffic cannot fall through to an ordinary WAN merely because nft state was
lost. The guard persists when the container stops.

A separate service adds the preferred route only while both the container and
`wg-quick@<interface>.service` are active; it is `BindsTo`/`After` both and
removes only that preferred route on stop. The managed `wg-quick` drop-in
requires and verifies the guard, wants the route service, and verifies the
runtime gateway public key, listen port, single global IPv4 address, absence of
a global IPv6 address, and full public-key→exact-`/32` peer map in
`ExecStartPost`. Broad, missing, extra, or key/address-mismatched peers fail the
bound generation; `ExecStopPost` forces `wg-quick down` after a failed start.
Raw
`wg-quick up`, `wg setconf`, and post-start `wg` peer mutation bypass that
contract and are unsupported: an egress gateway must activate WireGuard only
through its systemd `wg-quick@` unit.

Expiry is an enforced runtime fence, not only manifest metadata. Guard install
and verification compare the current UTC epoch with the mesh-bound
`expires_at` and fail startup at or after the deadline. The managed `wg-quick`
drop-in hard-requires and orders itself after the generation-specific persistent
expiry timer. The timer is `BindsTo`/`PartOf` WireGuard without reverse
`After=wg-quick@`, avoiding a dependency cycle while ensuring it exists before
WireGuard starts. It fires at the exact bound UTC deadline, and its non-manually-
startable stop service stops the `wg-quick@` unit. The route then disappears
through its WireGuard binding while the terminal guard remains.
`Persistent=true` covers a missed timer deadline after downtime, and the startup
gate independently rejects an already expired generation.

Hard preflight checks also require native Linux, rootful Podman 5.8 or newer,
host IPv4 forwarding, non-strict reverse-path filtering (`0` or `2`) on the
relevant paths, and the exact bound WireGuard peer map.

The declaration carries no Nord credential; the container references a
separately created rootful Podman secret. The image pins the NordVPN 5.2.0
package by content with fixed architecture-specific `.deb` SHA-256 values for
amd64 and arm64. Its C broker opens and validates the fixed root-owned CLI,
starts `nordvpn login --token` in a PTY with no credential in `argv` or the
environment, and waits for the exact prompt plus disabled `ECHO`/`ECHONL`.
Only then does it disable core dumps/process dumpability, open the fixed
root-only secret, forward and wipe the token, and discard child output. Prompt
drift fails before the secret is opened. Nord state is deliberately ephemeral,
so a replaced container performs a fresh login rather than reusing a state
volume. The base-image digest is syntactically pinned but still needs operator
provenance review.

Only one managed dependency drop-in exists at the fixed path
`50-short-circuit-nord-egress.conf`; generation cutover must replace it
atomically. Before removing an old guard, mask and stop the WireGuard unit,
stop/mask the previous generation, verify its preferred route and interface are
gone, and run that generation's explicit guard decommission. Install the new
root-owned generation and fixed drop-in, reload systemd, and only then unmask
and start WireGuard through systemd. The decommission script refuses cleanup
unless the WireGuard unit is masked and inactive and its interface and
preferred routes are absent.

The Quadlets contain no `[Install]` section, and rendering neither copies any
artifact to its mapped root-owned destination nor creates a secret, builds an
image, logs into Nord, starts a unit, changes a route, or tests live egress.
The Linux gateway boundary also does not install a persistent kill switch on an
authorized leaf. If that leaf's WireGuard interface is torn down, its ordinary
WAN route can return; end-to-end no-fallback therefore remains a native-Linux
gateway and leaf integration gate.

## Access Through the Tunnel

After connecting with a WireGuard client, the tunnel IP of the server host is
reachable for:

- **SMB**: `smb://<server-tunnel-ip>` (e.g. `smb://10.99.0.1`)
- **HTTPS**: private web UI, reverse proxy, or other HTTPS service
- **SSH**: `ssh user@<server-tunnel-ip>`

See `docs/access-modes.md` for detailed patterns per service type.

## Integration with Other Repos

- `./util-repos/snowbridge` uses this repo to establish the WireGuard tunnel
  used for remote SMB and HTTPS file-share access.
- `./util-repos/pit-box` will extend the SSH access patterns available through
  the tunnel.
- `./util-repos/traction-control` owns application-level writer fencing and
  replication policy; tunnel reachability is never treated as write leadership.
- `./util-repos/nordility` manages end-user Nord state. `short-circuit` only
  declares the optional Meshnet carrier and the isolated Linux NordVPN egress
  contract; it does not log a host into Nord or silently change its default
  route.

## Requirements

- Linux host with `bash` 4+, `systemctl`, and a supported package manager
  (`dnf`, `apt-get`, or `yum`).
- Root access for installation steps.
- `wireguard-tools` and `dnsmasq` (installed automatically if missing).
- `qrencode` for QR code export (installed automatically if requested).
- Temporary macOS private-underlay mode: Homebrew `wireguard-tools` and
  `wireguard-go`, with activation supervised through `sudo wg-quick`.
- NordVPN egress experiments: native Linux, rootful Podman 5.8 or newer,
  `/dev/net/tun`, `NET_ADMIN`, host IPv4 forwarding, non-strict `rp_filter`,
  a full runtime WireGuard peer map exactly matching every bound leaf public
  key and `/32`, and a locally created Podman secret.
  `scripts/setup_wireguard.sh` does not install this egress path.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q
bash tests/test_nord_token_login_podman.sh
```

The Podman test rebuilds the egress image from this checkout, exercises a
delayed-echo hostile CLI, and probes the exact no-echo prompt of the pinned real
NordVPN 5.2 package without reading a credential.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
