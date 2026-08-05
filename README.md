# short-circuit

WireGuard VPN setup and configuration utility for private remote access.

This repo lives under:

- `./util-repos/short-circuit`

## Purpose

- Provide a scriptable WireGuard installer that works across Fedora, Debian,
  and Ubuntu hosts.
- Maintain profile-based configuration templates for two common access patterns:
  host-only VPN and wider home-LAN routing.
- Document a supervised, temporary macOS host-only hub for recovery periods;
  it is not a routed or automatically failing-over replacement for the Linux
  server.
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
- `scripts/render_wireguard_mesh.py`: fail-closed temporary-mesh renderer
- `config/wireguard/wg0-server.example.conf`: server config template (public-vpn)
- `config/wireguard/wg0-server.lan-vpn.example.conf`: server config template (lan-vpn)
- `config/wireguard/client-peer.example.conf`: client peer template (public-vpn)
- `config/wireguard/client-peer.lan-vpn.example.conf`: client peer template (lan-vpn)
- `config/wireguard/mesh.example.json`: synthetic temporary-mesh declaration
- `docs/setup-guide.md`: step-by-step setup walkthrough
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the tunnel
- `docs/temporary-macos-hub.md`: fenced temporary laptop-hub runbook
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
- Assign the WireGuard interface to the `trusted` firewalld zone.
- Enable and start `wg-quick@wg0`.

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
a **host-only** WireGuard peer under manual supervision. Use a fresh identity
and the reserved temporary range (`10.99.0.241`–`10.99.0.254`); never reuse the
home server's key or `10.99.0.1` address.

This recovery mode provides access only to deliberately exposed services on
the laptop. It does not enable forwarding, NAT, home-LAN access, peer-to-peer
transit, Podman bridging, or automatic failover. See
[docs/temporary-macos-hub.md](docs/temporary-macos-hub.md) for private-underlay
activation, deferred public double-NAT considerations, external validation,
expiry, and handback. An active Nord private underlay uses the
supervised `wireguard-tools`/`wireguard-go` path. A direct public endpoint with
WireGuard.app is a separately reviewed future/manual mode, is not emitted by
the current renderer, and leaves the existing app tunnel untouched.

Start from an inert, gitignored declaration; rendering does not activate it:

```bash
python3 scripts/render_wireguard_mesh.py init
python3 scripts/render_wireguard_mesh.py generate-key --node-id temp-mac-hub
```

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

## Requirements

- Linux host with `bash` 4+, `systemctl`, and a supported package manager
  (`dnf`, `apt-get`, or `yum`).
- Root access for installation steps.
- `wireguard-tools` and `dnsmasq` (installed automatically if missing).
- `qrencode` for QR code export (installed automatically if requested).
- Temporary macOS private-underlay mode: Homebrew `wireguard-tools` and
  `wireguard-go`, with activation supervised through `sudo wg-quick`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
