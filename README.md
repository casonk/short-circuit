# short-circuit

WireGuard VPN setup and configuration utility for private remote access.

This repo lives under:

- `./util-repos/short-circuit`

## Purpose

- Provide a scriptable WireGuard installer that works across Fedora, Debian,
  and Ubuntu hosts.
- Maintain profile-based configuration templates for two common access patterns:
  host-only VPN and wider home-LAN routing.
- Enable authenticated SMB, HTTPS, and SSH access from mobile or remote clients
  through a private WireGuard tunnel.
- Keep all real keys, endpoints, and host-specific values outside git.

## Supported Profiles

| Profile | Client Reach | Use Case |
|---|---|---|
| `wireguard-public-vpn` | Host tunnel IP only | Reach SMB, HTTPS, SSH on the server host |
| `wireguard-lan-vpn` | Host + full home LAN | Reach any LAN device through the tunnel |

## Repository Layout

- `scripts/setup_wireguard.sh`: installer for either profile
- `config/wireguard/wg0-server.example.conf`: server config template (public-vpn)
- `config/wireguard/wg0-server.lan-vpn.example.conf`: server config template (lan-vpn)
- `config/wireguard/client-peer.example.conf`: client peer template (public-vpn)
- `config/wireguard/client-peer.lan-vpn.example.conf`: client peer template (lan-vpn)
- `docs/setup-guide.md`: step-by-step setup walkthrough
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the tunnel
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
- Assign the WireGuard interface to the `trusted` firewalld zone.
- Enable and start `wg-quick@wg0`.

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
- `./util-repos/pit-stop` will extend the SSH access patterns available through
  the tunnel.

## Requirements

- Linux host with `bash` 4+, `systemctl`, and a supported package manager
  (`dnf`, `apt-get`, or `yum`).
- Root access for installation steps.
- `wireguard-tools` and `dnsmasq` (installed automatically if missing).
- `qrencode` for QR code export (installed automatically if requested).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
