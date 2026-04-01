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
4. Configure a `systemd` drop-in so `dnsmasq` waits for the WireGuard interface.
5. Assign the WireGuard interface to the `trusted` firewalld zone (if `firewalld`
   is active).
6. Enable and start `wg-quick@wg0`.
7. Print an ANSI QR code for the client peer config.

### Key Installer Flags

| Flag | Purpose |
|---|---|
| `--dns-hostname HOST` | Private hostname the DNS helper resolves to the server tunnel IP |
| `--generate-missing-keys` | Auto-fill placeholder key pairs before installing |
| `--enable-ip-forward` | Write a sysctl drop-in enabling IPv4/IPv6 forwarding (required for `wireguard-lan-vpn`) |
| `--skip-dns` | Do not install the dnsmasq split-DNS helper |
| `--skip-firewall` | Do not update firewalld |
| `--skip-start` | Install config without enabling or starting WireGuard |
| `--print-client-qr` | Print ANSI QR for client peer config |
| `--qr-output PATH` | Write PNG QR for client peer config |

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

## 4. Import Client Config

After the installer prints the QR code, import it on the client device:

- **iOS/Android**: open the WireGuard app and tap the `+` to scan the QR code.
- **macOS/Windows**: use the WireGuard desktop app to import the `.conf` file.
- Or transfer `config/wireguard/client-peer.public-vpn.local.conf` securely.

## 5. Verify the Connection

On the server:

```bash
sudo wg show wg0
sudo systemctl status wg-quick@wg0.service
sudo systemctl status dnsmasq.service
sudo firewall-cmd --zone=trusted --list-all
```

From the connected client, try:

- **Ping**: `ping 10.99.0.1`
- **SMB**: mount `smb://10.99.0.1` or `smb://<private-hostname>`
- **SSH**: `ssh user@10.99.0.1`

See `docs/access-modes.md` for service-specific connection details.
