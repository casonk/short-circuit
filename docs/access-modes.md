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

## Future: SSH In Depth

`./util-repos/pit-box` will provide deeper SSH-specific functionality layered
on top of the WireGuard tunnel established by this repo, including SSH key
management, bastion patterns, and host certificate workflows.
