# short-circuit — Contributor Architecture Blueprint

## Repository Purpose

`short-circuit` is the portfolio-standard WireGuard VPN setup and configuration
utility. It provides a scriptable installer and profile-based configuration
templates for establishing private WireGuard tunnels that enable authenticated
SMB, HTTPS, and SSH access to a home host from mobile or remote clients.

## Architecture Overview

```
Profile Selection  ─────────────────────────────────────────────────
  wireguard-public-vpn (host-only)
  wireguard-lan-vpn    (host + full home LAN)
                          │
                          ▼
Config Templates (config/wireguard/)
  wg0-server.example.conf          ← server interface + peer section
  wg0-server.lan-vpn.example.conf
  client-peer.example.conf         ← client interface + peer section
  client-peer.lan-vpn.example.conf
                          │
                          ▼ --init-local-configs
Local Configs (gitignored *.local.conf)
  wg0-server.<profile>.local.conf
  client-peer.<profile>.local.conf
                          │
     ┌──────────────────┬─┘
     ▼                  ▼
Key Generation    Placeholder Validation
(wg genkey)       (fail on remaining <...>)
     │                  │
     └──────────────────┘
                          │
                          ▼ sudo
Installer (scripts/setup_wireguard.sh)
  install /etc/wireguard/wg0.conf (600)
  sysctl ip_forward drop-in (--enable-ip-forward)
  dnsmasq split-DNS helper (/etc/dnsmasq.d/)
  systemd dnsmasq drop-in (After=wg-quick@wg0)
  firewalld zone assignment (trusted by default)
  wg-quick@wg0 enable + start
                          │
                          ▼
Running WireGuard Tunnel
  SMB  ─ smb://10.99.0.1 or smb://<private-hostname>
  HTTPS─ https://<private-hostname>
  SSH  ─ ssh user@10.99.0.1
                          │
          (wireguard-lan-vpn only)
                          ▼
LAN Forwarding
  client reaches any LAN host via host as gateway
```

## Key Components

### scripts/setup_wireguard.sh

The generalized WireGuard installer. Orchestrates config initialization, key
generation, endpoint auto-fill, OS package installation, config deploy,
split-DNS setup, firewall assignment, and service lifecycle. Supports both
profiles through a `--profile` flag.

### config/wireguard/

Profile-based WireGuard configuration templates. Example configs use
`<placeholder>` syntax throughout. Local configs (gitignored `*.local.conf`)
are the runtime inputs for the installer.

### docs/setup-guide.md

Step-by-step walkthrough from profile selection through client connection
verification. Covers key generation, endpoint configuration, and QR import.

### docs/access-modes.md

Service-specific connection patterns for SMB, HTTPS, and SSH through the
WireGuard tunnel. Covers both public-vpn and lan-vpn routing scopes.

## Design Principles

1. **Profile-scoped templates**: two distinct named profiles with their own
   example and local config pairs prevent accidental config mixing.
2. **Gitignored local state**: all host-specific values (keys, endpoints, IPs)
   live in `*.local.conf` files that are never committed.
3. **Coherent key-pair generation**: the installer treats server/client keys as
   linked pairs and generates or derives both when one or both placeholders
   remain.
4. **Generic defaults**: no service-specific or deployment-specific hostnames
   are hardcoded; all names are set via `--dns-hostname` at install time.
5. **Layered access**: the WireGuard tunnel is transport-only; SMB, HTTPS, and
   SSH services run independently on the host and are not managed by this repo.

## Future Integration

`./util-repos/pit-stop` will extend the SSH access patterns available through
the WireGuard tunnel established by this repo, providing SSH key management,
bastion patterns, and host certificate workflows.

Last reviewed: `2026-04-01`
