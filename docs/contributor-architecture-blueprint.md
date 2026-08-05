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
  mesh.example.json                ← synthetic temporary-hub declaration
                          │
                          ▼ --init-local-configs
Local Configs (gitignored *.local.conf)
  wg0-server.<profile>.local.conf
  client-peer.<profile>.local.conf
                          │
     ┌──────────────────┬─────────────────────┐
     ▼                  ▼                     ▼
Key Generation    Placeholder Validation   Client Export
(wg genkey)       (fail on remaining       (.conf handoff,
                   <...>)                   optional QR)
     │                  │                     │
     └──────────────────┴─────────────────────┘
                          │
                          ▼ sudo
Installer (scripts/setup_wireguard.sh)
  install /etc/wireguard/wg0.conf (600)
  sysctl ip_forward drop-in (--enable-ip-forward)
  dnsmasq split-DNS helper (/etc/dnsmasq.d/)
  systemd dnsmasq drop-in (After=wg-quick@wg0)
  firewalld WAN-port allow (udp/ListenPort on public by default)
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

Temporary macOS Recovery Path (separate, host-only)
  mesh.example.json -> mesh.local.json (generation zero is inert)
  node-local key -> render_wireguard_mesh.py -> <node-id>.conf (0600)
  fresh identity at 10.99.0.254/32
  temporary peers at 10.99.0.241/32–10.99.0.253/32
  active Nord underlay -> supervised wireguard-tools/wireguard-go
  direct LAN/public endpoint -> deferred review; not renderer output
  no forwarding, NAT, peer transit, LAN routes, or automatic failover
  explicit expiry -> fence laptop -> restore canonical 10.99.0.1
```

## Key Components

### scripts/setup_wireguard.sh

The generalized WireGuard installer. Orchestrates config initialization, key
generation, endpoint auto-fill, client-config export, OS package installation,
config deploy, split-DNS setup, firewall assignment, and service lifecycle.
Supports both profiles through a `--profile` flag.

### scripts/render_wireguard_mesh.py

A fail-closed, render-only tool for the temporary private-underlay topology. It
initializes an inert local declaration, generates one node-local WireGuard key
pair, validates manual-static cutover/expiry/address constraints, and renders
only the requested node. Its `<node-id>.conf` is owner-only secret material;
the adjacent `manifest.json` and stdout contain no private key or
secret-derived digest. Rendering never activates a tunnel or writes firewall,
forwarding, NAT, launchd, systemd, or Podman configuration.

### config/wireguard/

Profile-based WireGuard configuration templates. The conventional `.conf`
examples use `<placeholder>` syntax. The mesh JSON example is a generation-zero
declaration with no nodes, endpoints, or keys. Local configs (`*.local.conf`,
`mesh.local.json`, and `mesh.local.d/`) are gitignored runtime inputs and
outputs.

### docs/setup-guide.md

Step-by-step walkthrough from profile selection through client connection
verification. Covers key generation, endpoint configuration, desktop export,
QR import, and the paired Apple mTLS profile flow from `wiring-harness`.

### docs/access-modes.md

Service-specific connection patterns for SMB, HTTPS, and SSH through the
WireGuard tunnel. Covers both public-vpn and lan-vpn routing scopes.

### config/wireguard/mesh.example.json

Synthetic, inactive declaration for a temporary macOS host-only hub. It
reserves a distinct address slice within `10.99.0.0/24` and contains no usable
endpoint or key material. The corresponding gitignored private declaration
records the underlay choice and lifecycle fence.

### docs/temporary-macos-hub.md

Manual recovery runbook for using a laptop while the canonical Linux server is
unavailable. It covers fresh identity generation, the command-line path over a
private underlay, deferred app/direct-endpoint considerations, external
handshake checks, key-safe config handling, explicit expiry, and ordered
handback. The Mac is a reachable application host, not a transit router or
failover elector.

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
6. **Unique recovery identity**: a temporary listener gets a fresh key and
   non-colliding `/32`; it never impersonates the canonical home server.
7. **No reachability-based leadership**: tunnel availability does not grant an
   application write lease. ACID/quorum fencing remains in the application and
   orchestration layers.
8. **Explicit recovery lifecycle**: temporary activation is supervised and
   time-bounded, and handback deactivates/fences the laptop before restoring the
   canonical server.

## Future Integration

`./util-repos/pit-box` will extend the SSH access patterns available through
the WireGuard tunnel established by this repo, providing SSH key management,
bastion patterns, and host certificate workflows.

Last reviewed: `2026-08-05`
