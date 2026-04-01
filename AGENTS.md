# AGENTS.md — short-circuit

> Scope: this file governs agent and contributor behavior for this repository.

Portfolio-wide standards live in `./util-repos/traction-control` from the
portfolio root. This repository is `./util-repos/short-circuit`.

## Repository Purpose

`short-circuit` is the portfolio-standard WireGuard VPN setup and configuration
utility. It provides a scriptable installer and profile-based configuration
templates for establishing private WireGuard tunnels that enable authenticated
SMB, HTTPS, and SSH access to a home host from mobile or remote clients.

The two supported access profiles are:

- `wireguard-public-vpn`: tunnel to the host only; the client reaches the host
  IP and services running on it
- `wireguard-lan-vpn`: tunnel that also routes the wider home LAN subnet through
  the host; the client reaches any LAN device

## Shared Portfolio References

- `./util-repos/traction-control`: portfolio-wide standards and repo baseline
- `./util-repos/archility`: standard architecture bootstrap and render tooling
- `./util-repos/auto-pass`: standard password-management utility repo
- `./util-repos/nordility`: standard VPN-switching utility repo
- `./util-repos/shock-relay`: standard external-messaging utility repo
- `./util-repos/snowbridge`: standard SMB-based file-sharing and phone-access
  utility repo

## Session Continuity

- Read `AGENTS.md`, `LESSONSLEARNED.md`, and local-only `CHATHISTORY.md` before
  making substantive repo changes.
- Update local-only `CHATHISTORY.md` after meaningful work.
- Add durable operational guidance to `LESSONSLEARNED.md` when a lesson should
  change future behavior.

## Key Files

- `README.md`
- `scripts/setup_wireguard.sh`: generalized WireGuard installer
- `config/wireguard/wg0-server.example.conf`: server config template
- `config/wireguard/wg0-server.lan-vpn.example.conf`: lan-vpn server template
- `config/wireguard/client-peer.example.conf`: client peer template
- `config/wireguard/client-peer.lan-vpn.example.conf`: lan-vpn client template
- `docs/setup-guide.md`: step-by-step WireGuard setup walkthrough
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the tunnel
- `docs/contributor-architecture-blueprint.md`
- `docs/diagrams/repo-architecture.puml`
- `docs/diagrams/repo-architecture.drawio`

## Operating Rules

1. This repo manages WireGuard tooling and configuration templates only. It does
   not manage the services accessed through the tunnel (Samba, Caddy, sshd).
2. Never commit real private keys, pre-shared keys, or actual endpoint hostnames
   or IP addresses.
3. Keep committed config examples generically useful across deployments. Actual
   host values belong in gitignored `*.local.conf` files.
4. When changing the script or config templates, update `docs/setup-guide.md`
   and the architecture docs in the same change.
5. Do not recommend exposing wireguard peer traffic directly to the public
   internet without firewall filtering.
6. Use Conventional Commits for any git history you create.

## Future Integration

`pit-stop` will later provide deeper SSH-specific functionality that complements
the WireGuard tunnel established by this repo.

Last reviewed: `2026-04-01`
