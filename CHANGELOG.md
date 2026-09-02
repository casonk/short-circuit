# CHANGELOG.md — short-circuit

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--arm-guard` can recreate the timestamped rollback timer for an already-applied pending WireGuard rollout.
- Guarded WireGuard rollback timer units now include the apply epoch so stale transient timers cannot block a later corrected rollout.
- Guarded WireGuard rollout state now archives completed or rolled-back metadata before starting the next apply, so a manual rollback does not block a corrected rollout.
- `scripts/guarded_wireguard_rollout.sh`: apply reviewed WireGuard
  candidate configs with root-owned rollback state, a 30-minute systemd guard,
  fresh-peer-handshake verification, and immediate restore when `wg-quick`
  rejects the candidate.
- Initial repository created from WireGuard tooling abstracted out of
  `snowbridge`.
- `scripts/setup_wireguard.sh`: generalized WireGuard installer supporting
  `wireguard-public-vpn` and `wireguard-lan-vpn` profiles, auto key generation,
  split-DNS helper installation, firewalld integration, and client QR export.
- `config/wireguard/`: generic server and client peer config templates for both
  profiles.
- `docs/setup-guide.md`: step-by-step WireGuard setup walkthrough.
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the
  WireGuard tunnel.
- Render-only, owner-only temporary macOS hub declarations with fresh per-node
  keys, private-underlay validation, narrow `/32` routes, 31-day expiry,
  duplicate-key rejection, generation-scoped artifacts, and manual handback
  fencing.
- Schema-v2 recovery declarations that keep WireGuard independent from Nord:
  per-leaf direct or Nord-Meshnet-carried hub endpoints, optional peer transit,
  explicit allowlisted NordVPN egress intent, public IPv4 DNS selection, and a
  mandatory IPv6 block until routed IPv6 is supported. Schema-v1 declarations
  remain readable through warning-backed, in-memory normalization only.
  Peer transit and NordVPN egress are mutually exclusive in the current
  fail-closed policy.
- An owner-only renderer plus isolated Linux/rootful-Podman NordLynx egress
  image contract. Active validation and rendering require the authoritative
  WireGuard declaration via `--mesh-config` and bind the generation, cutover
  epoch, expiry, canonical-document SHA-256, Linux gateway, interface, public
  DNS, and exact authorized leaf IDs and `/32`s.
- Three inert Quadlets plus a persistent host guard, container-bound preferred-
  route lifecycle, `wg-quick` dependency drop-in, mesh-binding record, staged
  build context, expiry stop/timer, and fixed root-owned install map. The
  complete staging set is 15 artifacts, including a C token-login helper. Hard
  preflight assertions cover native Linux, rootful Podman 5.8+, `/dev/net/tun`,
  IPv4 forwarding,
  non-strict reverse-path filtering, and exact equality between all bound leaf
  public-key→`/32` pairs and the runtime WireGuard peer map. Rendering installs
  or activates none of them.
- A NordVPN 5.2.0 image contract with pinned amd64/arm64 `.deb` SHA-256 values,
  file-mounted secret tokens, exact authorized leaf `/32` sources, default-deny
  forwarding, Nord-only NAT, namespace-local IPv4 forwarding, IPv6
  disable/drop, and no CRUD leadership. The Linux gateway boundary is not a
  persistent leaf-side kill switch; teardown of a leaf WireGuard interface can
  restore its ordinary WAN path, so live end-to-end no-fallback testing remains
  an explicit native-Linux and leaf integration gate.
- Interface-wide IPv4 and IPv6 terminal prohibit rules that remain effective
  after an nftables flush, plus an IPv4 terminal prohibit route and exact-source
  lookup/prohibit pairs. The preferred route unit is bound to both the healthy
  Nord container and systemd `wg-quick@` lifecycle.
- A fixed managed `wg-quick` drop-in that requires/verifies the persistent
  guard, wants the route service, hard-requires/orders itself after the expiry
  timer, and checks the complete WireGuard peer map in `ExecStartPost`. Raw
  `wg-quick`/`wg setconf` activation is unsupported; generation cutover
  atomically replaces the drop-in and masks/stops the prior generation before
  explicit guard decommission.
- A content-pinned Nord package download and bounded C PTY broker that executes
  `nordvpn login --token` without a positional credential, waits for the exact
  prompt and disabled terminal echo, and only then disables dumps, reads the
  root-only secret, forwards/wipes it, and suppresses all child output.
- Container regressions for a delayed-echo hostile CLI and for the exact prompt
  and no-echo state of the pinned real NordVPN 5.2.0 package.
- Runtime expiry enforcement for bound egress generations: a UTC startup gate
  rejects expired guard installation/verification, while a persistent systemd
  timer bound to/part of `wg-quick@` stops WireGuard at the exact `expires_at`
  deadline. WireGuard requires/orders after the timer; the timer has no reverse
  ordering edge. Route teardown follows the WireGuard binding and terminal
  protection remains.
- Portfolio governance baseline: `AGENTS.md`, `LESSONSLEARNED.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `.editorconfig`,
  `.pre-commit-config.yaml`, and GitHub templates.
