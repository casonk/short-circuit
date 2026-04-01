# LESSONSLEARNED.md — short-circuit

> Purpose: record durable lessons that should change how future agents and
> contributors work in this repository.

## How To Use This File

- Read this file before repeating setup or design work.
- Keep entries concise and reusable.
- Do not use this file as a session log.

## Lessons

- Document the repository around its real execution, curation, or integration flow instead of only the top-level folder list.
- Keep local-only, private, reference-only, or generated boundaries explicit so published or runtime behavior is not confused with offline material or non-committable inputs.
- Re-run repo-appropriate validation after changing generated artifacts, diagrams, workflows, or other CI-facing files so formatting and compatibility issues are caught before push.

### 2026-04-01 — WireGuard peer templates should generate missing key pairs coherently

- The server private key and the client public key form one pair, and the
  client private key and the server public key form the other.
- When both placeholders for a pair are still present, the setup script should
  generate and write a coherent pair automatically instead of failing on a
  missing key the repo is already in a position to create.

### 2026-04-01 — Setup scripts should treat checked-in sample values as incomplete config

- Generic placeholder detection is not enough when an example uses a realistic
  sample value such as `vpn.example.com:51820`.
- If a sample value would still produce a syntactically valid but unusable
  config, the setup script should fail with a targeted message instead of
  quietly proceeding or exporting a misleading client artifact.
- When there is a safe mechanical fallback, such as substituting the current
  public IP for a still-sample VPN endpoint, the script can apply it
  automatically but should still warn that a stable endpoint is the better
  final state.

### 2026-04-01 — VPN profile names should describe routing scope, not just transport

- A single generic WireGuard example blurs together two materially different
  setups: host-only access and wider home LAN routing.
- Prefer explicit repo profiles (`wireguard-public-vpn` vs `wireguard-lan-vpn`)
  so the intended AllowedIPs, forwarding requirements, and firewall expectations
  are visible at the template and installer level.

### 2026-04-01 — Multiple local profiles need distinct local filenames

- If two profiles share the same ignored local config paths, initializing the
  second profile silently overwrites the first profile's local state.
- Default local filenames should be profile-specific so users can keep both
  variants ready at once.

### 2026-04-01 — If a VPN profile advertises DNS, the installer should actually provide it

- Advertising a DNS server IP in the WireGuard client profile is not enough on
  its own; the repo also needs to configure a resolver on that tunnel address.
- For private hostname access, prefer a small split-DNS helper over teaching
  clients to browse the raw tunnel IP.
- On firewalld-based systems, the VPN interface itself needs an explicit zone
  assignment; otherwise some services may silently fail because the default zone
  does not allow them.
