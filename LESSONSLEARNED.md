# LESSONSLEARNED.md — short-circuit

> Purpose: record durable lessons that should change how future agents and
> contributors work in this repository.

## How To Use This File

- Read this file before repeating setup or design work.
- Keep entries concise and reusable.
- Do not use this file as a session log.

## Lessons

- Every simultaneously active WireGuard device needs its own private/public key
  pair and unique tunnel IP. Reusing one client identity across devices makes
  the server endpoint flap between their NAT mappings ("last packet wins"),
  causing intermittent disconnects that keepalive or MTU changes cannot fix.
- When splitting a shared identity, retain one device on the existing peer,
  generate new keys for the others, add distinct server peer entries, and
  require importing the new profiles; changing only client IP addresses leaves
  the key collision intact.
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

### 2026-06-21 — Placeholder validation should ignore documentation comments

- WireGuard sample configs can legitimately mention `<placeholder>` tokens in
  explanatory comment lines even after every runtime field has been filled in.
- Validation should scan active config statements, not comment prose, or the
  repo will reject valid client exports and installer runs with misleading
  "still contains placeholder values" errors.

### 2026-06-21 — A WireGuard installer must open the WAN-side UDP listen port

- Assigning `wg0` to a permissive internal firewalld zone is not sufficient for
  remote clients; the server's WAN-facing zone must also allow inbound UDP on
  the configured `ListenPort`.
- If the installer manages firewalld at all, it should manage both pieces:
  public ingress on the listen port and the interface-to-zone mapping for
  post-handshake traffic.

### 2026-06-25 — Fixed-port scan resistance needs a dual-forward migration

- Changing a WireGuard listen port requires coordinated updates to the server
  config, live listener, WAN firewalld rule, every client Endpoint, and the
  router port-forward.
- Prepare client profiles first, temporarily forward both old and new UDP
  ports, switch the host, confirm a fresh handshake, and only then remove the
  old router forward.
- Preflight the prepared Endpoint host against the current public IP or stable
  DNS name. Port migration can otherwise preserve a stale direct-IP endpoint
  and make a correct router/firewall cutover look broken.
- A non-default fixed port is defense-in-depth against opportunistic scans; it
  does not replace firewall allowlisting or mitigate volumetric DoS.

### 2026-06-25 — Do not default WireGuard interfaces to firewalld trusted

- The `trusted` zone has an ACCEPT target and bypasses service allowlists.
- Default WireGuard installs to an explicit-service zone such as `wireguard`,
  then add only the services and ports peers require.

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
