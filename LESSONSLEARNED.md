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
- Portfolio-general WireGuard/VPN installer and example conventions live in
  `traction-control/LESSONSLEARNED.md` (agents read it first); the entries here
  are repo-specific. Up-integrated from here: coherent key-pair generation,
  treating realistic sample values as incomplete config, routing-scope profile
  names, profile-specific local filenames, DNS resolver provisioning, and
  firewalld zone assignment.

### 2026-09-02 — Do not default WireGuard interfaces to firewalld trusted

- The `trusted` zone has an ACCEPT target and bypasses service allowlists.
- Default WireGuard installs to an explicit-service zone such as `wireguard`,
  then add only the services and ports peers require.

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

### 2026-08-05 — A temporary Mac hub needs a distinct identity and activation path

- Never copy an offline server's WireGuard private key or tunnel address onto a
  temporary laptop. Reserve a separate address slice, listener port, key pair,
  expiry, and ordered handback so both identities cannot become active by
  accident.
- Do not assume two macOS Network Extension VPN applications can form a nested
  underlay and overlay. When an existing private mesh tunnel must remain active,
  use a separately reviewed command-line `wireguard-go`/`wg-quick` session with
  narrow host routes, or move routed hub duties to native Linux.
- Prove that every selected leaf can keep the private underlay and command-line
  WireGuard overlay active simultaneously. An app-only client is not a valid
  recovery peer merely because it supports each VPN separately, and the inner
  UDP path is proven only by a handshake after the hub listener is active.
- Keep the first recovery phase host-only. A successful WireGuard handshake is
  transport evidence, not permission to enable forwarding, NAT, peer transit,
  or application write leadership.

### 2026-08-05 — Nord transport and Nord egress need separate policy fields

- Keep WireGuard as the mesh identity and authenticated transport. Nord
  Meshnet may be a per-link carrier, while NordVPN egress is an independent
  routing decision; using “Nord” for both hides materially different trust and
  failure boundaries.
- Scope full-tunnel egress to named leaves and make its DNS, IPv6 behavior,
  gateway platform, forwarding, NAT, and no-fallback requirements explicit.
  Rendering `0.0.0.0/0` is intent, not proof that a fail-closed gateway exists.
- Carry that authorization into every data-plane layer as the same leaf `/32`
  set. WireGuard peer `/32` cryptokey routing is the first anti-spoof boundary;
  container filtering and host policy routes must not widen it to the enclosing
  mesh subnet.
- Isolate NordVPN egress on native Linux or a rootful Linux network namespace.
  A temporary macOS hub without reviewed selective routing must remain
  host-only and cannot become an egress gateway merely because the Nord app is
  connected.

### 2026-08-06 — A fail-closed egress route needs one canonical mesh binding

- Make a dependent egress renderer consume the authoritative mesh declaration,
  not an independently maintained copy. Bind generation, cutover epoch, expiry,
  canonical-document hash, Linux gateway identity, WireGuard interface, public
  DNS, authorized leaf IDs, and their exact `/32`s into every staged generation.
- Do not combine peer transit and commercial VPN egress until a single policy
  can prove both safely. Blocking that combination is safer than allowing a
  broad overlay route to bypass an exact-source Internet-egress boundary.
- Install a terminal prohibit and nftables guard before WireGuard can accept
  authorized traffic, and keep that guard after the container stops. Add and
  remove only the preferred gateway route with the healthy container lifecycle;
  ordinary service teardown must not create a physical-WAN fallback window.
- Privileged units must consume root-owned staged scripts, bindings, and build
  context. A rendered unit that refers to a user-writable clone or ignored
  runtime directory crosses the trust boundary even if the generated text is
  otherwise correct.
- Verify host forwarding, non-strict reverse-path filtering, and one exact
  WireGuard peer `/32` per authorized leaf immediately before enabling the
  preferred route. Never silently mutate those host-global prerequisites.
- Gateway-side fail-closed policy is not a leaf-side kill switch. Bringing down
  an authorized leaf's WireGuard interface can restore its ordinary WAN route,
  so end-to-end no-fallback is not proven until native-Linux gateway tests and a
  persistent leaf policy have both passed.
- Pin the NordVPN package version and per-architecture package digest when the
  entrypoint depends on version-specific CLI behavior. Keep base-image digest
  provenance as a separate operator review instead of overstating a syntactic
  digest check.

### 2026-08-06 — Fail-closed routing needs a single supervised runtime lifecycle

- Bind every expected WireGuard leaf public key to its exact `/32`, then compare
  the complete runtime peer map for equality before egress routing. Address-only
  checks do not catch the wrong peer key, extra peers, or broad `AllowedIPs`.
- Keep interface-wide IPv4 and IPv6 terminal prohibit rules outside nftables in
  addition to the nft defense-in-depth policy. An nftables flush must not turn
  forwarded WireGuard traffic into physical-WAN fallback.
- Make the preferred route depend on both the healthy egress container and the
  systemd-managed WireGuard interface. Have the `wg-quick` drop-in pull the
  route service and perform a post-start peer-binding check so neither side can
  win a startup race.
- Declare raw `wg-quick`, `wg setconf`, and live peer mutation unsupported when
  the safety contract lives in systemd dependencies. A correct drop-in cannot
  protect an activation path that bypasses it.
- Use one fixed managed drop-in filename and replace it atomically at generation
  cutover. Mask and stop the old WireGuard and egress units before explicit old-
  guard decommission so two generation dependency graphs cannot coexist and the
  interface cannot race back during cleanup.
- When a pinned third-party CLI has a no-positional-secret terminal flow, use a
  fixed PTY broker: execute only the secret-free command, match the exact
  prompt, verify terminal echo is disabled, and only then disable dumps and
  open the secret. Bound the exchange, wipe it immediately, suppress all child
  output, and never fall back to a credential-bearing argument. A real pinned-
  package prompt probe belongs beside the adversarial mock regression.
- Count and stage every build input, including helper source, in the root-owned
  generation contract. Version pins are not content pins unless the downloaded
  package is also checked against an expected digest.
- Treat a bound UTC expiry as an enforced lifecycle fence, not documentation.
  Reject expired generations during guard startup/verification and also attach
  a persistent deadline timer to the systemd WireGuard unit. At expiry, stop
  WireGuard so its bound preferred route is removed while terminal prohibit
  state remains; retain the startup check for missed deadlines and clock-aware
  defense in depth.
- Make expiry readiness a hard, acyclic dependency: the WireGuard drop-in
  `Requires` and orders `After` the timer, while the timer is `BindsTo`/`PartOf`
  WireGuard without ordering itself after WireGuard. Symmetric ordering would
  create the very startup cycle that the expiry fence is meant to prevent.

### 2026-08-09 — Guest isolation is a transport boundary, not a WireGuard failure

- Sharing a WAN address or IP subnet does not prove local peer reachability.
  Access-point client isolation can discard the UDP packet before WireGuard can
  authenticate it; classify that WLAN separately from a trusted LAN.
- Do not disable guest isolation merely to reach a private hub. When the router
  cannot express a VLAN/firewall exception, keep the guest isolated and use one
  stable public/direct or opaque UDP relay endpoint across trusted Wi-Fi,
  isolated Wi-Fi, and off-site networks.
- A WireGuard peer has one current endpoint, not a priority-ordered failover
  list. Prefer a stable endpoint across network changes; treat private LAN paths
  as explicit optimizations and never label application-writer selection as
  network failover.
- Keep commercial VPN egress independent from roaming transport. In the
  outbound-only design, Nord may protect reviewed Linux egress but must not be
  silently selected as the phone-to-mesh carrier.
- Prefer one stable endpoint in one ordinary iPhone profile. An opaque relay can
  accept a client-facing port such as UDP 443 while the hub retains its local
  listener port, but the NATed hub must separately maintain an outbound relay
  client; a rendered declaration does not provision or prove that path.
- Define “works across networks” honestly: it covers Internet paths that permit
  outbound UDP to the selected endpoint, not captive portals before login,
  offline networks, or networks that block every usable outbound UDP port.

### 2026-08-27 — One mobile tunnel can use disjoint service peers without transit

- A replacement iOS profile can contain one temporary-mesh peer and one or
  more canonical service peers when every `AllowedIPs` entry is that peer's
  exact `/32`. Do not substitute the temporary mesh subnet, peer transit, a
  default route, or an application-writer choice for explicit service peers.
- Bind the temporary peer, client identity, generation, and expiry exactly to
  the active mesh declaration. Canonical peers must stay outside the temporary
  mesh subnet and remain independently reviewed endpoints.

### 2026-09-02 — Remote WireGuard config changes need a host-owned rollback guard

- Apply risky WireGuard config changes through a root-owned guard that
  snapshots the prior config before restart and schedules verification outside
  the SSH session. A foreground sleep loop is not a remote-access fail-safe.
- Judge success by a fresh peer handshake newer than the apply
  timestamp, not by `wg-quick` being active alone. If the deadline expires
  first, restore the prior config and restart WireGuard automatically.

### 2026-09-02 — Rollback guard units need per-rollout identity

- A systemd transient rollback guard should include the apply epoch or another
  rollout identifier in its unit name. A stable per-interface unit name can
  remain loaded after rollback and block the next corrected apply.
- If a prior timer fires early against newer metadata, it can report “pending”
  and exit without providing the intended deadline rollback, so the scheduling
  identity must bind to the rollout generation.

### 2026-09-02 — Confirm router forwarding against the current LAN address

- When a coherent WireGuard server/client config still produces no handshake
  from cellular, verify that the router forwards the public UDP port to the
  host's current LAN address. DHCP drift from one LAN address to another can
  silently leave the listener healthy but unreachable from outside.
- Use `tcpdump` on the WAN-facing interface while toggling a cellular client:
  packets arriving means debug keys/runtime WireGuard state; no packets means
  debug router forwarding, NAT, ISP, or upstream path first.
