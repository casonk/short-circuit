# short-circuit — Contributor Architecture Blueprint

## Repository Purpose

`short-circuit` is the portfolio-standard WireGuard VPN setup and configuration
utility. It provides a scriptable installer and profile-based configuration
templates for establishing private WireGuard tunnels that enable authenticated
SMB, HTTPS, and SSH access to a home host from mobile or remote clients.

## Architecture Overview

```
Conventional Linux profiles
  config templates -> gitignored *.local.conf -> setup_wireguard.sh (root)
    -> /etc/wireguard/wg0.conf + dnsmasq + firewalld + wg-quick@wg0
    -> host-only services or explicitly configured home-LAN routing

Declarative recovery topology (separate render-only path)
  mesh.example.json (schema v2, generation zero is inert)
    -> gitignored mesh.local.json + one node-local private key
    -> render_wireguard_mesh.py
    -> owner-only <node-id>.conf + key-free manifest

  WireGuard identity/routing
    hub  10.99.0.254/32
    leaf 10.99.0.241/32–10.99.0.253/32
    per-leaf hub_transport
      direct            -> routable LAN/public/DNS WireGuard endpoint
      opaque-udp-relay  -> stable public opaque datagram forwarder
      nord-meshnet      -> RFC6598 endpoint; Nord is only an outer carrier

  Independent policy
    peer_transit false -> leaf routes hub /32 only
    peer_transit true  -> leaf routes recovery /28; activation still required
    egress disabled    -> no Internet route through hub
    egress nord-vpn    -> allowlisted leaves render defaults + DNS
      -> Linux hub required
      -> mutually exclusive with peer_transit
      -> render_nord_egress_container.py requires --mesh-config
      -> binds generation/epoch/expiry/hash/gateway/interface/DNS
         + full leaf public-key-to-exact-/32 map
      -> 15 inert artifacts, adding expiry stop/timer and C token helper
      -> persistent IPv4/IPv6 terminal guard before wg-quick/container
      -> route BindsTo healthy container and systemd wg-quick unit
      -> fixed managed drop-in verifies guard and runtime peers
      -> expires_at gates startup and schedules persistent wg-quick stop timer
      -> root-owned binding, scripts, services, drop-in, and build context
      -> isolated rootful Podman/NordLynx contract
      -> exact authorized leaf /32s only
      -> default-deny forwarding, NAT only on NordLynx, IPv6 blocked

  Roaming coverage (separate key-free policy)
    roaming-policy.example.json -> ignored roaming-policy.local.json
      + validated mesh generation/binding
      -> render_roaming_policy.py
      -> owner-only roaming-plan.json + roaming-plan.md
    lan-direct          -> trusted WLAN only
    public-direct       -> stable endpoint across declared network classes
    opaque-udp-relay    -> forwards encrypted datagrams; does not terminate WG
    stable-primary      -> one path must cover trusted/isolated/off-site
    Nord role           -> egress-only; never a roaming carrier

  access-bundle.example.json -> ignored access-bundle.local.json
    + active mesh declaration + existing leaf private key
      -> render_wireguard_access_bundle.py
      -> replacement iOS profile with one temporary hub and canonical exact-/32 peers

  No render path activates an interface, route, firewall, forwarding, NAT,
  systemd, Podman, Nord login, failover, or application writer leadership.
  The authorized leaf still needs a persistent local no-fallback policy.
```

## Key Components

### scripts/setup_wireguard.sh

The generalized WireGuard installer. Orchestrates config initialization, key
generation, endpoint auto-fill, client-config export, OS package installation,
config deploy, split-DNS setup, firewall assignment, and service lifecycle.
Supports both profiles through a `--profile` flag.

### scripts/check_wireguard_edge.sh

A read-only operator preflight for the public WireGuard edge. It compares the
server `ListenPort`, client `Endpoint`, detected public IPv4, and current host
LAN IPv4, then prints the router UDP forward that must exist. With
`--expected-router-target`, DHCP drift or a stale router rule fails before a
remote-only maintenance window.

### scripts/guarded_wireguard_rollout.sh

A root-run config applicator for remote-safe WireGuard changes. It snapshots
the active `/etc/wireguard/<interface>.conf`, stores owner-only rollback state
under `/var/lib/short-circuit/wireguard-rollout/`, installs a candidate config,
restarts `wg-quick@<interface>`, and arms a transient `systemd-run` verification
outside the operator's SSH session. Success requires a selected peer to record a
fresh handshake after the apply epoch; timeout restores the previous config and
restarts WireGuard. Immediate `wg-quick` restart failure also restores the prior
config before returning. The `--arm-guard` mode rehydrates pending metadata to
schedule the same timestamp-bound guard when an apply succeeded but timer
creation failed.

### scripts/render_wireguard_mesh.py

A fail-closed, render-only tool for the temporary topology. Schema v2 validates
the fixed recovery identity plan, node platforms, manual cutover and expiry,
per-leaf `direct`, `opaque-udp-relay`, or `nord-meshnet` transport, optional
peer transit, and explicit `disabled` or `nord-vpn` egress. It renders only the
requested node. A private direct or Nord endpoint retains the mesh listen port;
a public mapping or opaque relay may expose another canonical UDP port. The
`<node-id>.conf` is owner-only secret material; the adjacent `manifest.json`
and stdout contain no private key or secret-derived digest.

For authorized NordVPN-egress leaves, the WireGuard file contains default
routes, IPv6 capture, and the declaration's DNS servers. For the Linux hub,
the manifest reports required forwarding, NAT, and fail-closed policy. Peer
transit and NordVPN egress are rejected together. Those are requirements, not
performed actions: the renderer never changes a tunnel, route, firewall,
forwarding, NAT, launchd, systemd, Podman, or Nord state.

The mesh renderer itself remains inactive, but `expires_at` is not advisory for
a bound Linux Nord egress generation: the dependent renderer turns it into a
UTC startup gate and a persistent systemd expiry timer.

The loader continues to validate schema-v1 documents and normalizes them to v2
in memory. RFC6598 legacy endpoints map to `nord-meshnet`; other previously
accepted private endpoints map to `direct`; peer transit and egress remain
disabled. The CLI warns and does not rewrite the private source.

### scripts/render_roaming_policy.py

A separate fail-closed policy validator classifies `trusted-wlan`,
`isolated-wlan`, and `offsite` without changing the schema-v1/v2 mesh renderer
or its Nord-egress binding. It consumes the authoritative mesh declaration,
checks the expected mesh generation and hub identity, and embeds the canonical
mesh hash/binding in an owner-only, key-free decision plan.

`lan-direct` accepts only a private literal endpoint and only the trusted WLAN
class. `public-direct` and `opaque-udp-relay` require a global address or
canonical DNS endpoint; their reviewed client-facing NAT/relay port may differ
from the mesh listen port, while `lan-direct` must match it. Nord is fixed to
`egress-only`. The initial
`stable-primary` strategy does not model a WireGuard endpoint list: one selected
path must cover all required classes. `audit-only` reports gaps; `required`
fails closed when coverage is incomplete or the primary kind/endpoint differs
from a mesh leaf's declared transport. `lan-direct` and `public-direct` align
with mesh `direct`; `opaque-udp-relay` aligns with the same mesh transport mode.
One aligned stable endpoint leaves the standard iPhone profile unchanged across
network transitions. The plan still records reachability and profile updates
as false. Rendering performs no router, DNS, WireGuard, iOS On-Demand, route,
firewall, relay provisioning, or Air-side outbound relay-client action. Public
ingress remains default-deny except for the reviewed WireGuard UDP port, with
management protected separately. The network coverage claim excludes captive,
offline, and all-UDP-blocked paths.

### config/wireguard/

Profile-based WireGuard configuration templates. The conventional `.conf`
examples use `<placeholder>` syntax. The schema-v2 mesh JSON example is a
generation-zero declaration with no nodes, endpoints, or keys, with transit
and egress disabled. The roaming-policy JSON example is likewise inert and
contains no endpoint or SSID. Local configs (`*.local.conf`,
`mesh.local.json`, `roaming-policy.local.json`, and `mesh.local.d/`) are
gitignored runtime inputs and outputs.

### scripts/render_nord_egress_container.py and containers/nord-egress/

The Python renderer accepts an owner-only, credential-free schema-v1 contract
under ignored `runtime/`. Generation zero is inert. An enabled validation or
render requires `--mesh-config`, loads that declaration through the
authoritative mesh validator, and creates a canonical binding containing the
generation, cutover epoch, expiry, normalized-document SHA-256, Linux gateway
address and public key, WireGuard interface, public DNS, authorized leaf IDs,
exact sorted `/32`s, and the full expected WireGuard leaf public-key→`/32`
map. The egress declaration's generation, subnet, interface, and `/32` list
must match; peer transit must remain false.

An enabled generation targets native Linux, rootful Podman 5.8 or newer,
`/etc/containers/systemd`, an isolated `/29` or `/30` bridge, the fixed
file-mounted Podman-secret target, fail-closed mode, no CRUD leadership, and
disabled/dropped IPv6. `mesh_source_subnet` is validation context, not
authorization. The container's bootstrap DNS comes only from the bound mesh.

Rendering produces 15 owner-only, generation-scoped staging artifacts:

- three Quadlets (`.build`, `.network`, and `.container`);
- a persistent host-guard script and service;
- a container-lifecycle preferred-route script and service;
- a `wg-quick` dependency drop-in;
- an expiry-stop service and persistent expiry timer;
- the mesh binding;
- a staged `Containerfile`, entrypoint, and C token-login helper; and
- the install manifest.

The install map targets `/etc/containers/systemd`, `/etc/systemd/system`, and a
generation-specific root-owned directory under `/etc/short-circuit/nord-egress`.
Root units never refer to the user-writable repository or ignored output tree.
The Quadlets have no `[Install]` section and remain outside systemd’s search
path. The renderer does not create the Podman secret, pull/build the image,
install/start a unit, log into Nord, or change a host route.

The staged build context supplies an isolated Linux NordLynx egress namespace.
It content-pins NordVPN 5.2.0 with fixed amd64/arm64 `.deb` SHA-256 values. The
Ubuntu base uses a syntactically pinned digest whose provenance still requires
operator review. The entrypoint requires root, `/dev/net/tun`, `NET_ADMIN`, the
Podman secret mounted at the fixed token path, the exact authorized `/32` set,
fail-closed mode, no CRUD leadership, and IPv6 disabled/dropped. It admits
forwarded IPv4 only from those addresses and only to `nordlynx`, permits only
established return traffic, and masquerades only on that interface. Loss of
NordLynx leaves the forward policy default-deny.

The pinned NordVPN 5.2 CLI supports a secret-free `nordvpn login --token`
invocation. The C broker opens the validated CLI into a PTY, requires its exact
prompt and disabled terminal echo, and only then disables dumps, opens the
fixed root-owned secret, forwards/wipes it, and suppresses child output. No
credential appears in `argv` or the environment, and there is no fallback when
the prompt contract drifts. The helper source is staged so the root-owned build
context is complete and reviewable; Nord runtime state remains ephemeral.

WireGuard’s per-peer `/32` entries are the first cryptokey-routing anti-spoof
boundary. The route verifier compares the complete runtime `wg show ...
allowed-ips` map against every mesh-bound leaf public-key→exact-`/32` pair;
broad, missing, extra, and mismatched peer entries all fail.

The rendered host guard binds source rules to the WireGuard input interface,
establishes an IPv4 terminal prohibit route plus interface-wide IPv4 and IPv6
prohibit rules, and isolates the bridge in nftables. The policy rules survive
an nftables flush, so loss of the nft table cannot expose an ordinary-WAN
fallback. It is required before both `wg-quick` and the container and has no
automatic `ExecStop`; explicit decommission refuses to remove it while
WireGuard or preferred routes remain.

The route service is `BindsTo`/`After` the healthy container, its network, and
the systemd `wg-quick@` unit. The fixed managed `wg-quick` drop-in requires and
verifies the guard, wants the route service, hard-requires/orders itself after
the expiry timer, and performs complete runtime identity verification in
`ExecStartPost`, including the gateway public key, listen port, exact single
IPv4 address, absence of global IPv6, and complete peer map. `ExecStopPost`
forces `wg-quick down` after any failed start. Before adding a preferred route,
hard assertions also verify
rootful Linux, Podman 5.8+, host IPv4 forwarding, and non-strict `rp_filter`.
Stopping either WireGuard or the container removes only the preferred route;
terminal rules remain.

Expiry has two enforcement points. Guard installation/verification compares
the current UTC epoch with the bound `expires_at` and rejects an expired
generation at startup. The persistent expiry timer is
`BindsTo`/`PartOf` the WireGuard unit and schedules the exact bound UTC deadline.
It deliberately has no reverse `After=wg-quick@` edge; the WireGuard drop-in is
instead `Requires`/`After` the timer, making expiry readiness a hard startup
invariant without a dependency cycle. Its `RefuseManualStart` stop service
stops WireGuard when the timer fires; route teardown follows through `BindsTo`,
while the terminal guard persists. The timer catches missed deadlines after
downtime, and the startup gate remains an independent fence.

This is a systemd-only activation contract. Raw `wg-quick up`, `wg setconf`,
or live `wg` peer mutation bypasses the dependency and verification hooks and
is unsupported. The single fixed
`50-short-circuit-nord-egress.conf` drop-in must be atomically replaced during
generation cutover. The old WireGuard unit and generation services are masked
and stopped before the old guard's explicit decommission; cleanup verifies the
unit is masked/inactive, the interface is absent, and no preferred route
remains. Rendered artifacts remain inert until an operator performs that
reviewed cutover and completes native-Linux traffic tests.

This protects traffic after it enters the mesh; it is not a persistent leaf-
side kill switch. Tearing down an authorized leaf's WireGuard interface can
restore its ordinary WAN route, so end-to-end no-fallback remains an explicit
leaf integration gate.

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
unavailable. It covers fresh identity generation; direct, opaque public UDP
relay, and Nord Meshnet-carried endpoints; external handshake checks; key-safe
config handling; explicit expiry; and ordered handback. The Mac is a reachable
application host, not a transit router, NordVPN egress gateway, or failover
elector.

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
9. **Transport/egress separation**: WireGuard is always the authenticated mesh
   transport. Nord Meshnet may carry its UDP packets; NordVPN egress is a
   distinct, allowlisted Linux routing policy.
10. **Fail-closed egress**: declaring full-tunnel routes is not enough. The
    gateway needs isolated forwarding, Nord-only NAT, IPv6 blocking, DNS
    control, a persistent terminal guard, a container-lifecycle preferred route,
    and deliberate outage testing. Gateway protection does not replace a
    persistent leaf-side no-fallback policy.
11. **Runtime identity equality**: source-address filters are insufficient on
    their own. Before egress routing, the complete WireGuard runtime peer map
    must exactly equal the bound public-key→`/32` generation.
12. **One supervised lifecycle**: fail-closed dependencies are effective only
    through systemd. Generation cutover atomically replaces the fixed managed
    drop-in and decommissions the masked, stopped prior generation before the
    new unit can start.
13. **Stable endpoint before optimization**: roaming is reliable only when one
    public/direct or opaque relay path remains reachable across trusted,
    isolated, and off-site networks. Keep guest isolation enabled and treat
    private LAN paths as local-only optimizations, not fallback coverage.

## Future Integration

`./util-repos/pit-box` will extend the SSH access patterns available through
the WireGuard tunnel established by this repo, providing SSH key management,
bastion patterns, and host certificate workflows.

Last reviewed: `2026-08-09`
