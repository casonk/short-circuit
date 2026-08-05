# Temporary macOS WireGuard Hub

This runbook describes a temporary, host-only WireGuard listener on a MacBook
while the canonical home server is unavailable. In WireGuard terms the laptop
is still a peer; "hub" describes the temporary connection shape, not a special
WireGuard server role.

This phase intentionally does **not** make the laptop a router. A connected
peer can reach services explicitly running on the laptop at `10.99.0.254`, but
cannot reach another WireGuard peer, the home LAN, a Podman bridge, or the
Internet through the laptop.

The committed declaration in
[`../config/wireguard/mesh.example.json`](../config/wireguard/mesh.example.json)
is synthetic and inactive. Put the real endpoint, public keys, and expiry in a
gitignored local declaration; record operational ownership in the private
handoff log. CLI mode also needs a gitignored, owner-only source-key file. Both
that file and the rendered `.conf` contain a private key and must remain mode
`0600` in a protected local directory; an approved secret store may be used
for custody outside the active session.

## Safety Contract

- Generate a fresh laptop key pair. Never copy the offline home server's
  private key onto the laptop.
- Preserve `10.99.0.1/32` for the canonical home server. The temporary epoch
  uses `10.99.0.240/28`: `.254` for the laptop and `.241` through `.253` for
  temporary peers. Each peer owns exactly one `/32`.
- Give remote peers only `10.99.0.254/32` in `AllowedIPs`. Do not advertise
  `10.99.0.0/24`, a home-LAN subnet, or `0.0.0.0/0` during this phase.
- Leave IPv4/IPv6 forwarding and NAT disabled. Do not add `pf` forwarding or
  NAT rules and do not bind the tunnel to a Podman bridge.
- Keep activation manual and supervised in one of the two modes below. Do not
  add a login item, launch daemon, health-triggered takeover, or automatic
  failover.
- Set a real UTC expiry in the private declaration and calendar. Expiry is a
  stop condition, not an automatic extension. Schema v1 limits an active
  declaration to 31 days from validation time.
- Treat application write leadership separately from tunnel reachability.
  WireGuard can authenticate and carry packets; it cannot provide an ACID
  writer lease or prevent split brain.

## Address and Identity Plan

| Purpose | Address | Rule |
|---|---:|---|
| Canonical home server | `10.99.0.1/32` | Reserved; never assigned to the laptop |
| Existing canonical peers | `10.99.0.2/32` onward | Keep with their original profiles |
| Temporary peer pool | `10.99.0.241/32`–`10.99.0.253/32` | One fresh identity per device |
| Temporary laptop hub | `10.99.0.254/32` | Fresh laptop-only identity |

The temporary pool is inside the portfolio's canonical `10.99.0.0/24` plan,
but does not reuse canonical addresses. Give the temporary tunnel a distinct
name such as `temp-mac-hub`; clients should retain their canonical home-server
tunnel as a separate, inactive profile.

Schema v1 fixes the recovery listener at UDP `51821` so it cannot be confused
with the canonical server's usual `51820` listener or stale forwarding rules.
Changing the port requires a new reviewed schema rather than an ad hoc local
override.

## Declaration and Render Contract

The checked-in `mesh.example.json` is generation zero: `cutover_epoch` is zero,
`expires_at` is null, and `nodes` is empty. It is safe to publish and impossible
to render. Initializing a local declaration does not activate a tunnel.

Before a private declaration can render, it must have all of the following:

- `generation` and `cutover_epoch` of at least one;
- a future, canonical UTC expiry such as `YYYY-MM-DDTHH:MM:SSZ`;
- `failover_mode` fixed to `manual-static`;
- at least two nodes with exactly one `hub` and one or more `leaf` roles;
- unique node IDs and public keys, the hub fixed at `10.99.0.254/32`, and
  leaves limited to `10.99.0.241/32` through `10.99.0.253/32`;
- the exact recovery subnet `10.99.0.240/28` and listener UDP `51821`; and
- a literal private `underlay_endpoint` plus port on the hub.

The hub entry uses `id`, `role`, `address`, `public_key`, and
`underlay_endpoint`. Each leaf uses `id`, `role`, `address`, and `public_key`;
leave its endpoint absent in this listener topology. Copy public values from
the node-local `.pub` files—never place a private key in the JSON document.

Node IDs become `wg-quick` basenames and therefore match
`[a-z][a-z0-9-]{0,14}`. For example, use `temp-mac-hub`, not a long descriptive
hostname. The renderer creates `<node-id>.conf` and a key-free local
`manifest.json`. The `.conf` is complete and importable but contains the node's
private key; the JSON manifest and command output must never contain that key
or a secret-derived digest. Treat the manifest's private topology metadata as
local-only even though it contains no key material.

## Activation Modes and Current Scope

macOS Network Extension VPN applications cannot be assumed to nest. Apple's
[`NETunnelProviderManager`](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)
documentation permits only one enterprise VPN configuration to be enabled at
a time. Because both NordVPN and WireGuard.app use Apple's VPN facilities, do
not try to activate WireGuard.app over an active Nord tunnel.

The modes are mutually exclusive. The repository's renderer implements only
Mode A and rejects public endpoints. Mode B is documented as a separately
reviewed fallback, not as an activation path produced by this change.

### Mode A: private mesh underlay with command-line WireGuard

Prefer an already authenticated private underlay, such as an existing Nord
Meshnet relationship, when both devices can directly reach the laptop's
private underlay address. Set the remote peer's WireGuard `Endpoint` to that
literal private IP and the temporary UDP port. The renderer accepts RFC 1918,
RFC 6598, or IPv6 unique-local underlay addresses, never a public address or
hostname. Keep the WireGuard
`AllowedIPs` narrow so the outer endpoint itself continues to use the underlay
rather than being captured by the inner tunnel.

Keep Nord connected and use the Homebrew `wireguard-tools` plus `wireguard-go`
userspace path instead of WireGuard.app. WireGuard's
[installation page](https://www.wireguard.com/install/) documents
`brew install wireguard-tools` for macOS.

Choose the first real leaf from the supported rows below. Both ends must keep
the outer Nord Meshnet path active while running command-line WireGuard for the
inner tunnel.

| Candidate leaf | Mode A status | Requirement |
|---|---|---|
| macOS | Supported for initial validation | Nord Meshnet plus Homebrew `wireguard-tools`/`wireguard-go`; do not use WireGuard.app |
| Linux | Supported for initial validation | Nord Meshnet plus kernel/userspace `wg-quick`; verify the hub endpoint keeps its outer route |
| iPhone or iPad | Unsupported | NordVPN and WireGuard.app cannot provide the required simultaneous outer and inner VPN layers |
| Android, Windows, or app-only clients | Not approved for the first leaf | Use only after independently proving simultaneous outer and inner tunnels without route capture |

With those tools already installed, bring the rendered file up only for the
supervised session:

Before activation, confirm both nodes are linked and online in Nord Meshnet and
that the required peer has **Remote access to your device** enabled. Nord's
[permission guide](https://meshnet.nordvpn.com/features/explaining-permissions/remote-access-permissions)
describes that per-peer control. This host-only UDP listener does not need
traffic-routing or local-network permissions; do not widen them.

Do not activate against a placeholder or laptop-generated leaf identity. The
selected leaf must generate and retain its private key locally, and the laptop
declaration must receive only that leaf's public key before the hub is started.

```bash
sudo wg-quick up /absolute/protected/path/temp-mac-hub.conf
sudo wg show  # Darwin reports the generated utun interface here
caffeinate -s -i  # keep this supervised terminal open while the hub is needed
# Press Ctrl-C to release the sleep assertion, then stop the tunnel:
sudo wg-quick down /absolute/protected/path/temp-mac-hub.conf
```

Keep the laptop connected to AC power and its network session logged in. The
`caffeinate` command is deliberately foreground-only: it is not a launch agent
or an availability promise, and stopping it does not stop WireGuard by itself.
Always run the explicit `wg-quick down` command before ending supervision.

Do not proceed if `wg-quick` would add anything broader than the declared
temporary `/32` routes. This is WireGuard-over-private-underlay, not a
replacement for either layer. Before activation, verify the outer path from
the leaf using Nord's peer-online state and an approved reachable service (or
ICMP where allowed) at the laptop's Meshnet address. Do not infer reachability
from the laptop being able to see itself in the mesh application. WireGuard's
UDP listener does not exist until the hub is up and does not answer arbitrary
UDP probes; prove the inner path only afterward with an authenticated leaf
handshake and increasing counters.

### Mode B (deferred): WireGuard.app with a direct LAN or public endpoint

Disconnect Nord first, then use the official WireGuard app linked from the
[WireGuard installation page](https://www.wireguard.com/install/). This mode
requires a separately reviewed standard WireGuard `.conf` with a direct LAN or
public endpoint. The current renderer intentionally refuses such an endpoint,
and the existing WireGuard.app tunnel must remain untouched.

Use public forwarding only when no private underlay is available. If the
laptop sits behind both an ISP gateway and a local router, reserve the laptop's
LAN address and forward the same UDP port at both layers:

```text
public UDP 51821
  -> ISP gateway:51821
  -> local router:51821
  -> laptop LAN address:51821
```

Use a stable public DNS name if available. A carrier-grade NAT or an upstream
network outside your control may make inbound forwarding impossible; switch to
a reachable private underlay or a deliberately managed relay instead of
opening unrelated ports. Forward only WireGuard's UDP listener—never publish
SMB, SSH, HTTPS, SFTP, Podman, or database ports as a workaround.

## Build and Render the macOS Tunnel

The repository renderer produces a narrow, host-only WireGuard config for the
private-underlay command-line path only. Linux `wg-quick@` systemd and
firewalld steps in the normal server installer do not apply to this temporary
macOS phase.

1. Initialize the ignored generation-zero declaration. This refuses to
   overwrite an existing local declaration and does not activate anything.

   ```bash
   python3 scripts/render_wireguard_mesh.py init
   ```

2. Generate the laptop's fresh key pair. The defaults are
   `config/wireguard/mesh.local.d/keys/temp-mac-hub.key` (secret, mode `0600`)
   and its `.pub` companion.

   ```bash
   python3 scripts/render_wireguard_mesh.py generate-key \
     --node-id temp-mac-hub
   ```

   Generate each leaf key on the device that owns it and exchange only the
   `.pub` value. Do not centralize every node's private key on the laptop.

3. Edit `config/wireguard/mesh.local.json`: advance `generation` and
   `cutover_epoch`, set a UTC expiry no more than 31 days ahead, add
   `temp-mac-hub` at
   `10.99.0.254/32`, and add approved leaves beginning at `10.99.0.241/32`.
   Put the laptop's literal private mesh address and port in its
   `underlay_endpoint`. The declaration contains no private keys.

4. Validate the declaration, then render only the local laptop node:

   ```bash
   python3 scripts/render_wireguard_mesh.py validate
   python3 scripts/render_wireguard_mesh.py render --node-id temp-mac-hub
   ```

5. Find the artifacts under
   `config/wireguard/mesh.local.d/rendered/generation-<N>/temp-mac-hub/`. The
   renderer writes `temp-mac-hub.conf` mode `0600` plus a key-free local
   `manifest.json`; neither file is committed. Render a leaf only on the system
   that holds that leaf's private key. A changed key or declaration advances
   both generation and cutover epoch and renders into a new generation
   directory; never overwrite the prior artifact in place. After the new
   handshake succeeds, revoke the old public key and remove its private
   artifact through the approved secret-removal process.

6. Review the generated configuration before activation: no canonical server
   private key, no default route, no LAN route, no peer-pool route, and no
   `PostUp`, `PostDown`, forwarding, or NAT hooks. Do not paste the config into
   a terminal log because its `PrivateKey` is usable secret material.

7. Activate with supervised Mode A only. macOS sleep, network changes, or tool
   exit can remove availability; this is not a 24/7 service promise.

If Mode B is reviewed and implemented later, WireGuard.app's import/export
controls may be used for its private `.conf` handoff. An imported or exported
configuration contains private key material: transfer it through an approved
encrypted channel, import it only on the intended device, then remove the
handoff copy and empty the Trash. Never commit it or attach it to an issue,
chat, or CI artifact. Preserve the existing canonical app tunnel; do not edit
it in place to create the temporary identity.

## Validate from Outside

Validate from a second device on a genuinely different network. For current
Mode A, ensure the client is reaching the laptop's Nord Meshnet address rather
than a local LAN address. If Mode B is reviewed later, turn off the client's
home Wi-Fi and use cellular or another external network to test its public
path.

1. Bring up the supervised laptop hub, then activate the remote profile and
   confirm a recent authenticated handshake plus increasing receive/transmit
   counters at both ends. This is the first valid UDP listener test.
2. Reach `10.99.0.254` from the remote device. Test an application port only if
   that service is intentionally bound and protected on the laptop; a
   successful WireGuard handshake does not prove an application is listening.
3. Inspect the remote routing table and confirm `10.99.0.1`, every other
   temporary peer `/32`, and home-LAN addresses are not routed to this tunnel.
   Connection attempts must not cross the tunnel either. Those negative checks
   prove the host-only fence remains intact.
4. Disable and re-enable the client once to prove the endpoint survives a new
   NAT mapping. Record the observed external network, endpoint, handshake time,
   and result without recording private keys.

WireGuard's own
[quick-start guidance](https://www.wireguard.com/quickstart/) explains key
generation, peer `AllowedIPs`, endpoints, and persistent keepalives. Endpoint
reachability and application authorization still require separate tests.

## Expiry, Fencing, and Handback

Do not turn recovery into automatic failover. When the home server is ready:

1. Announce the handback and stop application writes through the temporary
   path. Let the application's normal transaction/lease mechanism fence its
   writer; tunnel state is not a writer election.
2. Deactivate `temp-mac-hub` on the laptop—`wg-quick down` in
   Mode A or Deactivate in WireGuard.app in Mode B. Confirm its transfer
   counters stop and no temporary peer reports a fresh handshake.
3. Remove both public UDP forwarding rules, or the temporary private-underlay
   allowance, before enabling the canonical listener.
4. Bring up the canonical home-server tunnel on its original identity and
   `10.99.0.1`. Activate canonical client profiles one at a time and validate
   their external handshakes and required services.
5. Re-enable application writes only after the canonical coordinator has
   passed its own quorum, storage, and writer-fencing checks.
6. Revoke/delete every temporary peer and laptop private key, remove private
   exports, mark the declaration expired, and retain only a key-free audit
   record.

If the expiry arrives before the server is ready, deactivate and reassess; do
not silently extend the epoch or reuse the identity in a new temporary period.

## When a Routed Hub Is Actually Required

Use a native Linux host or a dedicated Linux VM with a stable network attachment
for routed access, peer-to-peer forwarding, home-LAN reachability, or unattended
operation. That design needs explicit IP forwarding, firewall zones/rules,
return routes or narrowly scoped NAT, monitoring, and a reviewed activation
path. It is a separate `wireguard-lan-vpn` deployment—not a flag to add to this
macOS host-only tunnel.

Apple documents VPN deployment as a managed network service in its
[VPN overview](https://support.apple.com/guide/deployment/vpn-overview-depae3d361d0/web).
The official WireGuard Apple client is implemented through Apple's networking
facilities; its source and platform notes are available in the
[WireGuard Apple repository](https://git.zx2c4.com/wireguard-apple/about/).
