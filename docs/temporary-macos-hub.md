# Temporary macOS WireGuard Hub

This runbook describes a temporary WireGuard listener on a MacBook while the
canonical home server is unavailable. In WireGuard terms the laptop is still a
peer; “hub” describes the temporary hub-and-spoke connection shape, not a
special WireGuard server role.

WireGuard is the authenticated recovery transport in both supported endpoint
modes. A leaf can reach the hub directly, or Nord Meshnet can carry the
WireGuard UDP exchange over its private RFC6598 path. Nord Meshnet does not
replace WireGuard keys, addresses, peer policy, or application authorization.

The Mac procedure remains host-only. It does not make the laptop a router,
peer-transit node, home-LAN gateway, Podman bridge, or NordVPN Internet egress
gateway. A connected leaf can reach deliberately exposed services on the
laptop at `10.99.0.254`; all broader routing needs a separate reviewed
activation path.

The committed declaration in
[`../config/wireguard/mesh.example.json`](../config/wireguard/mesh.example.json)
is synthetic and inactive. Real endpoints, public keys, DNS choices, and expiry
belong in a gitignored local declaration. A rendered `.conf` and its source-key
file contain a private key and must remain owner-only (`0600`) under a protected
local directory or approved secret store.

## Safety Contract

- Generate a fresh laptop key pair. Never copy the offline home server’s
  private key onto the laptop.
- Preserve `10.99.0.1/32` for the canonical home server. The temporary epoch
  uses `10.99.0.240/28`: `.254` for the laptop and `.241` through `.253` for
  temporary leaves. Each identity owns exactly one `/32`.
- Keep `mesh.peer_transit` false and egress disabled for the temporary Mac.
  Leaves then receive only `10.99.0.254/32` in `AllowedIPs`.
- Leave IPv4/IPv6 forwarding and NAT disabled. Do not add PF forwarding/NAT or
  bind the tunnel to a Podman bridge.
- Keep activation manual and supervised. Do not add a login item, launch
  daemon, health-triggered takeover, or reachability-based failover.
- Give every leaf exactly one selected `hub_transport`. Changing its endpoint
  or mode is a reviewed generation/cutover change, not automatic fallback.
- Set a real UTC expiry in the private declaration and calendar. Schema v2
  limits an active declaration to 31 days from validation time.
- Treat application writer leadership separately from reachability. WireGuard
  cannot grant an ACID writer lease or prevent split brain.

## Address and Identity Plan

| Purpose | Address | Rule |
|---|---:|---|
| Canonical home server | `10.99.0.1/32` | Reserved; never assigned to the laptop |
| Existing canonical peers | `10.99.0.2/32` onward | Keep with their original profiles |
| Temporary leaf pool | `10.99.0.241/32`–`10.99.0.253/32` | One fresh identity per device |
| Temporary laptop hub | `10.99.0.254/32` | Fresh laptop-only identity |

The recovery listener remains fixed at UDP `51821`, separate from the
canonical server’s usual `51820`. Node IDs become `wg-quick` basenames and must
match `[a-z][a-z0-9-]{0,14}`.

## Schema-v2 Declaration

Generation zero is inert: epoch zero, null expiry, no nodes, no peer transit,
and disabled egress. An active declaration requires:

- `generation` and `cutover_epoch` of at least one;
- a future canonical UTC expiry (`YYYY-MM-DDTHH:MM:SSZ`);
- `failover_mode: manual-static`;
- the fixed recovery `/28` and UDP port;
- exactly one hub and one or more leaves with unique IDs, addresses, and keys;
- a supported `platform` on every node; and
- exactly one `hub_transport` on each leaf and none on the hub.

A host-only Mac declaration uses this policy shape:

```json
{
  "mesh": {
    "name": "temporary-macos-host-only",
    "subnet": "10.99.0.240/28",
    "listen_port": 51821,
    "peer_transit": false
  },
  "egress": {
    "mode": "disabled",
    "gateway_node_id": null
  }
}
```

The hub node identifies the local platform but has no endpoint:

```json
{
  "id": "temp-mac-hub",
  "role": "hub",
  "platform": "macos",
  "address": "10.99.0.254/32",
  "public_key": "<hub-public-key>"
}
```

Copy only public values into the declaration. Never place a private key there.

### Direct WireGuard transport

A direct leaf reaches the WireGuard listener without depending on Nord Meshnet:

```json
{
  "id": "leaf-direct",
  "role": "leaf",
  "platform": "linux",
  "address": "10.99.0.241/32",
  "public_key": "<leaf-public-key>",
  "hub_transport": {
    "mode": "direct",
    "endpoint": "vpn.example.com:51821"
  }
}
```

Direct mode accepts a canonical DNS name or routable unicast LAN/public IP.
Only WireGuard UDP should be forwarded from the public edge. Never expose SMB,
SSH, HTTPS, SFTP, Podman, or database ports as a workaround. A double-NAT path
requires an address reservation plus the same UDP forward at both routers; an
upstream carrier-grade NAT may make it impossible.

Direct mode is independent from Nord, but that does not mean every simultaneous
Nord client arrangement works. If the Nord app owns the Mac’s default route,
prove that WireGuard replies to the remote endpoint use the expected outer
path. Do not infer symmetric reachability from a rendered config.

### Nord Meshnet carrier

A leaf can instead carry the same WireGuard session over an already
authenticated Nord Meshnet relationship:

```json
{
  "hub_transport": {
    "mode": "nord-meshnet",
    "endpoint": "100.64.10.5:51821"
  }
}
```

This mode accepts only a literal RFC6598 IPv4 address. The leaf and hub must
keep the Nord Meshnet relationship online, and the leaf must have **Remote
access to your device** permission. Traffic-routing and local-network
permissions are not required for the host-only listener and should remain off.

macOS Network Extension VPN applications cannot be assumed to nest. Keep Nord
connected and use Homebrew `wireguard-tools`/`wireguard-go` for the inner
WireGuard session rather than trying to enable WireGuard.app alongside the
Nord app. Both ends must prove that the outer Meshnet path remains reachable
after the inner `/32` route is installed.

| Candidate leaf | Nord-carrier status | Requirement |
|---|---|---|
| macOS | Supported for supervised validation | Nord Meshnet plus command-line WireGuard |
| Linux | Supported for supervised validation | Nord Meshnet plus kernel/userspace `wg-quick` |
| iPhone or iPad | Unsupported for the first validation | Two simultaneous app VPN layers are not assumed |
| Android, Windows, app-only clients | Not initially approved | First prove simultaneous carrier and WireGuard behavior |

## Peer Transit and Internet Egress Are Separate

`mesh.peer_transit: true` gives non-egress leaves the recovery `/28` route and
marks the hub manifest as requiring forwarding. It does not enable forwarding.
The temporary Mac runbook therefore keeps it false. The schema also rejects
`peer_transit: true` together with `egress.mode: nord-vpn`; the current
outbound-only egress boundary authorizes named `/32`s and is not a peer router.

`egress.mode: nord-vpn` is not Nord Meshnet. It is a request for selected leaves
to send Internet traffic through an isolated NordLynx gateway. The declaration
requires:

- a hub whose `platform` is `linux`;
- explicit `authorized_leaf_ids`;
- one through four reviewed public IPv4 `dns_servers`; and
- `ipv6_policy: block` until routed IPv6 is supported.

Authorized leaves render `AllowedIPs = 0.0.0.0/0, ::/0` plus those DNS servers.
Other leaves keep their host-only route. The hub keeps one leaf `/32` per peer.
Manifests mark forwarding, NAT, and fail-closed egress as requirements while
explicitly reporting that none was activated.

macOS cannot be selected as this egress gateway. The current repository does
not implement selective PF routing, a macOS Nord namespace, or a safe way to
keep direct WireGuard outer packets off the Nord egress path.

The image contract under `../containers/nord-egress/` is for native Linux or
rootful Linux Podman. Its separate ignored declaration carries exact
`authorized_source_addresses`, one `/32` for each mesh node named in
`egress.authorized_leaf_ids`. It must never authorize the containing recovery
subnet. The hub retains one peer `/32` per leaf as WireGuard’s cryptokey-routing
anti-spoof boundary.

`scripts/render_nord_egress_container.py` validates that credential-free
declaration only when it is bound to the authoritative mesh through
`--mesh-config`. The binding fixes the generation, cutover epoch, expiry,
normalized-document SHA-256, Linux gateway address and public key, WireGuard
interface, mesh-provided public DNS, authorized leaf IDs, and exact source
`/32`s. It also binds every leaf's WireGuard public key to its exact `/32` for
runtime verification. The duplicated generation, subnet, interface, and source
list must agree, while peer transit must remain false.

The owner-only ignored output now includes 15 artifacts: three Quadlets; host-
guard and route-lifecycle scripts/services; a `wg-quick` dependency drop-in;
an expiry-stop service and persistent timer; `mesh-binding.json`; a staged
`Containerfile`, entrypoint, and C token helper; and a manifest. Its install map
uses only future root-owned paths under
`/etc/containers/systemd`, `/etc/systemd/system`, and
`/etc/short-circuit/nord-egress/`; root units never refer to the user-writable
clone. The Quadlets reference a separately created rootful Podman secret, have
no `[Install]` section, and are not copied into systemd’s search path by the
renderer.

If later installed on Linux, the container logs into Nord from that mounted
secret, selects NordLynx, enables Nord’s kill switch, admits only the declared
leaf `/32`s, NATs them only through `nordlynx`, and disables/drops IPv6. The
NordVPN 5.2.0 `.deb` is content-pinned against fixed amd64/arm64 SHA-256
values. The built C broker starts the pinned CLI's no-positional-token flow in
a PTY, waits for the exact prompt and disabled echo, and only then disables
dumps, reads/forwards/wipes the root-owned secret, and suppresses child output.
No token enters process arguments or the environment. If NordLynx disappears,
the forwarding policy remains default-deny
rather than falling back to the ordinary container bridge.

The rendered host guard preserves the same `/32` authorization at the native-
Linux boundary. It is ordered before `wg-quick` and the container, installs a
terminal IPv4 route plus interface-wide IPv4/IPv6 prohibit rules and nftables
isolation, and persists when the container stops. The policy-rule terminal
denials survive an nftables flush. The preferred route service is
`BindsTo`/`After` both the healthy container and systemd `wg-quick` unit. The
fixed `wg-quick` drop-in requires/verifies the guard, wants that route service,
and verifies the gateway public key, listen port, exact IPv4/no-global-IPv6
identity, and complete public-key→exact-`/32` peer map after interface startup.
Failed starts force `wg-quick down` through `ExecStopPost`. Hard preflight also
requires rootful Podman 5.8+, `/dev/net/tun`, host IPv4 forwarding, and
non-strict `rp_filter`.

Raw `wg-quick up`, `wg setconf`, and live peer mutation bypass the dependency
drop-in and are unsupported for this Linux egress path. Safe generation
cutover uses only systemd activation, atomically replaces the fixed managed
drop-in, and masks/stops the old WireGuard and generation services before
explicitly decommissioning the old guard. The cleanup action refuses to remove
terminal protection while the WireGuard unit can restart, its interface still
exists, or a preferred route remains.

On that Linux path, the mesh expiry is active policy. Guard startup and
verification fail when the bound UTC deadline has passed. The managed drop-in
hard-requires and orders itself after a persistent timer that is
`BindsTo`/`PartOf` the systemd WireGuard unit without reverse ordering. At
`expires_at`, its dedicated stop service stops WireGuard, which removes the
bound preferred route while leaving the terminal guard intact. This timer does
not change the temporary Mac procedure: the Mac remains manually supervised and
host-only.

This namespace does not host WireGuard, join Meshnet, or hold application
leadership. None of `render_wireguard_mesh.py`,
`render_nord_egress_container.py`, or `setup_wireguard.sh` installs an
artifact, creates or exposes a token, logs into Nord, starts the egress path, or
tests live traffic.

The host guard is also not a persistent leaf-side kill switch. If an authorized
leaf tears down its WireGuard interface, its ordinary WAN route can return.
End-to-end no-fallback therefore remains a native-Linux gateway and leaf
integration gate even after the artifacts have rendered successfully.

## Build and Render the Mac Tunnel

1. Initialize the ignored generation-zero declaration. Initialization refuses
   to overwrite an existing file and activates nothing.

   ```bash
   python3 scripts/render_wireguard_mesh.py init
   ```

2. Generate the laptop’s fresh key pair. The default files are owner-only
   under `config/wireguard/mesh.local.d/keys/`.

   ```bash
   python3 scripts/render_wireguard_mesh.py generate-key \
     --node-id temp-mac-hub
   ```

   Generate each leaf key on the owning device and exchange only its `.pub`
   value. Do not centralize leaf private keys on the laptop.

3. Edit `config/wireguard/mesh.local.json`. Advance generation and cutover
   epoch, set the expiry, add the Mac hub, and add leaves with the selected
   per-leaf transport. Keep peer transit false and egress disabled.

4. Validate, then render only the local node:

   ```bash
   python3 scripts/render_wireguard_mesh.py validate
   python3 scripts/render_wireguard_mesh.py render --node-id temp-mac-hub
   ```

5. Review the generation-scoped artifacts under
   `config/wireguard/mesh.local.d/rendered/`. The `.conf` is mode `0600` and
   contains the private key. The adjacent local manifest is key-free but still
   private topology metadata.

6. Confirm the config contains no canonical-server key, default route, LAN
   route, peer-pool route, `PostUp`, or `PostDown`. Its manifest must report
   activation, routing, forwarding, and NAT as false.

7. Activate only during the supervised session:

   ```bash
   sudo wg-quick up /absolute/protected/path/temp-mac-hub.conf
   sudo wg show
   caffeinate -s -i
   # Press Ctrl-C to release the sleep assertion, then stop the tunnel:
   sudo wg-quick down /absolute/protected/path/temp-mac-hub.conf
   ```

Keep the laptop on AC power. Stopping `caffeinate` does not stop WireGuard; run
the explicit `wg-quick down` command before ending supervision.

### Legacy schema-v1 declarations

The CLI continues to read schema v1. It validates the old document first,
maps RFC6598 endpoints to `nord-meshnet` and other accepted private endpoints
to `direct`, supplies conservative platform labels, disables transit and
egress, and normalizes to schema v2 in memory. It prints a warning and never
rewrites the source.

Migrate the private file deliberately. Advance generation and cutover epoch so
new output goes to a new reviewed directory; do not overwrite generation-one
artifacts. A schema migration alone does not require key rotation, though any
provisional or improperly shared key still must be replaced.

## Validate from Outside

Use a second device on a genuinely different network.

1. Prove the selected outer path first: the direct LAN/public path or the
   authorized Nord Meshnet address.
2. Bring up the supervised hub and leaf. Confirm a recent authenticated
   handshake and increasing counters at both ends.
3. Reach `10.99.0.254`. Test an application port only when that service is
   intentionally bound and protected on the laptop.
4. Confirm `10.99.0.1`, every other temporary leaf, the home LAN, and Internet
   defaults are not routed to this host-only tunnel.
5. Disable and re-enable the leaf once to test a new NAT mapping. Record the
   network, transport mode, endpoint, handshake time, and outcome without
   recording private keys.

A UDP listener does not answer an arbitrary probe, and a rendered profile is
not reachability evidence. The authenticated handshake is the first valid
WireGuard path test.

## Expiry, Fencing, and Handback

When the home server is ready:

1. Announce handback and stop application writes through the temporary path.
   Let the application’s transaction/lease mechanism fence its writer.
2. Run `wg-quick down` on the Mac. Confirm transfer counters stop and no leaf
   reports a fresh handshake.
3. Remove temporary public UDP forwards or Meshnet access allowances.
4. Restore the canonical home-server identity at `10.99.0.1` and validate its
   external handshakes and required services one client at a time.
5. Re-enable application writes only after the canonical coordinator passes
   its own quorum, storage, and writer-fencing checks.
6. Revoke temporary peers, remove their private artifacts through the approved
   secret-removal process, expire the declaration, and retain only a key-free
   audit record.

If expiry arrives first, deactivate and reassess. Do not silently extend the
epoch or reuse the temporary identity.

## References

- WireGuard installation: <https://www.wireguard.com/install/>
- WireGuard quick start: <https://www.wireguard.com/quickstart/>
- Apple `NETunnelProviderManager`:
  <https://developer.apple.com/documentation/networkextension/netunnelprovidermanager>
- Nord Meshnet remote-access permissions:
  <https://meshnet.nordvpn.com/features/explaining-permissions/remote-access-permissions>
- Local egress-container contract:
  [`../containers/nord-egress/README.md`](../containers/nord-egress/README.md)
