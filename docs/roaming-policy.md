# WireGuard roaming policy

The roaming policy classifies where a WireGuard endpoint is reachable without
pretending that a peer supports an ordered endpoint list. It is a render-only,
key-free plan bound to one validated recovery-mesh generation. It never changes
a tunnel, router, DNS record, firewall, route, Nord setting, or application
writer.

## Network classes

| Class | Local peer access | Safe path |
|---|---:|---|
| `trusted-wlan` | yes | private LAN endpoint or stable public endpoint |
| `isolated-wlan` | no | stable public/direct endpoint or opaque UDP relay |
| `offsite` | no | stable public/direct endpoint or opaque UDP relay |

An isolated guest network can share a WAN address and even an IPv4 subnet with
the hub while its access point still drops client-to-client frames. A private
RFC 1918 endpoint is therefore valid only on `trusted-wlan`.

Some consumer routers expose only a Boolean network-separation control. That
cannot safely express “keep the guest isolated except for UDP to one LAN host,”
and a separate layer-3 packet filter must not be assumed to bypass access-point
isolation. Keep guest isolation enabled. A genuinely narrow mesh WLAN requires
VLAN-aware routing/firewall hardware; a dedicated non-isolated SSID is only a
degraded trusted LAN, not a guest-equivalent boundary.

## Supported path declarations

- `lan-direct` uses a literal private address and is restricted to
  `trusted-wlan`.
- `public-direct` uses a global address or canonical DNS name whose WireGuard
  listener is reachable from every declared network class.
- `opaque-udp-relay` uses a global address or canonical DNS name and forwards
  encrypted WireGuard datagrams to the same peer identity without terminating
  WireGuard.

The client-facing port for `public-direct` or `opaque-udp-relay` may differ
from the hub's WireGuard listen port when a reviewed NAT mapping or relay
forwards it. This permits externally reachable ports such as UDP 443 while the
hub continues listening on its generation-bound port. A true `lan-direct` path
and a `nord-meshnet` transport have no such intermediary and must use the hub
listen port.

`opaque-udp-relay` is also a first-class mesh `hub_transport.mode`, not only a
roaming-policy label. Each aligned iPhone leaf renders the stable public relay
address as its one ordinary WireGuard endpoint. Air remains the WireGuard peer
and must maintain a separate outbound relay client from behind NAT to the
forwarder; that client is not part of the iPhone profile.

If a relay terminates WireGuard, it is not opaque. It becomes a trusted mesh
node, needs its own overlay identity and forwarding policy, and application
traffic still needs end-to-end TLS or SSH protection.

Nord is deliberately absent from path selection. `nord_role` must remain
`egress-only`: NordVPN can protect outbound traffic at a reviewed Linux gateway,
but it does not carry the phone-to-mesh session in this policy.

## Stable-primary strategy

The first supported strategy is `stable-primary`. One public/direct or opaque
relay path must cover `trusted-wlan`, `isolated-wlan`, and `offsite`. WireGuard
then keeps one endpoint while the phone changes source addresses and networks.
This avoids competing iOS tunnel profiles and does not claim endpoint-list
failover: the same imported QR/profile remains selected across those changes.

An optional LAN path may remain in the declaration for diagnostics or a future
explicit optimization, but it is not selected automatically. `audit-only`
accepts an incomplete declaration and reports its uncovered network classes.
`required` rejects incomplete coverage and also requires every declared mesh
leaf's `hub_transport` mode and endpoint to match the stable primary: policy
`lan-direct` and `public-direct` map to mesh `direct`, while policy
`opaque-udp-relay` maps to mesh `opaque-udp-relay`. That is a
configuration-alignment gate, not deployment proof: the renderer neither
updates/imports phone profiles nor provisions DNS, public compute, the relay,
or Air's outbound relay client. Every plan therefore records
`reachability_verified: false` and `wireguard_profiles_updated: false`.

Coverage means Internet-connected networks that permit outbound UDP to the
selected endpoint. It cannot include a captive portal before login, a network
without Internet access, or a network that blocks every usable outbound UDP
port. UDP `443` is a useful relay choice where it is allowed; it is not a way to
turn WireGuard into HTTPS or bypass an explicit UDP prohibition.

## Public ingress and verification gate

A public/direct listener or relay must use default-deny ingress and expose only
the reviewed WireGuard UDP port. Protect relay management separately with a
restricted SSH or provider control path; do not expose an administration UI
alongside roaming traffic. Phone source addresses will change, so a static
source-IP allowlist is not the authentication boundary. WireGuard's
authenticated handshake is still required, while the firewall minimizes every
other exposed port and service.

DNS syntax and declared class coverage are not reachability evidence. A relay
must actually be provisioned, its public listener and forwarding path tested,
and Air's outbound relay client kept healthy. Before a path can be operational,
align and import the intended leaf profiles, then prove recent authenticated
handshakes and bidirectional counters from trusted Wi-Fi, isolated Wi-Fi,
unrelated external Wi-Fi, and cellular without changing the imported iPhone
profile. Repeat the test through relay outage and recovery. A future
access-bundle renderer must consume this policy before a different endpoint or
client-facing port can be deployed automatically.

The official WireGuard configuration format assigns one current endpoint to a
peer and updates that endpoint from correctly authenticated packets. It does not
define a priority-ordered endpoint list. The Apple app supports On-Demand rules
for Wi-Fi SSIDs and cellular, but those app settings are not embedded in a
standard QR/wg-quick profile. See the official
[WireGuard `wg(8)` reference](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8)
and
[WireGuard Apple strings/source](https://git.zx2c4.com/wireguard-apple/tree/Sources/WireGuardApp/Base.lproj/Localizable.strings).

## Workflow

Create an owner-only local declaration:

```bash
python3 scripts/render_roaming_policy.py init
```

Bind and validate it against the current mesh generation:

```bash
python3 scripts/render_roaming_policy.py validate \
  --policy config/wireguard/roaming-policy.local.json \
  --mesh-config config/wireguard/mesh.local.json
```

Render an owner-only, key-free decision plan:

```bash
python3 scripts/render_roaming_policy.py render \
  --policy config/wireguard/roaming-policy.local.json \
  --mesh-config config/wireguard/mesh.local.json
```

Rendering is not deployment. `validate` reports both aggregate declared-path
gaps and selected-primary gaps; an inert policy reports coverage as not
evaluated. Application CRUD leadership remains governed by ACID leases/fencing;
network reachability never elects a writer.
