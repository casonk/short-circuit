# NordVPN egress container contract

This directory is the build context for a dedicated Linux network namespace
that sends an allowlisted WireGuard source subnet through NordLynx. It does not
host the WireGuard mesh, join Nord Meshnet, change application leadership, or
alter host routes.

The image follows NordVPN's documented Ubuntu container installation pattern:
install the native Linux package, grant `NET_ADMIN`, provide `/dev/net/tun`,
use headless token login, select NordLynx, and enable the Linux kill switch.
The package is deliberately pinned to 5.2.0 so the entrypoint can verify its
source-defined settings output instead of trusting non-idempotent setter exit
codes. Fixed amd64 and arm64 `.deb` SHA-256 values pin that package by content,
not only by filename. The base-image digest check is syntactic; an operator must
still verify that digest against the intended official Ubuntu manifest.
The repository adds a stricter forwarding boundary: IPv6 is disabled and
dropped, and forwarded IPv4 is accepted only when its source matches an exact,
configured WireGuard peer `/32` in the nftables `authorized_sources` interval
set. The same set constrains reverse destinations and NordLynx masquerading.
There is no permitted fallback from forwarded mesh traffic to the ordinary
container bridge interface.

WireGuard cryptokey routing is the anti-spoof boundary: the Linux WireGuard hub
must bind each authorized `/32` to the corresponding peer public key through
`AllowedIPs`. The container set is defense in depth and does not independently
authenticate a packet that the host routes to its bridge address. The broader
`mesh_source_subnet` is retained only as a validation and routing context; it is
not an nftables acceptance or NAT rule.

The preferred-route verifier compares the complete runtime WireGuard peer map
against every leaf public-key→exact-`/32` pair in the bound mesh, including
leaves that are not authorized for egress. Missing, broad, extra, or mismatched
entries fail the generation rather than relying on address-only filtering.

References:

- <https://support.nordvpn.com/hc/en-us/articles/20465811527057-How-to-build-the-NordVPN-Docker-image>
- <https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-use-a-token-with-NordVPN-on-Linux>
- <https://support.nordvpn.com/hc/en-us/articles/20398711101329-How-can-I-use-NordLynx-in-the-NordVPN-app-for-Linux>
- <https://support.nordvpn.com/hc/en-us/articles/19509682644369-NordVPN-Kill-Switch-how-does-it-work>

`scripts/render_nord_egress_container.py` requires Podman 5.8 or newer and
produces 15 owner-only staging artifacts under the ignored `runtime/` tree:
three Quadlets; host-guard and route-lifecycle scripts/services; a managed
`wg-quick` drop-in; an expiry-stop service and persistent timer; the mesh
binding; staged `Containerfile`, entrypoint, and C token-login helper; and the
manifest. None contains an `[Install]` section, so rendering does not install,
enable, or start anything. The manifest maps the other 14 files to fixed future
root-owned paths under `/etc/containers/systemd`,
`/etc/systemd/system`, or
`/etc/short-circuit/nord-egress/<gateway>-g<generation>/`.
Generated root units never reference the user-writable repository or runtime
tree. The operator must separately create the named rootful Podman secret from
a local file, verify the base digest, and review/install the mapped artifacts.

The persistent host guard assigns a deterministic Podman bridge interface and
adds source lookup/prohibit pairs for exact authorized `/32`s arriving on the
configured WireGuard interface. It also installs an IPv4 terminal prohibit
route plus interface-wide IPv4 and IPv6 prohibit rules before `wg-quick` and
the container. Those policy rules survive an nftables flush, preserving the
terminal no-ordinary-WAN path while the nft layer is restored. The nftables
table isolates both sides of the bridge, blocks bridge access to host INPUT,
drops forwarded IPv6, peer transit, private/LAN destinations, unknown
WireGuard sources, and non-established return traffic.

The preferred-route service is `BindsTo`/`After` both the healthy egress
container and systemd `wg-quick@` unit and removes only its preferred routes
when either stops. The fixed managed `wg-quick` drop-in requires and verifies
the guard, wants the route service, and verifies the complete runtime peer map
in `ExecStartPost`. Raw `wg-quick up`, `wg setconf`, and post-start peer
mutation bypass these hooks and are unsupported.

The mesh-bound UTC expiry is enforced at both startup and runtime. Guard install
and verification reject the generation at or after `expires_at`. The managed
drop-in hard-requires and orders itself after a persistent timer that is
`BindsTo`/`PartOf` the WireGuard unit and schedules that exact deadline. The
timer has no reverse `After=wg-quick@` edge, avoiding a dependency cycle. Its
dedicated `RefuseManualStart` service stops WireGuard when the timer fires. The
preferred route then disappears through its WireGuard binding while terminal
guard state remains. A missed deadline after downtime is fenced by both the
persistent timer and the startup check.

Stopping the guard service does not remove security state. Decommission is an
explicit script operation and refuses to proceed until the WireGuard unit is
masked and inactive, the interface is gone, and preferred routes are absent.
Generation cutover must atomically replace the one fixed
`50-short-circuit-nord-egress.conf` drop-in, mask/stop the old WireGuard and
generation units, decommission the old guard, and only then unmask/start the
new systemd-managed generation. This avoids a restart race or physical-WAN
fallback window.

The pinned NordVPN 5.2 CLI supports `nordvpn login --token` without a positional
credential. The C PTY broker validates and opens the fixed CLI, waits for its
exact token prompt and disabled terminal echo, and only then disables dumps,
opens the fixed root-owned Podman secret, forwards and wipes it, and discards
all CLI output. The token never enters the shell, child `argv`, or environment;
there is no positional-token fallback. Nord state has no persistent volume, so
container replacement intentionally performs a fresh login.

These are still reviewable render artifacts, not a claim of a working
production gateway. Native Linux must prove Quadlet generation, policy-rule and
route syntax, the return path, Nord handshake, kill-switch outage behavior,
DNS behavior, external IP, and physical-WAN non-fallback before activation.
