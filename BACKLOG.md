# BACKLOG.md

Portfolio backlog for this repository. Pending items are candidates for execution —
manually or via crew-chief. Entries sourced from archility audit are tagged
`[archility:YYYY-MM-DD]`; manual entries use `[manual:YYYY-MM-DD]`.

The archility twice-weekly job populates this file automatically via `archility audit --write-backlog`.
To execute a backlog item with crew-chief: `crew-chief agent "Work on item: <item text>"`.
Mark items `[x]` when complete and move them to Done.

## Pending

- [ ] [manual:2026-08-09] Provision and independently test one stable
  public/direct or opaque UDP relay endpoint plus Air's supervised outbound
  relay client before promoting the roaming policy from `audit-only` to
  `required`; test the same imported iPhone profile on trusted Wi-Fi, isolated
  Wi-Fi, unrelated external Wi-Fi, cellular, relay outage, and return. Prove
  default-deny ingress exposes only the reviewed WireGuard UDP port, keeps
  relay management on a separately protected path, and states the required
  Internet/outbound-UDP boundary explicitly.
- [ ] [manual:2026-08-09] Publish the roaming plan's JSON/Markdown pair with an
  atomic generation-directory commit and safe orphan-staging recovery. Current
  rollback handles ordinary write failures but not a power loss between files.
- [ ] [manual:2026-08-09] Regenerate and inspect both architecture PNG/SVG
  pairs when the shared PlantUML/draw.io render binaries are installed; the
  editable sources contain the roaming-policy change but exports are stale.
- [ ] [manual:2026-08-09] Move private router automation into a private-first
  repository only after removing embedded credentials, encrypting/ignoring raw
  snapshots, enforcing owner-only permissions, and adding redacted fixtures,
  readback, rollback, and no-network dry-run tests.

## In Progress

## Done

- [x] [manual:2026-08-27] Added the multi-service-peer access-bundle renderer.
  It binds the current client and one temporary peer to the active mesh, then
  renders one replacement iOS profile with one or more canonical peers on
  disjoint exact `/32` routes. It never enables transit, a default route, or
  application-writer selection.
