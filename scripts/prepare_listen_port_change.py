#!/usr/bin/env python3
"""Prepare a WireGuard listen-port change without touching the live host.

Writes a candidate server config per local server file with ``ListenPort`` set
to ``--new-port``, rewrites the ``Endpoint`` port in the local client profiles
(a backup is kept beside each), and re-exports the client QR codes. Nothing is
installed and no service is touched: feed the candidate to

    sudo ./scripts/guarded_wireguard_rollout.sh --apply --candidate PATH \\
      --public-zone ZONE

Only ignored local files are read or written (``*.local.conf``), and a file
whose port does not match the current listen port is reported and left alone,
so an Endpoint that points at a different host is never rewritten.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = Path("config/wireguard")
DEFAULT_OUTPUT = Path("artifacts/wireguard-port-migration")
LISTEN = re.compile(r"^(\s*ListenPort\s*=\s*)(\d+)(\s*)$", re.MULTILINE)
ENDPOINT = re.compile(r"^(\s*Endpoint\s*=\s*)(.+):(\d+)(\s*)$", re.MULTILINE)


class PrepareError(Exception):
    """A safe, user-facing failure."""


def parse_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise PrepareError(f"not a port number: {text!r}") from exc
    if not 1 <= port <= 65535:
        raise PrepareError(f"port out of range 1-65535: {port}")
    return port


def listen_port(text: str) -> int | None:
    match = LISTEN.search(text)
    return int(match.group(2)) if match else None


def with_listen_port(text: str, port: int) -> str:
    return LISTEN.sub(lambda m: f"{m.group(1)}{port}{m.group(3)}", text, count=1)


def endpoint_ports(text: str) -> list[int]:
    return [int(m.group(3)) for m in ENDPOINT.finditer(text)]


def with_endpoint_port(text: str, old: int, new: int) -> str:
    """Change only Endpoint lines that use ``old``; IPv6 brackets and hosts are kept."""

    def swap(match: re.Match) -> str:
        if int(match.group(3)) != old:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}:{new}{match.group(4)}"

    return ENDPOINT.sub(swap, text)


def _ignored(path: Path, root: Path) -> bool:
    """True when git ignores ``path``; unknown state counts as not ignored."""
    result = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "-q", "--", str(path)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def prepare(
    root: Path,
    new_port: int,
    output: Path,
    *,
    qr: bool = True,
    dry_run: bool = False,
    stamp: str | None = None,
) -> list[str]:
    """Do the work and return report lines (no secret values)."""
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    config = root / CONFIG_DIR
    servers = sorted(config.glob("wg0-server*.local.conf"))
    clients = sorted(config.glob("client-peer*.local.conf"))
    if not servers:
        raise PrepareError(f"no local server config in {CONFIG_DIR} (wg0-server*.local.conf)")
    out_dir = output if output.is_absolute() else root / output
    report: list[str] = []
    for path in [*servers, *clients]:
        if not _ignored(path.relative_to(root), root):
            raise PrepareError(f"{path.name} is not git-ignored; refusing to touch it")
    if _inside(out_dir, root) and not _ignored((out_dir / "x").relative_to(root), root):
        raise PrepareError(f"{output} is not git-ignored; refusing to write secrets there")

    old_ports = set()
    for path in servers:
        text = path.read_text(encoding="utf-8")
        old = listen_port(text)
        if old is None:
            report.append(f"skip   {path.name}: no ListenPort")
            continue
        if old == new_port:
            report.append(f"skip   {path.name}: already {new_port}")
            continue
        old_ports.add(old)
        target = out_dir / path.name
        report.append(f"server {path.name}: {old} -> {new_port} (candidate {_rel(target, root)})")
        if not dry_run:
            _write_private(target, with_listen_port(text, new_port))
    if len(old_ports) > 1:
        raise PrepareError(f"server configs disagree on the current port: {sorted(old_ports)}")
    if not old_ports:
        return [*report, "nothing to change"]
    old = old_ports.pop()

    for path in clients:
        text = path.read_text(encoding="utf-8")
        ports = endpoint_ports(text)
        if old not in ports:
            report.append(f"skip   {path.name}: no Endpoint on port {old} (ports {ports})")
            continue
        report.append(f"client {path.name}: Endpoint {old} -> {new_port}")
        if dry_run:
            continue
        backup = path.with_name(f"{path.name}.bak-{stamp}")
        shutil.copy2(path, backup)
        backup.chmod(0o600)
        _write_private(path, with_endpoint_port(text, old, new_port))
        if qr:
            report.append(render_qr(path, out_dir / (path.stem + ".png"), root))
    report.append("live host untouched; next: guarded_wireguard_rollout.sh --apply --candidate")
    return report


def render_qr(config: Path, png: Path, root: Path) -> str:
    if shutil.which("qrencode") is None:
        return f"qr     {config.name}: qrencode not installed, skipped"
    png.parent.mkdir(parents=True, exist_ok=True)
    with config.open("rb") as handle:
        result = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", str(png)],
            stdin=handle,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        return f"qr     {config.name}: qrencode failed"
    png.chmod(0o600)
    return f"qr     {config.name}: {_rel(png, root)}"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)) if _inside(path, root) else str(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--new-port", required=True, help="UDP listen port to prepare.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT), help="Candidate directory.")
    parser.add_argument("--root", default=str(REPO_ROOT), help=argparse.SUPPRESS)
    parser.add_argument("--no-qr", action="store_true", help="Do not re-export QR PNGs.")
    parser.add_argument("--dry-run", action="store_true", help="Report without writing.")
    args = parser.parse_args(argv)
    try:
        lines = prepare(
            Path(args.root).resolve(),
            parse_port(args.new_port),
            Path(args.output_dir),
            qr=not args.no_qr,
            dry_run=args.dry_run,
        )
    except PrepareError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
