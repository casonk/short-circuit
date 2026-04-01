# CHANGELOG.md — short-circuit

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial repository created from WireGuard tooling abstracted out of
  `snowbridge`.
- `scripts/setup_wireguard.sh`: generalized WireGuard installer supporting
  `wireguard-public-vpn` and `wireguard-lan-vpn` profiles, auto key generation,
  split-DNS helper installation, firewalld integration, and client QR export.
- `config/wireguard/`: generic server and client peer config templates for both
  profiles.
- `docs/setup-guide.md`: step-by-step WireGuard setup walkthrough.
- `docs/access-modes.md`: SMB, HTTPS, and SSH access patterns through the
  WireGuard tunnel.
- Portfolio governance baseline: `AGENTS.md`, `LESSONSLEARNED.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `.editorconfig`,
  `.pre-commit-config.yaml`, and GitHub templates.
