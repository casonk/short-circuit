# Security Policy

## Reporting a Vulnerability

If you discover a security issue in this repository, please report it privately
rather than opening a public issue.

Contact the repository owner directly through GitHub. Do not include sensitive
details such as real keys or endpoint addresses in public bug reports.

## Sensitive Content

This repository should never contain:

- Real WireGuard private keys or pre-shared keys
- Actual public endpoint hostnames or IP addresses
- Machine-specific local configuration files

Local-only files matching `config/wireguard/*.local.conf` are gitignored for
this reason. Do not commit them.
