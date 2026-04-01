# Contributing to short-circuit

Thank you for your interest in contributing.

## How to Contribute

1. Open an issue describing the problem or improvement before starting large
   changes.
2. Fork the repository and create a feature branch from `main`.
3. Make your changes. Keep commits focused and use
   [Conventional Commits](https://www.conventionalcommits.org/) prefixes:
   `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.
4. Validate locally with `pre-commit run --all-files`.
5. Open a pull request against `main` using the provided template.

## What To Keep Out of This Repo

- Real private keys, pre-shared keys, or passphrases.
- Actual endpoint hostnames or public IP addresses.
- Machine-specific local config files (`*.local.conf`).
- Shared files or session state from the protected host.

## Code Style

- Shell scripts: `set -euo pipefail`, consistent `log`/`warn`/`fail` helper
  pattern.
- Config templates: use `<placeholder>` syntax for values that must be
  replaced before use.
- Documentation: plain Markdown, wrap at 80 characters where practical.
