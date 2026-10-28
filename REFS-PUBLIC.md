# REFS-PUBLIC.md - Public References

> Record external public repositories, datasets, documentation, APIs, or other
> public resources that this repository utilizes or depends on.
> This file is tracked and intentionally kept free of private or local-only details.

## Public Repositories

- No fixed external code repository is the main upstream; the repo automates local WireGuard profile installation and host configuration.

## Public Datasets and APIs

- https://api.cloudflare.com/client/v4/ — Cloudflare DNS API used by the
  optional mesh-endpoint DDNS updater
- https://api.ipify.org/, https://ifconfig.me/ip, and https://icanhazip.com/ —
  bounded public IPv4 lookup fallbacks used by edge checks and DDNS updates

## Documentation and Specifications

- https://www.wireguard.com/ - WireGuard protocol and configuration reference
- https://firewalld.org/documentation/ - firewalld reference for Fedora firewall automation
- https://thekelleys.org.uk/dnsmasq/doc.html - dnsmasq reference for split-DNS setup
- https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/ —
  Cloudflare DNS record API reference used by the DDNS updater

## Notes

- Actual keys, endpoints, and host IPs stay local-only. This tracked file only records the public networking documentation the repo relies on.
