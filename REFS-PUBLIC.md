# REFS-PUBLIC.md - Public References

> Record external public repositories, datasets, documentation, APIs, or other
> public resources that this repository utilizes or depends on.
> This file is tracked and intentionally kept free of private or local-only details.

## Public Repositories

- No fixed external code repository is the main upstream; the repo automates local WireGuard profile installation and host configuration.

## Public Datasets and APIs

- No standing public data APIs are required; the repo configures private VPN, DNS, SMB, HTTPS, and SSH access paths.

## Documentation and Specifications

- https://www.wireguard.com/ - WireGuard protocol and configuration reference
- https://firewalld.org/documentation/ - firewalld reference for Fedora firewall automation
- https://thekelleys.org.uk/dnsmasq/doc.html - dnsmasq reference for split-DNS setup

## Notes

- Actual keys, endpoints, and host IPs stay local-only. This tracked file only records the public networking documentation the repo relies on.
