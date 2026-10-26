#!/usr/bin/env bash

detect_main_table_default_interface() {
  if [[ -n "${SHORT_CIRCUIT_TEST_PUBLIC_INTERFACE:-}" ]]; then
    printf '%s\n' "${SHORT_CIRCUIT_TEST_PUBLIC_INTERFACE}"
    return
  fi

  command -v ip >/dev/null 2>&1 || {
    printf 'error: ip command is required to determine the main-table default interface\n' >&2
    return 1
  }

  local interface
  interface="$(ip -4 route show table main default | awk '
    $1 == "default" {
      for (i = 1; i < NF; i++) {
        if ($i == "dev") {
          print $(i + 1)
          exit
        }
      }
    }
  ')"
  if [[ -z "${interface}" ]]; then
    printf 'error: could not determine the IPv4 main-table default interface\n' >&2
    return 1
  fi
  printf '%s\n' "${interface}"
}

detect_public_ipv4() {
  local interface="${1:-}"
  local url
  local candidate
  if [[ -n "${SHORT_CIRCUIT_TEST_PUBLIC_IPV4:-}" ]]; then
    printf '%s\n' "${SHORT_CIRCUIT_TEST_PUBLIC_IPV4}"
    return
  fi
  [[ -n "${interface}" ]] || {
    printf 'error: an interface is required for a direct public IPv4 lookup\n' >&2
    return 1
  }
  command -v curl >/dev/null 2>&1 || {
    printf 'error: curl command is required to detect the public IPv4\n' >&2
    return 1
  }

  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://icanhazip.com"
  do
    candidate="$(
      curl -4 -fsS --interface "${interface}" --max-time 10 "${url}" 2>/dev/null |
        tr -d '[:space:]'
    )" || continue
    if [[ "${candidate}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
  printf 'error: unable to detect the public IPv4 via interface %s\n' "${interface}" >&2
  return 1
}
