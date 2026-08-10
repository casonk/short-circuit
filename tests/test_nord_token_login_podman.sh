#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN_CONNECTION="${PODMAN_CONNECTION:-podman-machine-default}"
PRODUCTION_IMAGE="${PRODUCTION_IMAGE:-localhost/short-circuit-nord-egress:token-test}"
TEST_IMAGE="${TEST_IMAGE:-localhost/short-circuit-nord-token-login-test:local}"
REAL_PROMPT_IMAGE="${REAL_PROMPT_IMAGE:-localhost/short-circuit-nord-real-prompt-test:local}"
CONTEXT="${REPO_ROOT}/tests/containers/nord-token-login"
PINNED_CONFIG="${REPO_ROOT}/config/wireguard/nord-egress-container.example.json"

IFS=$'\t' read -r BASE_IMAGE NORDVPN_PACKAGE_VERSION < <(
  python3 -c \
    'import json,sys; c=json.load(open(sys.argv[1], encoding="utf-8"))["build"]; print(c["base_image"], c["nordvpn_package_version"], sep="\t")' \
    "${PINNED_CONFIG}"
)

# Always compile the helper and entrypoint from this checkout. An existing tag
# is not accepted as evidence because it may refer to stale source.
podman --connection "${PODMAN_CONNECTION}" build \
  --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  --build-arg "NORDVPN_PACKAGE_VERSION=${NORDVPN_PACKAGE_VERSION}" \
  --tag "${PRODUCTION_IMAGE}" \
  --file "${REPO_ROOT}/containers/nord-egress/Containerfile" \
  "${REPO_ROOT}/containers/nord-egress"

podman --connection "${PODMAN_CONNECTION}" build \
  --build-arg "PRODUCTION_IMAGE=${PRODUCTION_IMAGE}" \
  --tag "${TEST_IMAGE}" \
  --file "${CONTEXT}/Containerfile" \
  "${CONTEXT}"

podman --connection "${PODMAN_CONNECTION}" run --rm --network none "${TEST_IMAGE}"

podman --connection "${PODMAN_CONNECTION}" build \
  --build-arg "PRODUCTION_IMAGE=${PRODUCTION_IMAGE}" \
  --tag "${REAL_PROMPT_IMAGE}" \
  --file "${CONTEXT}/Containerfile.real-prompt" \
  "${CONTEXT}"

podman --connection "${PODMAN_CONNECTION}" run --rm \
  --network none \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  "${REAL_PROMPT_IMAGE}"
