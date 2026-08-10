#!/bin/sh

set -eu

/etc/init.d/nordvpn start >/dev/null 2>&1
ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
    if timeout 3 nordvpn status >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$ready" = true

nordvpn set analytics off >/dev/null 2>&1 || true
nordvpn settings | grep -Fx 'User Consent: disabled' >/dev/null
test ! -e /run/secrets/nordvpn-token

# Reaching the missing-secret error proves that the content-pinned real CLI
# emitted the exact expected prompt and disabled ECHO/ECHONL first. Any drift
# in either behavior fails earlier with the secure-prompt error instead.
if /usr/local/sbin/nord-token-login 2> /tmp/probe-error; then
    echo "prompt probe unexpectedly logged in" >&2
    exit 1
fi
grep -Fx 'nord-token-login: invalid token secret' /tmp/probe-error >/dev/null
echo "NordVPN 5.2.0 exact prompt and no-echo state passed"
