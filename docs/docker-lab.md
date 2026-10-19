# Docker evaluation

[Overview](../README.md) · [Documentation index](README.md)

This local ARM64 lab runs real Headscale, our private read-only admin adapter,
digest-pinned Nginx, and two official Linux clients. All identities/domains are
fictitious. It never reads company configuration, DNS credentials or OAuth secrets.
Google is disabled only in disposable lab state; enrollment uses one-use ten-minute
ephemeral workload keys. This does not qualify human Google sign-in.

Fetch the locked upstream artifacts with `tools/tailgate.py fetch ... --platform
linux_arm64 --output .cache/linux_arm64`, build the locked relay with
`tools/tailgate.py build-derper`, and build the admin:

```sh
python3 tools/build-admin.py --platform linux_arm64 --output .cache/linux_arm64/tailgate-admin
python3 tools/docker_lab.py up --state runtime/docker-lab
python3 tools/docker_lab.py check --state runtime/docker-lab
```

Open <http://127.0.0.1:18110>. The randomly generated operator token is in
`runtime/docker-lab/secrets/login-token`, readable only by its owner. Read it
locally when signing in; never paste it into tracked documents. The Headscale API
key stays server-side. The API key expires after 24 hours and the disposable TLS
certificate after one day. Recreate the lab after expiry; this is a review stack,
not an unattended deployment. No company administration UI is exposed.

If the console's upstream API credential expires during review, rotate only that
lab credential and sign in again:

```sh
python3 tools/docker_lab.py renew --state runtime/docker-lab
```

Renewal checks ownership labels, atomically replaces the private credential and
restarts only this lab's admin container. It never uses company state. Recreate the
whole lab after its test certificate expires.

The gateway publishes only loopback ports 18110 (private console HTTP) and 18443
(test-CA HTTPS controller). Inside its namespace, controller, metrics and admin
listen on numeric loopback. Two client bridges are internal and isolated from
each other. Only the gateway bridge has normal Docker connectivity, needed for
host port publication. Controllers/clients use ordinary-user UID, read-only roots,
dropped capabilities, no-new-privileges and memory/CPU/PID limits. Writable state is
tmpfs; restarting the controller loses the lab. No TUN, privileged mode, Docker
socket, published SOCKS port or company state is mounted. The test CA signing key
is never mounted into any container. Every executable is checked against locked
artifact/build receipts before image construction. Acquisition receipts are local
provenance records, not independently signed attestations.

`check` qualifies actual inventory, read-only default, credential projection,
CSRF/origin rejection, sessions, self MagicDNS, owned relay map and runtime
containment. Run `tools/integration.py --artifacts .cache/linux_arm64` separately
for three-client allowed/denied application traffic, peer MagicDNS, forced DERP and
deletion revocation. It cleans its own resources. Admin lifecycle regressions run
with `node tools/admin-browser-test.mjs`; meaningful mutation/API qualification is
in `tools/admin-smoke.py`. These tests use no external JavaScript packages.

Stop and remove only this lab, including its private credentials:

```sh
python3 tools/docker_lab.py down --state runtime/docker-lab
```

The private HTTP console assumes a trusted local computer and trusted sibling
localhost services. Cookies are host-scoped across ports; shared proxy clients also
share a login-rate-limit bucket. Do not convert this token adapter into a public
console. Google administrator authentication and authorization remain required.
