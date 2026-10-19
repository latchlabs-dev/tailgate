# Migration gateway

[Overview](../../README.md) · [Documentation index](../../docs/README.md)

This Go service joins two **separate container network namespaces**, each running
one official `tailscaled`. Ordinary devices keep their existing single client.
There is no custom VPN implementation or application-specific port mapping.

```
Hosted device -> hosted VPN -> hosted gateway -> private transit
              -> Tailgate gateway -> Tailgate VPN -> approved service
```

The hosted gateway advertises the entire destination IPv4 pool. Its administrator
must approve that route and allow the intended clients/services. Its Go-enforced
`allowed_users` list is empty by default: nobody can bridge until explicitly
listed, even if the hosted ACL permits everyone. Tailgate must
separately grant the gateway identity access to the destination services. An empty
Tailgate policy remains deny-all. New devices in the pool need no additional route,
but still require destination service listeners and Tailgate authorization.

Each hop uses kernel forwarding and source NAT. The destination sees the **Tailgate
gateway's identity/IP**, not the hosted user. Original callers are authorized on
the hosted gateway before source NAT; application SSH/TLS authentication remains available end to end.
The gateway can read unencrypted application traffic, like any subnet router.

For live panel-managed rules, use the [common configuration service](CONFIG-SERVICE.md).
The local `allowed_users` workflow below remains available for staged upgrades;
central mode replaces it and never falls back to local grants.

## Runtime contract

- Linux, root PID 1 in each dedicated container; **never host networking, host PID
  mode, privileged mode, another service's namespace, or the controller host**.
- Read-only filesystem; private writable `/run`, `/tmp`, and persistent `/state`.
  State contains private client keys: root-only, never tracked or reused from a
  different client. Protect volume backups as credentials.
- Only `NET_ADMIN`, `NET_RAW`, and `/dev/net/tun`; no Docker socket or host mounts.
  Enable `net.ipv4.ip_forward=1`, disable strict `rp_filter` in these namespaces.
- A separate egress bridge for each container; one dedicated, non-masquerading transit
  bridge with a /29 subnet and fixed private addresses. Do not attach other clients
  or services to the transit bridge. No published host ports.
- Verified binaries and digest-pinned image prepared by `tools/gateway_image.py`.
  No runtime package downloads. Go 1.27.1, standard library only.

The service owns INPUT/FORWARD/OUTPUT filter policy **inside its container only**.
It preserves Docker's embedded-DNS NAT and replaces only its `TG_GATEWAY` NAT
chain. Both clients use `netfilter-mode=off`: our default-drop forwarding/input
rules replace the incompatible automatic CGNAT anti-spoof filter. Explicit route
priority on the hosted side sends the destination pool to the transit peer before
the client's table 52. The Tailgate side uses its official client's peer routes.
Use the explicit `iptables-nft` backend consistently. Docker's `--internal` bridge
mode cannot carry this path: it drops bridged packets destined outside the transit
subnet. Isolation instead comes from dedicated bridges, namespace firewalls, no
published ports, and explicit egress default-gateway priority.

Forwarding begins closed until the local client is Running with an address in the
expected pool. IPv4 pool mismatch, client loss of readiness, daemon death, or
address change exits the process and closes forwarding; container restart restores
the same persisted identity. `/run/gateway-ready` reports **local readiness** only;
it does not attest remote route approval, remote connectivity, or authorization.
The hosted gateway closes its user gate on reported client health problems,
except the pinned client's exact informational warning about peers advertising
routes while `--accept-routes=false`. That warning is expected: unrelated subnet
routers must not disable bridge access, and their routes remain unaccepted. All
other messages, including unknown warnings or failures accompanying this warning,
still close the gate. Recheck the exact exception when upgrading the official
client ([upstream warning](https://github.com/tailscale/tailscale/blob/v1.102.5/health/healthmsg/healthmsg.go)).
It refreshes device ownership from local client status every second; a failed
status command times out after three seconds and exits closed. Revocation is
subject to the control plane delivering the new identity/policy state. As with
the official client, a cached network map is not proof of instantaneous control
connectivity, and an unreported outage can delay remote revocation.

## User access boundary

Only exact lowercase account emails in `allowed_users` are admitted. The gateway
joins each peer's authenticated `UserID` to the official client's user profile,
then installs exact IPv4 source rules for that user's devices present in the
current network map. It rejects tagged, expired, shared-flagged, unknown and
ambiguous identities. It never trusts a caller-supplied email, hostname, DNS
record, subnet route, or a manually entered IP allowlist. This authorizes devices
owned by the account, not individual OS sessions or people behind a proxy on an
authorized device. The host administrator and the allowed devices remain trusted.

Both directions of forwarded traffic and UDP/TCP bridge DNS are checked. Identity
withdrawal updates the namespace firewall, including established flows. No
wildcard established-flow rule bypasses DNS admission. An empty or omitted list
allows neither bridge traffic nor bridge DNS; it does not change native network
permissions. All allowed users share the gateway's separately approved destination
service grants. Reverse initiation remains disabled for everyone.

Change the root-controlled JSON and **recreate the hosted container** to apply an
allowlist change, retaining its state volume. Configuration is startup-only;
editing a bind-mounted file alone does not apply it, and atomic replacement can
leave an existing file mount pointing to an old inode. Stop the hosted container
first for urgent revocation. Recreation terminates existing bridge sessions.
Never roll back to an older gateway that lacks user enforcement while the hosted
ACL is broad; stop the bridge instead.

Hosted ACLs remain an additional boundary. Tailscale ACL rules are additive:
adding a narrow group rule beside `* -> *:*` does not restrict the broad rule.
The Go gate is therefore enforced independently of hosted ACLs. If narrowing the
hosted policy too, explicitly preserve native/subnet/exit-node permissions and
exclude the destination pool and bridge DNS from broad grants; validate the
resulting policy with allowed/denied tests before saving.

## Configuration and enrollment

Mount JSON at `/config/gateway.json`; validate without mutation with `--check`:

```json
{
  "role": "hosted",
  "hostname": "migration-hosted",
  "login_server": "https://login.tailscale.com",
  "destination_pool": "100.80.0.0/16",
  "dns_domain": "mesh.example.com",
  "transit_address": "10.231.0.2",
  "transit_peer": "10.231.0.3",
  "allowed_users": []
}
```

The other container uses role `tailgate`, its controller HTTPS origin, a distinct
hostname, and the transit addresses reversed; it cannot configure users. Add
explicit emails such as `alice@example.com` only to the hosted list after review.
Optional `auth_key_file` must be
`/secrets/auth-key`, mounted read-only and readable by root without DAC_OVERRIDE.
Without a key, obtain the enrollment URL from `tailscale status --json` **inside
that container**. Enrollment, hosted subnet-route approval, Tailgate service
approval, and hosted split-DNS configuration are distinct operations.

Do not manually change client preferences: the service pins accept-routes=false,
accept-dns=false, netfilter-mode=off, snat-subnet-routes=false and ssh=false. Hosted
advertises only the configured pool; Tailgate advertises no routes or exit node.
Normal Linux hosted clients must enable acceptance of approved subnet routes.

## DNS and limitations

Hosted gateway listens on **its hosted IPv4:53** over UDP and TCP. Configure that
address as a restricted nameserver for the Tailgate MagicDNS domain in the hosted
console. It forwards across the isolated transit to the Tailgate gateway's
`5353`, then to that client's local Quad100 (`100.100.100.100:53`).

Only single-question A queries for that exact domain or its descendants are
forwarded. AAAA returns NODATA because the bridge is IPv4-only. Other names/types
are refused; malformed/compressed questions are dropped. This is a bounded
MagicDNS bridge, not a general recursive resolver or arbitrary DNS proxy. TCP,
timeouts, concurrency limits, response validation and UDP truncation are included.

Reverse-initiated connections, IPv6 forwarding, automatic synchronization of user
identities/ACLs, HA failover, and arbitrary L2/broadcast protocols are not included.
Stopping either gateway disconnects cross-network sessions; native devices on each
network continue independently. Remove hosted route/DNS settings before retiring
and revoking the two gateway identities. Preserve source-network administration.

## Qualification

```sh
cd components/gateway
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race ./...
# From repository root, with the locked Go first in PATH:
python3 tools/build-gateway.py --platform linux_arm64 --output .cache/linux_arm64/tailgate-gateway
python3 tools/gateway_integration.py --artifacts .cache/linux_arm64
```

The isolated lab uses two disposable Headscale controllers and real official
kernel clients. This qualifies the packet path, separate ACLs, NAT, UDP/TCP DNS,
allowlisted versus unlisted devices under an unrestricted hosted ACL, empty-list
closure, native access preservation, identity/established-flow revocation and
recovery with another hosted subnet router advertising an approved unrelated route;
it does not prove hosted vendor-console approval or live
fleet behavior. See also the existing `tools/integration.py --example partitioned`
suite. Lab state/secrets are temporary and cleanup is restricted to owned resources.

Upstream references: [netfilter modes](https://tailscale.com/docs/reference/netfilter-modes),
[subnet routers](https://tailscale.com/docs/features/subnet-routers),
[local Quad100](https://tailscale.com/docs/reference/quad100),
[pinned identity status schema](https://github.com/tailscale/tailscale/blob/v1.102.5/ipn/ipnstate/ipnstate.go),
[tailnet policy syntax](https://tailscale.com/docs/reference/syntax/policy-file).
