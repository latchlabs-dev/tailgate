# Central bridge configuration

[Gateway](README.md) · [Administration](../admin/README.md)

The **Migration bridge** panel and gateway readers use the same durable Go
configuration service inside `tailgate-admin`. No additional database, package,
or external configuration product is required. It manages the bridge on/off
switch and exact hosted-account whitelist. Destination devices/ports remain under
the existing **Access controls** approval workflow. Network topology and client
identity stay in deployment configuration: changing pools, transit addresses,
DNS suffixes or enrollment credentials requires an intentional gateway rollout.

## Install the common service

Create a private registry readable by the administrator service:

```json
{
  "state_path": "/var/lib/tailgate-admin/bridge-config.json",
  "gateways": [
    {"id": "migration", "token_file": "/etc/tailgate-admin/secrets/migration-reader"}
  ]
}
```

Use `--config-service-file /etc/tailgate-admin/config-service.json` and
`--allow-config-changes` alongside the existing authentication/workflow flags.
Without the latter, the panel is read-only. The registry and each reader secret
must be private, with an existing service-owned mode 0700 state directory.
Generate a different random credential (at least 32 characters) for each gateway;
store actual credentials outside Git. A new state starts disabled with no accounts.
The configured console origin must be HTTPS. Preserve existing Google-only login.

The same console proxy must pass `/gateway-config/v1/<id>` to the administrator
listener. It must preserve the exact Host and Authorization headers and must not
cache responses. Browser requests use normal administrator session/CSRF checks;
company-member sessions cannot read or change bridge configuration. Reader tokens
only allow GET of their own gateway's rules and cannot mutate configuration.

State uses an exclusive process lock, atomic replacement and fsync. Each save
requires the current revision; conflicting saves return 409. The durable audit
records the administrator, timestamp, revision and complete saved rule, retaining
up to 512 recent entries within the 2 MiB state budget. Archive it externally if an
unbounded audit history is required. Failed storage closes all gateway reads until
operator recovery. Back up this state and the registry with the controller's
existing private backup set. Changes to registered gateway IDs require a reviewed
state/registry migration; silently dropping configured gateways is rejected.

## Configure a gateway reader

Replace `allowed_users` in the hosted bootstrap JSON with:

```json
"config_service": {
  "url": "https://console.example.com/gateway-config/v1/migration",
  "gateway": "migration",
  "token_file": "/secrets/config-token"
}
```

Mount the matching secret root-owned, mode 0600 and read-only at that path. Do not
mount administrator login or controller API credentials into a gateway. Only the
hosted role accepts a configuration source. Nonempty local `allowed_users` and a
remote source cannot be combined. Existing local-file deployments remain supported
for staged upgrades, but a configured remote reader **never falls back** to them.

The supervisor polls in its existing one-second loop with a two-second HTTP
request timeout. It validates TLS, refuses redirects, binds the response to the
gateway ID, validates the schema and email list, and rejects regressing revisions
or changes within an already observed revision. A failed read, unavailable or unsafe
secret, malformed response, disabled rule or empty list immediately supplies an
empty allowlist on that loop iteration. No cached allow grants are used on failure.
Recovery requires a successful fresh read. Polling, client-status checks and
firewall command execution mean enforcement is asynchronous, not instantaneous.

Firewall reconciliation still checks authenticated device ownership and removes
both forwarding and DNS permission, including existing flows. No restart or local
JSON edit is needed for panel changes. The panel shows **saved desired state**;
it does not claim that an offline gateway applied a revision. `/run/gateway-ready`
continues to mean local client readiness, not configuration or remote authorization.

Stop the hosted container for emergency closure. Bootstrap endpoint/credential
mount changes require recreation while retaining its client state volume. For
reader rotation, stop hosted first, install a fresh credential on both ends, restart
the config service to reload its registry, recreate hosted and verify denial/allow
behavior. Never substitute an older unrestricted image as recovery.

## Qualification

`tools/gateway_integration.py` builds the real admin service and runs it alongside
disposable controllers. It changes rules through the same authenticated API used
by the panel, proves live allow/deny, empty-list and master-disable behavior,
revokes an established TCP connection, stops/restarts the service to prove closed
TCP/UDP/DNS and durable recovery, and checks that updates did not restart the
gateway. Native unlisted-user access, destination ACLs, tagged identity revocation,
route-warning compatibility, reverse denial and confinement remain covered.
Go tests also cover session/CSRF/member boundaries, reader scope, revision conflicts,
persistence failure, unknown responses, redirects, TLS and request timeouts.
The local preview uses fictitious in-memory rules; it is never a live reader service.
