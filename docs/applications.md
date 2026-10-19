# Private application deployment CLI

[Overview](../README.md) · [Input contract](../schemas/README.md)

Tailgate's application CLI stages a database, an OIDC web application, an
immutable container, and a private service endpoint. The reusable validator,
plan renderer and phase runner are in `tools/applications.py`. Each installation
supplies an adapter for its PostgreSQL, identity, registry, host, certificate
and controller operations. The Azimut adapter and real host mapping belong in
the separate deployment repository.

This is a CLI workflow. It does not add a deployment control to the
administration console. Creating an application or DNS record does not grant a
device access. Use the existing reviewed Tailgate policy workflow for exact
source, destination and port permissions after the application is healthy.

## Inputs

- `application.json`: a unique name; PostgreSQL database, role and Secret
  Manager reference; ZITADEL project and confidential OIDC web application
  with exact HTTPS callbacks; digest-pinned image, ports, health path and
  optional environment secret references; private hostname, enrolled IPv4
  address and audience.
- `platform.json`: deployment-owned database and application SSH targets,
  public OIDC issuer, management API URL and organization ID, registry prefix,
  Tailgate address pool and application
  domain, ingress mode, certificate location, secret store project, controller
  record path and adapter argv. Namespace mode also names the network and
  client systemd units that must be running before ingress. Its `status` stays `template` until the
  chosen host and credentials are qualified.

There are no secret values in either input. Duplicate JSON keys, unknown
fields, an unpinned or nonapproved image registry, public ingress addresses,
non-HTTPS callbacks and application names outside the private namespace are
rejected. Both inputs are hashed into the rendered plan. Review that plan
before any apply command.

## Local example

```sh
python3 tools/applications.py validate \
  examples/application.json examples/application-platform.json
python3 tools/applications.py render \
  examples/application.json examples/application-platform.json \
  --output build/example-app
```

The example is a nonoperational template. Rendering writes `plan.json`,
`compose.yaml`, `private-nginx.conf`, `private-service.json` and a
short operator note. Compose publishes the container only on localhost or
the installation's isolated namespace veth. The Nginx listener binds only
the enrolled Tailgate address. A namespace proxy uses a separate Nginx
process inside that namespace; the host's existing proxy is untouched. Use
one dedicated namespace and Tailgate client per application when deploying
multiple applications to the same host. The application image must supply a
Docker HEALTHCHECK; the installation adapter should verify its status and
the running image identity.

## Apply contract

After an installation has replaced the template values, pinned an image
digest and marked both inputs ready:

```sh
python3 tools/applications.py render app.json platform.json --output build/app
python3 tools/applications.py apply app.json platform.json \
  --output build/app --plan-sha256 SHA_FROM_RENDER
```

The runner passes `--plan PATH --phase NAME` to the installation adapter
without a shell. Phases run in this order: `preflight`, `database`,
`identity`, `runtime`, `ingress`, `verify`. A private receipt records
completed phases; an interrupted run resumes at the first incomplete phase
after rechecking the plan hash. An adapter must make its stages safe to retry
and independently verify created resources. A failure stops the sequence.
There is no automatic rollback of a database or identity project.

The installation must supply the enrolled app-host identity, a DNS-01
certificate, a private namespace transport path when used, exact firewall
rules, and independent recovery access before applying. The plan is not a
substitute for a real client test of permitted and denied access. The
application must also implement its own ZITADEL OIDC authorization and
database migrations; this tool provisions their external dependencies.

The ZITADEL adapter may use the Management v1 project and OIDC application
endpoints on installations that still expose them. Those endpoints are
deprecated upstream, so an installation should pin and qualify the adapter
against its actual ZITADEL version before applying.
