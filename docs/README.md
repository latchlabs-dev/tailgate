# Core documentation

[Project overview](../README.md)

## Learn the design

- [Architecture](architecture.md): why the components exist, control and data paths, approval boundaries and migration.
- [Component interfaces](components.md): controller, relay, HTTPS, administration and exit-node contracts.
- [Input contract](../schemas/README.md): validated configuration, explicit policy and address pools.
- [Upstream provenance](provenance.md): pinned versions, artifact verification and licenses.

## Build and verify

- [Development guide](development.md): prerequisites, local rendering, artifact builds and validation paths.
- [Docker lab](docker-lab.md): disposable controller, console and official clients.
- [Administration component](../components/admin/README.md): preview, authentication, approval ledger and operator interfaces.
- [Google branding asset](../components/admin/GOOGLE-BRANDING.md): sign-in asset provenance.
- [Public information site](../components/public-site/README.md): configuration and rendering of public pages.
- [Migration gateway](../components/gateway/README.md): isolated dual-client bridge, allowlist and integration lab.

Company setup, live host records and recovery belong in the deployment repository. Its exact core pin is an independent release choice.

# Application deployments

Use the [private application deployment CLI](applications.md) to validate and
stage PostgreSQL, ZITADEL, immutable runtime and Tailgate private ingress
through installation-owned adapters.
