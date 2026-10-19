# Component interfaces

[Overview](../README.md) · [Documentation index](README.md)

## Controller, policy, DNS and enrollment

Headscale 0.29.4 runs as an unprivileged systemd service. Linux ARM64 and AMD64 binaries are locked. It uses SQLite/WAL, private loopback HTTP/metrics/gRPC, a restricted local administrative socket, explicit policy, automatic device DNS, a watched A/AAAA record file, and a company relay map. Ninety-day human node expiry is the proposed baseline; tags remain non-expiring and require lifecycle review.

Google is the initial OIDC adapter. Systemd `LoadCredential` supplies `oidc_client_secret`; the controller reads `${CREDENTIALS_DIRECTORY}/oidc_client_secret`. Require verified email, explicit domain/user filters, PKCE S256 and strict provider availability at startup. Google groups do not become policy groups automatically. Workload enrollment uses short-lived, narrowly tagged upstream pre-authentication keys; neither keys nor the local administrator socket should be exposed publicly.

The supplied Nginx controller template carries HTTP/1.1 Upgrade headers for the control protocol and DERP and preserves long-lived requests. `/verify` permits only configured relay addresses. Embedded verification stays inside Headscale. External DNS records and trusted TLS are deployment prerequisites. Qualify both standard-client enrollment and actual relay traffic through the chosen proxy.

## Owned relay

Pilot: Headscale's embedded DERP with client verification, public TCP 443 through the controller proxy and UDP STUN 3478. Company: build `tailscale.com/cmd/derper` from the locked Tailscale version with locked Go, run the emitted systemd service, provide per-relay DNS-01 certificates and unique regions. Manual certificate directory uses the relay hostname's `.crt` and `.key` files. Confirm flags against the built executable before installation. No Tailscale-hosted relay map is fetched.

Standalone admission explicitly fails closed when the controller verifier is unavailable. This increases the outage dependency. Relay verification source IPs must match the controller allowlist; deployments with egress NAT must substitute the verified observed egress IP. The template requires direct public HTTPS on a dedicated relay host. Provisioning/firewall and failure-domain choices are deployment work.

## Private HTTPS and certificates

Use the host's maintained Nginx with `components/https/app.nginx.conf.in`, bound to the enrolled IPv4 only. Application backends bind localhost. No HTTP redirect or public app listener is created. Domain aliases do not separate access at one IP:443; the renderer rejects multiple audiences sharing that destination.

lego 5.5.2 is the pinned ACME DNS-01 implementation. Deployment names a supported provider, scopes its credentials, runs staging issuance first, then public issuance, and schedules renewal. Certificates must reach Nginx's configured `.crt`/`.key` paths with correct permissions; validate configuration before graceful reload. Provider-specific IAM, DNS challenges, public records and secret files are deployment inputs. No certificate authority or DNS token is part of this repository.

## Optional exit node

The locked Linux Tailscale daemon/CLI are the building blocks. Enroll a dedicated host with an operator-controlled exit tag. Enable IPv4/IPv6 forwarding, advertise exit routes, approve `0.0.0.0/0` and `::/0` centrally, and grant authorized sources access to `autogroup:internet`. Preserve deny cases. The deployment adapter must separately qualify firewall/NAT, public/private DNS, IPv6 leaks and outage behavior. This does not alter the controller's Tailscale account.

## Optional administration UI

The first-party [Tailgate administration component](../components/admin/README.md) is a separately built Go service with embedded web assets. It provides a fictitious local preview, a private authenticated Headscale adapter, Google-only company sign-in and an optional persistent approval workflow. Rendering the controller does not install it.

Company requests and administrator decisions are durable. Company approval unlocks device setup; network enrollment and device/service permission remain separate. Administrators require an exact allowlist and persistent Google identity pins. Enrollment OIDC alone never grants console access.

The optional database-policy workflow supports device/team proposals, explicit review/apply, revocation and reconciliation. Protected unique tags select exact devices on both sides of a grant, and the ledger preserves ownership lost through upstream tagging. It needs explicit deny-all initialization and one policy writer. Keep its ledger, controller database and administrator identity state together in backups. DNS remains a deployment-managed inventory view; arbitrary route approval, user provisioning and enrollment-key issuance are separate operations. Private connected mode defaults to read-only unless changes are explicitly enabled.

## Public information site

The [public-site component](../components/public-site/README.md) renders a homepage, privacy, terms and support pages from deployment-specific disclosures. It exposes no live device inventory. Configure the administration service's public-site link separately and qualify provider branding against the actual published pages.

## Migration gateway

The [Go gateway](../components/gateway/README.md) uses two isolated official clients, separate state and namespaces, and a one-way IPv4 path between distinct pools. The hosted side requires an explicit user allowlist; empty means nobody can bridge. The Tailgate side still needs independently approved destination services. Source NAT makes its own identity the destination policy's source. Scoped UDP/TCP DNS, reverse-initiation denial and fail-closed readiness are part of its contract; IPv6 forwarding and hosted-provider qualification are not supplied by its disposable lab.

## Privacy and updates

Controller client-logtail and update checks are disabled; client distributions still need platform-specific telemetry and update qualification. The selected release baseline does not constitute fleet certification. Supply-chain and client platform evidence belongs in the deployment journal. See [upstream provenance](provenance.md) for sources and license boundaries.
