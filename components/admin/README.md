# Tailgate administration

[Overview](../../README.md) · [Documentation index](../../docs/README.md)

First-party UI inspired by Tailscale's administration layout, with original Tailgate styling and no copied Tailscale assets. Five views: Machines, Users, Access controls, DNS and Settings. The browser uses a narrow backend adapter rather than receiving the privileged Headscale API key.

The console supports searchable/filterable inventory, address copying, device details, standard-client enrollment instructions, deliberate rename/expire/remove actions, and Google administrator sign-in with an explicit allowlist. A configured approval workflow adds reviewed per-device/team grants, unique protected tags and revocation. Users and DNS remain inventory views. Route approvals, user provisioning, enrollment-key issuance and team-specific administrator roles remain separate operations.

Healthy operational checks appear as one status link in the header. Settings contains the health summary and a collapsed complete checklist; warnings and failures remain prominent. Blocked approvals and pending work have concise links to Access controls. An empty network shows enrollment guidance rather than irrelevant search/filter controls. No healthy checklist or technical service inventory is repeated above the machine list.

DNS distinguishes private MagicDNS resolution inside the client from default upstream resolution for internet names. Its displayed search domains include the automatic MagicDNS suffix before additional configured domains; a disabled MagicDNS setting does not claim that automatic suffix. Clients must accept network DNS settings for automatic OS integration.

## Local preview

Build with the existing locked Go 1.27.1 toolchain. No package installation, frontend build, remote fonts, analytics or CDN assets are needed.

```sh
python3 tools/build-admin.py --platform darwin_arm64 --output .cache/darwin_arm64/tailgate-admin
.cache/darwin_arm64/tailgate-admin --demo
```

Open <http://127.0.0.1:18100>. Six fictitious devices and two `example.com` users are held only in memory. The preview is clearly labeled; edits reset on restart. No Headscale connection or company credentials are loaded in this mode.

## Private connected mode

Supply a separately generated administrator login token of at least 32 characters and a Headscale API key in distinct owner-only files. Generate secrets directly into private files; never place their values in command arguments or repository content. Headscale keys have upstream expiration; rotation is an operating procedure.

```sh
.cache/darwin_arm64/tailgate-admin \
  --headscale-url http://127.0.0.1:18090 \
  --api-key-file /private/path/headscale-api-key \
  --login-token-file /private/path/admin-login-token \
  --config-file /private/path/headscale.json
```

Defaults to read-only connected mode. Add `--allow-device-changes` only when intentionally enabling rename, expire and remove. The UI requires the current device name as confirmation before expiring/removing. Headscale remains authoritative and can reject an operation. The adapter is qualified against **Headscale 0.29.4**; do not assume other API versions are interchangeable.

The config reader supports the renderer's **JSON** configuration, not arbitrary YAML. It projects only DNS, control URL, relay-map source and file-backed policy information. The config and its policy/record files must be readable by the process. Missing configuration is shown as unavailable. Config changes are displayed on refresh; this UI does not apply or reload them. REST does not expose client hardware or OS/version in this pinned node representation. Configure the optional device metadata collector below to display these fields for live devices.

For a remote private console, keep the server on loopback and use SSH forwarding. If browser origin differs, supply an exact `--origin`; proxy Host must match it. Every write requires same-origin requests and a session CSRF token. An HTTP upstream is allowed only at a numeric loopback address; HTTPS uses normal trust verification. API redirects are rejected, credential fields are stripped from responses, payloads are bounded, and arbitrary API proxying is unavailable.

Administrator tokens are exchanged for random, HttpOnly, SameSite=Strict session cookies with an eight-hour lifetime and CSRF protection. HTTPS origins use Secure `__Host-` cookies. Invalid sign-in attempts are rate-limited; a correct high-entropy token still succeeds when another caller exhausts the same source-IP budget. Sessions are memory-only and are lost on restart. No request access logger is installed. Device action logs contain action, node ID and result, never credentials. This token flow is for private operator access and local qualification. Company deployments should use the Google-only mode below. Device-enrollment OIDC does not authenticate this console.

Loopback access assumes the operator trusts other services on that hostname. Cookies are scoped to a host and path, not a TCP port: a browser can send this console's cookie to another HTTP service on `127.0.0.1`. HttpOnly prevents JavaScript reading the cookie; it does not prevent a sibling server receiving it. Keep private operator access on a trusted workstation. A company deployment should use a dedicated HTTPS administration hostname, with its own qualified authentication and proxy configuration.

The token sign-in limiter uses the direct connection's source IP and deliberately ignores forwarded-IP headers. SSH forwarding or a reverse proxy can make all callers share one loopback address. Wrong credentials remain subject to the shared five-attempt window; valid credentials bypass that invalid-attempt budget without clearing it. The token mode still assumes private operator access. Do not weaken the limit or trust arbitrary forwarding headers for public exposure. Google-only mode does not use this token-login bucket.

Sign-out and expired sessions immediately clear protected browser views, overlays, labels and CSRF state. Pending requests are aborted, and an authentication epoch prevents late inventory, login or mutation results from restoring those views. A new login is disabled until the previous server sign-out finishes, avoiding a cookie deletion race. Network failure during sign-out is reported because clearing the local view alone does not prove server session revocation.

## Google-only administrator mode

When the approval workflow is configured, `/start` provides company user sign-in
and access requests. It uses the same registered Google callback with a separate
member purpose bound to server-owned OAuth state. A signed, verified Workspace
domain must match the workflow's allowed domains. Member sessions can submit and
read only their own company requests; inventory, policy and administrator writes
remain administrator-only. Company sign-in never adds an administrator.

Requests and administrator approve/decline decisions persist in the existing
approval ledger, including the verified subject, reviewer, dates and optional
note. Requests appear in Access controls and administrator notifications. An
approved member's panel shows setup steps for devices with and without Tailscale,
plus that member's device status. The 30-second workflow monitor automatically
admits eligible enrolled devices only when their exact Google subject **and**
email match an approved request. It uses the same exact-node proposal, protected
tag, durable receipt and policy read-back as manual approval. At request review,
an administrator can optionally choose one already-approved destination and
concrete port; those exact service permissions follow this member's current and
later devices. Other services stay outside the grant. Revoking company access
stops future automatic admission and withdraws the member's approved devices;
Google account suspension remains a separate offboarding step. Google's Testing
audience still applies to both sign-in flows.

Use a dedicated HTTPS administration hostname, separate from the controller and other applications. Keep the application listener on numeric loopback and terminate HTTPS with a trusted reverse proxy that preserves the exact configured Host. Disable request/query access logging for OAuth callbacks: authorization codes must not enter shared Nginx logs. Google mode rejects HTTP, numeric/localhost browser origins, preview mode and a simultaneous `--login-token-file`. There is no runtime provider override, insecure TLS option or token fallback.

Provide a JSON configuration file that is not group/other writable. The secret file must be absolute, owner-only and contain only the Google Web client secret. All example values below are fictitious:

```json
{
  "client_id": "12345-example.apps.googleusercontent.com",
  "client_secret_file": "/run/credentials/tailgate-admin.service/google_client_secret",
  "identity_store_file": "/var/lib/tailgate-admin/identities.json",
  "admin_emails": ["alice@example.com"]
}
```

```sh
.cache/linux_arm64/tailgate-admin \
  --listen 127.0.0.1:18100 \
  --origin https://admin.example.com \
  --headscale-url http://127.0.0.1:18090 \
  --api-key-file /etc/tailgate-admin/secrets/headscale-api-key \
  --config-file /etc/tailgate/headscale.json \
  --google-config-file /etc/tailgate-admin/google.json
```

Register exactly `https://admin.example.com/auth/google/callback` on the Google **Web application** OAuth client. Restrict Google test users while the consent app is in Testing, then qualify the intended production audience. Tailgate authorizes only the exact lowercase email addresses in `admin_emails`, with Google's signed `email_verified: true` claim. Non-Gmail accounts additionally require a signed Workspace `hd` claim matching their exact email domain. Domain membership, a network enrollment login, aliases, wildcard addresses and an unapproved Google identity confer no console access. Changing the allowlist or provider secret requires restarting the service, which also revokes its in-memory sessions.

The first successful validated administrator login pins the canonical Google issuer and immutable `sub` in `identity_store_file`; later logins with a different subject for the same allowlisted email are rejected. Provision its parent directory with mode `0700` owned by the service user. The store and its process lock are owner-only, updates are atomic and fsynced, and a second writer is rejected. Preserve this file in private backups. Replacing an administrator's pinned identity after an account recreation is an explicit operator recovery procedure, never an automatic email match.

The authorization-code flow uses random state, a browser-bound Secure/HttpOnly/Lax temporary cookie, nonce, PKCE S256, five-minute single-use transactions and fixed Google discovery/token/JWKS endpoints. TLS trust and redirects are enforced. ID tokens require a verified RS256 signature and issuer, audience/authorized party, issuance/expiration/not-before time, nonce, subject and exact verified administrator email. Duplicate JSON members and unsafe RSA keys are rejected; signing keys honor cache headers with a one-hour maximum. Access and refresh tokens are not retained. Administrator and member sessions use a Secure/HttpOnly/Strict host-only `__Host-tailgate_session` cookie with a fixed eight-hour lifetime from successful Google sign-in, after ID token validation. Writes additionally require the existing origin/CSRF checks. Logout, current role allowlist checks, expiry and service restart end sessions.

Sign-in starts have a direct-IP budget of 15 per minute and a global budget of 60 per minute, keeping five-minute pending transactions below the bounded state cap. Proxy forwarding headers do not alter these budgets. A production reverse proxy should additionally limit the start endpoint by its actual external source IP; shared-proxy bursts can temporarily affect new sign-in starts. Existing authenticated sessions remain usable. These bounds limit authentication resource usage; they do not promise availability against unrestricted traffic flooding.

Authentication failure diagnostics write only finite operator categories, such as `transaction_missing`, `provider_exchange`, `id_token_signature`, `claims_nonce`, `claims_workspace_domain` or `account_allowlist`. Each category emits at most one line per ten seconds. Logs contain no request URLs/query strings, authorization codes, tokens, provider bodies, email addresses, subjects or credentials; browser rejection responses remain generic. `transaction_missing` means the browser-bound transaction is absent from this process, not proof of a specific cause. Correlate it with service start/restart time before attributing a failure to deployment. Sessions and pending five-minute sign-in transactions are memory-only: restarting the service invalidates in-flight sign-ins as well as existing sessions. Finish deployment, open the clean console URL, and start a fresh Google sign-in after a restart. Do not reuse an earlier callback URL.

The Headscale API key is validated and reread from its owner-only file for each upstream request. Operators can rotate it by atomically replacing that file without restarting this service or losing browser sessions. Missing, too-short, multiline or overly permissive replacement files fail closed; a previously loaded key is never reused as fallback. The Google client secret is loaded at startup and needs a deliberate restart after rotation.

Optional `--public-site-url https://control.example.com` requires an exact HTTPS DNS origin and adds prominent homepage/privacy/terms/support links to the login screen and console footer. The public-site origin is intentionally non-secret metadata; unauthenticated session metadata still exposes no inventory or administrator allowlist. Publish operator-reviewed information using `components/public-site`, then qualify its URLs against the consent screen. The Google sign-in button uses an unchanged locally embedded pre-approved asset; its provenance and accessibility details are in `GOOGLE-BRANDING.md`.

## Device and access approval workflow

The optional workflow is a single administrator of Headscale's **database-backed** policy. Bootstrap with the explicit JSON policy `{"grants":[]}` before exposing enrollment. Missing `grants`, `grants: null`, legacy ACLs, assignable tags and unmanaged policy features are rejected. Never switch a public controller to database mode before an explicit deny-all policy is initialized and verified. Do not mix workflow policy writes with CLI, another UI, Terraform or other policy writers.

Provide this deployment-specific configuration outside the component repository:

```json
{
  "state_path": "/var/lib/tailgate-admin/approvals.json",
  "allowed_domains": ["example.com"]
}
```

Add `--workflow-config-file /etc/tailgate-admin/workflow.json` to the administration command. Add `--allow-access-changes` explicitly to enable proposals, approval/rejection, revocation and reconciliation. Without the latter flag, the workflow is read-only and its policy monitor does not run. The ledger directory must already exist with mode `0700`, owned by the service account. Its file and single-writer lock are owner-only; updates use atomic replacement, fsync and a bounded JSON format. Back up the approval ledger **together with** Headscale's database/configuration/keys and the administrator identity store. Restoring only one side does not reconstruct a consistent approval network.

The Access approvals screen lists exact live devices, their observed Google owners and their approval status. An administrator selects the approved device set, selects actual source devices for a named team, selects destination devices, and enters concrete ports such as `tcp:443` or `udp:53`. The generated complete desired plan remains reviewable/editable. Submitting a proposal writes only the private review queue. A separate **Review and approve → Approve and apply** action changes access. Rejection changes no network policy. Self-review is permitted; this is an explicit approval workflow, not a mandatory two-person approval scheme.

Example complete desired plan, using fictitious live device IDs:

```json
{
  "device_ids": ["1", "2"],
  "teams": [{"name": "developers", "device_ids": ["1"]}],
  "grants": [{"team": "developers", "destination_ids": ["2"], "ports": ["tcp:443"]}]
}
```

Teams contain exact devices. The member request workflow can add a later machine automatically after matching its exact verified Google subject and email to an approved company request; it still creates a separate device receipt and unique tag. Ports require a single numeric TCP/UDP port; wildcards, ranges, raw IP/CIDR destinations, subnet routing, exit-node permissions and enrollment-key issuance are excluded from this initial workflow. Unattended server enrollment and previously tagged servers need a separate reviewed administrator enrollment process; the workflow does not infer a human owner for those devices.

An eligible new device must have an allowed lowercase company email, Headscale's `oidc` provider, and its recorded exact Google issuer/subject identifier. Google has both `https://accounts.google.com` and legacy `accounts.google.com` issuer forms; only those exact issuer forms with a single subject segment are accepted. This is a projection of the upstream enrollment identity, **not** a second member ID-token verification. Headscale's stored user representation does not expose the signed Workspace `hd` claim; the member's earlier request did verify it. A domain email alone never grants access; the approved request subject and email must both match the current node. Configure and qualify the controller's Google enrollment audience separately.

Each approval creates a random 128-bit `tag:tailgate-…` selector with an empty tag-owner list. Ordinary enrolled users cannot claim these tags. The compiler uses only these unique selectors on **both** source and destination sides, with an explicit grants array. It never grants access by reusable device IP or by company-wide identity. A deleted node's reused IPv4/IPv6 address therefore does not inherit its approval. Privileged Headscale API/database administrators remain trusted: they can override policies or assign tags outside this workflow. Protect that credential and keep a single policy writer.

Headscale's force-tagging operation erases its current user ownership. Tailgate first durably saves the original user ID, observed email and immutable Google provider identifier, plus the node ID/machine-key fingerprint and approval tag. The ordinary UI projects the preserved owner without exposing machine keys or raw provider identifiers. Tagging changes personal-device features: personal Taildrop and owner-dependent SSH semantics must not be assumed to remain available. Revoking removes all source/destination participation first and retains the historical tag/identity receipt. Deleting withdraws and verifies grants before calling Headscale deletion. Restoring personal-device ownership requires deletion and re-enrollment; the pinned Headscale API rejects an empty tag assignment. Offboarding must consult the ledger's **original identity**, rather than only the now-tagged Headscale owner.

Approval checks the proposal revision and a fresh authoritative inventory fingerprint. It persists an application intent and original owner receipts, installs the new empty-owner tag definitions while preserving the currently approved grants, assigns the exact tags, verifies live IDs/keys/tags and eligibility, then checks, installs and reads back the complete final policy. An interrupted, uncertain or failed transition blocks new approvals and attempts to install and verify deny-all. Durable `denial_verified` distinguishes proven denial from an unreachable coordinator; the UI does not claim that cached client access was removed when enforcement could not be checked. Unverified denial is retried after controller recovery. Explicit reconciliation verifies deny-all, clears the blocked transition and requires a new reviewed plan to restore grants. Partially tagged devices may need deletion/re-enrollment.

When access writes are enabled, a monitor starts immediately and checks every 30 seconds after each bounded check completes. Expired receipts, changed node keys, missing/reassigned/duplicated approval tags, inventory uncertainty or outside policy changes withdraw **all** grants and block new access changes. This is a deliberate fail-closed availability trade-off: a single unsafe approval can interrupt other network access until reconciliation. A receipt preserves the original node expiry; when there is no explicit expiry, it expires after 90 days. A tagged re-authentication that clears Headscale expiry does not extend that receipt. Detection is bounded polling plus request time, rather than instant enforcement. While the coordinator cannot be reached, policy updates and revocation cannot be proven; cached client connectivity may continue. A process supervisor, operational monitoring and independent recovery access are required.

The current ledger supports up to 512 lifetime historical device receipts, 64 teams, 128 grants/proposals and 512 recent audit entries. Approve at most 16 new devices per proposal, retaining the existing approved set while adding the next batch. Transactions have an eight-second request budget plus a separate bounded denial attempt; a slow or interrupted application requires reconciliation. It does not silently discard original device identities. Large deployments need deliberate archival/capacity work. Session-authorized mutations retain the same exact-origin/CSRF checks, and every proposal/application/rejection/revocation/reconciliation records its actor and revision. The private token lab remains available for isolated qualification; company deployment should use Google-only administrator mode.

## Administrator operational alerts

Optional `--operations-status-file /private/path/operations.json` reads a non-secret regular file that is not group/other writable. It accepts only a bounded projection, with an RFC3339 timestamp and `pass`, `warning`, `fail` or `disabled` status values:

```json
{
  "generated_at": "2026-01-01T12:00:00Z",
  "checks": [{"name": "Backup", "status": "pass", "message": "Recent recovery point verified"}]
}
```

Malformed/unavailable projections become a warning, and a projection older than five minutes shows a freshness warning. Use a separate privileged monitor to generate this safe projection; never include raw provider errors, secrets or log contents. All authenticated administrators see these checks, pending access/device counts and any blocked/unverified enforcement notice on every console page. This is an in-console alert channel. Email recipients/delivery require a separately configured transport and are not implied by a successful UI update.

## Validation

```sh
cd components/admin
GOTOOLCHAIN=local GOWORK=off go test -race ./...
GOTOOLCHAIN=local GOWORK=off go vet ./...
cd ../..
node --test tools/admin-browser-test.mjs
python3 tools/admin-smoke.py \
  --headscale .cache/darwin_arm64/headscale \
  --admin .cache/darwin_arm64/tailgate-admin
```

The native check starts real Headscale in disposable loopback-only state, tests authenticated inventory, secret projection, policy/DNS display, CSRF/confirmation rejection, rename/expire/remove and logout, then cleans up all services/state. Its manual test enrollment configuration must never be installed. This is API qualification, not proof of company Google login, real-device WireGuard revocation or production deployment.

Go Google-auth tests use a locally trusted TLS fake provider injected only in `_test.go`, with real RSA signatures and complete callback/state/PKCE exchanges. They test claim/signature/binding/replay rejection, strict configuration, redirect refusal, cancelled callbacks and session/logout behavior. They do not prove Google project access, configured callback/test users, real human consent or deployed reverse-proxy exposure. Those are deployment acceptance checks.

Workflow tests use a fake authoritative Headscale adapter that enforces staged tag definitions and reads the durable original identity receipt before permitting ownership-changing tags. They cover exact selector generation, stale owners/keys/revisions, untrusted issuer/domain rejection, null/absent allow-all bootstrap traps, revocation before deletion, rejected confirmations, expiry/key/tag drift, policy drift, CSRF/read-only boundaries, failed enforcement followed by recovery, interrupted state and secret-free projections. These tests complement the pinned Headscale native tag/policy qualification; they do not claim real-device WireGuard packet delivery or human Google consent.

The Node check executes the shipped JavaScript with a minimal DOM and controlled fetch responses. It covers logout while a snapshot is pending, clearing on 401, and stale login/mutation results. It uses only built-in Node modules and no packages. This deterministic lifecycle regression complements actual browser testing; it does not reproduce browser cookie handling, rendering or Google sign-in.

Design references: [Tailscale machine filtering](https://tailscale.com/docs/features/access-control/device-management/how-to/filter), [Headscale API](https://headscale.net/0.29.1/ref/api/), [pinned API schema](https://github.com/juanfont/headscale/blob/v0.29.4/gen/openapiv2/headscale/v1/headscale.swagger.json). No Tailscale UI source/assets or Headplane code is incorporated.

### Google sign-in error references

Rejected callbacks clear the browser flow cookie and redirect to a server-rendered HTML page at `/auth/google/error`, without issuing a session or retaining OAuth codes in its URL. The page provides a retry button and a non-sensitive `TG-` error reference, also present in the finite backend diagnostic. Repeated rejections within the same category and ten-second logging window share an event reference; a new window receives a fresh reference. Messages are fixed categories; reference shape is validated and all HTML template values are escaped. Tokens, email claims and provider bodies never appear on this page or in its diagnostics.


## Exact workload admission and local operator review

A pre-tagged server can become eligible for the existing proposal/review workflow through an operator-installed `workloads` array in the private workflow configuration. Each entry contains `id`, `fingerprint`, `tag` and a finite RFC3339 `expiry`. The fingerprint is the SHA256 of the compact JSON object with fields `ID` and `Key`, holding the exact node ID and machine key. The configuration must be a regular private file owned by the administrator process, or root-owned with only service-group read access (0640 or stricter). Symlinks, group write and access by other users are rejected. This pin only enables review; it grants no ports. A different node/key/tag remains ineligible.

Approval replaces the enrollment tag with a unique unclaimable approval tag and stores a workload receipt without inventing a Google identity. Removed, changed or expired pins trigger the existing fail-closed reconciliation. Valid expired pins still load after restart so the monitor can withdraw access. Workload receipts persist the original enrollment tag and pin expiry; human receipt validation remains unchanged.

For an authorized operator with existing server-side administrator credentials, `--operator-request-file=/private/request.json` reviews a plan without starting an HTTP listener. The normal administrator must be stopped because the same durable identity/approval files require exclusive locks. Run as their existing owner and retain the existing Google configuration and private Headscale API credential. There is no public token-login fallback or new credential.

The request has `actor` (an explicit `operator:name` audit identity), `revision`, `inventory`, `plan`, `comment` and `reconcile`. Review output supplies the current revision and inventory digest. Applying requires `--operator-apply` with exactly those reviewed values; stale inventory/revisions fail. The same proposal, tag staging, policy validation/readback, durable receipts and audit transitions are used as browser approval. Bootstrap reconciliation is limited to an empty plan with no receipts. After a verified deny-all withdrawal, an operator may explicitly reconcile and apply a reviewed plan that excludes changed or expired devices; the current plan must be empty and the inventory/revision must still match. Operator attribution is distinct from a Google-authenticated browser actor.

## Common gateway configuration

The [central bridge configuration service](../gateway/CONFIG-SERVICE.md) adds the
**Migration bridge** panel, durable revisioned rules and scoped gateway readers.
Administrators can enable/disable bridging and update exact account whitelists
without restarting gateways. It uses existing console authentication and is
installed with `--config-service-file` and `--allow-config-changes`.

## Device model and operating-system metadata

Headscale's node API omits Hostinfo. Use `tools/export-device-metadata.py` as a separate scheduled collector with read access to the controller SQLite database. It opens SQLite in read-only mode and atomically writes only node ID, reported hostname, model identifier, OS/version, architecture and client version. Raw Hostinfo, network endpoints and keys never enter the projection. Keep the output in a private, administrator-owned directory readable by the console service; do not give the console database access.

```sh
python3 tools/export-device-metadata.py --database /var/lib/headscale/db.sqlite --output /var/lib/device-metadata/devices.json
# Add to the console's existing arguments:
# --device-metadata-file /var/lib/device-metadata/devices.json
```

Run the collector every minute. The console ignores missing, invalid, writable-by-others or older-than-five-minutes exports. It joins by node ID and reported hostname, without changing registered names, DNS or access policy. Metadata is client-reported, not verified hardware identity. Collection time means when the stored metadata was read, not when the device last contacted the controller; last seen remains separate.

Machines show the reported model identifier and OS/version beneath their editable name. Search includes model, OS, architecture and client version. Details show the original hostname, model, OS, architecture, client version and metadata collection time. Missing fields remain “Not reported”; model identifiers are retained without guessing a marketing name.

## Services and reauthentication

The Services tab lists named catalog entries and endpoints already present in the applied plan. Each service is one approved destination device plus one concrete TCP/UDP port. Naming or adding a service changes only the catalog, never access. The private approval ledger persists the catalog with administrator-role, CSRF and revision/inventory guards.

Manage access selects people and offers a separate review/apply step. Permissions bind to an opaque identifier derived from the verified Google subject, never an email or device ID. A grant applies to all of that person’s approved devices, including devices approved later; enrollment remains a separate requirement. Deselecting a person revokes that endpoint across their devices and overrides older company automatic-access settings. The Users page and recipient names open a permission detail view. Workload grants and unrelated endpoints are retained. Enforcement still uses exact, unclaimable device tags internally. Blocked or read-only workflows hide mutation controls. Services describe approved endpoints, not discovered listeners or application health.

Headscale 0.29.4 deliberately removes tags on user reauthentication without requested tags ([upstream behavior](https://headscale.net/0.29.4/ref/tags/#convert-from-tagged-to-personal-node)). The periodic reconciler restores an existing tag only for a device still in the approved plan whose machine fingerprint, original Google subject/user/email, unexpired device and approval, and absent foreign tags match. Excluded devices, revoked company requests, workloads and changed identities are not repaired. The approval expiry is retained.

Repair validates the projected complete plan and existing policy, persists a pending transaction before writes, rechecks identity before each mutation, and verifies authoritative readback. Success changes no grants and increments the revision to invalidate stale proposals. Failure/interruption still fails closed. The pinned native test models reauthentication only in stopped disposable SQLite state and verifies repair via the real API.

An already-blocked older deployment can use private operator requests with `restore_reauthenticated: true`, `reconcile: true` and an exact reviewed recovery plan. Review projects safe restoration without mutation; apply checks the original inventory/revision before restoring tags and using normal deny-all reconciliation and approval. It never infers a recovery plan or restores revoked devices.

Existing installations can explicitly migrate personal source grants using an operator request with `migrate_user_services: true`. Review returns the expanded plan and user permission intent without changing state; apply requires the same inventory/revision. This preserves workload sources and expands each existing personal grant to the same verified user’s other approved devices. Managed endpoint revocations remain durable even with no current devices. Service catalog entries and intent survive device withdrawal; an unavailable destination grants nothing until approved again.
