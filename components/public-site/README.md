# Tailgate public information site

[Overview](../../README.md) · [Documentation index](../../docs/README.md)

Static, original Tailgate pages for the application's public homepage, privacy,
terms and support links. This component makes no live API requests, exposes no
device inventory, and loads no scripts, external fonts or analytics. Its gate
mark is original geometric artwork, distinct from the Tailscale and Google
brands. `logo.py` regenerates the SVG and antialiased 120×120 RGBA PNG using the
Python standard library; the PNG is 1,015 bytes.

```sh
python3 tools/render-public-site.py \
  --config /private/deployment/public-site.json \
  --output /private/staging/new-public-site
```

The output must be a fresh empty staging directory. The renderer rejects
unknown/duplicate configuration fields, unsafe links, missing policies and
email addresses in public content, escapes all supplied text, and writes only these files:

```
index.html
privacy/index.html
terms/index.html
support/index.html
assets/site.css
assets/enrollment.css
assets/tailgate-logo.svg
assets/tailgate-logo.png
enrollment-errors/STATUS.html
```

The fixed sign-in error pages use Tailgate branding, status-specific messages,
recovery instructions, support links and non-sensitive `TG-SIGNIN-STATUS` support
codes. These identify error categories, not individual backend events. They
contain no upstream bodies, identities, auth links or callback parameters.
They are marked noindex and must be served internally with no-store and
no-referrer headers. An expired or used link asks the user to check whether the
device is already connected before restarting sign-in.

`enrollment.py` generates the Nginx locations for `/register`, `/oidc` and `/auth`.
Failed browser authentication responses use the fixed pages; status codes are
preserved. Successful HTML confirmation, registration, reauthentication and SSH
authorization screens receive Tailgate branding through exact static fragment
replacements and same-origin CSS. Redirects, cookies, form actions, hidden CSRF
fields and escaped device/identity values stay upstream. APIs, Noise/control
upgrade, DERP, health and relay admission keep their existing handlers. The
deployment repository stages and verifies this proxy fragment alongside the pages.

This requires Nginx's HTTP substitution module. It changes presentation outside
the upstream binary, so no Headscale fork is maintained. Replacements are tied
to the locked 0.29.4 templates; an upstream upgrade must review those templates
and rerun integration and browser checks. The original inline logo is hidden by
CSS, while its class and the upstream CSRF field name remain in HTML source.
Never globally replace the word Headscale: it can occur in a real device name
and is part of the authentication field/cookie name.

The strict version-2 JSON schema is illustrated in `examples/public-site.json`.
Public pages have no email addresses or mailto links. Support directs users to
their company's internal support channel. The homepage is a brief introduction
with separate Get started and Admin login links; the member entry point is
`admin_url + /start`. All operator, audience, date, retention, infrastructure and legal statements
come from that deployment JSON. The fictitious example contains editing
instructions and must be replaced before publication. The operator must review
its actual identity/profile claims, device records, approvals/audit, cookies,
cloud/authentication/backup providers, retained histories and deletion handling.
No company policy, legal guarantees, deployment script or secret belongs here.

Serve `/`, `/privacy`, `/terms`, `/support` and their directory forms using
explicit static locations. Serve only the fixed `/assets/` directory; do not
replace the controller's protocol/API catch-all. The pages use external CSS
and same-origin images, so `default-src 'none'; style-src 'self'; img-src 'self';
form-action 'none'; frame-ancestors 'none'; base-uri 'none'` is compatible.
Render and inspect a staging release, then install it through the deployment
repository's normal reviewed procedure.

Google requires a publicly accessible descriptive homepage and a linked
same-domain privacy policy that explains Google-data practices. The consent
screen's privacy URL must match the public link. Development/testing use can
remain **Testing** with explicitly listed pilot accounts; generating these
pages neither verifies branding nor changes OAuth publishing status.
[Google brand-verification guidance](https://developers.google.com/identity/protocols/oauth2/production-readiness/brand-verification)

Google recommends a square 120px logo, accepts PNG/JPG/BMP up to 1MB, and expects
current support/contact and prominent in-product privacy information.
Authorized-domain/ownership and provider branding checks remain deployment
tasks. [Manage OAuth App Branding](https://support.google.com/cloud/answer/15549049?hl=en)

The private console's optional `--public-site-url https://control.example.com`
adds public information links to its login and footer. The console's Google
button uses Google's locally served, unmodified pre-approved image, not this
original Tailgate logo. See `components/admin/GOOGLE-BRANDING.md`.

```sh
python3 -m unittest discover -s tests -p test_public_site.py -v
```

Tests check exact output, escaped hostile text, rejected unsafe configuration,
existing-output preservation and the PNG's dimensions/CRC/decompressed layout.
The documented `tools/integration.py` test additionally checks all 17 sign-in
error statuses on GET/POST, non-reflection of callback parameters, internal-only
pages and protocol error passthrough through the pinned Nginx image. It checks
the common template contract against the real controller binary, then tests
confirmation and success branding with fictitious HTML fixtures, preserving
redirects/cookies/forms and rejecting missing cookies or mismatched CSRF fields.
The real official-client networking regression follows. Fixture confirmation
does not prove a real Google callback or enroll a human device.
Deployment must additionally check anonymous HTTPS reachability, linked URLs,
actual published disclosures and continued controller enrollment/protocol paths.
