# Google sign-in button provenance

[Overview](../../README.md) · [Documentation index](../../docs/README.md)

The administration console uses Google's unmodified pre-approved light button
image for the Google sign-in action. It is served from the embedded local route
`/google-sign-in.png`, without a runtime Google font, image request or SDK.

| Field | Value |
| --- | --- |
| Source | https://developers.google.com/static/identity/gsi/web/images/standard-button-white.png |
| Retrieved | 2026-10-09 |
| SHA-256 | `892062091f35e69dd838ba4a4f238d37a0562d52ecda6406eb343a1127251409` |
| PNG dimensions | 354×80 |
| Rendered dimensions | 177×40, preserving the exact aspect ratio |
| Bytes | 5,331 |

The enclosing native button has the accessible name “Sign in with Google”. The
image is decorative to assistive technology and a hidden matching text label
is present. Keyboard interaction, disabled state and the existing single-use
Google authorization-code flow remain unchanged. No separate authentication
fallback is introduced.

Google provides downloadable pre-approved PNG/SVG button assets and permits
scaling while preserving their aspect ratio. These Google trademark assets are
used only to identify the Google sign-in action under the
[Sign in with Google Branding Guidelines](https://developers.google.com/identity/branding-guidelines).
They are not original Tailgate artwork or a general logo license. The original
Tailgate consent/logo asset lives under `components/public-site/assets`.

This source review does not assert that Google verified the deployed consent
screen, accepted a logo upload or published the branding. Those provider checks
are separate, and the pilot's OAuth audience remains Testing.
