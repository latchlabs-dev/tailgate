# Upstream provenance and maintenance

[Overview](../README.md) · [Documentation index](README.md)

`versions.lock.json` records actual upstream publication timestamps, artifact SHA-256 digests from upstream GitHub release metadata (and Tailscale package checksum endpoints), build interfaces and licenses. Recheck upstream security releases deliberately; retain the seven-day package restrictions. No upstream source is vendored.

| Component | Baseline | Primary source |
| --- | --- | --- |
| Headscale | 0.29.4, published 2026-09-23 | [release](https://github.com/juanfont/headscale/releases/tag/v0.29.4), [configuration](https://github.com/juanfont/headscale/blob/v0.29.4/config-example.yaml) |
| DERP and Linux clients | Tailscale 1.102.5, published 2026-09-29 | [source](https://github.com/tailscale/tailscale/tree/v1.102.5), [packages](https://pkgs.tailscale.com/stable/) |
| DNS-01 ACME client | lego 5.5.2, published 2026-09-23 | [release](https://github.com/go-acme/lego/releases/tag/v5.5.2), [Google DNS](https://go-acme.github.io/lego/dns/gcloud/) |
| Proxy | Maintained host Nginx; exact package recorded by deployment | [proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) |
| Build toolchain | Go 1.27.1 | [Go release history](https://go.dev/doc/devel/release) |

Headscale/Tailscale code uses BSD-3-Clause, lego uses MIT, Nginx BSD-2-Clause. Distribution of built artifacts must retain each project's notices. Existing official macOS/Windows GUI clients have different open-source boundaries; [Tailscale's open-source inventory](https://tailscale.com/opensource) is authoritative.

Networking interfaces and limits: [Headscale OIDC](https://headscale.net/stable/ref/oidc/), [policy](https://headscale.net/stable/ref/policy/), [DNS](https://headscale.net/stable/ref/dns/), [DERP](https://headscale.net/stable/ref/derp/), [reverse proxy](https://headscale.net/stable/ref/integration/reverse-proxy/), [upgrades](https://headscale.net/stable/setup/upgrade/). TLS: [Let's Encrypt DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge), [Certificate Transparency](https://letsencrypt.org/docs/ct-logs/).

Enrollment presentation uses exact fragments from the locked0.29.4
[general HTML](https://github.com/juanfont/headscale/blob/v0.29.4/hscontrol/templates/general.go),
[registration confirmation](https://github.com/juanfont/headscale/blob/v0.29.4/hscontrol/templates/register_confirm.go)
and [authentication success](https://github.com/juanfont/headscale/blob/v0.29.4/hscontrol/templates/auth_success.go)
templates, through [Nginx HTTP substitution](https://nginx.org/en/docs/http/ngx_http_sub_module.html).
The upstream binary is unchanged. Local fixtures contain fictitious identities;
integration also checks shared markup against the actual pinned binary. Review
all three templates and browser rendering on an upstream upgrade, since shared
markup checks alone cannot prove every confirmation/success fragment remains
compatible.
