"""Fixed public sign-in messages and browser-only proxy error handling."""
import re


# Presentation contract for the pinned upstream 0.29.4 HTML. Keep replacements
# specific to markup; never replace "headscale" globally because it is also the
# CSRF field/cookie name and may be present in a legitimate device/user name.
UPSTREAM_MAIN = '<main class="md-typeset" style="max-width: min(800px, 90vw); width: 100%;">'
UPSTREAM_FOOTER = ('<footer style="color: var(--md-default-fg-color--light); font-size: 0.8em; '
                   'line-height: 1.6; margin-top: 4rem; text-align: center;">Powered by '
                   '<a href="https://github.com/juanfont/headscale" rel="noreferrer noopener" '
                   'target="_blank">Headscale</a></footer>')
BRAND = ('<header class="enrollment-brand"><a href="/" aria-label="Tailgate home">'
         '<img src="/assets/tailgate-logo.svg" width="38" height="38" alt="">Tailgate</a></header>')
FOOTER = ('<footer class="enrollment-footer"><span>Tailgate</span><nav aria-label="Information">'
          '<a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/support">Support</a></nav></footer>')


def replacements():
    return [
        ('<link href="/favicon.ico" rel="icon">', '<link href="/assets/tailgate-logo.svg" rel="icon" type="image/svg+xml">'),
        ('<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect">', ''),
        ('<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">', ''),
        ('</head>', '<link href="/assets/enrollment.css" rel="stylesheet"><meta name="robots" content="noindex"></head>'),
        (UPSTREAM_MAIN, '<main class="tailgate-enrollment">'+BRAND),
        (UPSTREAM_FOOTER, FOOTER),
        ('<title>Headscale - Confirm node registration</title>', '<title>Confirm your device · Tailgate</title>'),
        ('<h2>Confirm node registration</h2>', '<h1>Confirm your device</h1>'),
        ('<p>A device is asking to be added to your tailnet. Please review the details below and confirm that this device is yours.</p>',
         '<p>Review these details and add this device to Tailgate only if it is yours.</p>'),
        ('>Confirm registration</button>', '>Add this device</button>'),
        ('<title>Headscale - Node Registered</title>', '<title>Device added · Tailgate</title>'),
        ('<title>Headscale - Node Reauthenticated</title>', '<title>Device signed in · Tailgate</title>'),
        ('<title>Headscale - SSH Session Authorized</title>', '<title>SSH access confirmed · Tailgate</title>'),
        ('>Node registered</strong>', '>Device added to Tailgate</strong>'),
        ('>Node reauthenticated</strong>', '>Device signed in to Tailgate</strong>'),
        ('>SSH session authorized</strong>', '>SSH access confirmed</strong>'),
        ('<h2>Getting started</h2>', '<h2>Next steps</h2>'),
        ('<p>Check out the documentation to learn more about headscale and Tailscale:</p>',
         '<p>For device setup or access questions, contact Tailgate support. Registration does not grant access to company services; an administrator reviews that separately.</p>'),
        ('href="https://headscale.net/stable/"', 'href="/support"'),
        ('>Headscale documentation</a>', '>Tailgate support</a>'),
    ]


def quote(value):
    return "'"+value.replace('\\', '\\\\').replace("'", "\\'").replace('$', '\\$')+"'"


def branding_nginx():
    block = '''        # HTML presentation only; form action, CSRF and identity values stay upstream.
        proxy_set_header Accept-Encoding "";
        gzip off;
        sub_filter_once on;
        add_header Referrer-Policy no-referrer always;
        add_header Cache-Control "no-store" always;
        add_header X-Robots-Tag noindex always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" always;
'''
    for old, new in replacements():
        block += f'        sub_filter {quote(old)} {quote(new)};\n'
    return block

ERRORS = {
    400: ('Sign-in could not be completed', 'The sign-in request is incomplete or no longer valid.'),
    401: ('This account cannot join Tailgate', 'Use an approved company Google account. Contact support if you need help with account access.'),
    403: ('Sign-in was not accepted', 'The sign-in could not be verified. Start again using an approved company Google account.'),
    404: ('This sign-in link is unavailable', 'The link may be incomplete or no longer available.'),
    405: ('Start sign-in again', 'This step cannot be reopened from browser history or a saved link.'),
    409: ('Sign-in could not be completed', 'This sign-in request could not be completed. Check the Tailscale app before starting again.'),
    410: ('This sign-in link has expired or been used', 'If the Tailscale app shows that your device is connected, you are done. Otherwise, start sign-in again.'),
    413: ('Sign-in could not be completed', 'The sign-in request could not be accepted. Start again from the Tailscale app.'),
    414: ('This sign-in link is invalid', 'The sign-in link could not be accepted. Start again to get a new link.'),
    415: ('Sign-in could not be completed', 'The sign-in request could not be accepted. Start again from the Tailscale app.'),
    422: ('Sign-in could not be completed', 'The sign-in request could not be accepted. Start again from the Tailscale app.'),
    429: ('Please wait before trying again', 'There have been too many sign-in attempts. Wait a few minutes, then start again.'),
    **{status: ('Tailgate sign-in is temporarily unavailable', 'Wait a few minutes, then start sign-in again. Contact support if this continues.')
       for status in (500, 501, 502, 503, 504)},
}


def nginx(root, backend):
    """Intercept browser auth errors only; keep original statuses and redirects.

    The placeholder root is resolved by a hash-verified deployment installer.
    Confirmation forms, cookies and upstream CSRF guards pass through. Static
    branding fragments are replaced only in HTML, never in protocol responses.
    """
    if root != '@@PUBLIC_SITE_ROOT@@' and not re.fullmatch(r'/[A-Za-z0-9_./-]+', root):
        raise ValueError('Unsafe public-site root')
    if not re.fullmatch(r'[a-z0-9.-]+:[0-9]{1,5}', backend) or not 1 <= int(backend.rsplit(':', 1)[1]) <= 65535:
        raise ValueError('Unsafe enrollment backend')
    block = '''    # Browser sign-in only: API, Noise, DERP and health remain upstream.
    location ~ ^/(register|oidc|auth)(/|$) {
        proxy_pass http://BACKEND;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header True-Client-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_intercept_errors on;
'''.replace('BACKEND', backend)
    block += branding_nginx()
    for status in ERRORS:
        block += f'        error_page {status} /enrollment-errors/{status}.html;\n'
    block += '    }\n'
    headers = ('add_header Content-Security-Policy "default-src \'none\'; style-src \'self\'; img-src \'self\'; '
               'base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'" always; '
               'add_header X-Content-Type-Options nosniff always; add_header Referrer-Policy no-referrer always; '
               'add_header Cache-Control "no-store" always; add_header X-Robots-Tag "noindex" always; ')
    for status in ERRORS:
        block += (f'    location = /enrollment-errors/{status}.html {{ internal; root {root}; '
                  f'try_files /enrollment-errors/{status}.html =500; default_type text/html; charset utf-8; {headers}}}\n')
    return block
