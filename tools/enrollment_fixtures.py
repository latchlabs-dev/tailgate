"""Fictitious pinned-template HTML for proxy tests; never a live Google session."""
import html
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('enrollment', ROOT/'components/public-site/enrollment.py')
enrollment = importlib.util.module_from_spec(spec); spec.loader.exec_module(enrollment)


def page(title, content):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
            '<link href="/favicon.ico" rel="icon">'
            '<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect">'
            '<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">'
            '<title>'+title+'</title></head>'
            '<body style="align-items: center; background-color: var(--hs-bg); display: flex; flex-direction: column; min-height: 100vh; padding: 3rem 1.5rem;" translate="no">'
            +enrollment.UPSTREAM_MAIN+'<svg class="headscale-logo" width="320" height="100"><text y="80">headscale</text></svg>'
            +content+'<p class="fixture-disclosure">Local test preview · fictitious device and identity</p>'
            +enrollment.UPSTREAM_FOOTER+'</main></body></html>')


def confirmation():
    rows=[('Hostname','Example Laptop'),('OS','macOS'),('Machine key','[demo1]'),('Registered to','Alex Example')]
    table='<table>'+''.join('<tr><td style="font-weight: 600; white-space: nowrap; color: var(--md-default-fg-color--light);">'+key+'</td><td>'+html.escape(value)+'</td></tr>' for key,value in rows)+'</table>'
    return page('Headscale - Confirm node registration',
        '<h2>Confirm node registration</h2><p>A device is asking to be added to your tailnet. Please review the details below and confirm that this device is yours.</p>'+table+
        '<form action="/register/confirm/test" method="POST"><input name="headscale_register_confirm" type="hidden" value="FIXTURE-CSRF"><button type="submit">Confirm registration</button></form>'
        '<p>If you do not recognise this device, close this window. The registration request will expire automatically.</p>')


def success(kind):
    title,heading,verb,message={
        'registered':('Headscale - Node Registered','Node registered','Registered','You can now close this window.'),
        'reauthenticated':('Headscale - Node Reauthenticated','Node reauthenticated','Reauthenticated','You can now close this window.'),
        'ssh':('Headscale - SSH Session Authorized','SSH session authorized','Authorized','You may return to your terminal.'),
    }[kind]
    box='<div role="status" style="padding: 24px; border: 1px solid var(--hs-border); border-radius: 8px; background: var(--hs-success-bg);"><strong style="color: var(--hs-success); display: block; font-size: 22px;">'+heading+'</strong>'+verb+' as <strong>Alex Example</strong>. '+message+'</div>'
    return page(title,box+'<h2>Getting started</h2><p>Check out the documentation to learn more about headscale and Tailscale:</p>'
        '<ul><li><a href="https://headscale.net/stable/" rel="noreferrer noopener" target="_blank">Headscale documentation</a></li>'
        '<li><a href="https://tailscale.com/docs" rel="noreferrer noopener" target="_blank">Tailscale docs</a></li></ul>')


def write(root):
    root=Path(root);root.mkdir(exist_ok=True)
    (root/'confirm.html').write_text(confirmation())
    for kind in ('registered','reauthenticated','ssh'):
        (root/(kind+'.html')).write_text(success(kind))
