#!/usr/bin/env python3
"""Render public Tailgate information pages from explicitly supplied facts.

No network, packages, live inventories, secrets, OAuth mutations or deployment.
"""
import argparse
import datetime
import hashlib
import html
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shutil
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT/'components/public-site'
spec = importlib.util.spec_from_file_location('enrollment', COMPONENT/'enrollment.py')
enrollment = importlib.util.module_from_spec(spec); spec.loader.exec_module(enrollment)
FIELDS = {'schema_version', 'site_origin', 'admin_url', 'operator_name',
          'effective_date', 'service_stage', 'availability',
          'privacy_sections', 'terms_sections', 'support_sections'}


def text(value, label, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value)>limit or any(ord(c)<32 and c not in '\n\t' for c in value):
        raise ValueError('Invalid '+label)
    return value


def origin(value, label):
    text(value, label, 512)
    u = urlsplit(value)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):
        raise ValueError(label+' must be an exact HTTPS origin')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', u.hostname) or '.' not in u.hostname:
        raise ValueError(label+' needs a DNS hostname')
    try:
        ipaddress.ip_address(u.hostname)
    except ValueError:
        pass
    else:
        raise ValueError(label+' needs a DNS hostname')
    if u.port not in (None,443) or u.hostname.endswith('.localhost'):
        raise ValueError(label+' requires the default HTTPS port')
    return 'https://'+u.hostname


def unique_pairs(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('Duplicate configuration field')
        result[k]=v
    return result


def validate(c):
    if not isinstance(c,dict) or set(c)!=FIELDS or type(c['schema_version']) is not int or c['schema_version']!=2:
        raise ValueError('Invalid public-site configuration fields/version')
    for key in ('site_origin','admin_url'):c[key]=origin(c[key],key)
    if c['site_origin']==c['admin_url']:raise ValueError('Admin needs a separate origin')
    for key in ('operator_name','availability'):text(c[key],key,1000)
    if re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', json.dumps(c)) or 'mailto:' in json.dumps(c).lower():
        raise ValueError('Public pages must not expose email addresses')
    if c['service_stage'] not in ('pilot','production'):raise ValueError('Invalid service stage')
    if not isinstance(c['effective_date'],str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',c['effective_date']):raise ValueError('Invalid effective date')
    datetime.date.fromisoformat(c['effective_date'])
    for key in ('privacy_sections','terms_sections','support_sections'):
        sections=c[key]
        if not isinstance(sections,list) or not 1<=len(sections)<=24:raise ValueError('Missing '+key)
        for section in sections:
            if not isinstance(section,dict) or set(section)!={'title','paragraphs'}:raise ValueError('Invalid page section')
            text(section['title'],'section title',120)
            if not isinstance(section['paragraphs'],list) or not 1<=len(section['paragraphs'])<=12:raise ValueError('Missing section text')
            for p in section['paragraphs']:text(p,'paragraph')
    return c


def escape(value):return html.escape(value,quote=True)


def navigation():
    return '<nav aria-label="Information"><a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/support">Support</a></nav>'


def page(c,title,description,content,path):
    home=escape(c['site_origin']);canonical=home+path
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · Tailgate</title><meta name="description" content="{escape(description)}">
<link rel="canonical" href="{canonical}"><link rel="icon" href="/assets/tailgate-logo.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/site.css"></head>
<body><header><a class="brand" href="/"><img src="/assets/tailgate-logo.svg" alt="" width="38" height="38">Tailgate</a>{navigation()}</header>
<main>{content}</main><footer><span>Tailgate · Operated by {escape(c['operator_name'])}</span>{navigation()}</footer></body></html>\n'''


def home(c):
    content=f'''<span class="eyebrow">Company access, made simple</span>
<h1>Your work. Within reach.</h1>
<p class="lead">Tailgate helps your team access the tools they need for work.</p>
<div class="actions"><a class="button" href="{escape(c['admin_url'])}/start">Get started</a><a class="button secondary" href="{escape(c['admin_url'])}">Admin login</a></div>
<p class="meta">Sign in with your company account to request access. An administrator will review your request.</p>'''
    return page(c,'Company access','Tailgate helps your team access the tools they need for work.',content,'/')


def document(c,key,title,intro):
    sections=''.join('<section><h2>'+escape(s['title'])+'</h2>'+''.join('<p>'+escape(p)+'</p>' for p in s['paragraphs'])+'</section>' for s in c[key])
    content=f'<article class="document"><h1>{title}</h1><p class="lead">{intro}</p><p class="meta">Effective {escape(c["effective_date"])} · {escape(c["operator_name"])}</p>{sections}</article>'
    return page(c,title,intro,content,'/'+key.replace('_sections',''))


def enrollment_error(c, status):
    title, message = enrollment.ERRORS[status]
    content = f'''<article class="signin-error" aria-labelledby="signin-title">
<span class="eyebrow">Tailgate sign-in</span><h1 id="signin-title">{escape(title)}</h1>
<p class="lead">{escape(message)}</p>
<section class="recovery"><h2>How to continue</h2>
<p>If your device is not connected, return to the Tailscale app and start sign-in again, or rerun the command that opened this page. Open the new link and complete all steps in the same browser.</p>
<p>Allow cookies for this site during sign-in. Keep this browser open until sign-in finishes. If it fails, get a new link instead of refreshing this page.</p></section>
<div class="actions"><a class="button" href="/support">Get help</a><a class="button secondary" href="/">Tailgate home</a></div>
<p class="meta">Support code: <strong>TG-SIGNIN-{status}</strong></p></article>'''
    result = page(c, title, 'Help completing Tailgate sign-in.', content, f'/enrollment-errors/{status}.html')
    return result.replace('<meta name="description"', '<meta name="robots" content="noindex"><meta name="description"', 1)


def render(config,output):
    config=Path(config);output=Path(output)
    if config.stat().st_size>128*1024:raise ValueError('Public configuration exceeds its limit')
    c=validate(json.loads(config.read_text(encoding='utf-8'),object_pairs_hook=unique_pairs))
    # Fixed output filenames; user data cannot select paths or create scripts.
    if output.exists() and any(output.iterdir()):raise ValueError('Output must be a fresh empty staging directory')
    output.mkdir(parents=True,exist_ok=True)
    assets=output/'assets';assets.mkdir(exist_ok=True)
    for name in ('tailgate-logo.svg','tailgate-logo.png'):
        shutil.copyfile(COMPONENT/'assets'/name,assets/name)
    shutil.copyfile(COMPONENT/'site.css',assets/'site.css')
    shutil.copyfile(COMPONENT/'enrollment.css',assets/'enrollment.css')
    (output/'index.html').write_text(home(c),encoding='utf-8')
    specs=[('privacy_sections','Privacy policy','How Tailgate handles your information.'),
           ('terms_sections','Terms of use','Using Tailgate for work.'),
           ('support_sections','Support','Help with Tailgate.')]
    for key,title,intro in specs:
        directory=output/key.replace('_sections','');directory.mkdir(exist_ok=True)
        (directory/'index.html').write_text(document(c,key,title,intro),encoding='utf-8')
    errors = output/'enrollment-errors'; errors.mkdir(exist_ok=True)
    for status in enrollment.ERRORS:
        (errors/f'{status}.html').write_text(enrollment_error(c, status), encoding='utf-8')
    files={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob('*')) if p.is_file()}
    return {'pages':['/','/privacy','/terms','/support'],'assets':'/assets/',
            'enrollment_error_statuses':list(enrollment.ERRORS),'files':files}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:receipt=render(args.config,args.output)
    except (ValueError,OSError) as exc:
        # Avoid echoing confidential or malformed configuration contents.
        parser.exit(1,'Public-site rendering failed: '+type(exc).__name__+'\n')
    print(json.dumps(receipt,indent=2,sort_keys=True))
