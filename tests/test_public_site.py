import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('public_site',ROOT/'tools/render-public-site.py')
site=importlib.util.module_from_spec(spec);spec.loader.exec_module(site)


class PublicSiteTest(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'examples/public-site.json').read_text())

    def render(self,c):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        root=Path(directory.name);config=root/'config.json';config.write_text(json.dumps(c))
        output=root/'site';receipt=site.render(config,output)
        return output,receipt

    def test_complete_static_pages_and_matching_privacy_links(self):
        output,receipt=self.render(self.config)
        expected={'index.html','privacy/index.html','terms/index.html','support/index.html','assets/site.css','assets/enrollment.css','assets/tailgate-logo.svg','assets/tailgate-logo.png'}
        expected.update(f'enrollment-errors/{status}.html' for status in site.enrollment.ERRORS)
        self.assertEqual(set(receipt['files']),expected)
        for filename in ('index.html','privacy/index.html','terms/index.html','support/index.html'):
            text=(output/filename).read_text()
            self.assertIn('href="/privacy"',text)
            self.assertIn('href="/terms"',text)
            self.assertIn('href="/support"',text)
            self.assertIn('/assets/site.css',text)
            self.assertNotIn('<script',text)
            self.assertNotIn('<style',text)
            self.assertNotIn('/api/',text)
            self.assertNotIn('analytics',text if filename=='index.html' else '')
        home=(output/'index.html').read_text()
        self.assertNotIn('Headscale',home)
        self.assertNotIn('Tailscale',home)
        self.assertIn('Get started',home)
        self.assertIn('Admin login',home)
        self.assertIn('An administrator will review your request',home)
        for path in output.rglob('*.html'):
            self.assertNotIn('mailto:',path.read_text())
            self.assertNotIn('@',path.read_text())

    def test_signin_errors_have_recovery_without_replaying_auth_or_exposing_upstream(self):
        output, receipt = self.render(self.config)
        for status in receipt['enrollment_error_statuses']:
            body = (output/f'enrollment-errors/{status}.html').read_text()
            self.assertIn('TG-SIGNIN-'+str(status), body)
            self.assertIn('complete all steps in the same browser', body)
            self.assertIn('content="noindex"', body)
            for unsafe in ('Headscale', 'headscale', 'hskey-', '/oidc/', '/register/', '<script'):
                self.assertNotIn(unsafe, body)

    def test_nginx_error_handling_is_limited_to_browser_auth(self):
        block = site.enrollment.nginx('/public/site', '127.0.0.1:18090')
        self.assertIn('location ~ ^/(register|oidc|auth)(/|$)', block)
        self.assertEqual(block.count('proxy_intercept_errors on;'), 1)
        self.assertEqual(block.count('internal;'), len(site.enrollment.ERRORS))
        for unsafe in ('location / {', 'location /api', 'location /ts2021', 'location /derp', 'location /health'):
            self.assertNotIn(unsafe, block)
        for root, backend in [('/site; injected', '127.0.0.1:18090'), ('/site', 'host:99999'), ('/site', 'host:80; injected')]:
            with self.assertRaises(ValueError): site.enrollment.nginx(root, backend)

    def test_branding_replacements_cannot_modify_authentication_fields(self):
        action='/register/confirm/hskey-authreq-DISPOSABLE-FIXTURE'
        form=f'<form action="{action}" method="POST"><input name="headscale_register_confirm" type="hidden" value="Headscale-CSRF-FIXTURE"><button type="submit">Confirm registration</button></form>'
        details='<table><tr><td>Hostname</td><td>Headscale &lt;script&gt;device&lt;/script&gt;</td></tr><tr><td>Registered to</td><td>Alex Headscale</td></tr><tr><td>OS</td><td>Registered to</td></tr></table>'
        body='<title>Headscale - Confirm node registration</title>'+site.enrollment.UPSTREAM_MAIN+details+form+site.enrollment.UPSTREAM_FOOTER
        for old,new in site.enrollment.replacements():body=body.replace(old,new,1)
        self.assertIn('Confirm your device · Tailgate',body)
        self.assertIn('Tailgate home',body)
        self.assertNotIn('Powered by',body)
        self.assertIn(f'action="{action}"',body)
        self.assertIn('name="headscale_register_confirm"',body)
        self.assertIn('value="Headscale-CSRF-FIXTURE"',body)
        self.assertIn('Headscale &lt;script&gt;device&lt;/script&gt;',body)
        self.assertIn('Alex Headscale',body)
        self.assertIn('<td>OS</td><td>Registered to</td>',body)
        self.assertNotIn('<script>',body)
        self.assertIn('Add this device</button>',body)
        config=site.enrollment.branding_nginx()
        self.assertNotIn("sub_filter 'Headscale'",config)
        self.assertIn('proxy_set_header Accept-Encoding "";',config)

    def test_supplied_text_is_escaped_and_cannot_create_scripts(self):
        c=copy.deepcopy(self.config);c['operator_name']='Example <script>alert(1)</script>'
        c['privacy_sections'][0]['paragraphs']=['<img src=x onerror=alert(1)> & "private"']
        output,_=self.render(c);text=(output/'privacy/index.html').read_text()
        self.assertNotIn('<script',text);self.assertNotIn('<img src=x',text)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;',text)
        self.assertIn('&lt;script&gt;',text)

    def test_logo_is_valid_small_square_png_with_checked_chunks(self):
        output,_=self.render(self.config);data=(output/'assets/tailgate-logo.png').read_bytes()
        self.assertLess(len(data),1048576);self.assertEqual(data[:8],b'\x89PNG\r\n\x1a\n')
        offset=8;image=[]
        while offset<len(data):
            size=struct.unpack('>I',data[offset:offset+4])[0];kind=data[offset+4:offset+8]
            payload=data[offset+8:offset+8+size];crc=struct.unpack('>I',data[offset+8+size:offset+12+size])[0]
            self.assertEqual(crc,zlib.crc32(kind+payload)&0xffffffff)
            if kind==b'IHDR':self.assertEqual(struct.unpack('>IIBBBBB',payload),(120,120,8,6,0,0,0))
            if kind==b'IDAT':image.append(payload)
            offset+=size+12
        self.assertEqual(len(zlib.decompress(b''.join(image))),120*(1+120*4))

    def test_rejects_bad_origins_contacts_incomplete_and_duplicate_config(self):
        for key,value in [('site_origin','javascript:alert(1)'),('site_origin','http://example.com'),('site_origin','https://user:password@example.com'),('site_origin','https://example.com/path'),('site_origin','https://127.0.0.1'),('admin_url','https://control.example.com'),('availability','Contact a@example.com'),('schema_version',True)]:
            with self.subTest(key=key,value=value):
                c=copy.deepcopy(self.config);c[key]=value
                with self.assertRaises(ValueError):site.validate(c)
        c=copy.deepcopy(self.config);del c['privacy_sections']
        with self.assertRaises(ValueError):site.validate(c)
        with self.assertRaises(ValueError):json.loads('{"a":1,"a":2}',object_pairs_hook=site.unique_pairs)

    def test_existing_output_is_not_silently_overwritten_or_published(self):
        output,_=self.render(self.config);(output/'unexpected-secret.json').write_text('unrelated')
        root=output.parent;config=root/'config.json'
        with self.assertRaises(ValueError):site.render(config,output)
        self.assertEqual((output/'unexpected-secret.json').read_text(),'unrelated')


if __name__=='__main__':unittest.main()
