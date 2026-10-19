import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import io

ROOT = Path(__file__).resolve().parents[1]
MODULE = importlib.util.spec_from_file_location('tailgate', ROOT/'tools/tailgate.py')
tailgate = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(tailgate)


class SafetyContract(unittest.TestCase):
    def setUp(self):
        self.spec = tailgate.read_json(ROOT/'examples/pilot.json')

    def rejects(self, change):
        change(self.spec)
        with self.assertRaises(ValueError): tailgate.validate(self.spec)

    def test_missing_policy_cannot_enable_allow_all(self):
        self.rejects(lambda s: s.update(policy={}))

    def test_partitioned_pools_are_rendered_and_default_is_unchanged(self):
        for name, expected in [('pilot', dict(tailgate.SUPPORTED_PREFIXES, allocation='sequential')),
                               ('partitioned', {'v4':'100.80.0.0/16',
                                                'v6':'fd7a:115c:a1e0:8000::/64',
                                                'allocation':'sequential'})]:
            with self.subTest(example=name), tempfile.TemporaryDirectory() as d:
                tailgate.render(tailgate.read_json(ROOT/'examples'/f'{name}.json'), d)
                self.assertEqual(expected, tailgate.read_json(Path(d)/'headscale.json')['prefixes'])

    def test_invalid_allocation_pools_are_rejected_before_render(self):
        cases = [None, [], {}, {'v4':'100.80.0.0/16'},
                 {'v4':'10.80.0.0/16', 'v6':'fd7a:115c:a1e0:8000::/64'},
                 {'v4':'100.80.0.1/16', 'v6':'fd7a:115c:a1e0:8000::/64'},
                 {'v4':'100.80.0.0/16', 'v6':'fd00:8000::/64'},
                 {'v4':'100.80.0.0/16', 'v6':'100.81.0.0/16'},
                 {'v4':'100.80.0.0/32', 'v6':'fd7a:115c:a1e0:8000::/64'},
                 {'v4':'100.80.0.0/16', 'v6':'fd7a:115c:a1e0:8000::/64', 'allocation':'unknown'},
                 {'v4':'100.80.0.0/16', 'v6':'fd7a:115c:a1e0:8000::/64', 'extra':True}]
        for prefixes in cases:
            with self.subTest(prefixes=prefixes):
                self.spec['controller']['prefixes'] = prefixes
                with self.assertRaises(ValueError): tailgate.validate(self.spec)

    def test_services_must_belong_to_selected_allocation_pool(self):
        self.spec = tailgate.read_json(ROOT/'examples/company.json')
        self.spec['controller']['prefixes'] = {'v4':'100.80.0.0/16', 'v6':'fd7a:115c:a1e0:8000::/64'}
        with self.assertRaisesRegex(ValueError, 'mesh IP'): tailgate.validate(self.spec)
        self.spec['services'][0]['address'] = '100.80.0.20'
        tailgate.validate(self.spec)

    def test_database_policy_is_explicit_and_keeps_initializer(self):
        self.spec['policy_storage']='database'
        with tempfile.TemporaryDirectory() as d:
            tailgate.render(self.spec,d)
            self.assertEqual({'mode':'database'},tailgate.read_json(Path(d)/'headscale.json')['policy'])
            self.assertEqual({'grants':[]},tailgate.read_json(Path(d)/'policy.json'))
        self.rejects(lambda s:s.update(policy_storage='unknown'))
        self.rejects(lambda s:s.update(policy={'grants':None}))

    def test_missing_google_filter_is_rejected(self):
        self.rejects(lambda s: s['identity'].update(allowed_domains=[], allowed_users=[]))

    def test_inline_secret_is_rejected(self):
        self.rejects(lambda s: s['identity'].update(client_secret='test-secret'))

    def test_public_controller_bind_is_rejected(self):
        self.rejects(lambda s: s['controller'].update(listen='0.0.0.0:8080'))

    def test_hostname_injection_is_rejected(self):
        self.rejects(lambda s: s['controller'].update(hostname='example.com; return 200;'))

    def test_collision_of_http_and_metrics_is_rejected(self):
        self.rejects(lambda s: s['controller'].update(metrics=s['controller']['listen']))

    def test_alternate_port_notation_cannot_bypass_collision_check(self):
        self.rejects(lambda s: s['controller'].update(metrics='127.0.0.1:018090'))

    def test_same_destination_different_audiences_is_rejected(self):
        self.spec = tailgate.read_json(ROOT/'examples/company.json')
        other = dict(self.spec['services'][0], name='finance.apps.example.com', audience='finance')
        self.rejects(lambda s: s['services'].append(other))

    def test_public_app_and_remote_plaintext_backend_are_rejected(self):
        self.spec = tailgate.read_json(ROOT/'examples/company.json')
        self.rejects(lambda s: s['services'][0].update(address='203.0.113.1'))
        self.spec = tailgate.read_json(ROOT/'examples/company.json')
        self.rejects(lambda s: s['services'][0].update(backend='192.168.1.2:3000'))

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'input.json'; p.write_text('{"grants":[],"grants":[{}]}')
            with self.assertRaises(ValueError): tailgate.read_json(p)

    def test_company_output_keeps_private_listeners_and_owned_relays(self):
        self.spec = tailgate.read_json(ROOT/'examples/company.json')
        with tempfile.TemporaryDirectory() as d:
            tailgate.render(self.spec, d)
            config = tailgate.read_json(Path(d)/'headscale.json')
            self.assertEqual([], config['derp']['urls'])
            self.assertFalse(config['derp']['server']['enabled'])
            self.assertEqual({'grants': self.spec['policy']['grants'],
                              'groups': self.spec['policy']['groups'],
                              'tagOwners': self.spec['policy']['tagOwners']},
                             tailgate.read_json(Path(d)/'policy.json'))
            app = (Path(d)/'dashboard.apps.example.com.nginx.conf').read_text()
            self.assertIn('listen 100.64.0.20:443 ssl;', app)
            self.assertNotIn('listen 80', app)
            self.assertIn('-verify-client-url-fail-open=false', (Path(d)/'relay-a.service').read_text())
            self.assertIn('deny all;', (Path(d)/'controller.nginx.conf').read_text())

    def test_draft_is_marked_and_cannot_admit_arbitrary_google_users(self):
        self.spec['identity'] = {'client_id':None, 'allowed_domains':[], 'allowed_users':[]}
        with tempfile.TemporaryDirectory() as d:
            tailgate.render(self.spec, d, draft=True)
            self.assertTrue(tailgate.read_json(Path(d)/'manifest.json')['draft'])
            self.assertEqual(['unconfigured@invalid.example'],
                             tailgate.read_json(Path(d)/'headscale.json')['oidc']['allowed_users'])

    def test_render_never_overwrites_existing_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            tailgate.render(self.spec, d)
            with self.assertRaises(ValueError): tailgate.render(self.spec, d)

    def test_corrupt_upstream_download_never_becomes_executable(self):
        with tempfile.TemporaryDirectory() as d, patch.object(tailgate.urllib.request,'urlopen',return_value=io.BytesIO(b'corrupt')):
            with self.assertRaisesRegex(ValueError,'checksum mismatch'):
                tailgate.fetch('headscale','linux_arm64',d)
            self.assertFalse((Path(d)/'headscale').exists())

    def test_unaged_release_is_rejected_before_download(self):
        lock=tailgate.read_json(ROOT/'versions.lock.json')
        lock['components']['headscale']['published_at']='2099-01-01T00:00:00Z'
        with tempfile.TemporaryDirectory() as d, patch.object(tailgate,'read_json',return_value=lock), patch.object(tailgate.urllib.request,'urlopen') as download:
            with self.assertRaisesRegex(ValueError,'too new'):tailgate.fetch('headscale','linux_arm64',d)
            download.assert_not_called()


if __name__ == '__main__': unittest.main()
