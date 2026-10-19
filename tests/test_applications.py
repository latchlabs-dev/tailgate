import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('applications', ROOT / 'tools' / 'applications.py')
applications = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ROOT / 'tools'))
spec.loader.exec_module(applications)


class ApplicationDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.app = applications.read_json(ROOT / 'examples' / 'application.json')
        self.platform = applications.read_json(ROOT / 'examples' / 'application-platform.json')

    def test_example_renders_private_runtime_and_no_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'bundle'
            plan = applications.render(self.app, self.platform, bundle)
            self.assertEqual(plan['phases'], list(applications.PHASES))
            self.assertIn('deny-all', plan['network_access'])
            compose = (bundle / 'compose.yaml').read_text()
            self.assertIn('10.203.120.1:18080:8080', compose)
            self.assertIn('@sha256:' + '0' * 64, compose)
            self.assertNotIn('password', compose.lower())
            nginx = (bundle / 'private-nginx.conf').read_text()
            self.assertIn('listen 100.120.0.10:443 ssl;', nginx)
            self.assertIn('proxy_pass http://10.203.120.1:18080;', nginx)
            self.assertEqual(applications.read_json(bundle / 'plan.json'), plan)
            with self.assertRaisesRegex(ValueError, 'output must be empty'):
                applications.render(self.app, self.platform, bundle)

    def test_rejects_unsafe_or_ambiguous_inputs(self):
        changes = [
            ('inline secret', lambda a, p: a['database'].update(password='literal')),
            ('unpinned image', lambda a, p: a['runtime'].update(image='registry.example.com/apps/sample-app:latest')),
            ('external registry', lambda a, p: a['runtime'].update(image='elsewhere.example.com/apps/sample-app@sha256:' + '0'*64)),
            ('public ingress', lambda a, p: a['ingress'].update(address='198.51.100.9')),
            ('wrong namespace', lambda a, p: a['ingress'].update(hostname='public.example.com')),
            ('shell-ish health', lambda a, p: a['runtime'].update(health_path='/health;id')),
            ('bad URL', lambda a, p: a['identity'].update(redirect_uris=['http://sample.apps.example.com/auth/callback'])),
            ('missing management URL', lambda a, p: p['identity'].pop('management_url')),
            ('insecure management URL', lambda a, p: p['identity'].update(management_url='http://zitadel.example.com')),
            ('management URL path', lambda a, p: p['identity'].update(management_url='https://zitadel.example.com/redirect')),
            ('management URL query', lambda a, p: p['identity'].update(management_url='https://zitadel.example.com?target=other')),
            ('nginx directive injection', lambda a, p: p['ingress'].update(certificate_root='/tmp/certs;\nlisten 0.0.0.0:443;')),
            ('missing client dependency', lambda a, p: p['ingress'].pop('client_unit')),
            ('unsafe client unit', lambda a, p: p['ingress'].update(client_unit='client.service\nExecStart=/bin/sh')),
            ('duplicate unit', lambda a, p: p['ingress'].update(client_unit=p['ingress']['network_unit'])),
            ('unknown platform field', lambda a, p: p.update(credential='literal'))
        ]
        for title, change in changes:
            with self.subTest(title=title):
                app, platform = copy.deepcopy(self.app), copy.deepcopy(self.platform)
                change(app, platform)
                with self.assertRaises((ValueError, KeyError)):
                    applications.validate(app, platform)

    def test_template_and_tamper_block_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'bundle'
            plan = applications.render(self.app, self.platform, bundle)
            with self.assertRaisesRegex(ValueError, 'template'):
                applications.apply(self.app, self.platform, bundle, plan['sha256'], ROOT)
            app, platform = copy.deepcopy(self.app), copy.deepcopy(self.platform)
            app['template'] = False
            app['runtime']['image'] = app['runtime']['image'][:-64] + '1' * 64
            platform['status'] = 'ready'
            with self.assertRaisesRegex(ValueError, 'plan SHA'):
                applications.apply(app, platform, bundle, plan['sha256'], ROOT)

    def test_apply_runs_each_phase_once_and_resumes_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = root / 'adapter.py'
            adapter.write_text(
                'import argparse,json,pathlib,sys\n'
                'p=argparse.ArgumentParser();p.add_argument("--plan");p.add_argument("--phase");a=p.parse_args()\n'
                'log=pathlib.Path(a.plan).parent/"calls.txt"\n'
                'with log.open("a") as f:f.write(a.phase+"\\n")\n'
                'if a.phase=="identity" and (log.parent/"fail").exists():sys.exit(7)\n')
            app, platform = copy.deepcopy(self.app), copy.deepcopy(self.platform)
            app['template'] = False
            app['runtime']['image'] = app['runtime']['image'][:-64] + '1' * 64
            platform['status'] = 'ready'
            platform['adapter'] = [sys.executable, str(adapter)]
            bundle = root / 'bundle'
            plan = applications.render(app, platform, bundle)
            (bundle / 'fail').touch()
            with self.assertRaises(subprocess.CalledProcessError):
                applications.apply(app, platform, bundle, plan['sha256'], root)
            self.assertEqual(applications.read_json(bundle / 'receipt.json')['completed'],
                             ['preflight', 'database'])
            (bundle / 'fail').unlink()
            receipt = applications.apply(app, platform, bundle, plan['sha256'], root)
            self.assertEqual(receipt['completed'], list(applications.PHASES))
            applications.apply(app, platform, bundle, plan['sha256'], root)
            calls = (bundle / 'calls.txt').read_text().splitlines()
            self.assertEqual(calls, ['preflight', 'database', 'identity', 'identity',
                                     'runtime', 'ingress', 'verify'])
            self.assertEqual((bundle / 'receipt.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
