import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import gateway_image


class GatewayImageSafety(unittest.TestCase):
    def fixture(self,root):
        source=root/'components/gateway';source.mkdir(parents=True)
        (source/'main.go').write_text('package main\n')
        artifacts=root/'artifacts';artifacts.mkdir()
        digests={}
        for name in ('tailscale','tailscaled','tailgate-gateway'):
            (artifacts/name).write_text(name);digests[name]=hashlib.sha256(name.encode()).hexdigest()
        lock={'minimum_release_age_days':7,'components':{'tailscale':{'version':'1.102.5',
              'artifacts':{'linux_arm64':{'sha256':'archive'}},'derper_build':{'go_version':'1.27.1'}}},
              'validation':{'gateway_base':{'created_at':'2020-01-01T00:00:00Z','image':'example@sha256:abc'}}}
        (root/'versions.lock.json').write_text(json.dumps(lock))
        (artifacts/'tailscale.fetch.json').write_text(json.dumps({'platform':'linux_arm64','version':'1.102.5',
            'archive_sha256':'archive','binary_sha256':{n:digests[n] for n in ('tailscale','tailscaled')}}))
        (artifacts/'tailgate-gateway.receipt.json').write_text(json.dumps({'platform':'linux_arm64','go_version':'1.27.1',
            'sha256':digests['tailgate-gateway'],'source_files':{'main.go':hashlib.sha256((source/'main.go').read_bytes()).hexdigest()}}))
        return artifacts

    def test_verified_context_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=self.fixture(root)
            (a/'private-key').write_text('DO NOT COPY')
            with patch.object(gateway_image,'ROOT',root):gateway_image.prepare(a,'linux_arm64',root/'out')
            self.assertEqual({p.name for p in (root/'out').iterdir()},
                             {'tailscale','tailscaled','tailgate-gateway','Dockerfile','receipt.json'})

    def test_binary_and_source_tampering_rejected_before_output(self):
        for target in ('artifacts/tailscaled','components/gateway/main.go'):
            with self.subTest(target=target),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);a=self.fixture(root);(root/target).write_text('changed')
                with patch.object(gateway_image,'ROOT',root),self.assertRaises(ValueError):
                    gateway_image.prepare(a,'linux_arm64',root/'out')
                self.assertFalse((root/'out').exists())

    def test_receipt_cannot_copy_arbitrary_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=self.fixture(root);p=a/'tailscale.fetch.json';r=json.loads(p.read_text())
            r['binary_sha256']['../private-key']='x';p.write_text(json.dumps(r))
            with patch.object(gateway_image,'ROOT',root),self.assertRaises(ValueError):
                gateway_image.prepare(a,'linux_arm64',root/'out')
            self.assertFalse((root/'out').exists())
