"""Reject stale/tampered executable receipts before any Docker execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import docker_lab


class DockerArtifactSafety(unittest.TestCase):
    def test_each_tampered_executable_is_rejected_before_image_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); binaries=root/'binaries';binaries.mkdir()
            def put(name,value): (binaries/name).write_text(json.dumps(value))
            def sha(name):return hashlib.sha256((binaries/name).read_bytes()).hexdigest()
            for name in ('headscale','tailscale','tailscaled','lego','derper'):
                (binaries/name).write_bytes(('verified fixture '+name).encode())
            lock={'components':{
                'headscale':{'artifacts':{'linux_arm64':{'sha256':sha('headscale')}}},
                'tailscale':{'version':'test','source':'https://example.com/source',
                    'derper_build':{'go_version':'locked'},'artifacts':{'linux_arm64':{'sha256':'locked-archive'}}},
                'lego':{'version':'test','artifacts':{'linux_arm64':{'sha256':'locked-archive'}}}}}
            for component,names in [('tailscale',['tailscale','tailscaled']),('lego',['lego'])]:
                put(component+'.fetch.json',{'platform':'linux_arm64','version':'test',
                    'archive_sha256':'locked-archive','binary_sha256':{n:sha(n) for n in names}})
            put('derper.build.json',{'platform':'linux_arm64','source':'https://example.com/source',
                                    'go_version':'locked','sha256':sha('derper')})
            (root/'versions.lock.json').write_text(json.dumps(lock))
            with patch.object(docker_lab,'ROOT',root):
                self.assertEqual(docker_lab.verify_artifacts(binaries),binaries.resolve())
                for name in ('headscale','tailscale','tailscaled','lego','derper'):
                    with self.subTest(name=name):
                        original=(binaries/name).read_bytes();(binaries/name).write_bytes(b'corrupt')
                        with patch.object(docker_lab,'command') as command:
                            with self.assertRaises(ValueError):docker_lab.build_image(binaries,root/'image','unused')
                            command.assert_not_called()
                        (binaries/name).write_bytes(original)
                receipt=json.loads((binaries/'tailscale.fetch.json').read_text())
                receipt['archive_sha256']='unlocked';put('tailscale.fetch.json',receipt)
                with self.assertRaises(ValueError):docker_lab.verify_artifacts(binaries)


if __name__=='__main__':unittest.main()
