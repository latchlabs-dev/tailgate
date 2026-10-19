#!/usr/bin/env python3
"""Prepare a digest-pinned gateway image context from verified local artifacts."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
from tailgate import ROOT, read_json


def prepare(artifacts, platform, output):
    artifacts, output = Path(artifacts).resolve(), Path(output).resolve()
    if output.exists(): raise ValueError('Output must not exist')
    lock = read_json(ROOT/'versions.lock.json')
    entry = lock['components']['tailscale']
    receipt = read_json(artifacts/'tailscale.fetch.json')
    if (receipt['platform'] != platform or receipt['version'] != entry['version'] or
            receipt['archive_sha256'] != entry['artifacts'][platform]['sha256']):
        raise ValueError('Client receipt differs from lock')
    binaries = dict(receipt['binary_sha256'])
    gateway = read_json(artifacts/'tailgate-gateway.receipt.json')
    source = ROOT/'components/gateway'
    actual = {str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(source.rglob('*')) if p.is_file()}
    if (gateway['platform'] != platform or gateway['source_files'] != actual or
            gateway['go_version'] != entry['derper_build']['go_version']):
        raise ValueError('Gateway differs from current source/toolchain')
    binaries['tailgate-gateway'] = gateway['sha256']
    if set(binaries) != {'tailscale','tailscaled','tailgate-gateway'}:
        raise ValueError('Unexpected binary receipt entries')
    for name, digest in binaries.items():
        if hashlib.sha256((artifacts/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Binary differs from receipt: '+name)
    base = lock['validation']['gateway_base']
    created = dt.datetime.fromisoformat(base['created_at'].replace('Z','+00:00'))
    if dt.datetime.now(dt.timezone.utc)-created < dt.timedelta(days=lock['minimum_release_age_days']):
        raise ValueError('Gateway base image is too new')
    output.mkdir(parents=True, mode=0o700)
    for name in binaries:
        shutil.copyfile(artifacts/name,output/name);(output/name).chmod(0o755)
    (output/'Dockerfile').write_text('FROM '+base['image']+'\n'
        'COPY tailscale tailscaled /usr/local/bin/\nCOPY tailgate-gateway /bin/\n'
        'USER 0:0\nENTRYPOINT ["/bin/tailgate-gateway"]\n')
    proof = {'platform':platform,'base':base,'binary_sha256':binaries,'gateway_build':gateway}
    (output/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    return {'platform':platform,'output':str(output),'binary_sha256':binaries,'base_image':base['image']}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts',required=True);p.add_argument('--platform',required=True,choices=['linux_arm64','linux_amd64'])
    p.add_argument('--output',required=True);a=p.parse_args()
    print(json.dumps(prepare(a.artifacts,a.platform,a.output),indent=2))
