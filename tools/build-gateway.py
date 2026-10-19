#!/usr/bin/env python3
"""Build the Go migration gateway offline with the locked toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tailgate import ROOT, read_json


def build(platform, output):
    version = read_json(ROOT/'versions.lock.json')['components']['tailscale']['derper_build']['go_version']
    if subprocess.check_output(['go', 'version'], text=True).split()[2] != 'go'+version:
        raise ValueError('Installed Go differs from locked toolchain')
    source = ROOT/'components/gateway'
    output = Path(output).resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    goos, goarch = platform.split('_')
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off',
               CGO_ENABLED='0', GOOS=goos, GOARCH=goarch)
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(output), '.'],
                   cwd=source, env=env, check=True)
    receipt = {'component':'tailgate-gateway', 'platform':platform, 'go_version':version,
               'dependencies':'Go standard library only',
               'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
               'source_files':{str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(source.rglob('*')) if p.is_file()}}
    output.with_name(output.name+'.receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({k:v for k,v in receipt.items() if k!='source_files'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['linux_arm64','linux_amd64'])
    parser.add_argument('--output', required=True)
    args = parser.parse_args(); build(args.platform, args.output)
