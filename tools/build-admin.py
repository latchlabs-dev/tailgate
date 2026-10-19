#!/usr/bin/env python3
"""Build the first-party UI using the existing locked Go toolchain, without downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tailgate import ROOT, read_json


def build(platform, output):
    go_version=read_json(ROOT/'versions.lock.json')['components']['tailscale']['derper_build']['go_version']
    actual=subprocess.check_output(['go','version'],text=True).split()[2]
    if actual!='go'+go_version:raise ValueError('Installed Go differs from locked toolchain')
    goos,goarch=platform.split('_');source=ROOT/'components/admin';output=Path(output).resolve()
    output.parent.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,GOTOOLCHAIN='local',GOWORK='off',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0',GOOS=goos,GOARCH=goarch)
    subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(output),'.'],cwd=source,env=env,check=True)
    files={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.rglob('*')) if p.is_file()}
    receipt={'schema_version':1,'component':'tailgate-admin','platform':platform,'go_version':go_version,
             'dependencies':'Go standard library only','sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
             'source_files':files}
    output.with_name(output.name+'.receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in receipt.items() if k!='source_files'},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform',required=True,choices=['darwin_arm64','linux_arm64','linux_amd64'])
    p.add_argument('--output',required=True);a=p.parse_args();build(a.platform,a.output)
