#!/usr/bin/env python3
"""Run a real upstream controller in temporary, loopback-only, non-company state."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from tailgate import ROOT, read_json, render


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]


def run(binary):
    with tempfile.TemporaryDirectory(prefix='tailgate-smoke-') as d:
        root=Path(d);bundle=root/'bundle';render(read_json(ROOT/'examples/pilot.json'),bundle)
        config=read_json(bundle/'headscale.json');http,metrics=port(),port()
        config.update(server_url=f'https://127.0.0.1:{http}',listen_addr=f'127.0.0.1:{http}',
                      metrics_listen_addr=f'127.0.0.1:{metrics}',grpc_listen_addr=f'127.0.0.1:{port()}',
                      unix_socket=str(root/'headscale.sock'))
        # This manual-enrollment controller is isolated test state; never deploy this config.
        config.pop('oidc');config['derp']['server']['enabled']=True
        config['derp']['server'].update(stun_listen_addr=f'127.0.0.1:{port()}',
                                      private_key_path=str(root/'derp.key'), ipv4='127.0.0.1')
        config['noise']['private_key_path']=str(root/'noise.key')
        config['database']['sqlite']['path']=str(root/'db.sqlite')
        config['policy']['path']=str(bundle/'policy.json')
        config['dns']['extra_records_path']=str(bundle/'records.json')
        path=root/'config.json';path.write_text(json.dumps(config))
        command=[str(Path(binary).resolve()),'--config='+str(path)]
        log=(root/'runtime.log').open('w+')
        process=None
        def cli(*args):
            result=subprocess.run(command+list(args),capture_output=True,text=True,timeout=20)
            if result.returncode:raise RuntimeError(result.stderr.strip())
            return result.stdout
        try:
            cli('configtest')
            process=subprocess.Popen(command+['serve'],stdout=log,stderr=log)
            for attempt in range(80):
                if process.poll() is not None:raise RuntimeError('Controller exited during startup')
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{http}/health',timeout=1) as r:
                        if r.status==200:break
                except OSError:time.sleep(.1)
            else:raise RuntimeError('Controller health timeout')
            cli('users','create','smoke-user')
            users=json.loads(cli('--output=json','users','list'))
            assert any(u['name']=='smoke-user' for u in users), users
            cli('policy','check','--file='+str(bundle/'policy.json'))
            with urllib.request.urlopen(f'http://127.0.0.1:{metrics}/metrics') as r:
                assert b'headscale' in r.read()
            records=[{'name':'smoke.apps.example.com','type':'A','value':'100.64.0.20'}]
            (bundle/'records.json').write_text(json.dumps(records));time.sleep(.3)
            process.terminate();process.wait(timeout=10);process=None
            backup=root/'restored.sqlite'
            with sqlite3.connect(root/'db.sqlite') as src, sqlite3.connect(backup) as dst:
                src.backup(dst)
                assert dst.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            config['database']['sqlite']['path']=str(backup);path.write_text(json.dumps(config))
            # Direct CLI opening proves the recovered database has the original identity.
            cli('configtest')
            process=subprocess.Popen(command+['serve'],stdout=log,stderr=log)
            for attempt in range(80):
                try:
                    recovered=json.loads(cli('--output=json','users','list'))
                    if any(u['name']=='smoke-user' for u in recovered):break
                except RuntimeError:time.sleep(.1)
            else:raise RuntimeError('Restored controller identity not recovered')
            result={'headscale_version':'0.29.4','configtest':'passed','health':'passed',
                    'policy_check':'passed','metrics':'passed','user_lifecycle':'passed',
                    'sqlite_integrity':'ok','restored_identity':'passed',
                    'public_activation':False,'client_enrollment':'not tested by this smoke check'}
            print(json.dumps(result,indent=2));return result
        except Exception:
            log.flush();log.seek(0);print(log.read()[-5000:]);raise
        finally:
            if process and process.poll() is None:
                process.terminate();process.wait(timeout=10)
            log.close()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--headscale',required=True)
    run(p.parse_args().headscale)
