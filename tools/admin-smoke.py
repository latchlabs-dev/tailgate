#!/usr/bin/env python3
"""Qualify admin authentication and lifecycle actions against disposable native Headscale."""
import argparse
import hashlib
import http.cookiejar
import json
import platform
from pathlib import Path
import secrets
import sqlite3
import sys
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from smoke import port
from tailgate import ROOT, read_json, render


def run(headscale, admin):
    headscale=Path(headscale).resolve();admin=Path(admin).resolve()
    target=platform.system().lower()+'_'+{'aarch64':'arm64','arm64':'arm64','x86_64':'amd64'}.get(platform.machine(),'unsupported')
    expected=read_json(ROOT/'versions.lock.json')['components']['headscale']['artifacts'][target]['sha256']
    if hashlib.sha256(headscale.read_bytes()).hexdigest()!=expected:raise ValueError('Native Headscale differs from the locked artifact')
    processes=[]
    with tempfile.TemporaryDirectory(prefix='tailgate-admin-test-') as d:
        root=Path(d);bundle=root/'bundle';render(read_json(ROOT/'examples/pilot.json'),bundle)
        config=read_json(bundle/'headscale.json');controller_port,metrics,ui=port(),port(),port()
        config.update(server_url=f'https://127.0.0.1:{controller_port}',listen_addr=f'127.0.0.1:{controller_port}',
                      metrics_listen_addr=f'127.0.0.1:{metrics}',grpc_listen_addr=f'127.0.0.1:{port()}',
                      unix_socket=str(root/'headscale.sock'))
        config.pop('oidc')  # Disposable manual test only; never install this config.
        config['derp']['server'].update(stun_listen_addr=f'127.0.0.1:{port()}',private_key_path=str(root/'derp.key'),ipv4='127.0.0.1')
        config['noise']['private_key_path']=str(root/'noise.key');config['database']['sqlite']['path']=str(root/'db.sqlite')
        config['policy']['path']=str(bundle/'policy.json');config['dns']['extra_records_path']=str(bundle/'records.json')
        path=root/'config.json';path.write_text(json.dumps(config));command=[str(headscale),'--config='+str(path)]
        log=(root/'runtime.log').open('w+')
        def cli(*args):
            r=subprocess.run(command+list(args),capture_output=True,text=True,timeout=20)
            if r.returncode:raise RuntimeError('Disposable Headscale command failed')
            return r.stdout.strip()
        def ready(url,process):
            for _ in range(100):
                if process.poll() is not None:raise RuntimeError('Disposable service exited')
                try:
                    with urllib.request.urlopen(url,timeout=1) as r:
                        if r.status==200:return
                except OSError:time.sleep(.1)
            raise RuntimeError('Disposable service readiness timeout')
        try:
            cli('configtest');p=subprocess.Popen(command+['serve'],stdout=log,stderr=log);processes.append(p)
            ready(f'http://127.0.0.1:{controller_port}/health',p)
            cli('users','create','admin-test','--email=alice@example.com')
            auth='hskey-authreq-'+secrets.token_urlsafe(18)
            cli('debug','create-node','--user=admin-test','--name=test-device','--key='+auth)
            cli('auth','register','--user=admin-test','--auth-id='+auth)
            # Synthetic metadata in disposable state exercises the actual pinned database schema.
            with sqlite3.connect(root/'db.sqlite') as db:
                db.execute('UPDATE nodes SET host_info=?', (json.dumps({'Hostname':'test-device','OS':'iOS','OSVersion':'18.0','DeviceModel':'iPhone14,7','GoArch':'arm64','IPNVersion':'1.0','NetInfo':{'private':'must-not-leak'}}),))
            metadata=root/'devices.json'
            subprocess.run([sys.executable,str(ROOT/'tools/export-device-metadata.py'),'--database',str(root/'db.sqlite'),'--output',str(metadata)],check=True)
            key=cli('apikeys','create','--expiration=10m');login=secrets.token_urlsafe(32)
            keypath=root/'api-secret';keypath.write_text(key);keypath.chmod(0o600)
            loginpath=root/'login-secret';loginpath.write_text(login);loginpath.chmod(0o600)
            origin=f'http://127.0.0.1:{ui}'
            p=subprocess.Popen([str(admin),'--listen',f'127.0.0.1:{ui}','--headscale-url',f'http://127.0.0.1:{controller_port}',
                                '--api-key-file',str(keypath),'--login-token-file',str(loginpath),
                                '--config-file',str(path),'--device-metadata-file',str(metadata),'--allow-device-changes'],stdout=log,stderr=log);processes.append(p)
            ready(origin+'/health',p)
            jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));csrf=''
            def request(route,payload=None,expected=200,token=None):
                body=None if payload is None else json.dumps(payload).encode()
                r=urllib.request.Request(origin+route,data=body,headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf if token is None else token})
                try:
                    with opener.open(r,timeout=10) as res:status=res.status;raw=res.read()
                except urllib.error.HTTPError as res:status=res.code;raw=res.read()
                if status!=expected:raise AssertionError(f'Admin {route} returned {status}, expected {expected}')
                if key.encode() in raw or login.encode() in raw:raise AssertionError('Credential in browser response')
                return json.loads(raw)
            request('/api/snapshot',expected=401)
            result=request('/api/login',{'token':login});csrf=result['csrf']
            snap=request('/api/snapshot');assert len(snap['nodes'])==1 and len(snap['users'])==1
            assert snap['settings']['magicDNS'] and snap['policy'].strip()=='{\n  "grants": []\n}'
            n=snap['nodes'][0];nid=n['id'];assert 'preAuthKey' not in n and 'nodeKey' not in n
            assert n['model']=='iPhone14,7' and n['os']=='iOS' and n['architecture']=='arm64'
            assert 'must-not-leak' not in json.dumps(snap)
            route=f'/api/machines/{nid}/'
            request(route+'rename',{'name':'renamed-device'},expected=403,token='wrong')
            request(route+'delete',{'confirmation':'wrong'},expected=409)
            request(route+'rename',{'name':'renamed-device'})
            snap=request('/api/snapshot');assert snap['nodes'][0]['givenName']=='renamed-device'
            request(route+'expire',{'confirmation':'renamed-device'})
            snap=request('/api/snapshot');assert snap['nodes'][0]['expiry']
            request(route+'delete',{'confirmation':'renamed-device'})
            assert request('/api/snapshot')['nodes']==[]
            request('/api/logout',{});request('/api/snapshot',expected=401)
            result={'headscale_version':'0.29.4','device_metadata':'passed','authenticated_inventory':'passed','credential_projection':'passed',
                    'policy_dns_display':'passed','csrf_rejection':'passed','destructive_confirmation':'passed',
                    'rename':'passed','expire':'passed','remove':'passed','session_revocation':'passed',
                    'company_state_used':False,'google_login_tested':False,'public_activation':False}
            print(json.dumps(result,indent=2));return result
        finally:
            for p in reversed(processes):
                if p.poll() is None:p.terminate();p.wait(timeout=10)
            log.close()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--headscale',required=True);p.add_argument('--admin',required=True)
    a=p.parse_args();run(a.headscale,a.admin)
