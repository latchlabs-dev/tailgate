#!/usr/bin/env python3
"""Disposable, rootless Docker controller/UI/client lab. No company configuration."""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from integration import command, free_port
from tailgate import ROOT, read_json, render


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_artifacts(directory, admin=False):
    """Receipts bind extracted/build outputs to the archive/source/toolchain lock."""
    directory = Path(directory).resolve()
    lock = read_json(ROOT/'versions.lock.json')
    platform = 'linux_arm64'
    if digest(directory/'headscale') != lock['components']['headscale']['artifacts'][platform]['sha256']:
        raise ValueError('Headscale digest differs from lock')
    for component in ('tailscale', 'lego'):
        receipt = read_json(directory/(component+'.fetch.json'))
        entry = lock['components'][component]
        if (receipt['platform'] != platform or receipt['version'] != entry['version'] or
                receipt['archive_sha256'] != entry['artifacts'][platform]['sha256']):
            raise ValueError(component+' receipt differs from lock')
        for name in (('tailscale', 'tailscaled') if component == 'tailscale' else ('lego',)):
            if digest(directory/name) != receipt['binary_sha256'][name]:
                raise ValueError(name+' digest differs from verified extraction receipt')
    receipt = read_json(directory/'derper.build.json')
    entry = lock['components']['tailscale']
    if (receipt['platform'] != platform or receipt['source'] != entry['source'] or
            receipt['go_version'] != entry['derper_build']['go_version'] or
            digest(directory/'derper') != receipt['sha256']):
        raise ValueError('Relay build differs from locked provenance receipt')
    if admin:
        receipt = read_json(directory/'tailgate-admin.receipt.json')
        source = ROOT/'components/admin'
        actual = {str(p.relative_to(source)): digest(p) for p in sorted(source.rglob('*')) if p.is_file()}
        if (receipt['platform'] != platform or receipt['source_files'] != actual or
                receipt['go_version'] != entry['derper_build']['go_version'] or
                digest(directory/'tailgate-admin') != receipt['sha256']):
            raise ValueError('Admin binary differs from current source/build receipt')
    return directory


def build_image(directory, output, image, admin=False):
    directory = verify_artifacts(directory, admin)
    output.mkdir()
    names = ['headscale', 'tailscale', 'tailscaled', 'derper', 'lego']
    if admin: names.append('tailgate-admin')
    for name in names:
        shutil.copyfile(directory/name, output/name)
        (output/name).chmod(0o755)
    version = read_json(ROOT/'versions.lock.json')['components']['tailscale']['derper_build']['go_version']
    if subprocess.check_output(['go','version'], text=True).split()[2] != 'go'+version:
        raise ValueError('Probe build requires locked Go toolchain')
    env = dict(os.environ, GOOS='linux', GOARCH='arm64', CGO_ENABLED='0',
               GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off')
    subprocess.run(['go','build','-trimpath','-o',str(output/'probe'),str(ROOT/'tools/probe.go')],env=env,check=True)
    # Trust store contains public roots, never a production private key.
    base = read_json(ROOT/'versions.lock.json')['validation']['nginx_image']
    (output/'Dockerfile').write_text('FROM '+base+' AS roots\nFROM scratch\n'
        'COPY --from=roots /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n'
        'COPY '+ ' '.join(names+['probe'])+' /bin/\nUSER 65532:65532\nENTRYPOINT ["/bin/headscale"]\n')
    command('docker','build','--quiet','--platform','linux/arm64','-t',image,str(output))


def hardening(uid, gid, memory='256m'):
    return ['--user',f'{uid}:{gid}','--read-only','--cap-drop=ALL',
            '--security-opt=no-new-privileges:true','--pids-limit=128','--memory='+memory,'--cpus=0.5']


def wait_client(name):
    for _ in range(60):
        result = subprocess.run(['docker','exec',name,'/bin/tailscale','status'],capture_output=True,text=True)
        if 'Logged out' in result.stdout or 'NeedsLogin' in result.stdout: return
        time.sleep(.1)
    raise RuntimeError('Client socket did not become ready')


def up(root, artifacts, ui_port, https_port):
    root = Path(root).resolve()
    if root.exists(): raise ValueError('Lab directory must not already exist')
    if os.getuid() == 0: raise ValueError('Run this local lab as an ordinary user')
    root.mkdir(parents=True, mode=0o700)
    uid, gid = os.getuid(), os.getgid()
    suffix = secrets.token_hex(4)
    state = {'schema_version':1,'prefix':'tailgate-lab-'+suffix,'containers':[],
             'networks':[],'image':'tailgate-lab:'+suffix,'ui':f'http://127.0.0.1:{ui_port}',
             'https_port':https_port,'client_names':{},'company_state_used':False}
    def save(): (root/'lab.json').write_text(json.dumps(state,indent=2)+'\n')
    save()
    def launch(name, *args):
        state['containers'].append(name); save()
        return command('docker','run','-d','--name',name,'--label','tailgate.lab='+suffix,*args)
    try:
        build_image(artifacts, root/'image', state['image'], admin=True)
        bundle = root/'bundle'; render(read_json(ROOT/'examples/pilot.json'),bundle)
        config = read_json(bundle/'headscale.json'); config.pop('oidc')
        config.update(unix_socket='/run/headscale.sock',server_url='https://control.example.com:8443')
        config['noise']['private_key_path']='/state/noise.key'
        config['database']['sqlite']['path']='/state/db.sqlite'
        config['policy']['path']='/config/policy.json'
        config['dns']['extra_records_path']='/config/records.json'
        config['derp']['server'].update(private_key_path='/state/derp.key')
        config['derp']['server'].pop('ipv4',None)
        (bundle/'headscale.json').write_text(json.dumps(config,indent=2)+'\n')
        cert = root/'cert'; cert.mkdir(mode=0o700)
        command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=Disposable Tailgate lab CA','-keyout',str(cert/'ca.key'),'-out',str(cert/'ca.crt'))
        command('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=control.example.com',
                '-keyout',str(cert/'server.key'),'-out',str(cert/'server.csr'))
        (cert/'extension').write_text('subjectAltName=DNS:control.example.com\nextendedKeyUsage=serverAuth\n')
        command('openssl','x509','-req','-in',str(cert/'server.csr'),'-CA',str(cert/'ca.crt'),
                '-CAkey',str(cert/'ca.key'),'-CAcreateserial','-days','1',
                '-extfile',str(cert/'extension'),'-out',str(cert/'server.crt'))
        for p in (cert/'ca.key',cert/'server.key'): p.chmod(0o600)
        nginx = read_json(ROOT/'versions.lock.json')['validation']['nginx_image']
        conf = (bundle/'controller.nginx.conf').read_text().replace('listen 443 ssl','listen 8443 ssl')
        conf = conf.replace('/var/lib/tailgate/acme/certificates/control.example.com.crt','/cert/server.crt')
        conf = conf.replace('/var/lib/tailgate/acme/certificates/control.example.com.key','/cert/server.key')
        (root/'nginx.conf').write_text('pid /tmp/nginx.pid;\nerror_log /dev/stderr warn;\nevents {}\nhttp {\n'
            'client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fcgi; '
            'uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;\n'+conf+
            '\nserver { listen 8081; access_log off; location / { proxy_pass http://127.0.0.1:18100; '
            'proxy_set_header Host $http_host; proxy_buffering off; } }\n}\n')
        network = state['prefix']; command('docker','network','create',network)
        state['networks'].append(network); save()
        gateway = state['prefix']+'-gateway'
        launch(gateway,'--network',network,'--network-alias','control.example.com',
               *hardening(uid,gid,'64m'),'--tmpfs',f'/tmp:uid={uid},gid={gid},mode=0700',
               '-p',f'127.0.0.1:{ui_port}:8081','-p',f'127.0.0.1:{https_port}:8443',
               '-v',str(root/'nginx.conf')+':/etc/nginx/nginx.conf:ro',
               '-v',str(cert/'server.crt')+':/cert/server.crt:ro',
               '-v',str(cert/'server.key')+':/cert/server.key:ro',
               '--entrypoint','nginx',nginx,'-g','daemon off;')
        ctrl = state['prefix']+'-controller'; state['controller']=ctrl; save()
        launch(ctrl,'--network','container:'+gateway,*hardening(uid,gid),
               '--tmpfs',f'/run:uid={uid},gid={gid},mode=0700',
               '--tmpfs',f'/state:uid={uid},gid={gid},mode=0700',
               '-v',str(bundle)+':/config:ro',state['image'],'--config=/config/headscale.json','serve')
        def cli(*args): return command('docker','exec',ctrl,'/bin/headscale','--config=/config/headscale.json',*args)
        for _ in range(100):
            try: cli('--output=json','users','list'); break
            except RuntimeError: time.sleep(.1)
        else: raise RuntimeError('Controller did not start')
        secret_dir = root/'secrets';secret_dir.mkdir(mode=0o700)
        for name, value in [('api-key',cli('apikeys','create','--expiration=24h')),('login-token',secrets.token_urlsafe(32))]:
            path=secret_dir/name;path.write_text(value);path.chmod(0o600)
        launch(state['prefix']+'-admin','--network','container:'+gateway,*hardening(uid,gid,'128m'),
               '-v',str(secret_dir)+':/secrets:ro','-v',str(bundle)+':/config:ro',
               '--entrypoint','/bin/tailgate-admin',state['image'],
               '--origin',state['ui'],'--headscale-url','http://127.0.0.1:18090',
               '--api-key-file','/secrets/api-key','--login-token-file','/secrets/login-token',
               '--config-file','/config/headscale.json')
        for user in ('alice','bob'):
            cli('users','create','lab-'+user,'--email='+user+'@example.com')
        users=json.loads(cli('--output=json','users','list'))
        for user in ('alice','bob'):
            user_id=next(u['id'] for u in users if u['name']=='lab-'+user)
            key=cli('preauthkeys','create','--user',str(user_id),'--expiration=10m','--ephemeral')
            keyfile=secret_dir/(user+'-key');keyfile.write_text(key);keyfile.chmod(0o600)
            net=state['prefix']+'-'+user;command('docker','network','create','--internal',net)
            state['networks'].append(net);save()
            command('docker','network','connect','--alias','control.example.com',net,gateway)
            name=state['prefix']+'-'+user;state['client_names'][user]=name;save()
            launch(name,'--network',net,*hardening(uid,gid),
                   '--tmpfs',f'/var/run/tailscale:uid={uid},gid={gid},mode=0700',
                   '--tmpfs',f'/state:uid={uid},gid={gid},mode=0700',
                   '-v',str(cert/'ca.crt')+':/etc/ssl/certs/ca-certificates.crt:ro',
                   '-v',str(keyfile)+':/secrets/auth-key:ro','-e','TS_NO_LOGS_NO_SUPPORT=true',
                   '--entrypoint','/bin/tailscaled',state['image'],'--tun=userspace-networking',
                   '--state=/state/client.state','--socks5-server=127.0.0.1:1055')
            wait_client(name)
            command('docker','exec',name,'/bin/tailscale','up','--login-server=https://control.example.com:8443',
                    '--auth-key=file:/secrets/auth-key','--hostname=lab-'+user,'--accept-dns=true')
        save();return {'ui':state['ui'],'state_directory':str(root),'clients':2,'mode':'private read-only',
                      'google_auth_tested':False,'company_state_used':False}
    except Exception:
        down(root); raise


def check(root):
    root=Path(root).resolve();state=read_json(root/'lab.json');origin=state['ui']
    jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));csrf=''
    def request(route, body=None, expected=200, headers=None):
        r=urllib.request.Request(origin+route,data=None if body is None else json.dumps(body).encode(),
             headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf,**(headers or {})})
        try:
            with opener.open(r,timeout=15) as response:status=response.status;raw=response.read()
        except urllib.error.HTTPError as response:status=response.code;raw=response.read()
        if status!=expected:raise AssertionError(f'{route}: got {status}, expected {expected}')
        for name in ('api-key','login-token'):
            if (root/'secrets'/name).read_bytes() in raw:raise AssertionError('Browser credential leakage')
        return json.loads(raw)
    request('/api/snapshot',expected=401)
    request('/api/snapshot',expected=403,headers={'Host':'evil.example.com'})
    csrf=request('/api/login',{'token':(root/'secrets/login-token').read_text()})['csrf']
    snap=request('/api/snapshot');assert len(snap['nodes'])==2 and len(snap['users'])==2
    assert snap['policy'].strip()=='{\n  "grants": []\n}' and not snap['writes']
    nid=snap['nodes'][0]['id']
    request(f'/api/machines/{nid}/rename',{'name':'changed'},expected=403)
    request('/api/logout',{},expected=403,headers={'X-CSRF-Token':'wrong'})
    request('/api/logout',{},expected=403,headers={'Origin':'https://evil.example.com'})
    for name in state['containers']:
        c=json.loads(command('docker','inspect',name))[0];h=c['HostConfig']
        assert c['Config']['User'].split(':')[0]!='0' and h['ReadonlyRootfs'] and h['CapDrop']==['ALL']
        assert 'no-new-privileges:true' in h['SecurityOpt'] and not h['Privileged']
        assert not any(m.get('Source','').endswith('docker.sock') for m in c['Mounts'])
        for mappings in (h.get('PortBindings') or {}).values():
            assert all(m['HostIp']=='127.0.0.1' for m in mappings)
    clients=state['client_names'];alice=clients['alice'];bob=clients['bob']
    def client(name,*args):return command('docker','exec',name,'/bin/tailscale',*args)
    alice_ip=client(alice,'ip','-4').splitlines()[0]
    assert alice_ip in client(alice,'dns','query','lab-alice.mesh.example.com')
    mapping=json.loads(client(alice,'debug','derp-map'));assert list(mapping['Regions'])==['999']
    assert all(n['HostName']=='control.example.com' for n in mapping['Regions']['999']['Nodes'])
    request('/api/logout',{});request('/api/snapshot',expected=401)
    return {'authenticated_real_inventory':'passed','read_only_default':'passed','secret_projection':'passed',
            'csrf_origin_and_host_rejection':'passed','session_revocation':'passed','magic_dns':'passed',
            'owned_relay_map':'passed','container_hardening':'passed','loopback_host_ports':'passed',
            'google_auth_tested':False,'company_state_used':False}


def down(root):
    root=Path(root).resolve();state=read_json(root/'lab.json')
    prefix=state['prefix']
    if not prefix.startswith('tailgate-lab-'):raise ValueError('Not a Tailgate lab manifest')
    for name in reversed(state['containers']):
        if not name.startswith(prefix+'-'):raise ValueError('Foreign container in manifest')
        command('docker','rm','-f',name,check=False)
    for name in reversed(state['networks']):
        if not name.startswith(prefix):raise ValueError('Foreign network in manifest')
        command('docker','network','rm',name,check=False)
    if not state['image'].startswith('tailgate-lab:'):raise ValueError('Foreign image in manifest')
    command('docker','image','rm',state['image'],check=False)
    shutil.rmtree(root)


def renew(root):
    """Rotate only this disposable lab's server-side API credential."""
    root=Path(root).resolve();state=read_json(root/'lab.json');prefix=state['prefix']
    if not prefix.startswith('tailgate-lab-'):raise ValueError('Not a Tailgate lab')
    for name in (state['controller'],prefix+'-admin'):
        c=json.loads(command('docker','inspect',name))[0]
        if c['Config']['Labels'].get('tailgate.lab')!=prefix.removeprefix('tailgate-lab-'):
            raise ValueError('Container ownership label differs from lab manifest')
    key=command('docker','exec',state['controller'],'/bin/headscale',
                '--config=/config/headscale.json','apikeys','create','--expiration=24h')
    path=root/'secrets/api-key';temporary=path.with_name('api-key.next')
    with temporary.open('w') as f:
        os.chmod(temporary,0o600);f.write(key)
    temporary.replace(path)
    command('docker','restart',prefix+'-admin')
    return {'rotated':True,'api_key_lifetime':'24h','company_state_used':False,
            'note':'Admin restart invalidates existing lab browser sessions; sign in again.'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['up','check','down','renew'])
    p.add_argument('--state',required=True);p.add_argument('--artifacts',default=str(ROOT/'.cache/linux_arm64'))
    p.add_argument('--ui-port',type=int,default=18110);p.add_argument('--https-port',type=int,default=18443)
    a=p.parse_args()
    if a.action=='up':result=up(a.state,a.artifacts,a.ui_port,a.https_port)
    elif a.action=='check':result=check(a.state)
    elif a.action=='renew':result=renew(a.state)
    else:down(a.state);result={'removed':True}
    print(json.dumps(result,indent=2))
