#!/usr/bin/env python3
"""Real official Linux clients + TLS Nginx + Headscale in disposable Docker state."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import ssl
from urllib.parse import urlsplit
from tailgate import ROOT, read_json, render
from prefix_migration import renumber


def command(*args, check=True):
    result=subprocess.run(list(args),capture_output=True,text=True,timeout=90)
    if check and result.returncode:
        # Arguments and upstream stderr can contain credentials or authorization URLs.
        raise RuntimeError('Command failed (exit '+str(result.returncode)+')')
    return result.stdout.strip() if check else (result.stdout+'\n'+result.stderr).strip()


def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]



def run(artifacts, example='pilot'):
    # Local import avoids a cycle: docker_lab reuses command/free_port above.
    from docker_lab import hardening, verify_artifacts
    artifacts=verify_artifacts(artifacts)
    artifacts=Path(artifacts).resolve();lock=read_json(ROOT/'versions.lock.json')
    uid,gid=os.getuid(),os.getgid()
    if uid==0:raise ValueError('Run this disposable integration as an ordinary user')
    restricted=hardening(uid,gid)
    suffix=str(int(time.time()))+'-'+str(free_port())
    network='tailgate-test-'+suffix;containers=[];images=[];networks=[]
    nginx=lock['validation']['nginx_image']
    with tempfile.TemporaryDirectory(prefix='tailgate-clients-') as d:
        root=Path(d);bundle=root/'bundle';render(read_json(ROOT/'examples'/f'{example}.json'),bundle)
        spec=importlib.util.spec_from_file_location('public_site', ROOT/'tools/render-public-site.py')
        public_site=importlib.util.module_from_spec(spec);spec.loader.exec_module(public_site)
        site=root/'site';public_site.render(ROOT/'examples/public-site.json',site)
        from enrollment_fixtures import write as write_enrollment_fixtures
        fixtures=root/'fixtures';write_enrollment_fixtures(fixtures)
        config=read_json(bundle/'headscale.json')
        config.pop('oidc');config.update(server_url='https://control.example.com:8443',
                                       listen_addr='0.0.0.0:8080',metrics_listen_addr='127.0.0.1:9090',
                                       grpc_listen_addr='127.0.0.1:50443',unix_socket='/run/headscale.sock')
        config['noise']['private_key_path']='/state/noise.key'
        config['database']['sqlite']['path']='/state/db.sqlite'
        config['policy']['path']='/config/policy.json';config['dns']['extra_records_path']='/config/records.json'
        config['derp']['server'].update(private_key_path='/state/derp.key',stun_listen_addr='0.0.0.0:3478')
        config['derp']['server'].pop('ipv4',None)
        (bundle/'headscale.json').write_text(json.dumps(config));(root/'state').mkdir()
        cert=root/'cert';cert.mkdir()
        (cert/'ca-config').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\n'
                                     '[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\n'
                                     'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
        command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-config',str(cert/'ca-config'),
                '-subj','/CN=Disposable Tailgate test CA','-keyout',str(cert/'ca.key'),'-out',str(cert/'ca.crt'))
        command('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=control.example.com',
                '-keyout',str(cert/'server.key'),'-out',str(cert/'server.csr'))
        (cert/'extension').write_text('subjectAltName=DNS:control.example.com\nextendedKeyUsage=serverAuth\n'
                                     'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                                     'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        command('openssl','x509','-req','-in',str(cert/'server.csr'),'-CA',str(cert/'ca.crt'),
                '-CAkey',str(cert/'ca.key'),'-CAcreateserial','-days','1',
                '-extfile',str(cert/'extension'),'-out',str(cert/'server.crt'))
        image_dir=root/'images';image_dir.mkdir()
        for name in ('headscale','tailscale','tailscaled','derper','lego'):
            shutil.copyfile(artifacts/name,image_dir/name);(image_dir/name).chmod(0o755)
        for path in (cert/'ca.key',cert/'server.key'):path.chmod(0o600)
        version=lock['components']['tailscale']['derper_build']['go_version']
        if subprocess.check_output(['go','version'],text=True).split()[2]!='go'+version:
            raise ValueError('Probe build requires locked Go toolchain')
        env=dict(os.environ,GOOS='linux',GOARCH='arm64',CGO_ENABLED='0',GOTOOLCHAIN='local',GOWORK='off',
                 GOPROXY='off',GOSUMDB='off')
        subprocess.run(['go','build','-trimpath','-o',str(image_dir/'probe'),str(ROOT/'tools/probe.go')],env=env,check=True)
        (image_dir/'Dockerfile').write_text('FROM scratch\nCOPY headscale tailscale tailscaled derper lego probe /bin/\nUSER 65532:65532\nENTRYPOINT ["/bin/headscale"]\n')
        image='tailgate-test-binaries:'+suffix
        try:
            command('docker','build','--quiet','--platform','linux/arm64','-t',image,str(image_dir));images.append(image)
            help_text=command('docker','run','--rm',*restricted,'--entrypoint','/bin/derper',image,'--help')
            # Go flag usage is printed to stderr even on successful help; capture both streams.
            if not help_text:
                help_text=command('docker','run','--rm',*restricted,'--entrypoint','/bin/derper',image,'--help',check=False)
            if 'verify-client-url-fail-open' not in help_text:raise RuntimeError('Relay admission flag missing')
            lego_help=command('docker','run','--rm',*restricted,'--entrypoint','/bin/lego',image,'run','--help')
            if '--env-file' not in lego_help or '--dns' not in lego_help:raise RuntimeError('ACME adapter flags missing')
            command('docker','network','create',network);networks.append(network)
            ctrl='tailgate-control-'+suffix
            containers.append(ctrl)
            command('docker','run','-d','--name',ctrl,'--network',network,*restricted,
                    '--tmpfs',f'/run:uid={uid},gid={gid},mode=0700',
                    '-v',str(bundle)+':/config:ro','-v',str(root/'state')+':/state','-v',str(fixtures)+':/fixtures:ro',
                    image,'--config=/config/headscale.json','serve')
            command('docker','exec','-d',ctrl,'/bin/probe','--enrollment-fixture','0.0.0.0:8089','/fixtures')
            proxy='tailgate-proxy-'+suffix
            conf=(bundle/'controller.nginx.conf').read_text().replace('127.0.0.1:18090',ctrl+':8080')
            conf=conf.replace('listen 443 ssl','listen 8443 ssl')
            conf=conf.replace('/var/lib/tailgate/acme/certificates/control.example.com.crt','/cert/server.crt')
            conf=conf.replace('/var/lib/tailgate/acme/certificates/control.example.com.key','/cert/server.key')
            conf=conf.replace('    location = /verify {',
                public_site.enrollment.nginx('/public',ctrl+':8080')+
                '    location ^~ /assets/ { root /public; }\n    location = /verify {')
            nginx_prefix=('pid /tmp/nginx.pid;\nerror_log /dev/stderr warn;\nevents {}\nhttp {\n'
                          'client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; '
                          'fastcgi_temp_path /tmp/fcgi; uwsgi_temp_path /tmp/uwsgi; '
                          'scgi_temp_path /tmp/scgi;\n')
            # A local upstream fixture exercises every intercepted status and
            # verifies successful callbacks/forms/cookies are left untouched.
            fixture='''server { listen 8082; access_log off; error_log /dev/null;
'''+public_site.enrollment.nginx('/public',ctrl+':8089')+'''
location ^~ /assets/ { root /public; }
location = /_template-contract { proxy_pass http://'''+ctrl+''':8080/register/hskey-authreq-AAAAAAAAAAAAAAAAAAAAAAAA; }
location / { proxy_pass http://'''+ctrl+''':8089; }
}
'''
            (root/'nginx.conf').write_text(nginx_prefix+conf+'\n'+fixture+'}\n')
            https=free_port()
            fixture_port=free_port()
            containers.append(proxy)
            command('docker','run','-d','--name',proxy,'--network',network,'--network-alias','control.example.com',
                    *restricted,'--tmpfs',f'/tmp:uid={uid},gid={gid},mode=0700',
                    '-p',f'127.0.0.1:{https}:8443','-p',f'127.0.0.1:{fixture_port}:8082',
                    '-v',str(root/'nginx.conf')+':/etc/nginx/nginx.conf:ro','-v',str(site)+':/public:ro',
                    '-v',str(cert/'server.crt')+':/cert/server.crt:ro',
                    '-v',str(cert/'server.key')+':/cert/server.key:ro',
                    '--entrypoint','nginx',nginx,'-g','daemon off;')
            last_error=''
            for attempt in range(60):
                try:
                    # Use a valid test CA and hostname check despite the loopback host mapping.
                    context=ssl.create_default_context(cafile=str(cert/'ca.crt'))
                    with socket.create_connection(('127.0.0.1',https),timeout=1) as s:
                        with context.wrap_socket(s,server_hostname='control.example.com') as tls:
                            tls.sendall(b'GET /health HTTP/1.0\r\nHost: control.example.com\r\n\r\n')
                            response=tls.recv(256)
                            if b'200' in response:break
                            last_error=repr(response)
                except OSError as error:last_error=str(error);time.sleep(.2)
            else:raise RuntimeError('TLS proxy did not become healthy: '+last_error)
            import http.client
            def fixture_request(path,method='GET',body=None,headers=None):
                connection=http.client.HTTPConnection('127.0.0.1',fixture_port,timeout=5)
                try:
                    connection.request(method,path,body=body,headers=headers or {})
                    response=connection.getresponse();return response.status,dict(response.getheaders()),response.read().decode()
                finally:connection.close()
            # Check common markup against the real pinned controller binary,
            # rather than accepting a self-consistent synthetic fixture alone.
            actual,_,upstream=fixture_request('/_template-contract',headers={'Accept':'text/html'})
            contract={'status':actual,'main':public_site.enrollment.UPSTREAM_MAIN in upstream,
                      'footer':public_site.enrollment.UPSTREAM_FOOTER in upstream,
                      'logo':'<svg class="headscale-logo"' in upstream}
            if actual!=200 or not all(contract[key] for key in ('main','footer','logo')):
                raise AssertionError('Pinned upstream HTML contract changed; review branding before upgrade: '+str(contract))
            for status in public_site.enrollment.ERRORS:
                for method in ('GET','POST'):
                    try:actual,headers,body=fixture_request(f'/register/status/{status}?code=PRIVATE-CODE&state=PRIVATE-STATE',method)
                    except http.client.RemoteDisconnected:raise AssertionError(f'Fixture disconnected for {status} {method}') from None
                    if (actual!=status or f'TG-SIGNIN-{status}' not in body or
                        any(value in body for value in ('Headscale','UNTRUSTED','PRIVATE-CODE','PRIVATE-STATE')) or
                        headers.get('Cache-Control')!='no-store' or headers.get('Referrer-Policy')!='no-referrer'):
                        raise AssertionError('Branded sign-in error status/body/privacy differs')
            for path in ('/oidc/missing','/auth/missing'):
                if 'TG-SIGNIN-404' not in fixture_request(path)[2]:raise AssertionError('Browser auth route was not intercepted')
            for path,status in (('/api/v1/node',401),('/ts2021',400),('/derp',503)):
                actual,_,body=fixture_request(path)
                if actual!=status or 'UNTRUSTED protocol body' not in body:raise AssertionError('Protocol response was intercepted')
            actual,headers,_=fixture_request('/register/start')
            if actual!=302 or urlsplit(headers.get('Location','')).path!='/oidc/callback' or 'state=test' not in headers.get('Set-Cookie',''):
                raise AssertionError('Auth redirect/cookie changed')
            actual,headers,_=fixture_request('/oidc/callback')
            if actual!=303 or urlsplit(headers.get('Location','')).path!='/register/confirm/test':
                raise AssertionError('Confirmation redirect changed')
            from http.cookies import SimpleCookie
            cookie=SimpleCookie();cookie.load(headers['Set-Cookie'])
            csrf=cookie['headscale_register_confirm'].value
            auth_headers={'Cookie':'headscale_register_confirm='+csrf,'Content-Type':'application/x-www-form-urlencoded'}
            actual,headers,body=fixture_request('/register/confirm/test',headers=auth_headers)
            if (actual!=200 or '<title>Confirm your device · Tailgate</title>' not in body or
                '<form action="/register/confirm/test" method="POST">' not in body or
                f'name="headscale_register_confirm" type="hidden" value="{csrf}"' not in body or
                'Add this device</button>' not in body or 'Powered by' in body or 'fonts.googleapis.com' in body):
                raise AssertionError('Confirmation branding/form/cookie changed')
            if fixture_request('/register/confirm/test')[0]!=403 or fixture_request('/register/confirm/test','POST','headscale_register_confirm=wrong',auth_headers)[0]!=403:
                raise AssertionError('Confirmation bypassed the upstream CSRF checks')
            actual,_,body=fixture_request('/register/confirm/test','POST','headscale_register_confirm='+csrf,auth_headers)
            if actual!=200 or 'Device added to Tailgate</strong>' not in body or 'Tailgate support</a>' not in body or 'Powered by' in body:
                raise AssertionError('Valid confirmation/success branding changed')
            for kind in ('registered','reauthenticated','ssh'):
                actual,_,body=fixture_request('/auth/success/'+kind)
                if actual!=200 or '<header class="enrollment-brand">' not in body or '<title>Headscale' in body or 'Powered by' in body:
                    raise AssertionError('Success screen retains upstream branding')
            if fixture_request('/enrollment-errors/400.html')[0]!=404:raise AssertionError('Internal error file became public')
            def cli(*args):return command('docker','exec',ctrl,'/bin/headscale','--config=/config/headscale.json',*args)
            def client(name,*args):return command('docker','exec',name,'/bin/tailscale',*args)
            clients={}
            for user in ('alice','bob','denied'):
                cli('users','create','smoke-'+user,'--email='+user+'@example.com')
            users=json.loads(cli('--output=json','users','list'))
            for user in ('alice','bob','denied'):
                user_id=next(u['id'] for u in users if u['name']=='smoke-'+user)
                key=cli('preauthkeys','create','--user',str(user_id),'--expiration','10m','--ephemeral')
                keyfile=root/(user+'-key');keyfile.write_text(key);keyfile.chmod(0o600)
                name='tailgate-'+user+'-'+suffix;clients[user]=name
                private_network=network+'-'+user
                command('docker','network','create','--internal',private_network);networks.append(private_network)
                command('docker','network','connect','--alias','control.example.com',private_network,proxy)
                containers.append(name)
                command('docker','run','-d','--name',name,'--network',private_network,*restricted,
                        '--tmpfs',f'/var/run/tailscale:uid={uid},gid={gid},mode=0700',
                        '--tmpfs',f'/state:uid={uid},gid={gid},mode=0700',
                        '-v',str(cert/'ca.crt')+':/etc/ssl/certs/ca-certificates.crt:ro',
                        '-v',str(keyfile)+':/secrets/auth-key:ro',
                        '-e','TS_NO_LOGS_NO_SUPPORT=true',
                        '--entrypoint','/bin/tailscaled',image,'--tun=userspace-networking',
                        '--state=/state/tailscaled.state','--socks5-server=127.0.0.1:1055')
                for attempt in range(30):
                    result=subprocess.run(['docker','exec',name,'/bin/tailscale','status'],capture_output=True,text=True)
                    if 'Logged out' in result.stdout or 'NeedsLogin' in result.stdout:break
                    time.sleep(.1)
                client(name,'up','--login-server=https://control.example.com:8443','--auth-key=file:/secrets/auth-key',
                       '--hostname=smoke-'+user,'--accept-dns=true')
                command('docker','exec',name,'/bin/probe','127.0.0.1:1055','--check')
                assigned = json.loads(client(name, 'status', '--json'))['TailscaleIPs']
                for family, version in (('v4', 4), ('v6', 6)):
                    addresses = [ipaddress.ip_address(value) for value in assigned if ipaddress.ip_address(value).version == version]
                    if len(addresses) != 1 or addresses[0] not in ipaddress.ip_network(config['prefixes'][family]):
                        raise AssertionError('Official client address is outside the selected pool')
            bob_ip=client(clients['bob'],'ip','-4').splitlines()[0]
            app='tailgate-app-'+suffix;(root/'app.conf').write_text(nginx_prefix+'server { listen 8080; listen [::]:8080; access_log off; location / { return 200 "private workflow ok"; } } }')
            containers.append(app)
            command('docker','run','-d','--name',app,'--network','container:'+clients['bob'],
                    *restricted,'--tmpfs',f'/tmp:uid={uid},gid={gid},mode=0700',
                    '-v',str(root/'app.conf')+':/etc/nginx/nginx.conf:ro',
                    '--entrypoint','nginx',nginx,'-g','daemon off;')
            command('docker','exec',app,'wget','-q','-O','-','http://127.0.0.1:8080')
            for name in containers:
                inspected=json.loads(command('docker','inspect',name))[0]
                host=inspected['HostConfig']
                if (inspected['Config']['User']!=f'{uid}:{gid}' or not host['ReadonlyRootfs'] or
                        host['CapDrop']!=['ALL'] or host['Privileged'] or
                        'no-new-privileges:true' not in host['SecurityOpt']):
                    raise AssertionError('Container containment differs from required settings')
                if any(m['Source'].endswith(('ca.key','docker.sock')) for m in inspected['Mounts']):
                    raise AssertionError('A forbidden signer/socket mount was present')
                for mappings in (host.get('PortBindings') or {}).values():
                    if any(m['HostIp']!='127.0.0.1' for m in mappings):
                        raise AssertionError('A test port was published beyond loopback')
            bob_bridge=json.loads(command('docker','inspect',clients['bob']))[0]['NetworkSettings']['Networks'][network+'-bob']['IPAddress']
            probe=subprocess.run(['docker','run','--rm','--network','container:'+clients['alice'],
                                  *restricted,'--entrypoint','wget',nginx,'-q','-T','2','-O','-',f'http://{bob_bridge}:8080'],
                                 capture_output=True,timeout=10)
            if probe.returncode==0:raise AssertionError('Direct Docker bridge traffic was not isolated')
            time.sleep(1)
            def request(user):
                try:return json.loads(command('docker','exec',clients[user],'/bin/probe','127.0.0.1:1055',bob_ip,'8080'))
                except RuntimeError as error:raise OSError(str(error))
            try:request('alice');raise AssertionError('Deny-all permitted traffic')
            except OSError:pass
            policy={'grants':[{'src':['alice@example.com'],'dst':['bob@example.com'],'ip':['tcp:8080']}]}
            (bundle/'policy.json').write_text(json.dumps(policy));command('docker','kill','--signal=HUP',ctrl)
            cli('policy','check','--file=/config/policy.json')
            last_error=''
            for attempt in range(10):
                try:
                    response=request('alice')
                    if response['status']==200 and 'private workflow ok' in response['body']:break
                    last_error=json.dumps(response)[:200]
                except OSError as error:last_error=str(error)
                time.sleep(.3)
            else:
                for user in ('alice','bob'):
                    status=json.loads(client(clients[user],'status','--json'))
                    print('Diagnostic:',user,'state=',status['BackendState'],
                          'peers=',[v.get('DNSName') for v in (status.get('Peer') or {}).values()])
                nodes=json.loads(cli('--output=json','nodes','list'))
                print('Owners:',[(n.get('given_name'),n.get('user',{}).get('name')) for n in nodes])
                raise RuntimeError('Allowed workflow did not connect: '+last_error)
            try:request('denied');raise AssertionError('Denied identity reached application')
            except OSError:pass
            # The runtime API supplies the actual DNS configuration to a normal client.
            dns=client(clients['alice'],'dns','query','smoke-bob.mesh.example.com')
            if bob_ip not in dns:raise AssertionError('MagicDNS response missing peer address')
            mapping=json.loads(client(clients['alice'],'debug','derp-map'))
            if len(mapping['Regions'])!=1:raise AssertionError('Unexpected external relay map')
            ping=client(clients['alice'],'ping','--until-direct=false','--timeout=10s',bob_ip)
            if 'DERP' not in ping:raise AssertionError('Forced relay ping did not show DERP')
            # Approval-style unique tags must select both source and destination.
            # This fixture uses workload keys; it does not impersonate Google or
            # claim to exercise the administration UI's approval transaction.
            tags={user:'tag:tailgate-'+secrets.token_hex(16) for user in ('alice','bob')}
            staged_policy={'tagOwners':{tag:[] for tag in tags.values()},'grants':policy['grants']}
            def install_policy(value):
                (bundle/'policy.json').write_text(json.dumps(value))
                cli('policy','check','--file=/config/policy.json')
                command('docker','kill','--signal=HUP',ctrl)
            install_policy(staged_policy)
            nodes=json.loads(cli('--output=json','nodes','list'))
            approved={user:next(n for n in nodes if n['given_name']=='smoke-'+user)
                      for user in ('alice','bob')}
            for user in ('alice','bob'):
                cli('nodes','tag','--identifier',str(approved[user]['id']),'--tags',tags[user])
            nodes=json.loads(cli('--output=json','nodes','list'))
            for user,original in approved.items():
                tagged=next(n for n in nodes if n['id']==original['id'])
                if tagged.get('tags')!=[tags[user]] or tagged.get('machine_key')!=original.get('machine_key'):
                    raise AssertionError('Approval tag was not retained on its exact node')
            unapproved=next(n for n in nodes if n['given_name']=='smoke-denied')
            if unapproved.get('tags'):raise AssertionError('Unapproved fixture acquired an approval tag')
            tagged_policy={'tagOwners':staged_policy['tagOwners'],
                           'grants':[{'src':[tags['alice']],'dst':[tags['bob']],'ip':['tcp:8080']}]}
            install_policy(tagged_policy)
            def allowed_tagged_request():
                for attempt in range(10):
                    try:
                        reply=request('alice')
                        if reply['status']==200 and 'private workflow ok' in reply['body']:return
                    except OSError:pass
                    time.sleep(.3)
                raise AssertionError('Unique source/destination tag grant did not permit its approved workflow')
            allowed_tagged_request()
            try:request('denied');raise AssertionError('Unapproved identity reached the tagged destination')
            except OSError:pass
            ping=client(clients['alice'],'ping','--until-direct=false','--timeout=10s',bob_ip)
            if 'DERP' not in ping:raise AssertionError('Tagged workflow did not use the owned relay')
            if example == 'partitioned':
                # Rehearse on synthetic test state only. Both official clients
                # must pick up new addresses without re-enrollment or new tags.
                before_nodes = json.loads(cli('--output=json', 'nodes', 'list'))
                before_policy = (bundle/'policy.json').read_bytes()
                command('docker', 'stop', ctrl)
                with sqlite3.connect(root/'state/db.sqlite') as database:
                    with sqlite3.connect(root/'pre-renumber.sqlite') as backup:
                        database.backup(backup)
                    config['prefixes'] = {'v4':'100.81.0.0/16', 'v6':'fd7a:115c:a1e0:8001::/64', 'allocation':'sequential'}
                    migration = renumber(database, config['prefixes'])
                (bundle/'headscale.json').write_text(json.dumps(config))
                command('docker', 'start', ctrl)
                for attempt in range(60):
                    try:
                        ready = True
                        for user, name in clients.items():
                            assigned = json.loads(client(name, 'status', '--json'))['TailscaleIPs']
                            expected = {node['after'][family] for node in migration['nodes'] for family in ('v4', 'v6')}
                            ready = ready and len(assigned) == 2 and all(value in expected for value in assigned)
                        if ready: break
                    except (RuntimeError, KeyError): pass
                    time.sleep(.3)
                else: raise AssertionError('Official clients did not reconnect with the new allocation pools')
                after_nodes = json.loads(cli('--output=json', 'nodes', 'list'))
                for old in before_nodes:
                    current = next(node for node in after_nodes if node['id'] == old['id'])
                    if any(current.get(field) != old.get(field) for field in ('machine_key', 'tags', 'user')):
                        raise AssertionError('Renumbering changed node identity, tags or owner')
                if (bundle/'policy.json').read_bytes() != before_policy:
                    raise AssertionError('Renumbering changed approval policy')
                bob_ip = client(clients['bob'], 'ip', '-4').splitlines()[0]
                bob_v6 = client(clients['bob'], 'ip', '-6').splitlines()[0]
                allowed_tagged_request()
                response = json.loads(command('docker','exec',clients['alice'],'/bin/probe','127.0.0.1:1055',bob_v6,'8080'))
                if response['status'] != 200: raise AssertionError('Renumbered IPv6 application access failed')
                try:request('denied');raise AssertionError('Renumbering widened access to an unapproved identity')
                except OSError:pass
                dns = client(clients['alice'],'dns','query','smoke-bob.mesh.example.com')
                if bob_ip not in dns:raise AssertionError('Renumbered MagicDNS address was not updated')
            # Withdraw permissions without deleting either approved device. A
            # new encrypted connection must fail while the application remains
            # locally healthy; re-grant verifies this was authorization, not an
            # application/container outage.
            install_policy({'tagOwners':staged_policy['tagOwners'],'grants':[]})
            for attempt in range(10):
                try:request('alice')
                except OSError:break
                time.sleep(.3)
            else:raise AssertionError('Withdrawn tag grant still permitted a new connection')
            healthy=command('docker','exec',app,'wget','-q','-O','-','http://127.0.0.1:8080')
            if 'private workflow ok' not in healthy:raise AssertionError('Revocation test application became unhealthy')
            install_policy(tagged_policy)
            allowed_tagged_request()
            # Expire/delete the server identity; verify connected client's next request fails.
            nodes=json.loads(cli('--output=json','nodes','list'))
            node=next(n for n in nodes if n['given_name']=='smoke-bob')
            cli('--force','nodes','delete','--identifier',str(node['id']));time.sleep(1)
            try:request('alice');raise AssertionError('Deleted node remained reachable')
            except OSError:pass
            result={'versions':{'headscale':'0.29.4','clients':'1.102.5','nginx':nginx},
                    'tls_proxy_and_control_upgrade':'passed','official_client_enrollment':3,
                    'tailgate_signin_errors':'passed','signin_error_statuses':len(public_site.enrollment.ERRORS),
                    'auth_redirect_cookie_and_confirmation':'passed','protocol_error_passthrough':'passed',
                    'confirmation_and_success_branding':'passed','csrf_form_and_cookie_preserved':'passed',
                    'deny_all':'passed','allowed_tcp_workflow':'passed','denied_identity':'passed',
                    'magic_dns':'passed','owned_relay_map':'passed','forced_derp':'passed',
                    'direct_underlay_blocked':'passed','node_revocation':'passed',
                    'unique_empty_owner_tags':'passed','tagged_allowed_workflow':'passed',
                    'tagged_unapproved_identity':'passed','tag_grant_withdrawal':'passed',
                    'tag_grant_restoration':'passed','tagged_forced_derp':'passed',
                    'container_containment':'passed','containers_checked':len(containers),
                    'allocation_pools':config['prefixes'], 'client_allocation':'passed',
                    'renumbering_and_identity_preservation':('passed' if example == 'partitioned' else 'not tested'),
                    'public_activation':False}
            print(json.dumps(result,indent=2));return result
        except Exception:
            for name in containers:
                # Never print upstream logs: even disposable logs may contain keys/auth URLs.
                raw=command('docker','inspect',name,check=False)
                try:
                    state=json.loads(raw)[0]['State']
                    print(json.dumps({'container':name,'status':state['Status'],
                                      'error':state['Error'],'exit_code':state['ExitCode']}))
                except (ValueError,KeyError,IndexError):
                    print(json.dumps({'container':name,'state':'unavailable'}))
            raise
        finally:
            for name in reversed(containers):command('docker','rm','-f',name,check=False)
            for n in reversed(networks):command('docker','network','rm',n,check=False)
            for name in images:command('docker','image','rm',name,check=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True)
    p.add_argument('--example', choices=('pilot', 'partitioned'), default='pilot')
    args = p.parse_args()
    run(args.artifacts, args.example)
