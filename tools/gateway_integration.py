#!/usr/bin/env python3
"""Disposable dual-controller, real kernel-client gateway qualification.

Only named/labelled resources created by this run are removed. NET_ADMIN and a
TUN device are confined to private container namespaces; no host network/PID,
Docker socket, host filesystem, production state or live accounts are mounted.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from docker_lab import verify_artifacts, hardening
from integration import command
from tailgate import ROOT, read_json, render


def run(artifacts):
    artifacts = verify_artifacts(artifacts)
    lock = read_json(ROOT/'versions.lock.json')
    receipt = read_json(artifacts/'tailgate-gateway.receipt.json')
    source = ROOT/'components/gateway'
    files = {str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(source.rglob('*')) if p.is_file()}
    if receipt['source_files'] != files or receipt['sha256'] != hashlib.sha256((artifacts/'tailgate-gateway').read_bytes()).hexdigest():
        raise ValueError('Gateway does not match source/build receipt')
    version = lock['components']['tailscale']['derper_build']['go_version']
    if receipt['go_version'] != version or receipt['platform'] != 'linux_arm64':
        raise ValueError('Gateway build is not locked Linux ARM64')
    if subprocess.check_output(['go','version'], text=True).split()[2] != 'go'+version:
        raise ValueError('Probe requires locked Go')
    if os.getuid() == 0: raise ValueError('Run the lab as an ordinary workstation user')
    prefix = 'tailgate-gateway-lab-'+secrets.token_hex(4)
    containers, networks = [], []
    image = prefix+':test'
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        root = Path(tmp)
        def create(name, *args):
            name = prefix+'-'+name
            command('docker','create','--name',name,'--label','tailgate.gateway-lab='+prefix,*args)
            containers.append(name)
            return name
        def start(name): command('docker','start',name)
        def cli(side,*args):return command('docker','exec',controllers[side],'/bin/headscale','--config=/config/headscale.json',*args)
        def client(name,*args):return command('docker','exec',name,'tailscale',*args)
        def wait(fn, description):
            last = None
            deadline=time.monotonic()+35
            while time.monotonic()<deadline:
                try:
                    value = fn()
                    if value:return value
                except (RuntimeError, KeyError, json.JSONDecodeError) as e:last = e
                time.sleep(.25)
            raise AssertionError(description) from last
        def ready(name):
            return wait(lambda: command('docker','exec',name,'cat','/run/gateway-ready'), 'gateway readiness')
        def packet(name,mode,address):
            return command('docker','exec',name,'/bin/gateway-probe',mode,address)
        def denied(fn):
            try:fn()
            except RuntimeError:return True
            raise AssertionError('Forbidden packet was delivered')
        def eventually_denied(fn):
            def attempt():
                try:fn();return False
                except RuntimeError:return True
            return wait(attempt,'permission withdrawal propagation')
        try:
            build = root/'build';build.mkdir()
            for name in ('headscale','tailscale','tailscaled','tailgate-gateway'):
                shutil.copyfile(artifacts/name,build/name);(build/name).chmod(0o755)
            env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0',GOOS='linux',GOARCH='arm64')
            subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(build/'gateway-probe'),str(ROOT/'tools/gateway-probe.go')],env=env,check=True)
            subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(build/'tailgate-admin'),'.'],cwd=ROOT/'components/admin',env=env,check=True)
            subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(build/'config-probe'),str(ROOT/'tools/config-probe.go')],env=env,check=True)
            (build/'Dockerfile').write_text('FROM '+lock['validation']['gateway_base']['image']+'\n'
                'COPY tailscale tailscaled /usr/local/bin/\nCOPY headscale tailgate-gateway gateway-probe tailgate-admin config-probe /bin/\nENTRYPOINT ["/bin/tailgate-gateway"]\n')
            command('docker','build','--quiet','-t',image,str(build))
            cert = root/'cert';cert.mkdir()
            command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Gateway lab CA',
                    '-keyout',str(cert/'ca.key'),'-out',str(cert/'ca.crt'))
            command('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=hosted.example.com',
                    '-keyout',str(cert/'server.key'),'-out',str(cert/'server.csr'))
            (cert/'ext').write_text('subjectAltName=DNS:hosted.example.com,DNS:tailgate.example.com\nextendedKeyUsage=serverAuth\n')
            command('openssl','x509','-req','-in',str(cert/'server.csr'),'-CA',str(cert/'ca.crt'),'-CAkey',str(cert/'ca.key'),
                    '-CAcreateserial','-days','1','-extfile',str(cert/'ext'),'-out',str(cert/'server.crt'))
            for p in (cert/'ca.key',cert/'server.key'):p.chmod(0o600)
            controllers, bundles = {}, {}
            for side,pool,v6 in [('hosted','100.64.0.0/16','fd7a:115c:a1e0:6400::/64'),('tailgate','100.80.0.0/16','fd7a:115c:a1e0:8000::/64')]:
                network=prefix+'-'+side;command('docker','network','create',network);networks.append(network)
                bundle=root/side;render(read_json(ROOT/'examples/partitioned.json'),bundle);bundles[side]=bundle
                config=read_json(bundle/'headscale.json');config.pop('oidc')
                config.update(server_url='https://'+side+'.example.com:8443',unix_socket='/run/headscale.sock')
                config['noise']['private_key_path']='/state/noise.key';config['database']['sqlite']['path']='/state/db.sqlite'
                config['prefixes']={'v4':pool,'v6':v6,'allocation':'sequential'}
                config['policy']['path']='/config/policy.json';config['dns']['extra_records_path']='/config/records.json'
                config['dns']['base_domain']=('old' if side=='hosted' else 'mesh')+'.example.com'
                config['derp']['server'].update(private_key_path='/state/derp.key');config['derp']['server'].pop('ipv4',None)
                (bundle/'headscale.json').write_text(json.dumps(config))
                proxy=(bundle/'controller.nginx.conf').read_text().replace('control.example.com',side+'.example.com').replace('listen 443 ssl','listen 8443 ssl')
                proxy=proxy.replace('/var/lib/tailgate/acme/certificates/'+side+'.example.com.crt','/cert/server.crt').replace('/var/lib/tailgate/acme/certificates/'+side+'.example.com.key','/cert/server.key')
                if side == 'hosted':
                    locations=''.join('location '+path+' { proxy_set_header Host $http_host; proxy_pass http://127.0.0.1:18100; }' for path in ('/gateway-config/', '/api/bridge-config', '/api/login'))
                    proxy=proxy.replace('server {','server { '+locations,1)
                (root/(side+'.nginx')).write_text('pid /tmp/nginx.pid; events {} http { client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; '+proxy+' }')
                nginx=create(side+'-proxy','--network',network,'--network-alias',side+'.example.com',*hardening(os.getuid(),os.getgid()),
                    '--tmpfs',f'/tmp:uid={os.getuid()},gid={os.getgid()}', '-v',str(root/(side+'.nginx'))+':/etc/nginx/nginx.conf:ro',
                    '-v',str(cert/'server.crt')+':/cert/server.crt:ro','-v',str(cert/'server.key')+':/cert/server.key:ro',
                    '--entrypoint','nginx',lock['validation']['nginx_image'],'-g','daemon off;');start(nginx)
                ctrl=create(side+'-controller','--network','container:'+nginx,*hardening(os.getuid(),os.getgid()),
                    '--tmpfs',f'/state:uid={os.getuid()},gid={os.getgid()}','--tmpfs',f'/run:uid={os.getuid()},gid={os.getgid()}',
                    '-v',str(bundle)+':/config:ro','--entrypoint','/bin/headscale',image,'--config=/config/headscale.json','serve');start(ctrl);controllers[side]=ctrl
                wait(lambda:cli(side,'--output=json','users','list'),'controller start')
            # The production admin binary serves the same durable configuration
            # to its panel and a scoped machine reader. All state is disposable.
            configdir=root/'common-config';configdir.mkdir(mode=0o700)
            configstate=root/'common-state';configstate.mkdir(mode=0o700)
            reader_token=secrets.token_hex(32)
            for name,value in [('reader',reader_token),('login',secrets.token_hex(32)),('api',secrets.token_hex(32))]:
                f=configdir/name;f.write_text(value);f.chmod(0o600)
            registry={'state_path':'/common-state/rules.json','gateways':[{'id':'migration','token_file':'/common-config/reader'}]}
            (configdir/'registry.json').write_text(json.dumps(registry));(configdir/'registry.json').chmod(0o600)
            configserver=create('config-service','--network','container:'+prefix+'-hosted-proxy',*hardening(os.getuid(),os.getgid()),
                '-v',str(configdir)+':/common-config:ro','-v',str(configstate)+':/common-state',
                '--entrypoint','/bin/tailgate-admin',image,'--origin=https://hosted.example.com:8443','--headscale-url=http://127.0.0.1:8080',
                '--api-key-file=/common-config/api','--login-token-file=/common-config/login',
                '--config-service-file=/common-config/registry.json','--allow-config-changes')
            start(configserver)
            def set_users(users):
                return command('docker','exec',configserver,'/bin/config-probe','https://hosted.example.com:8443',
                    '/common-config/login','migration',json.dumps(users) if users is not None else 'disabled')
            wait(lambda:set_users(['alice@example.com']),'common config service')
            def policy(side,grants):
                value={'grants':grants}
                if side == 'hosted': value['tagOwners']={'tag:unlisted':[]}
                (bundles[side]/'policy.json').write_text(json.dumps(value))
                cli(side,'policy','check','--file=/config/policy.json');command('docker','kill','--signal=HUP',controllers[side]);time.sleep(.5)
            def key(side,name):
                cli(side,'users','create',name,'--email='+name+'@example.com')
                uid=next(u['id'] for u in json.loads(cli(side,'--output=json','users','list')) if u['name']==name)
                value=cli(side,'preauthkeys','create','--user',str(uid),'--expiration=20m')
                # The parent directory is private (0700). Read-only individual
                # mounts must be readable by container root without DAC_OVERRIDE.
                p=root/(name+'.secret');p.write_text(value);p.chmod(0o444);return p
            restricted=['--read-only','--cap-drop=ALL','--cap-add=NET_ADMIN','--cap-add=NET_RAW','--device=/dev/net/tun',
                        '--security-opt=no-new-privileges:true','--pids-limit=128','--memory=256m','--cpus=1',
                        '--sysctl=net.ipv4.ip_forward=1','--sysctl=net.ipv4.conf.all.rp_filter=0',
                        '--tmpfs=/run:mode=0700','--tmpfs=/tmp:mode=0700','--mount=type=volume,destination=/state',
                        '-v',str(cert/'ca.crt')+':/etc/ssl/certs/ca-certificates.crt:ro','-e','TS_NO_LOGS_NO_SUPPORT=true']
            # Docker --internal drops bridged packets whose IP destination is
            # outside its subnet, including the routed overlay pool. A dedicated
            # non-masquerading bridge carries that traffic; namespace firewalls
            # restrict it and egress has explicit default-gateway priority.
            transit=prefix+'-transit';command('docker','network','create','--opt=com.docker.network.bridge.enable_ip_masquerade=false','--subnet=10.231.0.0/29',transit);networks.append(transit)
            gateways={}
            for side,own,peer in [('hosted','10.231.0.2','10.231.0.3'),('tailgate','10.231.0.3','10.231.0.2')]:
                k=key(side,'gateway-'+side)
                cfg={'role':side,'hostname':'gateway-'+side,'login_server':'https://'+side+'.example.com:8443','destination_pool':'100.80.0.0/16',
                     'dns_domain':'mesh.example.com','transit_address':own,'transit_peer':peer,'auth_key_file':'/secrets/auth-key'}
                if side == 'hosted': cfg['config_service']={'url':'https://hosted.example.com:8443/gateway-config/v1/migration','gateway':'migration','token_file':'/secrets/config-token'}
                p=root/(side+'-gateway.json');p.write_text(json.dumps(cfg))
                name=create(side+'-gateway','--network','name='+prefix+'-'+side+',gw-priority=1',*restricted,'--tmpfs=/secrets:mode=0700','-v',str(p)+':/config/gateway.json:ro','-v',str(k)+':/secrets/auth-key:ro',image)
                command('docker','network','connect','--ip',own,transit,name);start(name);gateways[side]=name
                if side == 'hosted': command('docker','exec',name,'sh','-c',"umask 077; printf '%s' '"+reader_token+"' > /secrets/config-token")
            hosted_ip=ready(gateways['hosted']);tailgate_ip=ready(gateways['tailgate'])
            clients={}
            for side,user in [('hosted','alice'),('hosted','denied'),('tailgate','server')]:
                k=key(side,user)
                name=create(user,'--network',prefix+'-'+side,*restricted,'-v',str(k)+':/secrets/auth-key:ro',
                    '--entrypoint','tailscaled',image,'--state=/state/client.state','--tun=tailscale0');start(name);clients[user]=name
                wait(lambda:client(name,'status','--json'),'client socket')
                client(name,'up','--login-server=https://'+side+'.example.com:8443','--auth-key=file:/secrets/auth-key','--hostname='+user,'--accept-routes=true','--accept-dns=false')
            server_ip=client(clients['server'],'ip','-4').strip()
            command('docker','exec','-d',clients['server'],'/bin/gateway-probe','serve')
            # Initial deny-all, then approve route separately from both ACLs.
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            node=next(n for n in json.loads(cli('hosted','--output=json','nodes','list')) if n['given_name']=='gateway-hosted')
            cli('hosted','nodes','approve-routes','--identifier',str(node['id']),'--routes','100.80.0.0/16')
            # Deliberately match the existing vendor allow-all policy: denial
            # must come from the Go identity gate, not a convenient source ACL.
            hosted_grants=[{'src':['*'],'dst':['*'],'ip':['*']}]
            target_grants=[{'src':['gateway-tailgate@example.com'],'dst':['server@example.com'],'ip':['tcp:8080','udp:8081']}]
            policy('hosted',hosted_grants)
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            policy('tailgate',target_grants)
            def tcp_ok():return packet(clients['alice'],'tcp',server_ip+':8080').startswith(tailgate_ip+':')
            wait(tcp_ok,'TCP across both official overlays with gateway source identity')
            print('Two-overlay TCP/SNAT passed',flush=True)
            # Existing subnet routers cause the official client to report an
            # informational warning because this gateway pins accept-routes=false.
            # Introduce one after forwarding starts and keep it through all DNS,
            # denial, revocation and restart checks below.
            client(clients['denied'],'set','--advertise-routes=192.0.2.0/24')
            router=next(n for n in json.loads(cli('hosted','--output=json','nodes','list')) if n['given_name']=='denied')
            cli('hosted','nodes','approve-routes','--identifier',str(router['id']),'--routes','192.0.2.0/24')
            route_warning='Some peers are advertising routes but --accept-routes is false'
            wait(lambda:route_warning in json.loads(client(gateways['hosted'],'status','--json')).get('Health',[]),'expected route-acceptance warning')
            # Allow the supervisor to observe the warning; a packet immediately
            # after the netmap update could race its one-second authorization loop.
            time.sleep(2)
            if not tcp_ok():raise AssertionError('Existing subnet router closed authorized forwarding')
            if '192.0.2.0/24' in command('docker','exec',gateways['hosted'],'ip','route','show','table','52'):
                raise AssertionError('Gateway accepted unrelated subnet route')
            print('Unrelated subnet router warning preserves authorized forwarding without accepting its route',flush=True)
            if not packet(clients['alice'],'udp',server_ip+':8081').startswith(tailgate_ip+':'):raise AssertionError('UDP/SNAT')
            denied(lambda:packet(clients['denied'],'tcp',server_ip+':8080'))
            denied(lambda:packet(clients['denied'],'udp',server_ip+':8081'))
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8082'))
            # Real DNS from hosted client, through both Go listeners and local Quad100.
            for mode in ('dns-udp','dns-tcp'):
                denied(lambda:command('docker','exec',clients['denied'],'/bin/gateway-probe',mode,hosted_ip+':53','server.mesh.example.com','A'))
                answer=command('docker','exec',clients['alice'],'/bin/gateway-probe',mode,hosted_ip+':53','server.mesh.example.com','A')
                if 'rcode=0 answers=1' not in answer or ipaddress.ip_address(server_ip).packed.hex() not in answer:raise AssertionError('MagicDNS forwarding')
                answer=command('docker','exec',clients['alice'],'/bin/gateway-probe',mode,hosted_ip+':53','server.mesh.example.com','AAAA')
                if 'rcode=0 answers=0' not in answer:raise AssertionError('IPv6 NODATA')
                answer=command('docker','exec',clients['alice'],'/bin/gateway-probe',mode,hosted_ip+':53','example.org','A')
                if 'rcode=5' not in answer:raise AssertionError('External DNS not refused')
            print('UDP, both ACL boundaries and UDP/TCP MagicDNS passed',flush=True)
            # Native connectivity for an unlisted user survives the bridge gate.
            command('docker','exec','-d',clients['alice'],'/bin/gateway-probe','serve')
            alice_ip=client(clients['alice'],'ip','-4').strip()
            wait(lambda:packet(clients['denied'],'tcp',alice_ip+':8080'),'unlisted user native access')
            # No implicit owner/admin allowance, even when both policies permit.
            hosted_started=json.loads(command('docker','inspect',gateways['hosted']))[0]['State']['StartedAt']
            set_users([])
            eventually_denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            denied(lambda:packet(clients['alice'],'udp',server_ip+':8081'))
            for mode in ('dns-udp','dns-tcp'):
                denied(lambda:command('docker','exec',clients['alice'],'/bin/gateway-probe',mode,hosted_ip+':53','server.mesh.example.com','A'))
            packet(clients['denied'],'tcp',alice_ip+':8080')
            set_users(['alice@example.com']);wait(tcp_ok,'remote allowlist restoration')
            set_users(None);eventually_denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            set_users(['alice@example.com']);wait(tcp_ok,'remote enable restoration')
            command('docker','stop',configserver)
            eventually_denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            denied(lambda:packet(clients['alice'],'udp',server_ip+':8081'))
            for mode in ('dns-udp','dns-tcp'):
                denied(lambda:command('docker','exec',clients['alice'],'/bin/gateway-probe',mode,hosted_ip+':53','server.mesh.example.com','A'))
            packet(clients['denied'],'tcp',alice_ip+':8080')
            start(configserver);wait(tcp_ok,'durable config recovery after service restart')
            if json.loads(command('docker','inspect',gateways['hosted']))[0]['State']['StartedAt']!=hosted_started:
                raise AssertionError('Config changes restarted gateway')
            # Revoke a live flow through the exact panel API, not a file rewrite.
            held=subprocess.Popen(['docker','exec',clients['alice'],'/bin/gateway-probe','tcp-held',server_ip+':8080'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                wait(lambda:command('docker','exec',clients['alice'],'cat','/run/probe-ready'),'remote established connection')
                set_users([])
                wait(lambda:alice_ip not in command('docker','exec',gateways['hosted'],'iptables-nft-save','-t','filter'),'remote rule withdrawal')
                command('docker','exec',clients['alice'],'touch','/run/probe-continue')
                out,err=held.communicate(timeout=10)
                if held.returncode or 'established flow revoked' not in out:raise AssertionError('Remote rule did not revoke established flow')
            finally:
                if held.poll() is None:held.kill();held.communicate()
                command('docker','exec',clients['alice'],'rm','-f','/run/probe-ready','/run/probe-continue')
            set_users(['alice@example.com']);wait(tcp_ok,'remote established revocation recovery')
            print('Panel API updates, remote disable, empty-list closure, service outage/restart and established revocation passed without gateway restart',flush=True)
            # More permissive remote policy still cannot turn the gateway into
            # an internet/LAN router or allow reverse-initiated transit.
            policy('tailgate',target_grants+[{'src':['server@example.com'],'dst':['gateway-tailgate@example.com'],'ip':['*']}])
            denied(lambda:packet(clients['server'],'tcp',tailgate_ip+':8080'))
            policy('tailgate',[])
            eventually_denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            packet(clients['server'],'tcp','127.0.0.1:8080')
            policy('tailgate',target_grants);wait(tcp_ok,'restored approval')
            policy('hosted',[])
            eventually_denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            policy('hosted',hosted_grants);wait(tcp_ok,'restored hosted approval')
            # A newly enrolled destination is covered by the original pool
            # route. Only its service authorization is added, not a port proxy
            # or a gateway route/configuration change.
            k=key('tailgate','new-server')
            newer=create('new-server','--network',prefix+'-tailgate',*restricted,'-v',str(k)+':/secrets/auth-key:ro',
                '--entrypoint','tailscaled',image,'--state=/state/client.state','--tun=tailscale0');start(newer)
            wait(lambda:client(newer,'status','--json'),'new destination client socket')
            client(newer,'up','--login-server=https://tailgate.example.com:8443','--auth-key=file:/secrets/auth-key',
                   '--hostname=new-server','--accept-dns=false','--accept-routes=true')
            new_ip=client(newer,'ip','-4').strip()
            command('docker','exec','-d',newer,'/bin/gateway-probe','serve')
            denied(lambda:packet(clients['alice'],'tcp',new_ip+':8080'))
            target_grants.append({'src':['gateway-tailgate@example.com'],'dst':['new-server@example.com'],'ip':['tcp:8080']})
            policy('tailgate',target_grants)
            wait(lambda:packet(clients['alice'],'tcp',new_ip+':8080').startswith(tailgate_ip+':'),'automatic pool coverage')
            # Exercise the forwarding guard even if an operator accidentally
            # advertises and approves a reverse route with permissive ACLs.
            packet(clients['alice'],'tcp','127.0.0.1:8080')
            client(gateways['tailgate'],'set','--advertise-routes=100.64.0.0/16')
            reverse_node=next(n for n in json.loads(cli('tailgate','--output=json','nodes','list')) if n['given_name']=='gateway-tailgate')
            cli('tailgate','nodes','approve-routes','--identifier',str(reverse_node['id']),'--routes','100.64.0.0/16')
            command('docker','exec',gateways['tailgate'],'ip','route','add','100.64.0.0/16','via','10.231.0.2')
            command('docker','exec',gateways['tailgate'],'ip','rule','add','pref','100','to','100.64.0.0/16','lookup','main')
            policy('tailgate',target_grants+[{'src':['server@example.com'],'dst':['100.64.0.0/16'],'ip':['tcp:8080']}])
            alice_ip=client(clients['alice'],'ip','-4').strip()
            wait(lambda:'100.64.0.0/16' in command('docker','exec',clients['server'],'ip','route','show','table','52'),'reverse test route propagation')
            denied(lambda:packet(clients['server'],'tcp',alice_ip+':8080'))
            client(gateways['tailgate'],'set','--advertise-routes=')
            policy('tailgate',target_grants)
            print('New destinations covered automatically; reverse initiation denied',flush=True)
            for side in ('tailgate','hosted'):
                command('docker','restart',gateways[side])
                if side == 'hosted': command('docker','exec',gateways[side],'sh','-c',"umask 077; printf '%s' '"+reader_token+"' > /secrets/config-token")
                ready(gateways[side]);wait(tcp_ok,'restart recovery')
            # Losing the Tailgate side must not cause fallback to underlay.
            command('docker','stop',gateways['tailgate'])
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            start(gateways['tailgate']);ready(gateways['tailgate']);wait(tcp_ok,'outage recovery')
            print('Both policy revocations and restart/outage recovery passed',flush=True)
            # Convert Alice's device to a tagged identity with all hosted ACLs
            # still permissive. The already-running gateway must withdraw it,
            # including an established connection; native access still works.
            held=subprocess.Popen(['docker','exec',clients['alice'],'/bin/gateway-probe','tcp-held',server_ip+':8080'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                wait(lambda:command('docker','exec',clients['alice'],'cat','/run/probe-ready'),'established connection')
                alice_node=next(n for n in json.loads(cli('hosted','--output=json','nodes','list')) if n['given_name']=='alice')
                cli('hosted','nodes','tag','--identifier',str(alice_node['id']),'--tags','tag:unlisted')
                wait(lambda:alice_ip not in command('docker','exec',gateways['hosted'],'iptables-nft-save','-t','filter'),'identity refresh removed tagged device')
                command('docker','exec',clients['alice'],'touch','/run/probe-continue')
                out,err=held.communicate(timeout=10)
                if held.returncode or 'established flow revoked' not in out:raise AssertionError('Established connection was not revoked: '+err[:200])
            finally:
                if held.poll() is None:held.kill();held.communicate()
            denied(lambda:packet(clients['alice'],'tcp',server_ip+':8080'))
            packet(clients['denied'],'tcp',alice_ip+':8080')
            print('Live identity refresh denied tagged owner and revoked established bridge flow; native access preserved',flush=True)
            for name in containers:
                inspected=json.loads(command('docker','inspect',name))[0];h=inspected['HostConfig']
                if h['Privileged'] or h['NetworkMode']=='host' or h['PidMode']=='host' or h.get('PortBindings'):raise AssertionError('Host isolation violation')
                if not h['ReadonlyRootfs'] or 'ALL' not in h['CapDrop']:raise AssertionError('Missing confinement')
            return {'company_state_used':False,'hosted_control':'disposable Headscale surrogate, not hosted vendor API',
                    'official_clients':'1.102.5','separate_pools':True,'ipv4_tcp_udp_snat':'passed','both_acl_boundaries':'passed',
                    'dns_udp_tcp':'passed','dns_scope_and_aaaa':'passed','grant_revocation':'passed',
                    'gateway_user_allowlist_with_wildcard_hosted_acl':'passed','empty_allowlist_denies_tcp_udp_dns':'passed',
                    'unrelated_subnet_router_warning':'passed',
                    'central_config_panel_api_live_updates_outage_durable_restart':'passed',
                    'central_config_established_flow_revocation':'passed',
                    'unlisted_user_native_access':'passed',
                    'tagged_identity_live_revocation_and_established_flow':'passed',
                    'automatic_new_destination':'passed','reverse_forwarding_denial':'passed',
                    'restart_and_outage_recovery':'passed','container_confinement':'passed','production_activation':False}
        except Exception:
            for name in containers:
                if name.endswith('-gateway'):
                    # Only our gateway writes stdout/stderr; daemon output is
                    # discarded. Never print upstream client/controller logs.
                    print(name.rsplit('-',2)[-2]+': '+command('docker','logs',name,check=False)[-1000:])
                    raw=command('docker','exec',name,'tailscale','status','--json',check=False)
                    try:
                        state=json.loads(raw)
                        print('backend:',state.get('BackendState'))
                        # Bounded categories, never raw daemon output or auth URLs.
                        print('health categories:', ['certificate' if 'x509' in h else 'control-connectivity' if 'control' in h.lower() else 'other' for h in state.get('Health',[])])
                    except ValueError:pass
                    side='hosted' if '-hosted-' in name else 'tailgate'
                    args=['docker','exec',name,'tailscale','up','--timeout=3s','--login-server=https://'+side+'.example.com:8443',
                          '--hostname=gateway-'+side,'--accept-dns=false','--accept-routes=false','--netfilter-mode=off',
                          '--snat-subnet-routes=false','--ssh=false','--auth-key=file:/secrets/auth-key',
                          '--advertise-routes='+('100.80.0.0/16' if side=='hosted' else '')]
                    result=subprocess.run(args,capture_output=True,text=True,timeout=10)
                    for line in result.stderr.splitlines():
                        if any(word in line.lower() for word in ('flag','permission denied','x509','invalid','error:')) and 'tskey-' not in line:
                            print('client configuration diagnostic:',line[:250])
            raise
        finally:
            for name in reversed(containers):command('docker','rm','-fv',name,check=False)
            for name in reversed(networks):command('docker','network','rm',name,check=False)
            command('docker','image','rm',image,check=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True)
    args=p.parse_args();print(json.dumps(run(args.artifacts),indent=2))
