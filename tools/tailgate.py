#!/usr/bin/env python3
"""Dependency-free, release-pinned component renderer and artifact acquisition."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONFIG = '/etc/tailgate'
STATE = '/var/lib/tailgate'
SUPPORTED_PREFIXES = {'v4': '100.64.0.0/10', 'v6': 'fd7a:115c:a1e0::/48'}


def mesh_prefixes(controller):
    prefixes = controller.get('prefixes', dict(SUPPORTED_PREFIXES, allocation='sequential'))
    require(isinstance(prefixes, dict) and set(prefixes) <= {'v4', 'v6', 'allocation'},
            'prefixes must contain only v4, v6 and allocation')
    require(prefixes.get('allocation', 'sequential') in ('sequential', 'random'),
            'unsupported address allocation strategy')
    result = {'allocation': prefixes.get('allocation', 'sequential')}
    for family, supported in SUPPORTED_PREFIXES.items():
        value = prefixes.get(family)
        require(isinstance(value, str), 'explicit IPv4 and IPv6 prefixes are required')
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise ValueError('prefix must be a canonical network: ' + family)
        parent = ipaddress.ip_network(supported)
        require(network.version == parent.version and network.subnet_of(parent),
                'prefix is outside official client support: ' + family)
        require(value == str(network), 'prefix must use canonical form: ' + family)
        require(network.num_addresses >= 4, 'prefix requires at least four addresses: ' + family)
        result[family] = value
    return result


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def domain(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value,
            'expected a fully qualified domain')
    require(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                for p in value.split('.')), 'invalid lowercase domain: ' + value)
    return value


def endpoint(value):
    require(isinstance(value, str), 'listener must be a string')
    try:
        host, port = value.rsplit(':', 1)
        ip = ipaddress.ip_address(host.strip('[]'))
        require(1 <= int(port) <= 65535, 'invalid listener port')
        require(ip.is_loopback, 'controller and metrics must bind loopback')
        canonical_host = '[' + str(ip) + ']' if ip.version == 6 else str(ip)
        require(value == canonical_host + ':' + str(int(port)), 'listener must use canonical form')
        return value
    except (ValueError, TypeError):
        raise ValueError('invalid loopback listener: ' + value)


def mesh_address(value, prefixes=None):
    ip = ipaddress.ip_address(value)
    prefix = (prefixes or SUPPORTED_PREFIXES)['v4' if ip.version == 4 else 'v6']
    require(ip in ipaddress.ip_network(prefix), 'application address must be a mesh IP')
    return ip


def validate(spec, draft=False):
    require(spec.get('schema_version') == 1, 'unsupported schema_version')
    c = spec['controller']
    prefixes = mesh_prefixes(c)
    domain(c['hostname']); domain(c['device_domain']); domain(c['application_domain'])
    require(c['hostname'] != c['device_domain'], 'MagicDNS domain equals controller')
    endpoint(c['listen']); endpoint(c['metrics'])
    require(c['listen'] != c['metrics'], 'HTTP and metrics listeners collide')
    if c.get('public_ipv4'):
        require(ipaddress.ip_address(c['public_ipv4']).version == 4, 'invalid public IPv4')
    identity = spec['identity']
    require('client_secret' not in identity, 'use a secret file, never inline client_secret')
    domains = identity.get('allowed_domains', [])
    users = identity.get('allowed_users', [])
    for d in domains: domain(d)
    for user in users:
        require(isinstance(user, str) and user.count('@') == 1 and '\n' not in user,
                'invalid identity email')
        domain(user.rsplit('@', 1)[1])
    if not draft:
        require(identity.get('client_id') and
                re.fullmatch(r'[A-Za-z0-9._-]+', identity['client_id']),
                'Google client_id is required')
        require(domains or users, 'explicit Google admission filter is required')
        cert = spec['certificates']
        require(cert.get('dns_provider') and
                re.fullmatch(r'[a-z0-9_]+', cert['dns_provider']), 'DNS provider is required')
        require(cert.get('email') and '@' in cert['email'], 'ACME contact email is required')
    policy = spec['policy']
    require(spec.get('policy_storage', 'file') in ('file', 'database'), 'invalid policy storage')
    require(isinstance(policy, dict) and isinstance(policy.get('grants'), list),
            'explicit grants list required; {} is not deny-all')
    require('acls' not in policy, 'this distribution uses grants; migrate ACLs explicitly')
    for grant in policy['grants']:
        require(all(isinstance(grant.get(k), list) and grant[k] for k in ('src','dst','ip')),
                'grants require nonempty src, dst, ip lists')
    relay = spec['relay']
    require(relay['mode'] in ('embedded', 'standalone'), 'invalid relay mode')
    nodes = relay.get('nodes', [])
    if relay['mode'] == 'standalone':
        require(nodes, 'standalone mode requires owned relay nodes')
    ids, names = set(), set()
    for node in nodes:
        domain(node['hostname'])
        require(isinstance(node['region_id'], int) and 1 <= node['region_id'] <= 65535,
                'invalid relay region id')
        require(node['region_id'] not in ids and node['hostname'] not in names,
                'duplicate relay region or hostname')
        ids.add(node['region_id']); names.add(node['hostname'])
        require(re.fullmatch(r'[a-z0-9-]+', node['code']), 'invalid relay code')
        require(ipaddress.ip_address(node['ipv4']).version == 4, 'relay requires IPv4')
    services = spec.get('services', [])
    names, audiences = set(), {}
    for service in services:
        domain(service['name'])
        require(service['name'].endswith('.' + c['application_domain']),
                'service outside application namespace')
        require(service['name'] not in names, 'duplicate service name')
        names.add(service['name'])
        ip = mesh_address(service['address'], prefixes)
        require(ip.version == 4, 'initial app proxy requires IPv4; add qualified IPv6 explicitly')
        require(re.fullmatch(r'127\.0\.0\.1:[0-9]+', service['backend']) is not None,
                'application backend must be host-local HTTP')
        endpoint(service['backend'])
        require(re.fullmatch(r'[a-z0-9-]+', service['audience']), 'invalid audience')
        previous = audiences.setdefault(service['address'], service['audience'])
        require(previous == service['audience'],
                'different audiences share an IP:443; separate endpoints or add application auth')
    return spec


def template(name, values):
    content = (ROOT / 'components' / name).read_text()
    for key, value in values.items():
        content = content.replace('@@' + key + '@@', str(value))
    require(not re.search(r'@@[A-Z_]+@@', content), 'unfilled template: ' + name)
    return content


def render(spec, output, draft=False):
    validate(spec, draft)
    output = Path(output)
    require(not output.exists() or not any(output.iterdir()), 'render output must be empty')
    c, identity, relay = spec['controller'], spec['identity'], spec['relay']
    embedded = relay['mode'] == 'embedded'
    config = {
        'server_url': 'https://' + c['hostname'], 'listen_addr': c['listen'],
        'metrics_listen_addr': c['metrics'], 'grpc_listen_addr': '127.0.0.1:50443',
        'grpc_allow_insecure': False, 'trusted_proxies': ['127.0.0.1/32', '::1/128'],
        'noise': {'private_key_path': STATE + '/noise_private.key'},
        'prefixes': mesh_prefixes(c),
        'derp': {'server': {'enabled': embedded, 'region_id': 999,
                  'region_code': 'owned-pilot', 'region_name': 'Owned pilot relay',
                  'verify_clients': True, 'stun_listen_addr': '0.0.0.0:3478',
                  'private_key_path': STATE + '/derp_private.key',
                  'automatically_add_embedded_derp_region': True},
                  'urls': [], 'paths': [] if embedded else [CONFIG + '/derp.json'],
                  'auto_update_enabled': False, 'update_frequency': '3h'},
        'disable_check_updates': True,
        'node': {'expiry': '2160h', 'ephemeral': {'inactivity_timeout': '30m'}},
        'database': {'type': 'sqlite', 'sqlite': {'path': STATE + '/db.sqlite',
                     'write_ahead_log': True, 'wal_autocheckpoint': 1000}},
        'tls_cert_path': '', 'tls_key_path': '', 'log': {'level':'info', 'format':'json'},
        'policy': ({'mode':'database'} if spec.get('policy_storage') == 'database'
                   else {'mode':'file', 'path': CONFIG + '/policy.json'}),
        'dns': {'magic_dns': True, 'base_domain':c['device_domain'],
                'override_local_dns': False, 'nameservers': {'global':[], 'split':{}},
                'search_domains': [], 'extra_records_path': CONFIG + '/records.json'},
        'unix_socket': '/run/tailgate/headscale.sock', 'unix_socket_permission': '0770',
        'oidc': {'issuer':'https://accounts.google.com',
                 'client_id': identity.get('client_id') or 'UNCONFIGURED',
                 'client_secret_path':'${CREDENTIALS_DIRECTORY}/oidc_client_secret',
                 'only_start_if_oidc_is_available': True, 'email_verified_required':True,
                 'scope':['openid','profile','email'], 'pkce':{'enabled':True, 'method':'S256'},
                 'allowed_domains':identity.get('allowed_domains', []),
                 'allowed_users':identity.get('allowed_users', [])},
        'logtail':{'enabled':False}, 'auto_update':{'enabled':False}, 'taildrop':{'enabled':False}
    }
    if embedded and c.get('public_ipv4'):
        config['derp']['server']['ipv4'] = c['public_ipv4']
    if draft and not (identity.get('allowed_domains') or identity.get('allowed_users')):
        config['oidc']['allowed_users'] = ['unconfigured@invalid.example']
    mapping = {'Regions':{}}
    for node in relay.get('nodes', []):
        mapping['Regions'][str(node['region_id'])] = {
            'RegionID':node['region_id'], 'RegionCode':node['code'], 'RegionName':node['code'],
            'Nodes':[{'Name':node['code'], 'RegionID':node['region_id'],
                      'HostName':node['hostname'], 'IPv4':node['ipv4'], 'IPv6':'none',
                      'DERPPort':443, 'STUNPort':3478}]}
    records = [{'name':s['name'], 'type':'A', 'value':s['address']}
               for s in sorted(spec.get('services', []), key=lambda x:x['name'])]
    files = {'headscale.json':config, 'policy.json':spec['policy'], 'records.json':records,
             'derp.json':mapping, 'manifest.json':{'schema_version':1, 'draft':draft,
               'controller':c['hostname'], 'components':read_json(ROOT / 'versions.lock.json')['components'],
               'input_sha256':hashlib.sha256(json.dumps(spec,sort_keys=True).encode()).hexdigest()}}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (output / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    values = {'HOST':c['hostname'], 'BACKEND':c['listen'],
              'CERT':STATE + '/acme/certificates/' + c['hostname'] + '.crt',
              'KEY':STATE + '/acme/certificates/' + c['hostname'] + '.key'}
    verify_allow = ''.join('        allow ' + n['ipv4'] + ';\n' for n in relay.get('nodes', []))
    values['VERIFY_ALLOW'] = verify_allow + '        deny all;'
    (output / 'controller.nginx.conf').write_text(template('controller/nginx.conf.in', values))
    (output / 'tailgate.service').write_text(template('controller/tailgate.service.in', {}))
    (output / 'tailgate-exit.service').write_text(template('exit-node/tailscaled.service.in', {}))
    for s in spec.get('services', []):
        vals = {'HOST':s['name'], 'ADDRESS':s['address'], 'BACKEND':s['backend'],
                'CERT':STATE + '/acme/certificates/' + s['name'] + '.crt',
                'KEY':STATE + '/acme/certificates/' + s['name'] + '.key'}
        (output / (s['name'] + '.nginx.conf')).write_text(template('https/app.nginx.conf.in', vals))
    for n in relay.get('nodes', []):
        vals = {'HOST':n['hostname'], 'CONTROL':c['hostname']}
        (output / (n['code'] + '.service')).write_text(template('relay/derper.service.in', vals))
    (output / 'README.txt').write_text(
        'Draft bundle: activation forbidden.\n' if draft else
        'Validated component bundle. Complete deployment preflight before activation.\n')


def fetch(component, platform, directory):
    lock = read_json(ROOT / 'versions.lock.json')
    entry = lock['components'][component]
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry['published_at'].replace('Z','+00:00'))
    require(age >= dt.timedelta(days=lock['minimum_release_age_days']), 'upstream release is too new')
    artifact = entry['artifacts'][platform]
    parsed = urllib.parse.urlparse(artifact['url'])
    require(parsed.scheme == 'https' and parsed.hostname in ('github.com','pkgs.tailscale.com'),
            'unexpected artifact origin')
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target) as temp:
        archive = Path(temp) / 'download'
        digest = hashlib.sha256()
        with urllib.request.urlopen(artifact['url'], timeout=90) as response, archive.open('wb') as dest:
            while True:
                block = response.read(1024 * 1024)
                if not block: break
                digest.update(block); dest.write(block)
        require(digest.hexdigest() == artifact['sha256'], 'artifact checksum mismatch')
        names = ['tailscale','tailscaled'] if component == 'tailscale' else [component]
        if artifact['format'] == 'binary':
            shutil.copyfile(archive, target / component)
        else:
            with tarfile.open(archive, 'r:gz') as tar:
                for name in names:
                    matches = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == name]
                    require(len(matches) == 1, 'archive missing or ambiguous binary: ' + name)
                    with tar.extractfile(matches[0]) as source, (target / name).open('wb') as dest:
                        shutil.copyfileobj(source, dest)
        for name in names:
            (target / name).chmod(0o755)
    receipt = {'component':component, 'platform':platform, 'version':entry['version'],
               'archive_sha256':artifact['sha256'],
               'binary_sha256':{n:hashlib.sha256((target/n).read_bytes()).hexdigest() for n in names}}
    (target/(component+'.fetch.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    notice = ROOT/'docs/upstream-licenses'/(component+'.txt')
    shutil.copyfile(notice, target/(component+'.LICENSE.txt'))
    print(json.dumps(dict(receipt, directory=str(target))))


def build_derper(platform, directory):
    lock = read_json(ROOT / 'versions.lock.json')['components']['tailscale']
    build = lock['derper_build']
    require(subprocess.check_output(['go','version'], text=True).split()[2] == 'go' + build['go_version'],
            'use the locked Go version; toolchain auto-download is disabled')
    system, arch = platform.split('_')
    target = Path(directory).resolve(); target.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOOS=system, GOARCH=arch, GOTOOLCHAIN='local', GOBIN=str(target))
    # go install cannot use GOBIN for cross compilation; build via a temporary module instead.
    with tempfile.TemporaryDirectory() as temp:
        module = Path(temp)
        shutil.copyfile(ROOT/'components/relay/build.go.mod', module/'go.mod')
        shutil.copyfile(ROOT/'components/relay/build.go.sum', module/'go.sum')
        env.pop('GOBIN', None)
        subprocess.run(['go','mod','download','tailscale.com'], cwd=module, env=env, check=True)
        subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(target/'derper'),
                        'tailscale.com/cmd/derper'], cwd=module, env=env, check=True)
        shutil.copyfile(module/'go.sum', target/'derper.go.sum')
        shutil.copyfile(module/'go.mod', target/'derper.go.mod')
        (target/'derper.build.json').write_text(json.dumps({'source':lock['source'],
             'go_version':build['go_version'], 'platform':platform,
             'sha256':hashlib.sha256((target/'derper').read_bytes()).hexdigest()}, indent=2)+'\n')
    print('Built locked derper; retain binary hash, go.sum and build receipt with deployment artifacts.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('validate','render'):
        p = sub.add_parser(name); p.add_argument('spec'); p.add_argument('--draft', action='store_true')
        if name == 'render': p.add_argument('--output', required=True)
    p = sub.add_parser('fetch'); p.add_argument('component', choices=['headscale','lego','tailscale'])
    p.add_argument('--platform', required=True, choices=['darwin_arm64','linux_arm64','linux_amd64'])
    p.add_argument('--output', required=True)
    p = sub.add_parser('build-derper'); p.add_argument('--platform', required=True, choices=['linux_arm64','linux_amd64'])
    p.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'validate': validate(read_json(args.spec), args.draft); print('Input valid')
        elif args.command == 'render': render(read_json(args.spec), args.output, args.draft); print('Bundle rendered')
        elif args.command == 'fetch': fetch(args.component, args.platform, args.output)
        elif args.command == 'build-derper': build_derper(args.platform, args.output)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'Error: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
