#!/usr/bin/env python3
"""Validate and run a staged, adapter-backed private application deployment.

This tool contains no company inventory or credentials. An installation supplies
its own adapter, which receives the validated plan path and one phase at a time.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

from tailgate import domain, read_json, require

PHASES = ('preflight', 'database', 'identity', 'runtime', 'ingress', 'verify')
SLUG = re.compile(r'[a-z][a-z0-9-]{1,39}')
IDENT = re.compile(r'[a-z][a-z0-9_]{1,62}')
SECRET = re.compile(r'[a-z][a-z0-9-]{2,254}')
IMAGE = re.compile(r'([a-z0-9.-]+(?::[0-9]+)?)/([a-z0-9._/-]+)@sha256:([0-9a-f]{64})')


def exact_keys(value, required, optional=(), label='object'):
    require(isinstance(value, dict), label + ' must be an object')
    require(set(required) <= set(value), label + ' missing required fields')
    require(set(value) <= set(required) | set(optional), label + ' has unknown fields')


def slug(value, label):
    require(isinstance(value, str) and SLUG.fullmatch(value) is not None, 'invalid ' + label)
    return value


def identifier(value, label):
    require(isinstance(value, str) and IDENT.fullmatch(value) is not None, 'invalid ' + label)
    return value


def secret(value, label):
    require(isinstance(value, str) and SECRET.fullmatch(value) is not None, 'invalid ' + label)
    return value


def port(value, label):
    require(type(value) is int and 1024 <= value <= 65535, 'invalid ' + label)
    return value


def https_url(value, label):
    require(isinstance(value, str), label + ' must be a URL')
    require(value == value.strip() and not any(ord(c) < 33 for c in value),
            label + ' contains whitespace or control characters')
    parsed = urlparse(value)
    require(parsed.scheme == 'https' and parsed.hostname and
            not parsed.username and not parsed.password and not parsed.fragment,
            label + ' must be HTTPS without credentials or fragment')
    domain(parsed.hostname)
    return value


def validate(app, platform):
    exact_keys(app, ('schema_version', 'name', 'database', 'identity', 'runtime', 'ingress'),
               ('template',), 'application')
    require(app['schema_version'] == 1, 'unsupported application schema')
    require(type(app.get('template', False)) is bool, 'template must be boolean')
    slug(app['name'], 'application name')
    db = app['database']
    exact_keys(db, ('name', 'role', 'password_secret'), label='database')
    identifier(db['name'], 'database name')
    identifier(db['role'], 'database role')
    secret(db['password_secret'], 'database secret reference')
    identity = app['identity']
    exact_keys(identity, ('project', 'application', 'redirect_uris', 'post_logout_redirect_uris',
                          'client_secret'), label='identity')
    for key in ('project', 'application'):
        require(isinstance(identity[key], str) and 1 <= len(identity[key]) <= 100 and
                all(ord(c) >= 32 for c in identity[key]), 'invalid identity ' + key)
    for key in ('redirect_uris', 'post_logout_redirect_uris'):
        require(isinstance(identity[key], list) and identity[key] and
                len(identity[key]) == len(set(identity[key])), 'invalid ' + key)
        for value in identity[key]:
            https_url(value, key)
            require(urlparse(value).hostname == app['ingress']['hostname'],
                    key + ' must use the private application hostname')
    secret(identity['client_secret'], 'OIDC client secret reference')
    runtime = app['runtime']
    exact_keys(runtime, ('image', 'host_port', 'container_port', 'health_path',
                         'environment_secrets'), label='runtime')
    require(isinstance(runtime['image'], str) and IMAGE.fullmatch(runtime['image']),
            'runtime image must be pinned by sha256 digest')
    port(runtime['host_port'], 'host port')
    port(runtime['container_port'], 'container port')
    require(isinstance(runtime['health_path'], str) and
            re.fullmatch(r'/[A-Za-z0-9_./-]*', runtime['health_path']) and
            '//' not in runtime['health_path'] and '..' not in runtime['health_path'],
            'invalid health path')
    require(isinstance(runtime['environment_secrets'], dict), 'environment_secrets must be a map')
    for key, value in runtime['environment_secrets'].items():
        require(re.fullmatch(r'[A-Z][A-Z0-9_]*', key) is not None, 'invalid environment variable')
        secret(value, 'environment secret reference')
    ingress = app['ingress']
    exact_keys(ingress, ('hostname', 'address', 'audience'), label='ingress')
    domain(ingress['hostname'])
    slug(ingress['audience'], 'audience')
    try:
        address = ipaddress.ip_address(ingress['address'])
    except ValueError:
        raise ValueError('invalid ingress address')
    require(address.version == 4, 'private ingress currently requires IPv4')

    exact_keys(platform, ('schema_version', 'status', 'database', 'identity', 'runtime',
                          'ingress', 'controller', 'secrets', 'adapter'), label='platform')
    require(platform['schema_version'] == 1, 'unsupported platform schema')
    require(platform['status'] in ('template', 'ready'), 'invalid platform status')
    pdb = platform['database']
    exact_keys(pdb, ('ssh', 'host', 'direct_port', 'pool_port'), label='platform database')
    for key in ('direct_port', 'pool_port'):
        port(pdb[key], 'database ' + key)
    require(pdb['direct_port'] != pdb['pool_port'], 'database ports collide')
    pid = platform['identity']
    exact_keys(pid, ('issuer', 'management_url', 'pat_secret', 'organization_id'),
               label='platform identity')
    https_url(pid['issuer'], 'identity issuer')
    https_url(pid['management_url'], 'identity management URL')
    management = urlparse(pid['management_url'])
    require(management.path in ('', '/') and not management.params and
            not management.query, 'identity management URL must be a bare HTTPS origin')
    secret(pid['pat_secret'], 'identity PAT secret')
    require(isinstance(pid['organization_id'], str) and
            re.fullmatch(r'[0-9]{3,30}', pid['organization_id']) is not None,
            'invalid ZITADEL organization id')
    prt = platform['runtime']
    exact_keys(prt, ('ssh', 'install_root', 'registry_prefix'), label='platform runtime')
    require(isinstance(prt['install_root'], str) and prt['install_root'].startswith('/opt/') and
            re.fullmatch(r'/[a-zA-Z0-9_./-]+', prt['install_root']) and
            '..' not in prt['install_root'], 'invalid install root')
    require(isinstance(prt['registry_prefix'], str) and
            re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+', prt['registry_prefix']),
            'invalid registry prefix')
    require(runtime['image'].startswith(prt['registry_prefix'] + '/'),
            'image is outside permitted registry')
    pin = platform['ingress']
    exact_keys(pin, ('application_domain', 'prefix', 'mode', 'certificate_root'),
               ('namespace', 'host_veth_ipv4', 'peer_veth_ipv4', 'network_unit',
                'client_unit'), 'platform ingress')
    domain(pin['application_domain'])
    require(ingress['hostname'].endswith('.' + pin['application_domain']),
            'application hostname outside private namespace')
    require(pin['mode'] in ('host-interface', 'namespace-proxy'), 'invalid ingress mode')
    try:
        prefix = ipaddress.ip_network(pin['prefix'], strict=True)
    except ValueError:
        raise ValueError('invalid Tailgate prefix')
    require(prefix.version == 4 and prefix.subnet_of(ipaddress.ip_network('100.64.0.0/10')) and
            address in prefix, 'ingress address outside Tailgate pool')
    require(isinstance(pin['certificate_root'], str) and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', pin['certificate_root']) is not None and
            '..' not in pin['certificate_root'] and '//' not in pin['certificate_root'],
            'invalid certificate root')
    if pin['mode'] == 'namespace-proxy':
        for key in ('namespace', 'host_veth_ipv4', 'peer_veth_ipv4',
                    'network_unit', 'client_unit'):
            require(key in pin, 'namespace proxy requires ' + key)
        require(re.fullmatch(r'[a-z][a-z0-9-]{1,40}', pin['namespace']) is not None,
                'invalid namespace')
        for key in ('network_unit', 'client_unit'):
            require(isinstance(pin[key], str) and
                    re.fullmatch(r'[a-z][a-z0-9-]{1,100}\.service', pin[key]) is not None,
                    'invalid ' + key)
        require(pin['network_unit'] != pin['client_unit'], 'network and client units collide')
        for key in ('host_veth_ipv4', 'peer_veth_ipv4'):
            candidate = ipaddress.ip_address(pin[key])
            require(candidate.version == 4 and
                    candidate in ipaddress.ip_network('10.0.0.0/8'), 'invalid ' + key)
        require(pin['host_veth_ipv4'] != pin['peer_veth_ipv4'], 'veth addresses collide')
        require(ipaddress.ip_address(pin['host_veth_ipv4']) in
                ipaddress.ip_network(pin['peer_veth_ipv4'] + '/30', strict=False),
                'veth addresses must share one /30')
    else:
        require(not any(key in pin for key in ('namespace', 'host_veth_ipv4',
                                              'peer_veth_ipv4', 'network_unit', 'client_unit')),
                'host-interface mode cannot set namespace proxy fields')
    psecrets = platform['secrets']
    exact_keys(psecrets, ('gcp_project',), label='platform secrets')
    require(re.fullmatch(r'[a-z][a-z0-9-]{4,62}', psecrets['gcp_project']) is not None,
            'invalid Secret Manager project')
    require(isinstance(platform['adapter'], list) and platform['adapter'] and
            all(isinstance(arg, str) and arg and not any(c in arg for c in '\n\r\0')
                for arg in platform['adapter']), 'adapter must be an argv list')
    controller = platform['controller']
    exact_keys(controller, ('ssh', 'records_path'), label='platform controller')
    require(controller['records_path'] == '/etc/tailgate/records.json',
            'controller records path must be the Tailgate managed records file')
    for label, target in [('database SSH', pdb['ssh']), ('runtime SSH', prt['ssh']),
                          ('controller SSH', controller['ssh'])]:
        require(isinstance(target, str) and re.fullmatch(r'[a-z][a-z0-9_-]*@[a-zA-Z0-9.-]+', target),
                'invalid ' + label)
    require(isinstance(pdb['host'], str) and
            ipaddress.ip_address(pdb['host']).version == 4, 'invalid database host')
    if platform['status'] == 'ready' and not app.get('template'):
        require(IMAGE.fullmatch(runtime['image']).group(3) != '0' * 64,
                'ready application has a placeholder image digest')
    return app, platform


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def plan(app, platform):
    validate(app, platform)
    body = {'schema_version': 1, 'application': app, 'platform': platform,
            'phases': list(PHASES), 'artifacts': artifacts(app, platform),
            'network_access': 'deny-all until a separate reviewed Tailgate grant is applied'}
    body['sha256'] = hashlib.sha256(canonical(body)).hexdigest()
    return body


def artifacts(app, platform):
    name, runtime, ingress = app['name'], app['runtime'], app['ingress']
    image = runtime['image']
    env_file = platform['runtime']['install_root'] + '/' + name + '/runtime.env'
    bind_address = (platform['ingress']['host_veth_ipv4']
                    if platform['ingress']['mode'] == 'namespace-proxy' else '127.0.0.1')
    compose = (f'services:\n  app:\n    image: "{image}"\n'
               f'    restart: unless-stopped\n    ports:\n'
               f'      - "{bind_address}:{runtime["host_port"]}:{runtime["container_port"]}"\n'
               f'    env_file:\n      - "{env_file}"\n'
               f'    security_opt:\n      - no-new-privileges:true\n')
    service = {'name': ingress['hostname'], 'address': ingress['address'],
               'proxy_to': bind_address + ':' + str(runtime['host_port']),
               'audience': ingress['audience'], 'mode': platform['ingress']['mode']}
    cert_root = platform['ingress']['certificate_root'].rstrip('/')
    nginx = (f'server {{\n    listen {ingress["address"]}:443 ssl;\n'
             f'    server_name {ingress["hostname"]};\n'
             f'    ssl_certificate {cert_root}/{ingress["hostname"]}.crt;\n'
             f'    ssl_certificate_key {cert_root}/{ingress["hostname"]}.key;\n'
             f'    ssl_protocols TLSv1.2 TLSv1.3;\n'
             f'    location / {{\n        proxy_pass http://{bind_address}:{runtime["host_port"]};\n'
             f'        proxy_set_header Host $host;\n'
             f'        proxy_set_header X-Forwarded-Proto https;\n'
             f'        proxy_set_header X-Forwarded-For $remote_addr;\n'
             f'    }}\n}}\n')
    return {'compose.yaml': compose,
            'private-service.json': json.dumps(service, indent=2, sort_keys=True) + '\n',
            'private-nginx.conf': nginx}


def render(app, platform, destination):
    result = plan(app, platform)
    output = Path(destination)
    require(not output.exists() or not any(output.iterdir()), 'output must be empty')
    output.mkdir(parents=True, exist_ok=True)
    for name, content in result['artifacts'].items():
        (output / name).write_text(content)
    (output / 'plan.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    (output / 'README.txt').write_text(
        'Rendered application deployment plan. No service or access grant has been applied.\n'
        'Keep runtime.env private; supply secret values through the installation adapter.\n'
        'Register private-service.json through the installation adapter; it is not\n'
        'a controller-renderer services entry when using a network namespace.\n'
        'Use the existing reviewed policy workflow for exact network access.\n')
    return result


def apply(app, platform, bundle, expected_sha, adapter_cwd):
    expected = plan(app, platform)
    require(not app.get('template') and platform['status'] == 'ready',
            'template input cannot be applied')
    require(expected['sha256'] == expected_sha, 'plan SHA does not match current inputs')
    bundle = Path(bundle).resolve()
    require(read_json(bundle / 'plan.json') == expected, 'rendered plan differs from current inputs')
    for name, content in expected['artifacts'].items():
        require((bundle / name).read_text() == content, 'rendered artifact differs from plan: ' + name)
    lock_path = bundle / '.apply.lock'
    with lock_path.open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt_path = bundle / 'receipt.json'
        receipt = read_json(receipt_path) if receipt_path.exists() else {
            'plan_sha256': expected_sha, 'completed': []}
        require(receipt.get('plan_sha256') == expected_sha, 'receipt belongs to another plan')
        require(receipt.get('completed') == list(PHASES[:len(receipt.get('completed', []))]),
                'invalid receipt phase sequence')
        for phase in PHASES[len(receipt['completed']):]:
            require(read_json(bundle / 'plan.json') == expected, 'plan changed during apply')
            for name, content in expected['artifacts'].items():
                require((bundle / name).read_text() == content,
                        'rendered artifact changed during apply: ' + name)
            argv = platform['adapter'] + ['--plan', str(bundle / 'plan.json'), '--phase', phase]
            subprocess.run(argv, cwd=adapter_cwd, check=True)
            receipt['completed'].append(phase)
            descriptor, temp_name = tempfile.mkstemp(prefix='.receipt-', dir=bundle)
            temp = Path(temp_name)
            with os.fdopen(descriptor, 'w') as file:
                json.dump(receipt, file, indent=2, sort_keys=True)
                file.write('\n')
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp, receipt_path)
            directory = os.open(bundle, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('validate', 'render', 'apply'):
        item = sub.add_parser(command)
        item.add_argument('application')
        item.add_argument('platform')
        if command != 'validate':
            item.add_argument('--output', required=True)
        if command == 'apply':
            item.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    try:
        app, platform = read_json(args.application), read_json(args.platform)
        validate(app, platform)
        if args.command == 'validate':
            print('Valid application and platform')
        elif args.command == 'render':
            result = render(app, platform, args.output)
            print(result['sha256'])
        else:
            receipt = apply(app, platform, args.output, args.plan_sha256,
                            Path(args.platform).resolve().parent)
            print('Completed: ' + ', '.join(receipt['completed']))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, BlockingIOError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
