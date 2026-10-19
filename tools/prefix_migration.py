"""Offline SQLite renumbering with identity, schema and policy preservation.

The caller must stop the controller and administrator, take and verify a backup,
and update configuration/listeners before restarting. This module never starts
services, enrolls clients or changes access policy.
"""
import hashlib
import ipaddress
import json


def networks(prefixes):
    result = {}
    for family, parent in (('v4', '100.64.0.0/10'), ('v6', 'fd7a:115c:a1e0::/48')):
        value = prefixes.get(family)
        if not isinstance(value, str): raise ValueError('Both allocation families are required')
        network = ipaddress.ip_network(value, strict=True)
        supported = ipaddress.ip_network(parent)
        if (network.version != supported.version or not network.subnet_of(supported)
                or str(network) != value or network.num_addresses < 4):
            raise ValueError('Unsupported or noncanonical allocation prefix')
        result[family] = network
    return result


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def digest_without_addresses(database):
    """Hash all schema/data, omitting only the two fields we intentionally change."""
    digest = hashlib.sha256()
    schema = list(database.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"))
    digest.update(json.dumps(schema, sort_keys=True).encode())
    for (name,) in database.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        cursor = database.execute('SELECT * FROM ' + quote(name))
        columns = [value[0] for value in cursor.description]
        retained = [i for i, column in enumerate(columns) if name != 'nodes' or column not in ('ipv4', 'ipv6')]
        rows = []
        for row in cursor:
            values = [({'bytes':value.hex()} if isinstance(value, bytes) else value)
                      for i, value in enumerate(row) if i in retained]
            rows.append(json.dumps(values, separators=(',', ':'), ensure_ascii=True))
        digest.update(json.dumps([name, [columns[i] for i in retained], sorted(rows)], separators=(',', ':')).encode())
    return digest.hexdigest()


def plan(database, prefixes):
    pools = networks(prefixes)
    rows = list(database.execute('SELECT id, ipv4, ipv6 FROM nodes ORDER BY id'))
    if any(len(rows) + 1 >= pool.num_addresses for pool in pools.values()):
        raise ValueError('Allocation pool is too small for the existing nodes')
    return [{'id':row[0], 'before':{'v4':row[1], 'v6':row[2]},
             'after':{family:str(pool.network_address + offset) for family, pool in pools.items()}}
            for offset, row in enumerate(rows, 1)]


def renumber(database, prefixes):
    if database.in_transaction: raise ValueError('Renumbering requires an independent offline transaction')
    database.execute('BEGIN IMMEDIATE')
    try:
        if database.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Database integrity check failed')
        before = digest_without_addresses(database)
        mapping = plan(database, prefixes)
        for item in mapping:
            cursor = database.execute('UPDATE nodes SET ipv4=?, ipv6=? WHERE id=?',
                                      (item['after']['v4'], item['after']['v6'], item['id']))
            if cursor.rowcount != 1: raise ValueError('Node inventory changed during renumbering')
        if digest_without_addresses(database) != before:
            raise ValueError('Renumbering changed identity, policy or unrelated database state')
        if database.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Renumbered database integrity check failed')
        database.commit()
        return {'nodes':mapping, 'preserved_state_sha256':before, 'sqlite_integrity':'ok'}
    except Exception:
        database.rollback()
        raise
