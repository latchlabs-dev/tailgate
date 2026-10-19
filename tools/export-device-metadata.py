#!/usr/bin/env python3
"""Export only display metadata from pinned Headscale SQLite, using read-only access."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile


def project(database):
    nodes = {}
    with sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=5) as db:
        for identifier, hostname, raw in db.execute('SELECT id, hostname, host_info FROM nodes'):
            try:
                host = json.loads(raw or '{}')
            except (ValueError, TypeError):
                continue
            if not isinstance(host, dict):
                continue
            fields = {'hostname': hostname}
            for target, source in {'os': 'OS', 'osVersion': 'OSVersion', 'model': 'DeviceModel',
                                   'architecture': 'GoArch', 'version': 'IPNVersion'}.items():
                value = host.get(source, '')
                if isinstance(value, str) and len(value.encode()) <= 256 and not any(c in value for c in '\x00\r\n'):
                    fields[target] = value
            nodes[str(identifier)] = fields
    return {'collectedAt': datetime.now(timezone.utc).isoformat(), 'nodes': nodes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    payload = json.dumps(project(args.database)).encode()
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError('Metadata exceeds size limit')
    destination = Path(args.output)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as f:
            temporary = f.name
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), 0o644)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)


if __name__ == '__main__':
    main()
