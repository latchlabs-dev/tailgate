import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('metadata', Path(__file__).parents[1] / 'tools/export-device-metadata.py')
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class DeviceMetadataTest(unittest.TestCase):
    def test_projection_excludes_private_hostinfo_and_handles_missing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db.sqlite'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE nodes (id INTEGER, hostname TEXT, host_info TEXT)')
                db.executemany('INSERT INTO nodes VALUES (?,?,?)', [
                    (1, 'localhost', json.dumps({'OS':'iOS','DeviceModel':'iPhone14,7','IPNVersion':'1.0','NetInfo':{'private':'secret'},'RoutableIPs':['secret']})),
                    (2, 'server', '{}'), (3, 'broken', 'invalid'),
                ])
            result = metadata.project(path)
            self.assertEqual(result['nodes']['1']['model'], 'iPhone14,7')
            self.assertEqual(result['nodes']['2']['model'], '')
            self.assertNotIn('3', result['nodes'])
            self.assertNotIn('secret', json.dumps(result))
            self.assertEqual(sqlite3.connect(path).execute('SELECT count(*) FROM nodes').fetchone()[0], 3)

if __name__ == '__main__':
    unittest.main()
