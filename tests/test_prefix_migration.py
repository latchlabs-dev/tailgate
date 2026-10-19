import importlib.util
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prefix_migration', ROOT/'tools/prefix_migration.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class PrefixMigration(unittest.TestCase):
    def setUp(self):
        self.database = sqlite3.connect(':memory:')
        self.addCleanup(self.database.close)
        self.database.executescript('''
            CREATE TABLE nodes (id INTEGER PRIMARY KEY, ipv4 TEXT UNIQUE, ipv6 TEXT UNIQUE,
                                machine_key TEXT, tags TEXT, expiry TEXT, user_id INTEGER);
            CREATE TABLE policies (id INTEGER PRIMARY KEY, policy TEXT);
            INSERT INTO nodes VALUES (3, '100.64.0.1', 'fd7a:115c:a1e0::1',
                                      'fixture-key-one', '["tag:approved-one"]', '2027-01-01', 5);
            INSERT INTO nodes VALUES (4, '100.64.0.2', 'fd7a:115c:a1e0::2',
                                      'fixture-key-two', '["tag:approved-two"]', '2027-02-01', 6);
            INSERT INTO policies VALUES (1, '{"grants":[]}');
        ''')
        self.prefixes = {'v4':'100.80.0.0/16', 'v6':'fd7a:115c:a1e0:8000::/64'}

    def test_only_addresses_change_and_sparse_node_ids_are_preserved(self):
        before = migration.digest_without_addresses(self.database)
        result = migration.renumber(self.database, self.prefixes)
        self.assertEqual([3, 4], [node['id'] for node in result['nodes']])
        self.assertEqual(['100.80.0.1', '100.80.0.2'], [node['after']['v4'] for node in result['nodes']])
        self.assertEqual(before, result['preserved_state_sha256'])
        self.assertEqual(before, migration.digest_without_addresses(self.database))
        self.assertEqual('fd7a:115c:a1e0:8000::2', self.database.execute('SELECT ipv6 FROM nodes WHERE id=4').fetchone()[0])

    def test_unrelated_state_change_rolls_back_all_addresses(self):
        original = list(self.database.execute('SELECT * FROM nodes ORDER BY id'))
        with patch.object(migration, 'digest_without_addresses', side_effect=['before', 'changed']):
            with self.assertRaisesRegex(ValueError, 'unrelated'):
                migration.renumber(self.database, self.prefixes)
        self.assertEqual(original, list(self.database.execute('SELECT * FROM nodes ORDER BY id')))
        self.assertFalse(self.database.in_transaction)

    def test_unsupported_or_insufficient_pool_cannot_mutate_state(self):
        original = list(self.database.execute('SELECT * FROM nodes ORDER BY id'))
        self.database.execute("INSERT INTO nodes VALUES (5, '100.64.0.3', 'fd7a:115c:a1e0::3', 'third', '[]', NULL, 7)")
        self.database.commit()
        for value in ('10.80.0.0/16', '100.80.0.1/16', '100.80.0.0/30'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                migration.renumber(self.database, dict(self.prefixes, v4=value))
        self.assertEqual(original, list(self.database.execute('SELECT * FROM nodes WHERE id < 5 ORDER BY id')))

    def test_unfinished_outer_transaction_is_rejected(self):
        self.database.execute('BEGIN')
        with self.assertRaisesRegex(ValueError, 'independent'):
            migration.renumber(self.database, self.prefixes)
