"""Qualified warehouse growth and explicit migration on disposable databases."""

import importlib
import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dfserver.core import DomainError


ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT.parent.parent
FIXTURE_SCHEMA = """
CREATE TABLE players(id TEXT PRIMARY KEY,local_name TEXT);
CREATE TABLE native_lobby_devices(player_id TEXT,device_id INTEGER,level INTEGER,
 PRIMARY KEY(player_id,device_id));
CREATE TABLE native_lobby_safehouse_upgrades(player_id TEXT,device_id INTEGER,
 target_level INTEGER,start_time INTEGER,end_time INTEGER);
CREATE TABLE native_lobby_props(gid INTEGER PRIMARY KEY,player_id TEXT REFERENCES players(id),
 template_id INTEGER,quantity INTEGER,grid_page_id INTEGER,x INTEGER,y INTEGER,
 length INTEGER,width INTEGER,UNIQUE(player_id,grid_page_id,x,y));
CREATE TABLE native_lobby_prop_rotations(gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid),rotated INTEGER);
CREATE TABLE native_lobby_weapon_parts(gid INTEGER PRIMARY KEY,weapon_gid INTEGER,template_id INTEGER);
CREATE TABLE native_lobby_currencies(player_id TEXT,currency_id INTEGER,amount INTEGER);
CREATE TABLE native_lobby_quest_progress(player_id TEXT,quest_id INTEGER,state INTEGER,objectives_json TEXT);
"""


class NativeWarehouseGrowthTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.database = Path(folder.name) / 'save.sqlite3'
        self.connection = sqlite3.connect(self.database)
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.executescript(FIXTURE_SCHEMA)
        self.connection.executemany('INSERT INTO players VALUES (?,?)', [('owner', 'Owner'), ('other', 'Other')])
        self.connection.execute('INSERT INTO native_lobby_currencies VALUES (?,?,?)', ('owner', 17020000010, 1234567))
        self.connection.execute('INSERT INTO native_lobby_quest_progress VALUES (?,?,?,?)', ('owner', 49001, 3, '[]'))
        self.connection.commit()

    def growth(self):
        self.assertIsNotNone(importlib.util.find_spec('dfserver.native_warehouse_growth'),
                             'Qualified warehouse growth is not implemented')
        return importlib.import_module('dfserver.native_warehouse_growth')

    def migrator(self):
        path = PROJECT / 'work/migrate_native_warehouse_geometry.py'
        self.assertTrue(path.is_file(), 'The explicit warehouse migration tool is not implemented')
        spec = importlib.util.spec_from_file_location('warehouse_migration_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def create_growth_schema(self):
        for statement in self.growth().SCHEMA.split(';'):
            if statement.strip():
                self.connection.execute(statement)
        self.connection.commit()

    def add_prop(self, gid, *, player='owner', page=2, x=0, y=0, length=1, width=1,
                 template=15080050096, quantity=1, rotated=0):
        self.connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
            (gid, player, template, quantity, page, x, y, length, width))
        if rotated:
            self.connection.execute('INSERT INTO native_lobby_prop_rotations VALUES (?,?)', (gid, rotated))
        self.connection.commit()

    def state(self):
        result = {}
        for name, in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            if not name.startswith('sqlite_'):
                result[name] = [tuple(row) for row in self.connection.execute('SELECT * FROM "' + name + '" ORDER BY rowid')]
        return result

    def test_legacy_without_explicit_geometry_remains_9x40_even_at_completed_level10(self):
        growth = self.growth()
        self.connection.execute('INSERT INTO native_lobby_devices VALUES (?,?,?)', ('owner', 1010, 10))
        self.connection.commit()
        before = self.state()
        self.assertEqual(growth.main_size(self.connection, 'owner'), (9, 40))
        self.assertEqual(self.state(), before)
        self.create_growth_schema()
        self.assertEqual(growth.main_size(self.connection, 'owner'), (9, 40))

    def test_explicit_new_account_uses_qualified_base_and_latest_completed_effect_not_sum(self):
        growth = self.growth()
        self.create_growth_schema()
        growth.initialize_new_player(self.connection, 'owner')
        self.connection.commit()
        for level, expected in enumerate((35, 37, 37, 40, 40, 43, 43, 47, 47, 51), 1):
            with self.subTest(level=level):
                self.connection.execute('INSERT INTO native_lobby_devices VALUES (?,?,?) '
                    'ON CONFLICT(player_id,device_id) DO UPDATE SET level=excluded.level', ('owner', 1010, level))
                self.assertEqual(growth.main_size(self.connection, 'owner'), (9, expected))
        row = self.connection.execute('SELECT * FROM native_lobby_warehouse_geometry WHERE player_id=?', ('owner',)).fetchone()
        self.assertEqual(json.loads(row['provenance_json'])['kind'], 'primary_creator_arithmetic')
        self.assertEqual(json.loads(row['migration_receipt_json'])['kind'], 'new_account_registration')
        self.assertEqual(growth.main_size(self.connection, 'other'), (9, 40))

    def test_pending_target_never_expands_committed_geometry(self):
        growth = self.growth()
        self.create_growth_schema()
        growth.initialize_new_player(self.connection, 'owner')
        self.connection.execute('INSERT INTO native_lobby_devices VALUES (?,?,?)', ('owner', 1010, 7))
        self.connection.execute('INSERT INTO native_lobby_safehouse_upgrades VALUES (?,?,?,?,?)', ('owner', 1010, 8, 1, 2))
        self.connection.commit()
        before = self.state()
        self.assertEqual(growth.main_size(self.connection, 'owner'), (9, 43))
        self.assertEqual(self.state(), before)
        self.connection.execute('UPDATE native_lobby_devices SET level=8 WHERE player_id=?', ('owner',))
        self.assertEqual(growth.main_size(self.connection, 'owner'), (9, 47))

    def test_preview_is_read_only_and_plan_is_deterministic(self):
        self.add_prop(11, y=39, length=2, width=1, quantity=7)
        self.add_prop(12, x=3, y=36, length=3, width=2, template=18010000010, rotated=1)
        self.add_prop(13, page=3, y=5)
        before = self.state()
        module = self.migrator()
        first = module.migrate(self.database)
        second = module.migrate(self.database)
        self.assertEqual(first['mode'], 'read_only_preview')
        self.assertTrue(first['can_apply'])
        self.assertEqual(first['accounts'], second['accounts'])
        owner = next(row for row in first['accounts'] if row['player_id'] == 'owner')
        self.assertEqual(owner['from_grid'], [9, 40])
        self.assertEqual(owner['to_grid'], [9, 35])
        self.assertEqual(owner['item_count'], 2)
        self.assertEqual(self.state(), before)
        self.assertEqual(list(self.database.parent.glob('*before*')), [])

    def test_apply_backs_up_all_tables_and_preserves_items_components_money_quests_and_other_pages(self):
        self.add_prop(11, y=39, length=2, width=1, quantity=7)
        self.add_prop(12, x=3, y=36, length=3, width=2, template=18010000010, rotated=1)
        self.add_prop(13, page=3, y=5)
        self.add_prop(14, player='other', y=39)
        self.connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?)', (91, 12, 3110000044))
        self.connection.commit()
        before = self.state()
        backup = self.database.parent / 'before.sqlite3'
        result = self.migrator().migrate(self.database, apply=True, player_ids=['owner'], backup_path=backup)
        self.assertEqual(result['mode'], 'applied')
        with closing(sqlite3.connect(backup)) as copy:
            self.assertEqual(copy.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(copy.execute('SELECT gid,y FROM native_lobby_props ORDER BY gid').fetchall(),
                             [(11, 39), (12, 36), (13, 5), (14, 39)])
            self.assertFalse(copy.execute("SELECT 1 FROM sqlite_master WHERE name='native_lobby_warehouse_geometry'").fetchone())
        after = self.state()
        for table in ('native_lobby_currencies', 'native_lobby_quest_progress', 'native_lobby_weapon_parts'):
            self.assertEqual(after[table], before[table])
        self.assertEqual(len(after['native_lobby_props']), len(before['native_lobby_props']))
        self.assertEqual(after['native_lobby_props'][2:], before['native_lobby_props'][2:])
        for old, new in zip(before['native_lobby_props'][:2], after['native_lobby_props'][:2]):
            self.assertEqual(old[:5], new[:5])
        self.assertEqual(self.growth().main_size(self.connection, 'owner'), (9, 35))
        self.assertEqual(self.growth().main_size(self.connection, 'other'), (9, 40))
        self.assertEqual(len(after['native_lobby_warehouse_geometry_migrations']), 1)
        self.connection.close()
        self.connection = sqlite3.connect(self.database)
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        self.assertEqual(self.growth().main_size(self.connection, 'owner'), (9, 35))
        repeated = self.migrator().migrate(self.database, apply=True, player_ids=['owner'])
        self.assertFalse(any(row['migration_needed'] for row in repeated['accounts']))
        self.assertEqual(self.connection.execute('SELECT COUNT(*) FROM native_lobby_warehouse_geometry_migrations').fetchone()[0], 1)

    def test_insufficient_space_refuses_the_entire_multiaccount_migration(self):
        self.add_prop(11, y=39)
        self.add_prop(12, player='other', length=9, width=36)
        before = self.state()
        module = self.migrator()
        preview = module.migrate(self.database)
        self.assertFalse(preview['can_apply'])
        with self.assertRaises(DomainError):
            module.migrate(self.database, apply=True)
        self.assertEqual(self.state(), before)

    def test_failed_write_rolls_back_positions_and_geometry_registration(self):
        self.add_prop(11, y=39)
        self.add_prop(12, x=3, y=36)
        self.connection.execute('CREATE TRIGGER reject_warehouse_move BEFORE UPDATE ON native_lobby_props '
            'WHEN NEW.gid=12 BEGIN SELECT RAISE(ABORT,"warehouse fixture failure"); END')
        self.connection.commit()
        before = self.state()
        backup = self.database.parent / 'before-trigger.sqlite3'
        with self.assertRaises(sqlite3.IntegrityError):
            self.migrator().migrate(self.database, apply=True, backup_path=backup)
        self.assertEqual(self.state(), before)
        self.assertTrue(backup.is_file())

    def test_completed_level_not_pending_target_controls_migration_target(self):
        self.connection.execute('INSERT INTO native_lobby_devices VALUES (?,?,?)', ('owner', 1010, 9))
        self.connection.execute('INSERT INTO native_lobby_safehouse_upgrades VALUES (?,?,?,?,?)', ('owner', 1010, 10, 1, 2))
        self.connection.commit()
        preview = self.migrator().migrate(self.database, player_ids=['owner'])
        self.assertEqual(preview['accounts'][0]['to_grid'], [9, 47])
        self.migrator().migrate(self.database, apply=True, player_ids=['owner'])
        self.assertEqual(self.growth().main_size(self.connection, 'owner'), (9, 47))

    def test_trigger_cannot_silently_change_a_protected_wallet_table(self):
        self.add_prop(11, y=39)
        self.connection.execute('CREATE TRIGGER alter_wallet AFTER UPDATE ON native_lobby_props '
            'BEGIN UPDATE native_lobby_currencies SET amount=amount-1; END')
        self.connection.commit()
        before = self.state()
        with self.assertRaises(RuntimeError):
            self.migrator().migrate(self.database, apply=True)
        self.assertEqual(self.state(), before)

    def test_actual_rotation_must_match_audited_plan_even_for_square_items(self):
        self.add_prop(11, y=39)
        self.connection.execute('CREATE TRIGGER alter_rotation AFTER UPDATE ON native_lobby_props '
            'BEGIN INSERT INTO native_lobby_prop_rotations VALUES (NEW.gid,1) '
            'ON CONFLICT(gid) DO UPDATE SET rotated=1; END')
        self.connection.commit()
        before = self.state()
        with self.assertRaises(RuntimeError):
            self.migrator().migrate(self.database, apply=True)
        self.assertEqual(self.state(), before)


if __name__ == '__main__':
    unittest.main()
