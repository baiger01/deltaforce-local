"""Real account SQLite checks for terminal materialization, without a server."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.native_match_loadout import ITEM_RAW, SLOT_RAW
from dfserver.gun_skins import SKINS
import hashlib
from portable_world_session import DurableWorldSession
import portable_loot_box_codec as boxes


SERVER = Path(__file__).resolve().parent.parent


class NativeMatchMaterializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = (importlib.import_module('dfserver.native_match_materializer')
                      if importlib.util.find_spec('dfserver.native_match_materializer') else None)

    def setUp(self):
        self.assertIsNotNone(self.module, 'Actual account terminal materializer is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'account.sqlite3'
        self.backend = Backend(self.path, SERVER / 'definitions.json')
        self.token = self.backend.register('settlement-test', 'local-password-123')['session']
        self.backend.native_identity(self.token)
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(1001, 11080004006, 108, length=2, width=2),
            self.prop(1002, 18010000006, 112, length=5, width=2),
            self.prop(1003, 15200000073, 108001, quantity=60, x=1),
            self.prop(1004, 15050500001, 108001, x=1, y=1),
            self.prop(1005, 14020000003, 2, x=10),
        ])
        with self.backend.connection() as connection:
            self.account = self.backend._authorize(connection, self.token)
            self.native = connection.execute('SELECT native_id FROM native_identities WHERE player_id=?',
                                             (self.account,)).fetchone()[0]
            self.backend._ensure_weapon_parts(connection, self.account)
            connection.execute('INSERT INTO native_lobby_weapon_bullets VALUES (?,?,?,?)',
                               (5001, 1002, 15200000073, 20))
            connection.execute('INSERT INTO native_lobby_keycard_health VALUES (?,?,?)', (1004, 37, 40))
            self.skin = next(skin for skin, row in SKINS.items() if row['weapon_id'] == 18010000006)
            connection.execute('INSERT INTO native_lobby_weapon_skins VALUES (?,?,?)', (1002, self.skin, 0))
            connection.execute('INSERT OR IGNORE INTO native_lobby_gun_skins VALUES (?,?,0,NULL)', (self.account, self.skin))
            connection.execute('INSERT INTO native_lobby_collection_props VALUES (?,?,?)',
                               (self.account, 14020000003, 2))
            connection.commit()
        self.initial = self.snapshot()
        self.store = DurableWorldSession(self.path)
        self.credential = self.store.admit(room_id=71, player_id=self.native,
            admission_id='materialization-a', token=b'a' * 32, snapshot=self.initial)

    @staticmethod
    def prop(gid, template_id, position, *, quantity=1, x=0, y=0, length=1, width=1):
        return dict(gid=gid, template_id=template_id, quantity=quantity,
                    grid_page_id=position, x=x, y=y, length=length, width=width)

    def snapshot(self):
        with self.backend.connection() as connection:
            rows = connection.execute('SELECT p.gid,p.template_id,p.quantity,p.grid_page_id,p.x,p.y,p.length,p.width,'
                'COALESCE(r.rotated,0) AS rotated FROM native_lobby_props p '
                'LEFT JOIN native_lobby_prop_rotations r ON r.gid=p.gid '
                'WHERE p.player_id=? AND p.grid_page_id<>2 ORDER BY p.gid', (self.account,)).fetchall()
            props = [self.backend._container_prop(connection, self.account, row) for row in rows]
        return dict(kind='local_account_carried_loadout_v1', props=props, selected_melee=None,
            body_layouts=[], source_item_catalog_sha256=hashlib.sha256(ITEM_RAW).hexdigest(),
            source_slot_catalog_sha256=hashlib.sha256(SLOT_RAW).hexdigest())

    def terminal(self, *, death=False, change=None):
        current = deepcopy(self.initial)
        if change:
            change(current)
        with self.backend.connection() as connection:
            connection.execute('UPDATE world_session_v1 SET current_json=?,revision=2 WHERE admission_id=?',
                               (json.dumps(current), self.credential.admission_id))
            connection.commit()
        retained = (1001, 1004) if death else tuple(p['gid'] for p in current['props'])
        return self.store.commit_terminal(self.credential, command_id='terminal-a',
            reason_name='Dead' if death else 'Escaped', expected_revision=2,
            terminal_evidence_sha256='c' * 64, retained_gids=retained)

    def apply(self, receipt):
        return self.store.materialize_terminal(self.credential, receipt.result_sha256, self.module.materialize)

    def dump(self):
        with self.backend.connection() as connection:
            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            return {table: tuple(tuple(row) for row in connection.execute('SELECT * FROM "' + table + '" ORDER BY rowid'))
                    for table in tables}

    def test_extraction_writes_real_items_ammo_rotation_and_durability(self):
        before = self.dump()
        def changes(snapshot):
            snapshot['props'][1]['weapon']['load_bullets'][0]['num'] = 19
            snapshot['props'][2].update(quantity=55, rotated=1)
            snapshot['props'][3]['health'] = 36
            snapshot['props'].append(dict(self.prop(7001, 14020000003, 108001, x=1, y=2),
                                          rotated=0, space_width=2))
        receipt = self.terminal(change=changes)
        applied = self.apply(receipt)
        self.assertTrue(applied.inventory_applied)
        with self.backend.connection() as connection:
            self.assertEqual(tuple(connection.execute('SELECT quantity,player_id FROM native_lobby_props WHERE gid=7001').fetchone()),
                             (1, self.account))
            self.assertEqual(connection.execute('SELECT quantity FROM native_lobby_props WHERE gid=1003').fetchone()[0], 55)
            self.assertEqual(connection.execute('SELECT rotated FROM native_lobby_prop_rotations WHERE gid=1003').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT quantity FROM native_lobby_weapon_bullets WHERE gid=5001').fetchone()[0], 19)
            self.assertEqual(tuple(connection.execute('SELECT health,health_max FROM native_lobby_keycard_health WHERE gid=1004').fetchone()), (36, 40))
        after = self.dump()
        self.assertEqual(after['native_lobby_collection_props'], before['native_lobby_collection_props'])
        self.assertEqual(after['native_lobby_weapon_parts'], before['native_lobby_weapon_parts'])
        self.assertEqual(after['native_lobby_weapon_skins'], before['native_lobby_weapon_skins'])
        self.assertEqual(after['native_lobby_gun_skins'], before['native_lobby_gun_skins'])
        self.assertIn(before['native_lobby_props'][-1], after['native_lobby_props'])
        self.assertEqual(DurableWorldSession(self.path).read_terminal(self.credential), applied)

    def test_death_removes_only_lost_carry_in_and_all_its_children(self):
        before = self.dump()
        self.apply(self.terminal(death=True))
        after = self.dump()
        self.assertEqual({r[0] for r in after['native_lobby_props']}, {1001, 1004, 1005})
        self.assertEqual(after['native_lobby_weapon_parts'], ())
        self.assertEqual(after['native_lobby_weapon_bullets'], ())
        self.assertEqual(after['native_lobby_collection_props'], before['native_lobby_collection_props'])
        self.assertEqual(after['native_lobby_keycard_health'], before['native_lobby_keycard_health'])

    def test_every_persisted_carry_in_change_is_rejected(self):
        mutations = [
            'UPDATE native_lobby_props SET quantity=59 WHERE gid=1003',
            'UPDATE native_lobby_props SET y=3 WHERE gid=1003',
            'INSERT INTO native_lobby_prop_rotations VALUES (1003,1)',
            'UPDATE native_lobby_keycard_health SET health=35 WHERE gid=1004',
            'UPDATE native_lobby_weapon_bullets SET quantity=18 WHERE gid=5001',
            'UPDATE native_lobby_weapon_skins SET skin_id=0 WHERE weapon_gid=1002',
            'UPDATE native_lobby_weapon_parts SET slot=99 WHERE gid=(SELECT MIN(gid) FROM native_lobby_weapon_parts)',
        ]
        receipt = self.terminal()
        for sql in mutations:
            with self.subTest(sql=sql):
                with self.backend.connection() as connection:
                    connection.execute('BEGIN IMMEDIATE')
                    connection.execute(sql)
                    changed = tuple(connection.iterdump())
                    with self.assertRaisesRegex(ValueError, 'carry.in|changed|concurrent'):
                        self.module.materialize(connection, receipt)
                    self.assertEqual(tuple(connection.iterdump()), changed)
                    connection.rollback()
        self.assertFalse(self.store.read_terminal(self.credential).inventory_applied)

    def test_failure_mid_write_rolls_back_account_and_applied_flag(self):
        def changes(snapshot):
            snapshot['props'][2]['quantity'] = 40
            snapshot['props'].append(dict(self.prop(7001, 14020000003, 108001, x=1, y=2), rotated=0, space_width=2))
        receipt = self.terminal(change=changes)
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER fail_materialization BEFORE UPDATE ON native_lobby_props WHEN NEW.gid=1003 "
                "BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM native_lobby_props WHERE gid=7001) "
                "THEN RAISE(ABORT,'injected failure after real account insert') "
                "ELSE RAISE(ABORT,'no prior account mutation') END; END")
            connection.commit()
        before = self.dump()
        with self.assertRaisesRegex(sqlite3.DatabaseError, 'after real account insert'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.store.read_terminal(self.credential).inventory_applied)

    def test_duplicate_receipt_after_reopen_is_idempotent_in_real_database(self):
        receipt = self.terminal(death=True)
        self.apply(receipt)
        before = self.dump()
        self.assertTrue(DurableWorldSession(self.path).materialize_terminal(
            self.credential, receipt.result_sha256, self.module.materialize).inventory_applied)
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self.module.materialize(connection, receipt)
            connection.commit()
        self.assertEqual(self.dump(), before)

    def test_missing_or_rebound_native_identity_and_forged_receipt_are_rejected(self):
        receipt = self.terminal()
        for candidate in (replace(receipt, player_id=self.native + 1),
                          replace(receipt, result_sha256='e' * 64)):
            with self.backend.connection() as connection:
                connection.execute('BEGIN IMMEDIATE')
                with self.assertRaises(ValueError):
                    self.module.materialize(connection, candidate)
                connection.rollback()
        with self.backend.connection() as connection:
            connection.execute('DELETE FROM native_identities WHERE player_id=?', (self.account,))
            connection.commit()
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def test_foreign_instance_gid_collision_does_not_overwrite_an_account(self):
        other_token = self.backend.register('other-account', 'local-password-123')['session']
        with self.backend.connection() as connection:
            other = self.backend._authorize(connection, other_token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                               (7001, other, 14020000003, 1, 2, 0, 0, 1, 1))
            connection.commit()
        def changes(snapshot):
            snapshot['props'].append(dict(self.prop(7001, 14020000003, 108001, x=1, y=2), rotated=0, space_width=2))
        receipt = self.terminal(change=changes)
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'GID|collision|owned'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def test_requires_transaction_and_rejects_unpersistable_condition(self):
        receipt = self.terminal()
        with self.backend.connection() as connection, self.assertRaisesRegex(ValueError, 'transaction'):
            self.module.materialize(connection, receipt)
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            altered = deepcopy(receipt.carry_out_snapshot)
            altered['props'][0]['armor_health'] = 25
            with self.assertRaises(ValueError):
                self.module.materialize(connection, replace(receipt, carry_out_snapshot=altered))
            connection.rollback()

    def test_actual_finite_pickup_without_redundant_width_hint_materializes(self):
        box = boxes.qualified_bindings()[0]
        loot = dict(self.prop(7001, 14020000003, 302), rotated=0,
                    source_note={'policy': 'finite test stock'})
        self.store.seed_box(self.credential, box, (loot,), world_position=(0, 0, 0))
        self.store.open_box(self.credential, box.object_path,
            accepted_server_position=(0, 0, 0), maximum_distance_cm=200)
        self.store.pickup(self.credential, cmd_gid=91, box_path=box.object_path, item_gid=7001,
            destination=dict(grid_page_id=108001, x=2, y=0, rotated=0),
            accepted_server_position=(0, 0, 0), maximum_distance_cm=200, expected_revision=1)
        receipt = self.store.commit_terminal(self.credential, command_id='actual-pickup', reason_name='Escaped',
            expected_revision=2, terminal_evidence_sha256='d' * 64,
            retained_gids=tuple(prop['gid'] for prop in self.store.current_snapshot(self.credential).snapshot['props']))
        self.assertTrue(self.apply(receipt).inventory_applied)
        with self.backend.connection() as connection:
            self.assertEqual(tuple(connection.execute('SELECT grid_page_id,x,y FROM native_lobby_props WHERE gid=7001').fetchone()),
                             (108001, 2, 0))

    def test_two_connections_materialize_one_immutable_receipt_once(self):
        receipt = self.terminal(death=True)
        def apply(_):
            return DurableWorldSession(self.path).materialize_terminal(self.credential,
                receipt.result_sha256, self.module.materialize)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(apply, range(2)))
        self.assertEqual(results[0], results[1])
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_match_materializations_v1').fetchone()[0], 1)
            self.assertEqual({r[0] for r in connection.execute('SELECT gid FROM native_lobby_props')}, {1001, 1004, 1005})

    def test_second_room_uses_saved_inventory_and_separate_idempotency_identity(self):
        self.apply(self.terminal(death=True))
        second = self.store.admit(room_id=72, player_id=self.native, admission_id='materialization-b',
            token=b'b' * 32, snapshot=self.snapshot())
        receipt = self.store.commit_terminal(second, command_id='terminal-b', reason_name='Escaped',
            expected_revision=1, terminal_evidence_sha256='d' * 64, retained_gids=(1001, 1004))
        self.assertTrue(self.store.materialize_terminal(second, receipt.result_sha256,
                                                       self.module.materialize).inventory_applied)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM native_match_materializations_v1').fetchone()[0], 2)

    def test_committed_unpersistable_condition_is_rejected_without_writes(self):
        def changes(snapshot):
            snapshot['props'][0]['unqualified_armor_health'] = 25
        receipt = self.terminal(change=changes)
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'persisted item field'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def test_catalog_skin_for_another_receiver_is_rejected(self):
        wrong = next(skin for skin, row in SKINS.items() if row['weapon_id'] != 18010000006)
        def changes(snapshot):
            snapshot['props'][1]['weapon']['skin_id'] = wrong
            snapshot['props'][1]['weapon']['skin_gid'] = 0
        receipt = self.terminal(change=changes)
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'cosmetic|skin|receiver'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def test_foreign_nested_gid_is_not_reused_as_a_new_root(self):
        other_token = self.backend.register('nested-owner', 'local-password-123')['session']
        with self.backend.connection() as connection:
            other = self.backend._authorize(connection, other_token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                               (8001, other, 18010000006, 1, 2, 0, 0, 5, 2))
            component = connection.execute('SELECT template_id FROM native_lobby_weapon_parts LIMIT 1').fetchone()[0]
            connection.execute('INSERT INTO native_lobby_weapon_parts VALUES (?,?,?,?,?)', (7001, 8001, 8001, 1, component))
            connection.commit()
        def changes(snapshot):
            snapshot['props'].append(dict(self.prop(7001, 14020000003, 108001, x=1, y=2), rotated=0, space_width=2))
        receipt = self.terminal(change=changes)
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'GID collision'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def test_unchanged_saved_dimension_representation_is_not_silently_rewritten(self):
        # This exact item/dimension distinction exists in the recovered account snapshot.
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                               (7001, self.account, 13020000441, 1, 108001, 1, 2, 1, 2))
            connection.commit()
        credential = self.store.admit(room_id=72, player_id=self.native, admission_id='legacy-dimensions',
            token=b'b' * 32, snapshot=self.snapshot())
        receipt = self.store.commit_terminal(credential, command_id='legacy-end', reason_name='Escaped',
            expected_revision=1, terminal_evidence_sha256='d' * 64, retained_gids=(1001, 1002, 1003, 1004, 7001))
        before = self.dump()
        self.assertTrue(self.store.materialize_terminal(credential, receipt.result_sha256,
                                                       self.module.materialize).inventory_applied)
        self.assertEqual(self.dump()['native_lobby_props'], before['native_lobby_props'])

    def test_new_item_cannot_claim_legacy_dimension_exception(self):
        def changes(snapshot):
            snapshot['props'].append(dict(self.prop(7001, 13020000441, 108001, x=1, y=2, width=2),
                                          rotated=0, space_width=2))
        receipt = self.terminal(change=changes)
        before = self.dump()
        with self.assertRaisesRegex(ValueError, 'dimensions'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)

    def seed_lobby_bindings(self, *, admit=True):
        # Exact schema and explicit/omitted projection contract from the lobby's
        # inventory/native_prop_bindings.py; no dependency on its package layout.
        with self.backend.connection() as connection:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS native_lobby_prop_bindings (
                    gid INTEGER PRIMARY KEY REFERENCES native_lobby_props(gid) ON DELETE CASCADE,
                    bind_type INTEGER NOT NULL CHECK(bind_type IN (0,1,2)),
                    bind_player INTEGER NOT NULL CHECK(bind_player>=0));
                CREATE TABLE IF NOT EXISTS native_lobby_loaded_bullet_bindings (
                    gid INTEGER PRIMARY KEY REFERENCES native_lobby_weapon_bullets(gid) ON DELETE CASCADE,
                    bind_type INTEGER NOT NULL CHECK(bind_type IN (0,1,2)),
                    bind_player INTEGER NOT NULL CHECK(bind_player>=0));
            ''')
            connection.executemany('INSERT INTO native_lobby_prop_bindings VALUES (?,?,?)',
                                   [(1002, 0, self.native), (1003, 1, 0)])
            connection.execute('INSERT INTO native_lobby_loaded_bullet_bindings VALUES (?,?,?)',
                               (5001, 2, self.native))
            connection.commit()
        self.initial = self.snapshot()
        # This is the exact shape emitted by the newer lobby projection.
        props = {prop['gid']: prop for prop in self.initial['props']}
        props[1002].update(bind_type=0, bind_player=self.native)
        props[1003].update(bind_type=1, bind_player=0)
        props[1002]['weapon']['load_bullets'][0].update(bind_type=2, bind_player=self.native)
        if admit:
            self.credential = self.store.admit(room_id=72, player_id=self.native,
                admission_id='binding-a', token=b'b' * 32, snapshot=self.initial)

    def test_binding_schema_migrates_without_backfilling_legacy_fields(self):
        with self.backend.connection() as connection:
            connection.execute('DROP TABLE IF EXISTS native_lobby_loaded_bullet_bindings')
            connection.execute('DROP TABLE IF EXISTS native_lobby_prop_bindings')
            connection.commit()
        self.backend = Backend(self.path, SERVER / 'definitions.json')
        with self.backend.connection() as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({'native_lobby_prop_bindings', 'native_lobby_loaded_bullet_bindings'} <= tables)
        self.apply(self.terminal(change=lambda snapshot: snapshot['props'][1]['weapon']['load_bullets'][0].update(num=19)))
        self.backend = Backend(self.path, SERVER / 'definitions.json')
        self.assertEqual(self.dump()['native_lobby_prop_bindings'], ())
        self.assertEqual(self.dump()['native_lobby_loaded_bullet_bindings'], ())
        for prop in self.snapshot()['props']:
            self.assertNotIn('bind_type', prop)
            self.assertNotIn('bind_player', prop)
            for bullet in prop.get('weapon', {}).get('load_bullets', []):
                self.assertNotIn('bind_type', bullet)
                self.assertNotIn('bind_player', bullet)

    def test_actual_lobby_binding_rows_project_without_adding_component_bindings(self):
        self.seed_lobby_bindings(admit=False)
        props = {prop['gid']: prop for prop in self.snapshot()['props']}
        self.assertEqual((props[1002].get('bind_type'), props[1002].get('bind_player')), (0, self.native))
        self.assertEqual((props[1003].get('bind_type'), props[1003].get('bind_player')), (1, 0))
        bullet = props[1002]['weapon']['load_bullets'][0]
        self.assertEqual((bullet.get('bind_type'), bullet.get('bind_player')), (2, self.native))
        self.assertNotIn('bind_type', props[1001])
        self.assertTrue(all('bind_type' not in row['prop_data'] for row in props[1002]['components']))

    def test_materializer_accepts_exact_lobby_root_and_loaded_binding_fields(self):
        for target in ('root', 'loaded'):
            with self.subTest(target=target):
                prop = deepcopy(self.initial['props'][1])
                node = prop if target == 'root' else prop['weapon']['load_bullets'][0]
                node.update(bind_type=0, bind_player=self.native)
                try:
                    normalized = self.module._normalize(prop)
                except ValueError as error:
                    self.fail(f'Actual lobby {target} binding was rejected: {error}')
                actual = normalized if target == 'root' else normalized['weapon']['load_bullets'][0]
                self.assertEqual((actual['bind_type'], actual['bind_player']), (0, self.native))

    def test_lobby_bindings_survive_terminal_sql_readback_and_idempotent_restart(self):
        self.seed_lobby_bindings()
        def changes(snapshot):
            snapshot['props'][1]['weapon']['load_bullets'][0]['num'] = 19
            snapshot['props'][2]['quantity'] = 59
            snapshot['props'].append(dict(self.prop(7001, 14020000003, 108001, x=1, y=2),
                                          bind_type=2, bind_player=self.native, rotated=0))
        receipt = self.terminal(change=changes)
        self.assertTrue(self.apply(receipt).inventory_applied)
        after = self.dump()
        self.assertEqual(after['native_lobby_prop_bindings'],
                         ((1002, 0, self.native), (1003, 1, 0), (7001, 2, self.native)))
        self.assertEqual(after['native_lobby_loaded_bullet_bindings'], ((5001, 2, self.native),))
        props = {prop['gid']: prop for prop in self.snapshot()['props']}
        self.assertEqual((props[1003]['quantity'], props[1003]['bind_type'], props[1003]['bind_player']), (59, 1, 0))
        self.assertEqual(props[1002]['weapon']['load_bullets'][0],
                         dict(id=15200000073, gid=5001, num=19, bind_type=2, bind_player=self.native))
        self.assertNotIn('bind_type', props[1004])
        self.backend = Backend(self.path, SERVER / 'definitions.json')
        self.assertTrue(DurableWorldSession(self.path).materialize_terminal(
            self.credential, receipt.result_sha256, self.module.materialize).inventory_applied)
        self.assertEqual(self.dump(), after)

    def test_concurrent_root_and_loaded_binding_changes_reject_without_writes(self):
        self.seed_lobby_bindings()
        receipt = self.terminal()
        for sql in (
            'UPDATE native_lobby_prop_bindings SET bind_type=2 WHERE gid=1002',
            'UPDATE native_lobby_prop_bindings SET bind_player=1 WHERE gid=1002',
            'DELETE FROM native_lobby_prop_bindings WHERE gid=1003',
            'INSERT INTO native_lobby_prop_bindings VALUES (1001,1,0)',
            'UPDATE native_lobby_loaded_bullet_bindings SET bind_type=0 WHERE gid=5001',
            'UPDATE native_lobby_loaded_bullet_bindings SET bind_player=1 WHERE gid=5001',
            'DELETE FROM native_lobby_loaded_bullet_bindings WHERE gid=5001',
        ):
            with self.subTest(sql=sql), self.backend.connection() as connection:
                connection.execute('BEGIN IMMEDIATE')
                connection.execute(sql)
                before = tuple(connection.iterdump())
                with self.assertRaisesRegex(ValueError, 'carry.in|changed|concurrent'):
                    self.module.materialize(connection, receipt)
                self.assertEqual(tuple(connection.iterdump()), before)
                connection.rollback()
        self.assertFalse(self.store.read_terminal(self.credential).inventory_applied)

    def test_death_cascades_root_and_loaded_bindings_without_orphans(self):
        self.seed_lobby_bindings()
        self.assertTrue(self.apply(self.terminal(death=True)).inventory_applied)
        after = self.dump()
        self.assertEqual(after['native_lobby_prop_bindings'], ())
        self.assertEqual(after['native_lobby_loaded_bullet_bindings'], ())
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('PRAGMA foreign_key_check').fetchall(), [])
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('INSERT INTO native_lobby_loaded_bullet_bindings VALUES (9999,0,0)')

    def test_binding_cleanup_does_not_require_sqlite_cascades_from_the_caller(self):
        self.seed_lobby_bindings(admit=False)
        for operation in ('lost_root', 'replaced_ammo'):
            with self.subTest(operation=operation), self.backend.connection() as connection:
                connection.execute('PRAGMA foreign_keys=OFF')
                connection.execute('BEGIN IMMEDIATE')
                if operation == 'lost_root':
                    self.module._remove(connection, self.account, 1002)
                    self.assertIsNone(connection.execute('SELECT 1 FROM native_lobby_prop_bindings WHERE gid=1002').fetchone())
                else:
                    prop = deepcopy(self.initial['props'][1])
                    prop['weapon']['load_bullets'] = []
                    self.module._write_features(connection, self.module._normalize(prop))
                self.assertIsNone(connection.execute('SELECT 1 FROM native_lobby_loaded_bullet_bindings WHERE gid=5001').fetchone())
                self.assertEqual(connection.execute('PRAGMA foreign_key_check').fetchall(), [])
                connection.rollback()

    def test_binding_failure_after_account_write_rolls_back_everything(self):
        self.seed_lobby_bindings()
        def changes(snapshot):
            snapshot['props'][1]['bind_type'] = 2
            snapshot['props'][1]['weapon']['load_bullets'][0]['num'] = 19
        receipt = self.terminal(change=changes)
        with self.backend.connection() as connection:
            connection.execute('''CREATE TRIGGER fail_binding BEFORE INSERT ON native_lobby_loaded_bullet_bindings
                WHEN EXISTS(SELECT 1 FROM native_lobby_prop_bindings WHERE gid=1002 AND bind_type=2)
                BEGIN SELECT RAISE(ABORT,'failure after root binding write'); END''')
            connection.commit()
        before = self.dump()
        with self.assertRaisesRegex(sqlite3.DatabaseError, 'after root binding write'):
            self.apply(receipt)
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.store.read_terminal(self.credential).inventory_applied)

    def test_materializer_rejects_invalid_or_unknown_binding_fields(self):
        cases = [dict(bind_type=kind, bind_player=owner) for kind, owner in
                 ((True, 0), (-1, 0), (3, 0), ('0', 0), (0, True), (0, -1), (0, 2**63), (0, '1'))]
        cases += [dict(bind_type=0), dict(bind_player=0), dict(bind_type=0, bind_player=0, binding_owner=1)]
        for target in ('root', 'loaded', 'component'):
            for fields in cases:
                with self.subTest(target=target, fields=fields):
                    prop = deepcopy(self.initial['props'][1])
                    node = (prop if target == 'root' else prop['weapon']['load_bullets'][0]
                            if target == 'loaded' else prop['components'][0]['prop_data'])
                    node.update(fields)
                    with self.assertRaisesRegex(ValueError, 'binding|persisted|component'):
                        self.module._normalize(prop)


if __name__ == '__main__':
    unittest.main()
