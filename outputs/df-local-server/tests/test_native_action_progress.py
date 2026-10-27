import importlib
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class NativeActionProgressTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('dfserver.native_action_progress'),
                             'Original action experience has no durable progression handler')
        self.progress = importlib.import_module('dfserver.native_action_progress')
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('action-owner', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=1, currencies={}, props=[])
        with self.backend.connection() as connection:
            connection.executescript(self.progress.SCHEMA)
            self.player_id = self.backend._authorize(connection, self.token)
            connection.commit()

    def grant(self, amount):
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            receipt = self.progress.grant(connection, self.player_id, amount, now=10000000)
            connection.commit()
        return receipt

    def profile(self):
        with self.backend.connection() as connection:
            return self.progress.profile_fields(connection, self.player_id)

    def state(self):
        with self.backend.connection() as connection:
            return {name: [tuple(row) for row in connection.execute('SELECT * FROM ' + name + ' ORDER BY 1')]
                    for name in ('players', 'native_lobby_levels', 'native_lobby_action_progress',
                                 'native_lobby_independent_level_baselines')}

    def test_action_upgrade_keeps_independent_legacy_levels_at_the_captured_baseline(self):
        self.backend.set_native_lobby_profile(self.token, level=17, currencies={}, props=[])
        self.grant(12100)
        self.assertEqual(self.profile()['level'], 18)
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            fields = self.progress.independent_profile_fields(connection, self.player_id)
            self.assertEqual((fields['account_level'], fields['blast_level']), (17, 17))
            row = connection.execute('SELECT * FROM native_lobby_independent_level_baselines').fetchone()
            self.assertEqual(row['baseline_reason'], 'explicit_local_legacy_profile_projection')
            connection.commit()

    def test_original_first_threshold_and_notification_use_within_level_experience(self):
        self.assertEqual(self.profile(), {'level': 1, 'exp': 0, 'next_level_exp': 2000})
        first = self.grant(1999)
        self.assertEqual((first['old_level'], first['level'], first['exp']), (1, 1, 1999))
        receipt = self.grant(1)
        self.assertEqual(self.profile(), {'level': 2, 'exp': 0, 'next_level_exp': 2500})
        self.assertEqual({name: receipt[name] for name in (
            'old_level', 'level', 'old_exp', 'exp', 'old_next_level_exp', 'next_level_exp',
            'old_total_exp', 'total_exp', 'delta_exp')}, {
            'old_level': 1, 'level': 2, 'old_exp': 1999, 'exp': 0,
            'old_next_level_exp': 2000, 'next_level_exp': 2500,
            'old_total_exp': 1999, 'total_exp': 2000, 'delta_exp': 1})
        fields = self.progress.notification_fields(550011, receipt)
        self.assertEqual(fields['source'], 0)
        self.assertNotIn('account_change', fields)
        codec = _candidate_codec()
        decoded = codec.decode(codec.encode('CSAccountExpChangeNtf', fields, sequence=9))
        self.assertEqual(decoded.name, 'CSAccountExpChangeNtf')
        self.assertEqual(decoded.fields['change']['level'], 2)
        self.assertEqual(decoded.fields['change']['old_exp'], '1999')
        self.assertEqual(decoded.fields['change']['total_exp'], '2000')
        self.assertEqual(decoded.fields['change'].get('exp', '0'), '0')

    def test_one_reward_can_cross_multiple_original_thresholds(self):
        self.grant(7600)
        self.assertEqual(self.profile(), {'level': 4, 'exp': 0, 'next_level_exp': 3700})
        self.grant(3701)
        self.assertEqual(self.profile(), {'level': 5, 'exp': 1, 'next_level_exp': 4300})

    def test_query_preserves_a_legacy_owned_level_without_creating_earned_experience(self):
        self.backend.set_native_lobby_profile(self.token, level=17, currencies={}, props=[])
        before = self.state()
        self.assertEqual(self.profile(), {'level': 17, 'exp': 0, 'next_level_exp': 12100})
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()['native_lobby_action_progress'], [])

    def test_first_real_reward_audits_legacy_floor_and_preserves_existing_xp_ledger(self):
        self.backend.set_native_lobby_profile(self.token, level=17, currencies={}, props=[])
        with self.backend.connection() as connection:
            connection.execute('UPDATE players SET xp=777 WHERE id=?', (self.player_id,))
            connection.commit()
        receipt = self.grant(12099)
        self.assertEqual((receipt['old_level'], receipt['level'], receipt['exp']), (17, 17, 12099))
        self.assertTrue(receipt['baseline_created'])
        with self.backend.connection() as connection:
            row = connection.execute('SELECT * FROM native_lobby_action_progress').fetchone()
            self.assertEqual(row['baseline_level'], 17)
            self.assertEqual(row['baseline_reason'], 'explicit_local_legacy_level_floor')
            self.assertEqual(row['earned_exp'], 12099)
            self.assertEqual(row['baseline_total_exp'], sum(self.progress.COSTS[:16]))
            self.assertEqual(connection.execute('SELECT xp FROM players').fetchone()[0], 777)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.profile(), {'level': 17, 'exp': 12099, 'next_level_exp': 12100})
        self.grant(1)
        self.assertEqual(self.profile(), {'level': 18, 'exp': 0, 'next_level_exp': 12700})

    def test_original_maximum_keeps_awarded_experience_without_inventing_level_61(self):
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        receipt = self.grant(9001)
        self.assertEqual(self.profile(), {'level': 60, 'exp': 9001, 'next_level_exp': 0})
        self.assertEqual(receipt['total_exp'] - receipt['old_total_exp'], 9001)

    def test_unauthorized_account_does_not_share_action_progress(self):
        self.grant(2500)
        other = self.backend.register('other-action-owner', 'local-password-123')['session']
        with self.backend.connection() as connection:
            other_id = self.backend._authorize(connection, other)
            self.assertEqual(self.progress.profile_fields(connection, other_id),
                             {'level': 1, 'exp': 0, 'next_level_exp': 2000})
        self.assertEqual(self.profile(), {'level': 2, 'exp': 500, 'next_level_exp': 2500})

    def test_failed_joined_reward_rolls_back_both_action_xp_and_saved_level(self):
        with self.backend.connection() as connection:
            connection.execute('CREATE TABLE diagnostic_reward_failure(value INTEGER CHECK(value>0))')
            connection.commit()
        before = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.backend.connection() as connection:
                connection.execute('BEGIN IMMEDIATE')
                self.progress.grant(connection, self.player_id, 7600, now=10000000)
                connection.execute('INSERT INTO diagnostic_reward_failure VALUES(0)')
        self.assertEqual(self.state(), before)

    def test_grant_requires_a_joined_transaction_and_rejects_invalid_amounts(self):
        before = self.state()
        with self.backend.connection() as connection:
            with self.assertRaises(ValueError):
                self.progress.grant(connection, self.player_id, 1)
        for amount in (0, -1, True, 1.5, '2000', 2**63):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.grant(amount)
        self.assertEqual(self.state(), before)

    def test_saved_levels_outside_the_source_curve_are_preserved_and_rejected(self):
        self.backend.set_native_lobby_profile(self.token, level=61, currencies={}, props=[])
        before = self.state()
        with self.assertRaises(ValueError):
            self.grant(1)
        self.assertEqual(self.state(), before)

    def test_existing_progress_cannot_silently_reinterpret_a_different_owned_level(self):
        self.grant(3000)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_levels SET level=7 WHERE player_id=?', (self.player_id,))
            connection.commit()
        before = self.state()
        with self.assertRaises(ValueError):
            self.grant(1)
        self.assertEqual(self.state(), before)


if __name__ == '__main__':
    unittest.main()
