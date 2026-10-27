import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend, DomainError


ROOT = Path(__file__).resolve().parent.parent


class NativeWarehouseRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('warehouse-registration', 'local-password-123')['session']

    def test_real_registration_enrolls_only_new_account_with_35_rows(self):
        self.assertEqual(self.backend.native_lobby_profile(self.token)['warehouse_grid'],
                         {'grid_length': 9, 'grid_width': 35})
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            saved = connection.execute('SELECT base_rows,provenance_json,migration_receipt_json '
                'FROM native_lobby_warehouse_geometry WHERE player_id=?', (player_id,)).fetchone()
        self.assertEqual(saved['base_rows'], 35)
        self.assertEqual(json.loads(saved['provenance_json'])['kind'], 'primary_creator_arithmetic')
        self.assertEqual(json.loads(saved['migration_receipt_json'])['kind'], 'new_account_registration')

    def test_new_account_completed_warehouse_two_has_37_rows_after_reopen(self):
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.backend.native_lobby_profile(self.token)['warehouse_grid'],
                         {'grid_length': 9, 'grid_width': 37})

    def test_existing_legacy_account_without_ledger_remains_40_rows_on_login(self):
        # Explicitly model an account created by the old service, before geometry enrollment.
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('DELETE FROM native_lobby_warehouse_geometry WHERE player_id=?', (player_id,))
            connection.commit()
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        token = self.backend.login('warehouse-registration', 'local-password-123')['session']
        self.assertEqual(self.backend.native_lobby_profile(token)['warehouse_grid'],
                         {'grid_length': 9, 'grid_width': 40})
        with self.backend.connection() as connection:
            self.assertIsNone(connection.execute('SELECT 1 FROM native_lobby_warehouse_geometry '
                                               'WHERE player_id=?', (player_id,)).fetchone())

    def test_failed_registration_rolls_back_player_account_and_geometry_together(self):
        with patch.object(self.backend, '_new_session', side_effect=DomainError('REGISTRATION_FAILED', 'probe')):
            with self.assertRaises(DomainError):
                self.backend.register('registration-rollback', 'local-password-123')
        with self.backend.connection() as connection:
            for table in ('players', 'accounts', 'native_lobby_warehouse_geometry'):
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
