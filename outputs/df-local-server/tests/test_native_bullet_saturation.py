from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver.core import Backend, DomainError
from dfserver import native_prop_bindings, weapon_ammo
from dfserver.gcp_data import decode_data_frame
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_bullet_response
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent
SHOTGUN, SHOTGUN_GID = 18060000011, 6400000000000000415
SHELL, SHELL_GID = 37240700001, 6400000000000000421
RIFLE, RIFLE_GID = 18010000006, 6400000000000000059
ROUND, ROUND_GID = 37110500001, 6400000000000000468
OTHER_ROUND, OTHER_GID = 37110400001, 6400000000000000255


class NativeBulletSaturationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('bullet-saturation', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            self.prop(SHOTGUN_GID, SHOTGUN, 111), self.prop(RIFLE_GID, RIFLE, 112),
            self.prop(SHELL_GID, SHELL, 2, quantity=20),
            self.prop(ROUND_GID, ROUND, 2, quantity=60, x=1),
            self.prop(OTHER_GID, OTHER_ROUND, 2, quantity=60, x=2)])
        with self.backend.connection() as connection:
            native_prop_bindings.set_binding(connection, SHELL_GID, 0, 17)
            connection.commit()
        self.codec = _candidate_codec()
        self.props()

    @staticmethod
    def prop(gid, item, page, *, quantity=1, x=0):
        metadata = ITEMS[str(item)]
        return {'gid': gid, 'template_id': item, 'quantity': quantity, 'grid_page_id': page,
                'x': x, 'y': 0, 'length': metadata['length'], 'width': metadata['width']}

    @staticmethod
    def command(*, count=5, bullet=SHELL, bullet_gid=SHELL_GID, gun=SHOTGUN, gun_gid=SHOTGUN_GID):
        return {'op_type': 1, 'bullet_id': bullet, 'bullet_gid': bullet_gid,
                'bullet_op_num': count, 'target_gun_rec_id': gun, 'target_gun_rec_gid': gun_gid}

    def props(self):
        return {row['gid']: row for row in self.backend.native_lobby_profile(self.token)['props']}

    def snapshot(self):
        with self.backend.connection() as connection:
            return {table: [tuple(row) for row in connection.execute('SELECT * FROM ' + table + ' ORDER BY 1')]
                    for table in ('native_lobby_props', 'native_lobby_weapon_bullets',
                                  'native_lobby_prop_bindings', 'native_lobby_loaded_bullet_bindings')}

    def wire(self, commands):
        key = b'0123456789abcdef'
        frame = _candidate_local_bullet_response(b'ABCD' + self.codec.encode(
            'CSDepositOperateBulletReq', {'cmds': commands}, sequence=17), self.backend,
            self.token, key, header_word4=12, header_word9=10)
        return self.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0]).fields

    def test_native_over_budget_request_adds_only_two_remaining_shells_and_reopens(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command(count=3)])
        loaded_before = self.props()[SHOTGUN_GID]['weapon']['load_bullets'][0]
        result = self.wire([self.command()])
        self.assertEqual(result['result'], 0)
        props = self.props()
        gun = props[SHOTGUN_GID]['weapon']
        self.assertEqual(gun['magazine_capacity'], 5)
        self.assertEqual(sum(row['num'] for row in gun['load_bullets']), 5)
        self.assertIn(loaded_before, gun['load_bullets'])
        self.assertEqual(props[SHELL_GID]['quantity'], 15)
        self.assertTrue(all((row['bind_type'], row['bind_player']) == (0, 17)
                            for row in gun['load_bullets']))
        state = self.snapshot()
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.snapshot(), state)
        self.assertEqual(self.props(), props)

    def test_native_full_five_round_request_succeeds_without_gid_or_binding_changes(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command()])
        before = self.snapshot()
        self.assertEqual(self.backend.native_lobby_operate_bullets(self.token, [self.command()]), [])
        result = self.wire([self.command()])
        self.assertEqual(result['result'], 0)
        self.assertFalse(result.get('changes', {}).get('prop_changes'))
        self.assertEqual(self.snapshot(), before)

    def test_full_rifle_does_not_implicitly_replace_loaded_ammunition(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command(count=30,
            bullet=ROUND, bullet_gid=ROUND_GID, gun=RIFLE, gun_gid=RIFLE_GID)])
        before = self.snapshot()
        result = self.wire([self.command(count=30, bullet=OTHER_ROUND,
            bullet_gid=OTHER_GID, gun=RIFLE, gun_gid=RIFLE_GID)])
        self.assertEqual(result['result'], 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual({row['id'] for row in self.props()[RIFLE_GID]['weapon']['load_bullets']}, {ROUND})

    def test_mixed_batch_keeps_full_gun_unchanged_and_loads_the_other_gun(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command()])
        before = self.props()
        moves = self.backend.native_lobby_operate_bullets(self.token, [self.command(),
            self.command(count=30, bullet=ROUND, bullet_gid=ROUND_GID, gun=RIFLE, gun_gid=RIFLE_GID)])
        self.assertTrue(moves)
        props = self.props()
        self.assertEqual(props[SHOTGUN_GID], before[SHOTGUN_GID])
        self.assertEqual(props[SHELL_GID], before[SHELL_GID])
        self.assertEqual(props[ROUND_GID]['quantity'], 30)
        self.assertEqual(sum(row['num'] for row in props[RIFLE_GID]['weapon']['load_bullets']), 30)

    def test_unknown_capacity_and_later_invalid_command_roll_back_every_transfer(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command(count=3)])
        before = self.snapshot()
        unknown = {**weapon_ammo.CATALOG, 'magazines': {}}
        with patch.object(weapon_ammo, 'CATALOG', unknown):
            with self.assertRaises(DomainError) as caught:
                self.backend.native_lobby_operate_bullets(self.token, [self.command()])
            self.assertEqual(caught.exception.code, 'INVALID_EQUIPMENT')
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(DomainError):
            self.backend.native_lobby_operate_bullets(self.token, [self.command(),
                self.command(gun=RIFLE, gun_gid=RIFLE_GID)])
        self.assertEqual(self.snapshot(), before)

    def test_full_gun_still_validates_owned_gid_positive_count_and_available_quantity(self):
        self.backend.native_lobby_operate_bullets(self.token, [self.command()])
        before = self.snapshot()
        for command in (self.command(count=16), self.command(count=0), self.command(bullet_gid=999999),
                        self.command(bullet=ROUND, bullet_gid=ROUND_GID)):
            with self.subTest(command=command), self.assertRaises(DomainError):
                self.backend.native_lobby_operate_bullets(self.token, [command])
            self.assertEqual(self.snapshot(), before)
        other = self.backend.register('other-bullet-owner', 'local-password-123')['session']
        with self.assertRaises(DomainError):
            self.backend.native_lobby_operate_bullets(other, [self.command()])
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
