from pathlib import Path
from types import SimpleNamespace
from collections import deque
import socket
import tempfile
import unittest

from dfserver.core import Backend, DomainError
from dfserver import native_prop_bindings, native_warehouse_extensions as extensions
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import StreamDecoder
from dfserver.handshake_diagnostic import _candidate_codec, _candidate_local_equip_response
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent
ITEM, SOURCE_GID = 37300600001, 6400000000000000484


class NativePartialStackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / 'save.sqlite3'
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.token = self.backend.register('partial-stacks', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.add(SOURCE_GID, ITEM, quantity=20, x=4, y=8)
        with self.backend.connection() as connection:
            native_prop_bindings.set_binding(connection, SOURCE_GID, 0, 17)
            connection.commit()
        self.codec = _candidate_codec()

    def add(self, gid, item, *, quantity=1, page=2, x=0, y=0):
        metadata = ITEMS[str(item)]
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, item, quantity, page, x, y, metadata['length'], metadata['width']))
            connection.commit()

    def props(self):
        return {row['gid']: row for row in self.backend.native_lobby_profile(self.token)['props']}

    def command(self, num=10, target=199997, **extra):
        return {'prop_id': ITEM, 'prop_gid': SOURCE_GID, 'src_pos': 2, 'target_pos': target,
                'target_prop_gid': 0, 'num': num, 'spec_loc': {}, **extra}

    def wire(self, commands):
        key = b'0123456789abcdef'
        frame = _candidate_local_equip_response(b'ABCD' + self.codec.encode(
            'CSDepositEquipPropReq', {'cmds': commands}, sequence=17), self.backend,
            self.token, key, header_word4=12, header_word9=10)
        return self.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0]).fields

    def test_recorded_ten_round_request_splits_to_real_pocket_and_survives_reopen(self):
        # Native trial1792475824236698400.log lines981/990; source GameItem max stack20.
        result = self.wire([self.command()])
        self.assertEqual(result['result'], 0)
        changes = result['deposit_change']['prop_changes']
        self.assertEqual([row['change_type'] for row in changes], [3, 1])
        self.assertEqual([int(row['delta']) for row in changes], [-10, 10])
        rows = self.props()
        source = rows[SOURCE_GID]
        destination = next(row for gid, row in rows.items() if gid != SOURCE_GID)
        self.assertEqual((source['quantity'], source['grid_page_id'], source['x'], source['y']), (10, 2, 4, 8))
        self.assertEqual((destination['quantity'], destination['grid_page_id'], destination['x']), (10, 199997, 1))
        self.assertEqual((destination['bind_type'], destination['bind_player']), (0, 17))
        self.assertEqual(sum(row['quantity'] for row in rows.values()), 20)
        self.backend = Backend(self.database, ROOT / 'definitions.json')
        self.assertEqual(self.props(), rows)

    def test_recorded_partial_move_crosses_encrypted_socket_dispatch(self):
        from dfserver.handshake_diagnostic import _continue_local_lobby
        key = b'0123456789abcdef'
        first = encode_data_frame((b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=1),),
            key, direction='client_to_server', header_word4=12, header_word9=1)
        second = encode_data_frame((b'EFGH' + self.codec.encode('CSDepositEquipPropReq',
            {'cmds': [self.command()]}, sequence=2),), key,
            direction='client_to_server', header_word4=12, header_word9=2)
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        client.settimeout(2)
        server.settimeout(2)
        client.shutdown(socket.SHUT_WR)
        _continue_local_lobby(server, StreamDecoder(), deque([second]), first,
            SimpleNamespace(session_key=key), self.backend.native_identity(self.token),
            self.backend, self.token, 10, {}, continuation_seconds=2)
        server.shutdown(socket.SHUT_WR)
        wire = b''
        while chunk := client.recv(65536):
            wire += chunk
        messages = [self.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
            compression_method=1).messages[0]) for frame in StreamDecoder().feed(wire)]
        result = next(row.fields for row in messages if row.name == 'CSDepositEquipPropRes')
        self.assertEqual(result['result'], 0)
        self.assertEqual([row['change_type'] for row in result['deposit_change']['prop_changes']], [3, 1])
        self.assertEqual(self.props()[SOURCE_GID]['quantity'], 10)
        self.assertEqual(sum(row['quantity'] for row in self.props().values() if row['template_id'] == ITEM), 20)

    def test_later_failed_command_rolls_back_new_instance_quantity_and_receipt(self):
        before = self.props()
        receipt = {}
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token,
                [self.command(), self.command(1, 108001)], receipt=receipt)
        self.assertEqual(receipt, {})
        self.assertEqual(self.props(), before)
        result = self.wire([self.command(), self.command(1, 108001)])
        self.assertNotEqual(result['result'], 0)
        self.assertNotIn('deposit_change', result)
        self.assertEqual(self.props(), before)

    def test_same_grid_split_keeps_source_cells_occupied(self):
        before = self.props()
        with self.assertRaises(DomainError):
            self.backend.native_lobby_move_props(self.token, [self.command(5, 2,
                spec_loc={'pos': 2, 'space_id': 1, 'start_x': 4, 'start_y': 8})])
        self.assertEqual(self.props(), before)
        result = self.wire([self.command(5, 2,
            spec_loc={'pos': 2, 'space_id': 1, 'start_x': 6, 'start_y': 8})])
        self.assertEqual(result['result'], 0)
        self.assertEqual(self.props()[SOURCE_GID]['quantity'], 15)
        destination = next(row for gid, row in self.props().items() if gid != SOURCE_GID)
        self.assertEqual((destination['quantity'], destination['x'], destination['y']), (5, 6, 8))

    def test_explicit_partial_merge_moves_requested_count_and_preserves_target_gid(self):
        self.add(9002, ITEM, quantity=5, page=199997, x=1)
        with self.backend.connection() as connection:
            native_prop_bindings.set_binding(connection, 9002, 0, 17)
            connection.commit()
        result = self.wire([self.command(3, target_prop_gid=9002, target_prop_id=ITEM)])
        self.assertEqual(result['result'], 0)
        self.assertEqual(set(self.props()), {SOURCE_GID, 9002})
        self.assertEqual((self.props()[SOURCE_GID]['quantity'], self.props()[9002]['quantity']), (17, 8))

    def test_full_pocket_overcount_and_partial_swap_fail_without_losing_quantity(self):
        for space in range(1, 6):
            self.add(9000 + space, ITEM, quantity=20, page=199997, x=space)
        before = self.props()
        for command in (self.command(), self.command(21), self.command(5, target_prop_gid=9001)):
            with self.subTest(command=command):
                self.assertNotEqual(self.wire([command])['result'], 0)
                self.assertEqual(self.props(), before)

    def test_split_from_original_ammunition_box_retains_installed_order(self):
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        self.add(9001, 20120010001)
        result = extensions.response_fields(SimpleNamespace(name='CSDepositOperateExtensionBoxReq', fields={
            'operation': 1, 'prop_id': 20120010001, 'prop_gid': 9001, 'src_pos': 2, 'dest_pos': 3001}),
            self.backend, self.token)
        self.assertEqual(result['result'], 0)
        self.assertEqual(self.wire([self.command(20, 3)])['result'], 0)
        result = self.wire([self.command(src_pos=3)])
        self.assertEqual(result['result'], 0)
        self.assertEqual(result['extension_pos_order'], [3001])
        rows = self.props()
        self.assertEqual((rows[SOURCE_GID]['grid_page_id'], rows[SOURCE_GID]['quantity']), (3, 10))
        self.assertEqual(sum(row['quantity'] for row in rows.values() if row['template_id'] == ITEM), 20)


if __name__ == '__main__':
    unittest.main()
