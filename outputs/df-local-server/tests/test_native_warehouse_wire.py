"""Exercise warehouse counters and extension operations through native messages."""

from pathlib import Path
from collections import deque
import socket
import tempfile
from types import SimpleNamespace
import unittest

from dfserver.candidate_business import CandidateBusinessCodec
from dfserver.handshake_diagnostic import _candidate_codec
from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame
from dfserver.gcp_framing import StreamDecoder
from dfserver.premium_shop import ITEMS


ROOT = Path(__file__).resolve().parent.parent


class WarehouseCounterCodecTests(unittest.TestCase):
    def test_unrelated_changes_preserve_cached_extension_counts(self):
        codec = _candidate_codec()
        fields = {'deposit_change': {'currency_changes': [
            {'currency_id': 17020000010, 'delta': -10, 'current_num': 90}]}}
        decoded = codec.decode(codec.encode('CSDepositChangeNtf', fields, sequence=0))
        self.assertEqual({key: decoded.fields['deposit_change'][key] for key in
            ('cur_extension_num', 'max_extension_num', 'upperlimit_extension_num')},
            {'cur_extension_num': -1, 'max_extension_num': -1, 'upperlimit_extension_num': -1})
        self.assertEqual(set(fields['deposit_change']), {'currency_changes'})

    def test_actual_zero_counts_are_retained_and_generic_codec_is_unchanged(self):
        fields = {'result': 0, 'changes': {'cur_extension_num': 0,
            'max_extension_num': 1, 'upperlimit_extension_num': 9}}
        codec = _candidate_codec()
        decoded = codec.decode(codec.encode('CSDepositOperateExtensionBoxRes', fields, sequence=8))
        self.assertEqual(decoded.fields['changes']['cur_extension_num'], 0)
        self.assertEqual(decoded.fields['changes']['max_extension_num'], 1)
        raw = CandidateBusinessCodec(ROOT / 'protocol/candidate_business.pb',
                                     ROOT / 'protocol/generated_class_metadata.json')
        unchanged = raw.decode(raw.encode('CSDepositChangeNtf', {'deposit_change': {}}, sequence=0))
        self.assertNotIn('max_extension_num', unchanged.fields.get('deposit_change', {}))


class WarehouseIntegrationWireTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('warehouse-wire', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[])
        self.backend.set_native_lobby_devices(self.token, {1010: 2})
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'

    def add_box(self):
        metadata = ITEMS['20030010001']
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (9001, player_id, 20030010001, 1, 2, 0, 0, metadata['length'], metadata['width']))
            connection.commit()

    def test_dispatch_applies_one_inventory_notification_before_box_callback(self):
        from dfserver.handshake_diagnostic import _continue_local_lobby
        from dfserver.gcp_data import encode_data_frame
        self.add_box()
        first = encode_data_frame((b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=1),),
            self.key, direction='client_to_server', header_word4=12, header_word9=1)
        second = encode_data_frame((b'EFGH' + self.codec.encode('CSDepositOperateExtensionBoxReq',
            {'operation': 1, 'prop_id': 20030010001, 'prop_gid': 9001,
             'src_pos': 2, 'dest_pos': 3001}, sequence=2),), self.key,
            direction='client_to_server', header_word4=12, header_word9=2)
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        client.settimeout(2)
        server.settimeout(2)
        client.shutdown(socket.SHUT_WR)
        result = {}
        _continue_local_lobby(server, StreamDecoder(), deque([second]), first,
            SimpleNamespace(session_key=self.key), self.backend.native_identity(self.token),
            self.backend, self.token, 10, result, continuation_seconds=2)
        server.shutdown(socket.SHUT_WR)
        wire = b''
        while chunk := client.recv(65536):
            wire += chunk
        frames = StreamDecoder().feed(wire)
        messages = [self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]) for frame in frames]
        self.assertEqual([row.name for row in messages], ['CSDepositGetPropsRes',
            'CSDepositChangeNtf', 'CSDepositOperateExtensionBoxRes'])
        self.assertEqual(messages[1].fields['extension_pos_order'], [3001])
        self.assertEqual(messages[1].fields['deposit_change']['cur_extension_num'], 1)
        self.assertEqual(messages[2].fields['result'], 0)

    def test_every_inventory_notice_keeps_actual_installed_box_order(self):
        from dfserver import native_warehouse_extensions as extensions
        from dfserver.gcp_data import encode_data_frame
        from dfserver.handshake_diagnostic import (_candidate_local_inventory_change_notification,
            _candidate_local_battle_pass_notifications, _candidate_local_activity_response_frames)
        self.add_box()
        fields = {'operation': 1, 'prop_id': 20030010001, 'prop_gid': 9001, 'src_pos': 2, 'dest_pos': 3001}
        self.assertEqual(extensions.response_fields(SimpleNamespace(
            name='CSDepositOperateExtensionBoxReq', fields=fields), self.backend, self.token)['result'], 0)
        change = [{'currency_id': 17020000010, 'delta': -10, 'current_num': 90}]
        reply = self.codec.encode('CSDepositEquipPropRes',
            {'result': 0, 'deposit_change': {'currency_changes': change}}, sequence=9)
        frame = encode_data_frame((reply,), self.key, direction='server_to_client',
            header_word4=12, header_word9=10)
        context = {'backend': self.backend, 'local_session': self.token}
        notifications = [_candidate_local_inventory_change_notification(frame, self.key,
            header_word4=12, header_word9=11, **context)]
        notifications += _candidate_local_battle_pass_notifications(
            {'_battle_pass_changes': {'currency_changes': change}}, self.key,
            header_word4=12, header_word9=12, **context)
        notifications += list(_candidate_local_activity_response_frames(frame, self.key,
            {'_local_activity_changes': {'currency_changes': change}}, **context)[:-1])
        self.assertEqual(len(notifications), 3)
        for notification in notifications:
            fields = self.codec.decode(decode_data_frame(notification, self.key,
                direction='server_to_client', compression_method=1).messages[0]).fields
            self.assertEqual(fields['extension_pos_order'], [3001])
            self.assertEqual(fields['deposit_change']['max_extension_num'], -1)

    def test_successful_ordinary_equipment_response_does_not_clear_box_tabs(self):
        from dfserver import native_warehouse_extensions as extensions
        from dfserver.handshake_diagnostic import _candidate_local_equip_response
        self.add_box()
        fields = {'operation': 1, 'prop_id': 20030010001, 'prop_gid': 9001, 'src_pos': 2, 'dest_pos': 3001}
        self.assertEqual(extensions.response_fields(SimpleNamespace(
            name='CSDepositOperateExtensionBoxReq', fields=fields), self.backend, self.token)['result'], 0)
        metadata = ITEMS['14020000006']
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (9002, player_id, 14020000006, 1, 2, 0, 0, metadata['length'], metadata['width']))
            connection.commit()
        command = {'prop_id': 14020000006, 'prop_gid': 9002, 'src_pos': 2, 'target_pos': 2, 'num': 1,
            'spec_loc': {'pos': 2, 'space_id': 1, 'start_x': 4, 'start_y': 4, 'x': 2, 'y': 2}}
        frame = _candidate_local_equip_response(b'ABCD' + self.codec.encode(
            'CSDepositEquipPropReq', {'cmds': [command]}, sequence=17), self.backend, self.token,
            self.key, header_word4=12, header_word9=10)
        result = self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]).fields
        self.assertEqual(result['result'], 0)
        self.assertEqual(result.get('extension_pos_order', []), [3001])

    def fetch(self, name):
        from dfserver.handshake_diagnostic import _candidate_local_deposit_response
        message = b'ABCD' + self.codec.encode(name, {}, sequence=5)
        frame = _candidate_local_deposit_response(message, self.backend, self.token, self.key,
            header_word4=12, header_word9=10)
        return self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]).fields

    def test_initial_fetch_uses_real_slots_and_enrolled_geometry(self):
        from dfserver.native_warehouse_growth import initialize_new_player
        with self.backend.connection() as connection:
            initialize_new_player(connection, self.backend._authorize(connection, self.token))
            connection.commit()
        fields = self.fetch('CSDepositGetPropsReq')
        self.assertEqual((fields['grid_pages'][0]['grid_length'],
                          fields['grid_pages'][0]['grid_width']), (9, 37))
        self.assertEqual((fields['cur_extension_num'], fields['max_extension_num'],
                          fields['upperlimit_extension_num']), (0, 1, 9))
        from dfserver.handshake_diagnostic import _candidate_main_deposit_grid
        self.assertEqual(_candidate_main_deposit_grid()['grid_width'], 40)

    def test_install_roundtrip_fetches_source_box_page_and_same_gid(self):
        from dfserver.handshake_diagnostic import _candidate_local_extension_response
        item_id, gid = 20030010001, 9001
        metadata = ITEMS[str(item_id)]
        with self.backend.connection() as connection:
            player_id = self.backend._authorize(connection, self.token)
            connection.execute('INSERT INTO native_lobby_props VALUES (?,?,?,?,?,?,?,?,?)',
                (gid, player_id, item_id, 1, 2, 0, 0, metadata['length'], metadata['width']))
            connection.commit()
        request = b'ABCD' + self.codec.encode('CSDepositOperateExtensionBoxReq',
            {'operation': 1, 'prop_id': item_id, 'prop_gid': gid, 'src_pos': 2, 'dest_pos': 3001}, sequence=6)
        entry = {}
        frame = _candidate_local_extension_response(request, self.backend, self.token, self.key,
            header_word4=12, header_word9=10, diagnostic_entry=entry)
        reply = self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.sequence, reply.fields['result']), (6, 0))
        from dfserver.handshake_diagnostic import _candidate_local_activity_response_frames
        frames = _candidate_local_activity_response_frames(frame, self.key, entry)
        notices = [self.codec.decode(decode_data_frame(value, self.key,
            direction='server_to_client', compression_method=1).messages[0]) for value in frames]
        self.assertEqual([value.name for value in notices],
                         ['CSDepositChangeNtf', 'CSDepositOperateExtensionBoxRes'])
        self.assertEqual(len(notices[0].fields['deposit_change']['prop_changes']), 1)
        self.assertEqual(self.fetch('CSDepositGetPropsReq')['cur_extension_num'], 1)
        result = self.fetch('CSDepositGetExtensionPropsReq')
        self.assertEqual(result['extension_slots'][0]['load_props'][0]['gid'], str(gid))
        self.assertEqual((result['in_extension_pages'][0]['grid_page_id'],
                          result['in_extension_pages'][0]['grid_width']), (3, 4))

    def test_growth_change_precedes_success_callback_and_repeated_query_is_quiet(self):
        from dfserver.handshake_diagnostic import (_candidate_local_warehouse_projection,
            _candidate_local_warehouse_changes, _candidate_local_activity_response_frames)
        from dfserver.native_warehouse_growth import initialize_new_player
        with self.backend.connection() as connection:
            initialize_new_player(connection, self.backend._authorize(connection, self.token))
            connection.commit()
        before = _candidate_local_warehouse_projection(self.backend, self.token)
        self.backend.set_native_lobby_devices(self.token, {1010: 4})
        entry = {}
        after = _candidate_local_warehouse_changes(self.backend, self.token, before, entry)
        request = self.codec.decode(self.codec.encode('CSSafehouseGetInfoReq', {}, sequence=19))
        from dfserver.gcp_data import encode_data_frame
        response = encode_data_frame((self.codec.response(request, {'result': 0}),), self.key,
            direction='server_to_client', header_word4=12, header_word9=10)
        frames = _candidate_local_activity_response_frames(response, self.key, entry)
        decoded = [self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0]) for frame in frames]
        self.assertEqual([row.name for row in decoded], ['CSDepositChangeNtf', 'CSSafehouseGetInfoRes'])
        change = decoded[0].fields['deposit_change']
        self.assertEqual((change['max_extension_num'], change['pos_changes'][0]['space'][0]['width']), (3, 40))
        unchanged = {}
        self.assertEqual(_candidate_local_warehouse_changes(self.backend, self.token, after, unchanged), after)
        self.assertNotIn('_local_activity_changes', unchanged)

    def test_connection_baseline_matches_sent_snapshot_when_another_connection_upgrades(self):
        from dfserver.handshake_diagnostic import (_candidate_local_deposit_response,
            _candidate_local_warehouse_response_projection, _candidate_local_warehouse_changes)
        request = b'ABCD' + self.codec.encode('CSDepositGetPropsReq', {}, sequence=7)
        frame = _candidate_local_deposit_response(request, self.backend, self.token, self.key,
            header_word4=12, header_word9=10)
        self.backend.set_native_lobby_devices(self.token, {1010: 4})
        sent = _candidate_local_warehouse_response_projection(frame, self.key, None)
        self.assertEqual((sent['grid']['grid_width'], sent['max_extension_num']), (37, 1))
        entry = {}
        actual = _candidate_local_warehouse_changes(self.backend, self.token, sent, entry)
        self.assertEqual((actual['grid']['grid_width'], actual['max_extension_num']), (40, 3))
        self.assertIn('warehouse_change', entry['_local_activity_changes'])

