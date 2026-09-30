"""Exercise the bounded diagnostic over a real socket pair with own DH data."""
import hashlib
import json
import socket
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from dfserver.candidate_business import CandidateBusinessCodec
from dfserver.core import Backend
from dfserver.business_envelope import BusinessEnvelope, parse_business_envelope
from dfserver.gcp_control import AuthRequest, parse_auth_response, parse_ready_response
from dfserver.gcp_crypto import decrypt_body, encrypt_body
from dfserver.gcp_data import encode_data_frame, decode_data_frame
from dfserver.gcp_framing import Frame, StreamDecoder
from dfserver.gcp_handshake import parse_ack_body, parse_ack_header
from dfserver.handshake_diagnostic import (_derived_ready_body, _session_bound_auth_body,
                                           _candidate_local_login_response,
                                           _candidate_local_state_response,
                                           _candidate_local_heartbeat_response,
                                           _candidate_local_nick_response,
                                           _candidate_local_unicode_conf_response,
                                           _candidate_local_hall_mode_response,
                                           _candidate_local_hero_response,
                                           _candidate_local_hero_select_response,
                                           _candidate_local_hero_unlock_response,
                                           _candidate_operator_base_fashions,
                                           _candidate_local_prepare_map_response,
                                           _candidate_local_map_board_catalog,
                                           _candidate_local_account_state_response,
                                           _candidate_local_deposit_response,
                                           _candidate_local_deposit_sort_response,
                                           _candidate_local_safehouse_response,
                                           _candidate_local_safehouse_unlock_response,
                                           _candidate_local_safehouse_config_response,
                                           _candidate_local_module_status_response,
                                           _candidate_local_lottery_purchase_summary,
                                           _candidate_local_commerce_result,
                                           _candidate_local_lobby_critical_response,
                                           _candidate_local_guide_stage_response,
                                           _candidate_read_only_empty_response,
                                           _suggest_local_game_nick, _candidate_codec,
                                           _log_request_progress, inspect_exchange)


class HandshakeDiagnosticTests(unittest.TestCase):
    def test_config_response_without_result_is_not_reported_as_login_error(self):
        key = b'0123456789abcdef'
        response = _candidate_codec().encode(
            'CSShopGetGameItemConfigRes', {'descs': []}, sequence=7)
        frame = encode_data_frame((response,), key, direction='server_to_client',
                                  header_word4=12, header_word9=7)
        self.assertIsNone(_candidate_local_commerce_result(frame, key))

    def test_live_request_log_does_not_copy_credentials_or_request_body(self):
        entry = {'request_name': 'CSMallBuyReq', 'local_commerce_result': 14032,
                 'response_sent': True, 'token': 'secret',
                 'request_body': {'password': 'secret'}, 'failure_detail': 'secret'}
        with patch('builtins.print') as output:
            _log_request_progress(entry, 'processed')
        event = json.loads(output.call_args.args[0])
        self.assertEqual(event['local_commerce_result'], 14032)
        self.assertEqual(event['request_name'], 'CSMallBuyReq')
        self.assertNotIn('secret', output.call_args.args[0])
        self.assertTrue(output.call_args.kwargs['flush'])

    def test_local_module_status_enables_trade_and_equipment(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        request = b'ABCD' + codec.encode('CSSwitchLoadModuleStatusReq', {}, sequence=17)
        frame = _candidate_local_module_status_response(
            request, key, header_word4=12, header_word9=17)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.name, 'CSSwitchLoadModuleStatusRes')
        self.assertEqual(reply.fields['result'], 0)
        unlocked = {int(row['module_id']) for row in reply.fields['status']
                    if row['is_unlocked']}
        self.assertTrue({2000, 2001, 3000, 3001, 3002, 9000, 10000} <= unlocked)

    def test_lottery_purchase_diagnostic_records_item_and_price(self):
        codec = _candidate_codec()
        request = b'ABCD' + codec.encode('CSShopBuyLotteryItemReq', {
            'buy_props': [{'item_id': 16110000026, 'num': 10,
                           'currency_type': 17020000010, 'price': 20000}]}, sequence=18)
        self.assertEqual(_candidate_local_lottery_purchase_summary(request), [{
            'item_id': 16110000026, 'num': 10,
            'currency_type': 17020000010, 'price': 20000,
            'slippage': 0, 'currency_type_substitute': 0,
            'price_substitute': 0}])

    def test_safehouse_unlock_and_mall_refresh_have_usable_values(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        requests = (
            ('CSSafehouseFuncIsUnlockReq', {'unlock_id': 321},
             _candidate_local_safehouse_unlock_response),
            ('CSSafehouseGetConfigReq', {'formula_sign': 'A1B2', 'upgrade_sign': 'C3D4'},
             _candidate_local_safehouse_config_response),
            ('CSMallGetLabelNo1ConfigReq', {}, _candidate_read_only_empty_response),
            ('CSMallGetCfgVersionReq', {}, _candidate_read_only_empty_response),
        )
        for sequence, (name, fields, handler) in enumerate(requests, 1):
            with self.subTest(name=name):
                request = b'ABCD' + codec.encode(name, fields, sequence=sequence)
                frame = handler(request, key, header_word4=12, header_word9=sequence)
                decoded = decode_data_frame(frame, key, direction='server_to_client',
                                            compression_method=1)
                reply = codec.decode(decoded.messages[0])
                self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                                 (name[:-3] + 'Res', sequence, 0))
                if name == 'CSSafehouseFuncIsUnlockReq':
                    self.assertEqual(reply.fields['params'][0]['unlock_id'], '321')
                elif name == 'CSSafehouseGetConfigReq':
                    self.assertEqual(reply.fields['new_formula_sign'], 'A1B2')
                    self.assertEqual(reply.fields['new_upgrade_sign'], 'C3D4')
                    self.assertEqual(reply.fields.get('upgrade_cfg', []), [])
                elif name == 'CSMallGetLabelNo1ConfigReq':
                    self.assertGreater(int(reply.fields['next_get_time']), time.time() + 3500)
                else:
                    self.assertEqual(reply.fields['version_info']['ver'], 'local-empty-v1')

    def test_lobby_critical_requests_receive_correlated_empty_results(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        for sequence, name in enumerate(('CSActivityGetReq',
                                         'CSAuctionWithdrawReq',
                                         'CSMarketWithdrawReq'), 101):
            with self.subTest(name=name):
                request = b'ABCD' + codec.encode(name, {}, sequence=sequence)
                frame = _candidate_local_lobby_critical_response(
                    request, key, header_word4=12, header_word9=sequence)
                decoded = decode_data_frame(frame, key, direction='server_to_client',
                                            compression_method=1)
                envelope = parse_business_envelope(decoded.messages[0])
                self.assertEqual(envelope.header['name'], name[:-3] + 'Res')
                self.assertEqual(envelope.header['client_sequence_id'], sequence)
                self.assertEqual(envelope.body, b'\x08\x00')

    def test_catalogued_base_hero_and_warehouse_have_nonempty_client_state(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backend = Backend(Path(temporary.name) / 'save.sqlite3', root / 'definitions.json')
        token = backend.register('local_login', 'separate-test-password')['session']
        key = b'0123456789abcdef'
        requests = (
            ('CSHeroGetHeroIDListReq', _candidate_local_hero_response, 41),
            ('CSHeroLoadHeroListReq', _candidate_local_hero_response, 42),
            ('CSDepositGetPropsReq', _candidate_local_deposit_response, 43),
        )
        replies = {}
        for name, handler, sequence in requests:
            with self.subTest(name=name):
                request = codec.encode(name, {}, sequence=sequence)
                if name == 'CSDepositGetPropsReq' or name.startswith('CSHero'):
                    frame = handler(b'ABCD' + request, backend, token, key,
                                    header_word4=12, header_word9=sequence)
                else:
                    frame = handler(b'ABCD' + request, key,
                                    header_word4=12, header_word9=sequence)
                decoded = decode_data_frame(frame, key, direction='server_to_client',
                                            compression_method=1)
                reply = codec.decode(decoded.messages[0])
                self.assertEqual(reply.name, name[:-3] + 'Res')
                self.assertEqual(reply.sequence, sequence)
                self.assertEqual(reply.fields['result'], 0)
                replies[name] = reply.fields
        listed_ids = replies['CSHeroGetHeroIDListReq']['hero_ids']
        heroes = replies['CSHeroLoadHeroListReq']['heros']
        self.assertEqual({hero['hero_id'] for hero in heroes}, set(listed_ids))
        self.assertIn('88000000025', listed_ids)
        self.assertIn('88000000027', listed_ids)
        self.assertEqual(len(listed_ids), 17)
        self.assertTrue({'88000000038', '88000000039', '88000000040',
                         '88000000041', '88000000045', '88000000046',
                         '88000000047', '88000000051'}.issubset(listed_ids))
        self.assertNotIn('88000000032', listed_ids)
        self.assertNotIn('88000000034', listed_ids)
        unlock_request = b'ABCD' + codec.encode('CSHeroGetUnlockInfoReq', {}, sequence=44)
        unlock_frame = _candidate_local_hero_unlock_response(
            unlock_request, key, header_word4=12, header_word9=44)
        unlock_reply = codec.decode(decode_data_frame(
            unlock_frame, key, direction='server_to_client',
            compression_method=1).messages[0])
        self.assertEqual({row['hero_id'] for row in unlock_reply.fields['unlock_info']},
                         set(listed_ids))
        for hero in heroes:
            equipped = hero['fashion_equipped']
            self.assertEqual(equipped[0]['slot'], 0)
            expected_fashion = _candidate_operator_base_fashions()[int(hero['hero_id'])]
            self.assertEqual(equipped[0]['id'], str(expected_fashion))
            self.assertNotEqual(equipped[0]['id'], hero['hero_id'])
            self.assertEqual(hero['fashion_list'][0]['fashion']['id'], str(expected_fashion))
            self.assertTrue(hero['can_use'])
            self.assertTrue(hero['is_blast_unlock'])
        main_grid = replies['CSDepositGetPropsReq']['grid_pages']
        self.assertEqual(len(main_grid), 1)
        self.assertEqual((main_grid[0]['grid_page_id'], main_grid[0]['grid_length'],
                          main_grid[0]['grid_width']), (2, 9, 40))

    def test_prepare_boards_acknowledged_and_hero_selection_persists(self):
        root = Path(__file__).resolve().parent.parent
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('map_test', 'separate-test-password')['session']
            for sequence, name in enumerate(('CSPrepareMapBoardReq',
                                             'CSPrepareTDMMapBoardReq',
                                             'CSPrepareBombMapBoardReq'), 50):
                request = b'ABCD' + codec.encode(name, {}, sequence=sequence)
                frame = _candidate_local_prepare_map_response(
                    request, backend, token, key,
                    header_word4=12, header_word9=sequence)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client', compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                                 (name[:-3] + 'Res', sequence, 0))
                if name == 'CSPrepareMapBoardReq':
                    board = reply.fields.get('board_info_array', [])
                    self.assertEqual(len(board), 2)
                    self.assertEqual({int(row['point_id']) for row in board}, {1})
                    self.assertEqual({int(row['match_mode_type']) for row in board}, {1, 3})
            with patch.dict('os.environ', {'DF_LOCAL_MAP_ID_PROBE': '10:12'}):
                _candidate_local_map_board_catalog.cache_clear()
                request = b'ABCD' + codec.encode('CSPrepareMapBoardReq', {}, sequence=55)
                frame = _candidate_local_prepare_map_response(
                    request, backend, token, key, header_word4=12, header_word9=55)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client', compression_method=1).messages[0])
                self.assertEqual([int(row['mode']['map_id']) for row in
                                  reply.fields['board_info_array']], [10, 11, 12])
                _candidate_local_map_board_catalog.cache_clear()
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / 'save.sqlite3'
            backend = Backend(db, root / 'definitions.json')
            token = backend.register('operator_test', 'separate-test-password')['session']
            request = b'ABCD' + codec.encode('CSHeroSelectHeroReq', {
                'hero_id': 88000000027, 'mode': 1}, sequence=53)
            frame = _candidate_local_hero_select_response(
                request, backend, token, key, header_word4=12, header_word9=53)
            reply = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client', compression_method=1).messages[0])
            self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                             ('CSHeroSelectHeroRes', 53, 0))
            self.assertEqual(reply.fields['hero_id'], '88000000027')
            self.assertEqual(backend.native_lobby_profile(token)['selected_hero_id'], 88000000027)
            backend = Backend(db, root / 'definitions.json')
            load_request = b'ABCD' + codec.encode('CSHeroLoadHeroListReq', {}, sequence=54)
            load_frame = _candidate_local_hero_response(
                load_request, backend, token, key, header_word4=12, header_word9=54)
            loaded = codec.decode(decode_data_frame(
                load_frame, key, direction='server_to_client', compression_method=1).messages[0])
            self.assertEqual(loaded.fields['sol_hero_selected'], '88000000027')

    def test_persisted_local_level_currency_and_warehouse_reach_native_replies(self):
        root = Path(__file__).resolve().parent.parent
        codec = _candidate_codec()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'save.sqlite3'
            backend = Backend(database, root / 'definitions.json')
            token = backend.register('local_login', 'separate-test-password')['session']
            backend.set_native_lobby_profile(token, level=60,
                currencies={17020000010: 10_000_000, 17888808888: 10_000_000},
                props=[{'gid': 7001, 'template_id': 15080050142, 'quantity': 1,
                        'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 1, 'width': 1},
                       {'gid': 7002, 'template_id': 15080050006, 'quantity': 1,
                        'grid_page_id': 2, 'x': 1, 'y': 0, 'length': 1, 'width': 1},
                       {'gid': 7003, 'template_id': 11070004001, 'quantity': 1,
                        'grid_page_id': 107, 'x': 0, 'y': 0, 'length': 1, 'width': 1},
                       {'gid': 7004, 'template_id': 11080001002, 'quantity': 1,
                        'grid_page_id': 108, 'x': 0, 'y': 0, 'length': 1, 'width': 1}])
            backend.set_native_lobby_devices(token, {1001: 1, 1002: 2})
            legacy_melee = backend.ensure_native_lobby_default_melee(token, 10080000001)
            reopened = Backend(database, root / 'definitions.json')
            identity = {'native_id': 42, 'username': 'local_login', 'game_nick': 'TestHero'}
            key = b'0123456789abcdef'
            for sequence, name in enumerate(('CSAccountGetPlayerProfileReq',
                                              'CSPlayerGetBasicInfoReq',
                                              'CSGetCurrencyReq', 'CSDepositGetPropsReq'), 1):
                request = b'ABCD' + codec.encode(name, {}, sequence=sequence)
                if name == 'CSDepositGetPropsReq':
                    frame = _candidate_local_deposit_response(request, reopened, token, key,
                                                              header_word4=12, header_word9=sequence)
                else:
                    frame = _candidate_local_account_state_response(request, reopened, token,
                                                                      identity, key, header_word4=12,
                                                                      header_word9=sequence)
                reply = codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                       compression_method=1).messages[0])
                self.assertEqual(reply.fields['result'], 0)
                if name == 'CSAccountGetPlayerProfileReq':
                    self.assertEqual((reply.fields['level'], reply.fields['account_level'],
                                      reply.fields['blast_level']), (60, 60, 60))
                elif name == 'CSPlayerGetBasicInfoReq':
                    self.assertEqual(reply.fields['info']['sol_level'], 60)
                elif name == 'CSGetCurrencyReq':
                    self.assertEqual(len(reply.fields['currencys']), 2)
                    self.assertTrue(all(row['num'] == '10000000' for row in reply.fields['currencys']))
                else:
                    props = reply.fields['grid_pages'][0]['props']
                    equipment = {int(slot['position']): slot
                                 for slot in reply.fields['equiped_props']}
                    self.assertTrue({101, 105, 107, 108, 111, 112, 114} <= equipment.keys())
                    self.assertEqual((equipment[111]['grid_space'][0]['length'],
                                      equipment[111]['grid_space'][0]['width']), (1, 1))
                    self.assertEqual(int(equipment[107]['capacity']), 14)
                    self.assertEqual(int(equipment[108]['capacity']), 8)
                    self.assertEqual(int(equipment[107]['src_prop_id']), 11070004001)
                    self.assertEqual(int(equipment[108]['src_prop_id']), 11080001002)
                    self.assertNotIn('health', equipment[107]['load_props'][0])
                    self.assertNotIn('health', equipment[108]['load_props'][0])
                    self.assertEqual({item['id'] for item in props},
                                     {'15080050142', '15080050006'})
                    self.assertEqual({item['gid'] for item in props}, {'7001', '7002'})
                    self.assertEqual(len(reply.fields['melee_weapons']), 15)
                    self.assertEqual(int(reply.fields['melee_weapons'][0]['id']), 18100000002)
                    self.assertEqual(reopened.native_lobby_profile(token)['melee_props'][0]['gid'],
                                     int(reply.fields['melee_weapons'][0]['gid']))
                    self.assertEqual(int(reply.fields['melee_weapons'][0]['gid']),
                                     legacy_melee['gid'])
                    self.assertEqual(int(equipment[113]['src_prop_id']), 18100000002)
                    self.assertEqual(int(equipment[113]['load_props'][0]['id']), 18100000002)
                    self.assertEqual(int(equipment[113]['load_props'][0]['gid']),
                                     legacy_melee['gid'])
                    self.assertEqual({(item['loc']['start_x'], item['loc']['start_y'],
                                       item['loc']['x'], item['loc']['y']) for item in props},
                                     {(0, 0, 1, 1), (1, 0, 1, 1)})
            request = b'ABCD' + codec.encode('CSDepositSortPositionReq', {'pos_id': 2}, sequence=5)
            frame = _candidate_local_deposit_sort_response(request, reopened, token, key,
                                                            header_word4=12, header_word9=5)
            reply = codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0])
            self.assertEqual((reply.name, reply.fields['result'], reply.fields['pos_id']),
                             ('CSDepositSortPositionRes', 0, 2))
            request = b'ABCD' + codec.encode('CSSafehouseGetInfoReq', {}, sequence=6)
            frame = _candidate_local_safehouse_response(request, reopened, token, key,
                                                        header_word4=12, header_word9=6)
            reply = codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0])
            self.assertEqual({int(row['device_id']): row['level']
                              for row in reply.fields['devices']}, {1001: 1, 1002: 2})
            backend.set_native_lobby_profile(token, level=60, currencies={}, props=[
                {'gid': 8001, 'template_id': 15080050142, 'quantity': 1,
                 'grid_page_id': 2, 'x': 0, 'y': 0, 'length': 2, 'width': 1},
                {'gid': 8002, 'template_id': 15080050006, 'quantity': 1,
                 'grid_page_id': 2, 'x': 1, 'y': 0, 'length': 1, 'width': 1}])
            request = b'ABCD' + codec.encode('CSDepositGetPropsReq', {}, sequence=7)
            with self.assertRaisesRegex(ValueError, 'Overlapping warehouse props'):
                _candidate_local_deposit_response(request, reopened, token, key,
                                                   header_word4=12, header_word9=7)

    def test_new_equipped_containers_with_contents_return_warehouse(self):
        root = Path(__file__).resolve().parent.parent
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('container_test', 'separate-test-password')['session']
            backend.set_native_lobby_profile(token, level=1, currencies={}, props=[
                {'gid': 8001, 'template_id': 11070005004, 'quantity': 1,
                 'grid_page_id': 107, 'x': 0, 'y': 0, 'length': 1, 'width': 1},
                {'gid': 8002, 'template_id': 11080009001, 'quantity': 1,
                 'grid_page_id': 108, 'x': 0, 'y': 0, 'length': 1, 'width': 1},
                {'gid': 8003, 'template_id': 15080050142, 'quantity': 1,
                 'grid_page_id': 107001, 'x': 1, 'y': 0, 'length': 1, 'width': 1},
                {'gid': 8004, 'template_id': 15080050006, 'quantity': 1,
                 'grid_page_id': 108001, 'x': 5, 'y': 0, 'length': 1, 'width': 1},
            ])
            request = b'ABCD' + codec.encode('CSDepositGetPropsReq', {}, sequence=8)
            frame = _candidate_local_deposit_response(request, backend, token, key,
                                                      header_word4=12, header_word9=8)
            reply = codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                   compression_method=1).messages[0])
            self.assertEqual(reply.fields['result'], 0)
            equipment = {int(slot['position']): slot for slot in reply.fields['equiped_props']}
            self.assertEqual([int(prop['gid']) for prop in equipment[107001]['load_props']],
                             [8003])
            self.assertEqual([int(prop['gid']) for prop in equipment[108001]['load_props']],
                             [8004])
            self.assertEqual(equipment[108001].get('grid_space', []), [])
            self.assertEqual(int(equipment[108001]['src_prop_id']), 11080009001)

    def test_candidate_login_reply_uses_authenticated_local_identity(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        request = codec.encode('CSAccountLoginReq', {}, sequence=7)
        key = b'0123456789abcdef'
        frame = _candidate_local_login_response(b'ABCD' + request,
                                                {'native_id': 123456789, 'username': 'own-user'},
                                                key, header_word4=12, header_word9=3)
        self.assertEqual((frame.command, frame.header_word4, frame.header_word9), (0x4013, 12, 3))
        decoded = decode_data_frame(frame, key, direction='server_to_client', compression_method=1)
        self.assertEqual(decoded.header.opaque_flag, 64)
        reply = codec.decode(decoded.messages[0])
        self.assertEqual((reply.name, reply.service, reply.sequence), ('CSAccountLoginRes', 'account', 7))
        self.assertEqual(reply.fields['player_id'], '123456789')
        self.assertEqual(reply.fields['game_nick'], 'own-user')

    def test_new_character_login_keeps_in_lobby_name_editor_available(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        request = codec.encode('CSAccountLoginReq', {}, sequence=7)
        frame = _candidate_local_login_response(
            b'ABCD' + request,
            {'native_id': 123456789, 'username': 'local_login',
             'game_nick': None, 'game_registered': False},
            key, header_word4=12, header_word9=3)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.fields['result'], 0)
        self.assertNotIn('game_nick', reply.fields)
        self.assertNotIn('is_register', reply.fields)

    def test_candidate_state_reply_keeps_local_player_id(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        request = codec.encode('CSStateGetInfoReq', {}, sequence=8)
        key = b'0123456789abcdef'
        frame = _candidate_local_state_response(b'WXYZ' + request,
                                                {'native_id': 123456789, 'username': 'own-user'},
                                                key, header_word4=12, header_word9=4)
        decoded = decode_data_frame(frame, key, direction='server_to_client', compression_method=1)
        self.assertEqual(decoded.header.opaque_flag, 64)
        reply = codec.decode(decoded.messages[0])
        self.assertEqual((reply.name, reply.service, reply.sequence), ('CSStateGetInfoRes', 'online', 8))
        self.assertEqual(reply.fields['PlayerID'], '123456789')
        self.assertEqual(reply.fields['result'], 0)

    def test_candidate_heartbeat_reply_is_unprefixed_and_correlated(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        request = codec.encode('CSOnlineHeartbeatReq', {'padding': 17}, sequence=9)
        key = b'0123456789abcdef'
        with patch('dfserver.handshake_diagnostic.time.time', return_value=1790756500.75):
            frame = _candidate_local_heartbeat_response(
                b'\0\0\0\5' + request, key, header_word4=12, header_word9=6)
        decoded = decode_data_frame(frame, key, direction='server_to_client', compression_method=1)
        self.assertEqual(decoded.header.opaque_flag, 64)
        reply = codec.decode(decoded.messages[0])
        self.assertEqual((reply.name, reply.service, reply.sequence),
                         ('CSOnlineHeartbeatRes', 'online', 9))
        self.assertEqual(reply.fields['padding'], 17)
        self.assertEqual(int(reply.fields['tick_count']), 1790756500)

    def test_read_only_bootstrap_probe_does_not_answer_mutations(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        request = codec.encode('CSShopGetMediaCDNMappingReq', {}, sequence=10)
        frame = _candidate_read_only_empty_response(
            b'\0\0\0\6' + request, key, header_word4=12, header_word9=7)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                         ('CSShopGetMediaCDNMappingRes', 10, 0))
        rank_request = BusinessEnvelope(b'', {
            'client_sequence_id': 14,
            'name': 'CSRankGetPlayerRankPercentageReq',
            'service': 'rank',
        }).encode()
        rank_frame = _candidate_read_only_empty_response(
            b'\0\0\0\x0e' + rank_request, key, header_word4=12, header_word9=8)
        rank_reply = codec.decode(decode_data_frame(
            rank_frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((rank_reply.name, rank_reply.sequence, rank_reply.fields['result']),
                         ('CSRankGetPlayerRankPercentageRes', 14, 0))
        with self.assertRaises(ValueError):
            _candidate_read_only_empty_response(
                b'\0\0\0\7' + codec.encode('CSAccountLoginReq', {}, sequence=11),
                key, header_word4=12, header_word9=8)

    def test_empty_local_market_catalogue_completes_guide_price_read(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        request = codec.encode('CSAuctionAutoLoadGuidePriceReq', {}, sequence=21)
        frame = _candidate_read_only_empty_response(
            b'\0\0\0\25' + request, key, header_word4=12, header_word9=22)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.name, reply.service, reply.sequence),
                         ('CSAuctionAutoLoadGuidePriceRes', 'auctionauto', 21))
        self.assertEqual(reply.fields['result'], 0)
        self.assertTrue(reply.fields['finish'])
        self.assertEqual(reply.fields.get('price_list', []), [])

    def test_local_guide_bootstrap_marks_all_client_stages_finished(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        request = codec.encode('CSGuideGetPlayerGuideReq', {}, sequence=22)
        frame = _candidate_read_only_empty_response(
            b'\0\0\0\0' + request, key, header_word4=12, header_word9=22)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(reply.fields['result'], 0)
        self.assertTrue(reply.fields['skip_all'])
        self.assertEqual(set(reply.fields['guide_stage_id']), {1, 2, 3, 5, 6, 7, 34})

    def test_local_guide_stage_requests_receive_finished_state(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        for sequence, name, fields in (
                (23, 'CSGuideSkipReq', {'reason': 1}),
                (24, 'CSGuidePassedReq', {'guide_stage_id': 3, 'skip': False})):
            with self.subTest(name=name):
                request = b'\0\0\0\0' + codec.encode(name, fields, sequence=sequence)
                frame = _candidate_local_guide_stage_response(
                    request, key, header_word4=12, header_word9=sequence)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                                 (name[:-3] + 'Res', sequence, 0))
                if name == 'CSGuidePassedReq':
                    self.assertEqual(set(reply.fields['guide_stage_id']),
                                     {1, 2, 3, 5, 6, 7, 34})

    def test_empty_mall_pages_are_marked_complete(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        for sequence, request_name, goods_field in (
                (23, 'CSMallGetBuyGoodsReq', 'buy_props'),
                (24, 'CSMallGetRecycleGoodsReq', 'recyle_props')):
            with self.subTest(request_name=request_name):
                request = codec.encode(request_name, {'start_index': 0, 'get_num': 10},
                                       sequence=sequence)
                frame = _candidate_read_only_empty_response(
                    b'\0\0\0\0' + request, key, header_word4=12,
                    header_word9=sequence)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client', compression_method=1).messages[0])
                self.assertEqual(reply.name, request_name[:-3] + 'Res')
                self.assertEqual(reply.sequence, sequence)
                self.assertEqual(reply.fields['result'], 0)
                self.assertTrue(reply.fields['is_finish'])
                self.assertEqual(reply.fields.get(goods_field, []), [])

    def test_local_hall_mode_transition_is_acknowledged(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        request = codec.encode('CSClientEnterHallModeReq', {'enter_mode_id': 5},
                               sequence=35)
        frame = _candidate_local_hall_mode_response(
            b'\0\0\0\0' + request, key, header_word4=12, header_word9=35)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.name, reply.service, reply.sequence, reply.fields['result']),
                         ('CSClientEnterHallModeRes', 'playerinfo', 35, 0))

    def test_character_name_protocol_persists_separately_from_login(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('local_login', 'separate-test-password')['session']
            for sequence, name, fields in (
                    (12, 'CSAccountValidateNickReq', {'nick': '离线干员'}),
                    (13, 'CSAccountRegisterReq', {'game_nick': '离线干员'})):
                frame = _candidate_local_nick_response(
                    b'ABCD' + codec.encode(name, fields, sequence=sequence),
                    backend, token, key, header_word4=12, header_word9=sequence)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client', compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                                 (name[:-3] + 'Res', sequence, 0))
            self.assertEqual(backend.native_identity(token)['game_nick'], '离线干员')

    def test_random_name_reply_is_valid_suggestion_without_creating_character(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('local_login', 'separate-test-password')['session']
            key = b'0123456789abcdef'
            request = codec.encode('CSAccountRandNickReq', {}, sequence=19)
            names = set()
            for _ in range(5):
                frame = _candidate_local_nick_response(
                    b'ABCD' + request, backend, token, key,
                    header_word4=12, header_word9=20)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client', compression_method=1).messages[0])
                self.assertEqual(reply.fields['result'], 0)
                self.assertTrue(reply.fields['nick'].startswith('DL'))
                self.assertLessEqual(len(reply.fields['nick']), 16)
                self.assertTrue(backend.validate_game_nick(token, reply.fields['nick'])['available'])
                names.add(reply.fields['nick'])
            self.assertGreater(len(names), 1)
            self.assertFalse(backend.native_identity(token)['game_registered'])

    def test_business_descriptor_is_reused_across_requests(self):
        self.assertIs(_candidate_codec(), _candidate_codec())

    def test_character_name_configuration_has_usable_rules(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        key = b'0123456789abcdef'
        request = codec.encode('CSAccountGetUnicodeConfReq', {}, sequence=15)
        frame = _candidate_local_unicode_conf_response(
            b'ABCD' + request, key, header_word4=12, header_word9=20)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                         ('CSAccountGetUnicodeConfRes', 15, 0))
        self.assertGreater(reply.fields['max_char_num'], 0)
        self.assertTrue(any(r['minRune'] <= ord('离') <= r['maxRune']
                            for r in reply.fields['white_list']))

    def test_new_character_wire_flow_accepts_name_and_persists_it(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('local_login', 'separate-test-password')['session']
            identity = backend.native_identity(token)
            expected = {'token': token, 'native_id': identity['native_id'],
                        'username': identity['username'], 'game_nick': None,
                        'game_registered': False}
            client, server = socket.socketpair()
            results = []
            worker = threading.Thread(target=lambda: results.append(
                inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                                 expected_identity=expected, response_probe=True,
                                 ready_probe=True, auth_identity_probe=True,
                                 business_login_probe=True, business_bootstrap_probe=True,
                                 backend=backend, local_session=token)))
            decoder = StreamDecoder()
            pending = []
            def receive():
                while not pending:
                    pending.extend(decoder.feed(client.recv(4096)))
                return pending.pop(0)
            try:
                client.settimeout(3)
                worker.start()
                client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                     b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
                self.assertEqual(receive().command, 0x1002)
                key = hashlib.md5(b'\x12').digest()
                auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
                client.sendall(Frame(11, 12, 0x2001, 0, 2, b'',
                                     encrypt_body(auth.encode(), key)).encode())
                self.assertEqual(receive().command, 0x2002)
                self.assertEqual(receive().command, 0x6002)
                for sequence, name, fields, reply_name in (
                        (1, 'CSAccountLoginReq', {}, 'CSAccountLoginRes'),
                        (2, 'CSStateGetInfoReq', {}, 'CSStateGetInfoRes'),
                        (3, 'CSAccountGetUnicodeConfReq', {}, 'CSAccountGetUnicodeConfRes'),
                        (4, 'CSAccountValidateNickReq', {'nick': '离线干员'}, 'CSAccountValidateNickRes'),
                        (5, 'CSAccountRegisterReq', {'game_nick': '离线干员'}, 'CSAccountRegisterRes')):
                    request = sequence.to_bytes(4, 'big') + codec.encode(name, fields, sequence=sequence)
                    client.sendall(encode_data_frame((request,), key, direction='client_to_server',
                                                     header_word4=12, header_word9=sequence + 2).encode())
                    response = codec.decode(decode_data_frame(
                        receive(), key, direction='server_to_client',
                        compression_method=1).messages[0])
                    self.assertEqual(response.name, reply_name)
                    self.assertEqual(response.fields['result'], 0)
                    if sequence == 2:
                        ping_header = bytes.fromhex(
                            '0000001700065c64c011a210000000010000000000000000')
                        client.sendall(Frame(11, 12, 0x9001, 0, 9,
                                             ping_header, b'').encode())
                        pong = receive()
                        self.assertEqual((pong.command, pong.extra_header, pong.body),
                                         (0x9001, ping_header, b''))
                        self.assertEqual(pong.payload_encryption_flag, 1)
                self.assertEqual(backend.native_identity(token)['game_nick'], '离线干员')
                client.shutdown(socket.SHUT_WR)
                worker.join(4)
                self.assertFalse(worker.is_alive())
                self.assertTrue(results[0]['character_registration_observed'])
                self.assertNotIn('离线干员', str(results[0]))
            finally:
                client.close()
                server.close()
                worker.join(4)

    def test_authenticated_followup_connection_accepts_name_request_first(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('local_login', 'separate-test-password')['session']
            identity = backend.native_identity(token)
            expected = {'token': token, 'native_id': identity['native_id'],
                        'username': identity['username'], 'game_nick': None,
                        'game_registered': False}
            client, server = socket.socketpair()
            results = []
            worker = threading.Thread(target=lambda: results.append(
                inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                                 expected_identity=expected, response_probe=True,
                                 ready_probe=True, auth_identity_probe=True,
                                 business_login_probe=True, business_bootstrap_probe=True,
                                 backend=backend, local_session=token)))
            decoder = StreamDecoder()
            pending = []
            def receive():
                while not pending:
                    pending.extend(decoder.feed(client.recv(4096)))
                return pending.pop(0)
            try:
                client.settimeout(3)
                worker.start()
                client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                     b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
                self.assertEqual(receive().command, 0x1002)
                key = hashlib.md5(b'\x12').digest()
                auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
                client.sendall(Frame(11, 12, 0x2001, 0, 2, b'',
                                     encrypt_body(auth.encode(), key)).encode())
                self.assertEqual(receive().command, 0x2002)
                self.assertEqual(receive().command, 0x6002)
                request = (3).to_bytes(4, 'big') + codec.encode(
                    'CSAccountRandNickReq', {}, sequence=3)
                client.sendall(encode_data_frame(
                    (request,), key, direction='client_to_server',
                    header_word4=12, header_word9=3).encode())
                reply = codec.decode(decode_data_frame(
                    receive(), key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.fields['result']),
                                 ('CSAccountRandNickRes', 0))
                self.assertTrue(reply.fields['nick'].startswith('DL'))
                client.shutdown(socket.SHUT_WR)
                worker.join(4)
                self.assertFalse(worker.is_alive())
                self.assertEqual(results[0]['business_login_probe_result'],
                                 'authenticated_followup_without_login')
            finally:
                client.close()
                server.close()
                worker.join(4)

    def test_business_responses_advance_server_transport_sequence(self):
        root = Path(__file__).resolve().parent.parent
        codec = CandidateBusinessCodec(root / 'protocol/candidate_business.pb',
                                       root / 'protocol/generated_class_metadata.json')
        client, server = socket.socketpair()
        results = []
        token = 'private-synthetic-test-value'
        worker = threading.Thread(target=lambda: results.append(
            inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                             expected_identity={'token': token, 'native_id': 123456789,
                                                'username': 'own-user'}, response_probe=True,
                             ready_probe=True, auth_identity_probe=True,
                             business_login_probe=True, business_bootstrap_probe=True)))
        try:
            client.settimeout(3)
            worker.start()
            client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                 b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
            decoder = StreamDecoder()
            frames = []
            while not frames:
                frames.extend(decoder.feed(client.recv(128)))
            key = hashlib.md5(b'\x12').digest()
            auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
            client.sendall(Frame(11, 12, 0x2001, 0, 2, b'',
                                 encrypt_body(auth.encode(), key)).encode())
            frames = []
            while len(frames) < 2:
                frames.extend(decoder.feed(client.recv(128)))
            self.assertEqual([f.header_word9 for f in frames], [2, 3])
            login = (3).to_bytes(4, 'big') + codec.encode('CSAccountLoginReq', {}, sequence=1)
            client.sendall(encode_data_frame((login,), key, direction='client_to_server',
                                             header_word4=12, header_word9=3).encode())
            frames = []
            while not frames:
                frames.extend(decoder.feed(client.recv(256)))
            self.assertEqual((frames[0].command, frames[0].header_word9), (0x4013, 4))
            self.assertEqual(codec.decode(decode_data_frame(
                frames[0], key, direction='server_to_client',
                compression_method=1).messages[0]).name, 'CSAccountLoginRes')
            friend = (4).to_bytes(4, 'big') + codec.encode('CSFriendGetApplyListReq', {}, sequence=2)
            client.sendall(encode_data_frame((friend,), key, direction='client_to_server',
                                             header_word4=12, header_word9=4).encode())
            frames = []
            while not frames:
                frames.extend(decoder.feed(client.recv(256)))
            self.assertEqual((frames[0].command, frames[0].header_word9), (0x4013, 5))
            self.assertEqual(codec.decode(decode_data_frame(
                frames[0], key, direction='server_to_client',
                compression_method=1).messages[0]).name, 'CSFriendGetApplyListRes')
            state = (5).to_bytes(4, 'big') + codec.encode('CSStateGetInfoReq', {}, sequence=3)
            client.sendall(encode_data_frame((state,), key, direction='client_to_server',
                                             header_word4=12, header_word9=5).encode())
            frames = []
            while not frames:
                frames.extend(decoder.feed(client.recv(256)))
            self.assertEqual((frames[0].command, frames[0].header_word9), (0x4013, 6))
            self.assertEqual(codec.decode(decode_data_frame(
                frames[0], key, direction='server_to_client',
                compression_method=1).messages[0]).name, 'CSStateGetInfoRes')
            client.shutdown(socket.SHUT_WR)
            worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertFalse(results[0]['business_state_response_sent'])
            self.assertEqual(results[0]['business_bootstrap_response_name'],
                             'CSFriendGetApplyListReq')
            self.assertEqual(results[0]['business_response_header_word9'], 4)
            self.assertEqual(results[0]['business_state_response_header_word9'], 5)
            self.assertTrue(any(row.get('request_name') == 'CSStateGetInfoReq'
                                and row.get('response_sent')
                                for row in results[0]['bounded_business_continuation']))
            self.assertNotIn(token, str(results[0]))
        finally:
            client.close()
            server.close()
            worker.join(4)

    def test_session_derived_ready_tuple_is_scoped_and_distinct(self):
        first = parse_ready_response(_derived_ready_body({'token': 'own-session-one'}))
        second = parse_ready_response(_derived_ready_body({'token': 'own-session-two'}))
        self.assertEqual((first.relay_position, first.relay_word64), (1, 1))
        self.assertNotEqual(first.relay_identity, bytes(16))
        self.assertNotEqual(first.relay_identity, second.relay_identity)
        self.assertEqual((first.compression_method, first.compression_limit), (0, 0))

    def test_auth_probe_binds_local_account_and_request_auth_type(self):
        token = 'private-synthetic-test-value'
        request = AuthRequest(0x1000, b'QQ', token.encode(), b'')
        body = _session_bound_auth_body(request, {'native_id': 123456789, 'token': token})
        response = parse_auth_response(body)
        self.assertEqual((response.common.opaque_word16, response.common.variant_type,
                          response.common.variant_value, response.common.opaque_word64),
                         (1, 2, 123456789, 123456789))
        self.assertEqual(response.extra_word16, request.auth_type)
        self.assertEqual(response.extra_data4096, token.encode())
        self.assertNotIn(token, repr(response))

    def test_parser_probe_does_not_send_auth_response_for_unmatched_token(self):
        client, server = socket.socketpair()
        results = []
        worker = threading.Thread(target=lambda: results.append(
            inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                             expected_identity={'token': 'expected-private-token',
                                                'native_id': 123456789,
                                                'username': 'own-user'}, response_probe=True)))
        try:
            client.settimeout(3)
            worker.start()
            client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                 b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
            decoder = StreamDecoder()
            frames = []
            while not frames:
                frames = decoder.feed(client.recv(128))
            key = hashlib.md5(b'\x12').digest()
            request = AuthRequest(0x1000, b'own-id', b'unmatched-private-token', b'')
            client.sendall(Frame(11, 12, 0x2001, 0, 1, b'',
                                 encrypt_body(request.encode(), key)).encode())
            worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(results[0]['outcome'], 'local_token_not_in_auth_data')
            self.assertFalse(results[0]['auth_response_sent'])
            self.assertNotIn('expected-private-token', str(results[0]))
        finally:
            client.close()
            server.close()
            worker.join(4)

    def test_parser_probe_requires_matching_local_token_and_uses_3366_layout(self):
        client, server = socket.socketpair()
        results = []
        token = 'private-synthetic-test-value'
        worker = threading.Thread(target=lambda: results.append(
            inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                             expected_identity={'token': token, 'native_id': 123456789,
                                                'username': 'own-user'}, response_probe=True,
                             ready_probe=True)))
        try:
            client.settimeout(3)
            worker.start()
            hello = Frame(11, 12, 0x1001, 0, 1,
                          b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'')
            client.sendall(hello.encode())
            decoder = StreamDecoder()
            frames = []
            while not frames:
                frames = decoder.feed(client.recv(128))
            key = hashlib.md5(b'\x12').digest()
            self.assertEqual(frames[0].command, 0x1002)
            request = AuthRequest(0x1000, b'own-id', b'prefix-' + token.encode() + b'-suffix', b'')
            client.sendall(Frame(11, 12, 0x2001, 0, 1, b'',
                                 encrypt_body(request.encode(), key)).encode())
            frames = []
            while len(frames) < 2:
                frames.extend(decoder.feed(client.recv(128)))
            self.assertEqual([frame.command for frame in frames], [0x2002, 0x6002])
            self.assertEqual([frame.header_word9 for frame in frames], [1, 2])
            auth_plaintext = decrypt_body(frames[0].body, key)
            self.assertEqual(len(auth_plaintext), 29)
            self.assertEqual(parse_auth_response(auth_plaintext).common.variant_type, 0)
            self.assertEqual(decrypt_body(frames[1].body, key), bytes(49))
            client.sendall(encode_data_frame((b'first', b'second'), key,
                                             direction='client_to_server',
                                             header_word4=13, header_word9=3).encode())
            worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(results[0]['outcome'], 'next_command_after_control_parser_probe')
            self.assertTrue(results[0]['post_response_data_decoded'])
            self.assertEqual(results[0]['post_response_data_message_lengths'], [5, 6])
            self.assertEqual(results[0]['post_response_message_shapes'][0]['message_length'], 5)
            self.assertTrue(results[0]['local_identity_correlations']['local_token_contained_in_auth_data'])
            self.assertEqual(results[0]['auth_response_probe_layout'], '0x3366_fixed_schema_zero_values')
            self.assertEqual(results[0]['ready_response_probe_layout'], '0x3366_v12_fixed_schema_zero_values')
            self.assertNotIn(token, str(results[0]))
        finally:
            client.close()
            server.close()
            worker.join(4)

    def test_loopback_exponent_one_exchange_without_modulus(self):
        client, server = socket.socketpair()
        results = []
        worker = threading.Thread(target=lambda: results.append(
            inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                             expected_identity={'token':'private-synthetic-test-value',
                                                'native_id':123456789,'username':'own-user'})))
        try:
            worker.start()
            # 2**6 mod 23 = 18; the diagnostic never receives modulus 23.
            hello = Frame(11, 12, 0x1001, 0, 1,
                          b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'')
            client.sendall(hello.encode())
            decoder = StreamDecoder()
            frames = []
            while not frames:
                frames = decoder.feed(client.recv(7))
            ack = frames[0]
            self.assertEqual(parse_ack_header(ack).server_public_key,
                             (2).to_bytes(64, 'big'))
            key = hashlib.md5(b'\x12').digest()
            self.assertEqual(parse_ack_body(decrypt_body(ack.body, key)).opaque_context, b'')
            credential = b'private-synthetic-test-value'
            request = AuthRequest(1, credential, b'own auth data', b'own context')
            client.sendall(Frame(11, 12, 0x2001, 0, 1, b'',
                                 encrypt_body(request.encode(), key)).encode())
            worker.join(4)
            self.assertFalse(worker.is_alive())
            result = results[0]
            self.assertEqual(result['outcome'], 'transport_auth_request_decoded')
            self.assertTrue(result['session_key_public'])
            self.assertFalse(result['auth_response_sent'])
            self.assertTrue(result['local_identity_correlations']['local_token_exact_field'])
            self.assertFalse(result['local_identity_correlations']['native_id_decimal_contained'])
            self.assertNotIn(credential.decode(), str(result))
        finally:
            client.close()
            server.close()
            worker.join(4)

    def test_ack_and_next_transport_command_without_credential_disclosure(self):
        client, server = socket.socketpair()
        results = []
        worker = threading.Thread(target=lambda: results.append(
            inspect_exchange(server, (23).to_bytes(64, 'big'), timeout=3)))
        try:
            worker.start()
            hello = Frame(11, 12, 0x1001, 0, 1,
                          b'\x03\x00\x01\x12' + bytes(64) + b'\x03own tail', b'')
            wire = hello.encode()
            for offset in range(0, len(wire), 7):
                client.sendall(wire[offset:offset + 7])
            decoder = StreamDecoder()
            frames = []
            while not frames:
                frames = decoder.feed(client.recv(5))
            self.assertEqual(len(frames), 1)
            ack = frames[0]
            self.assertEqual((ack.command, ack.header_word4, ack.header_word9), (0x1002, 12, 1))
            self.assertEqual((parse_ack_header(ack).compression_method,
                              parse_ack_header(ack).compression_threshold), (1, 500))
            public = int.from_bytes(parse_ack_header(ack).server_public_key, 'big')
            shared = pow(public, 6, 23)
            key = hashlib.md5(shared.to_bytes((shared.bit_length() + 7) // 8, 'big')).digest()
            self.assertEqual(parse_ack_body(decrypt_body(ack.body, key)).opaque_context, b'')
            credential = b'private-synthetic-test-value'
            request = AuthRequest(1, credential, b'own auth data', b'own context')
            client.sendall(Frame(11, 12, 0x2001, 0, 1, b'',
                                 encrypt_body(request.encode(), key)).encode())
            worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result['outcome'], 'transport_auth_request_decoded')
            self.assertTrue(result['ack_sent'])
            self.assertFalse(result['auth_response_sent'])
            self.assertEqual(result['credential_bytes'], len(credential))
            self.assertNotIn(credential.decode(), str(result))
        finally:
            client.close()
            server.close()
            worker.join(4)


if __name__ == '__main__':
    unittest.main()
