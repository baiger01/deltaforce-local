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
from types import SimpleNamespace

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
                                           _candidate_local_room_mode_response,
                                           _candidate_local_match_rank_response,
                                           _candidate_local_match_alloc_response,
                                           _candidate_local_solo_room_team_response,
                                           _candidate_local_solo_room_hero_response,
                                           _candidate_local_solo_room_ready_response,
                                           _candidate_local_match_prepare_probe,
                                           _candidate_local_match_join_probe,
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
                                            compression_method=1, max_output=1024 * 1024)
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
                                            compression_method=1, max_output=1024 * 1024)
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
                load_frame, key, direction='server_to_client', compression_method=1,
                max_output=1024 * 1024).messages[0])
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


class MapHandshakeDiagnosticTests(unittest.TestCase):
    """Check local map and match protocols with synthetic data and socket pairs."""

    def test_map_level_lock_uses_the_client_enum_and_observation_is_serialized(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        request = b'ABCD' + codec.encode('CSPrepareMapBoardReq', {}, sequence=7)
        catalog = [{'point_id': 1, 'map_id': 2201, 'match_mode_id': 142201103,
                    'min_level': 10, 'match_mode_type': 3}]
        backend = SimpleNamespace(native_lobby_profile=lambda _: {'level': 1})
        observation = {}
        with patch('dfserver.handshake_diagnostic._candidate_local_map_board_catalog',
                   return_value=catalog):
            frame = _candidate_local_prepare_map_response(
                request, backend, None, key, header_word4=12, header_word9=7,
                observation=observation)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        row = reply.fields['board_info_array'][0]
        self.assertEqual((row['lock_reason'], row['is_open']), (4, 0))
        self.assertEqual(observation['response_fields'], reply.fields)

    def test_room_mode_list_excludes_conflicting_map_ids(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        request = b'ABCD' + codec.encode('CSRoomGetMatchModeListReq',
                                         {'game_mode': 1}, sequence=49)
        for catalog in ('map_board_zero_dam_candidate_20260930.json',
                        'map_board_trial_modes_20260930.json'):
            with patch.dict('os.environ', {
                    'DF_LOCAL_MAP_BOARD_CATALOG': str(root / 'protocol' / catalog)}):
                frame = _candidate_local_room_mode_response(
                    request, key, header_word4=12, header_word9=49)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.fields['result']),
                                 ('CSRoomGetMatchModeListRes', 0))
                modes = reply.fields.get('mode_info_list', [])
                self.assertEqual(modes, [])

    def test_local_match_prepare_probe_declares_bots_without_a_fake_ds_endpoint(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('room_test', 'separate-test-password')['session']
            frame = _candidate_local_match_prepare_probe(
                backend, token, {'game_mode': 1, 'match_mode_id': 2}, key,
                header_word4=12, header_word9=47)
            notice = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual((notice.name, notice.sequence),
                             ('CSPrepareJoinMatchNtf', 0))
            members = notice.fields['room_member_infos']
            self.assertEqual(len(members), 4)
            self.assertFalse(members[0]['is_robot'])
            self.assertTrue(all(member['is_robot'] for member in members[1:]))
            self.assertEqual(notice.fields['player_id'],
                             str(backend.native_identity(token)['native_id']))

    def test_match_allocation_rejects_start_without_a_game_server(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        for sequence, name, fields in (
                (44, 'CSRoomMatchStartAllocReq', {
                    'mode_infos': [{'game_mode': 1, 'game_rule': 4, 'sub_mode': 10,
                                    'team_mode': 3, 'map_id': 1, 'match_mode_id': 1}],
                    'is_add_member': False, 'group_id': 0}),
                (45, 'CSRoomMatchQuitAllocReq', {'is_timeout': False,
                                                 'match_module': 1}),
                (46, 'CSMatchCheckTReq', {'node_id': ''}),
                (47, 'CSMatchRoomSolReadyTReq', {'room_id': 123}),
                (48, 'CSMatchRoomStartMatchTglogTReq', {'ds_room_id': 123,
                                                        'sec_report_data': '',
                                                        'client_start_time': ''})):
            request = b'ABCD' + codec.encode(name, fields, sequence=sequence)
            frame = _candidate_local_match_alloc_response(
                request, key, header_word4=12, header_word9=sequence)
            reply = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1).messages[0])
            expected_result = 1 if name == 'CSRoomMatchStartAllocReq' else 0
            self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                             (name[:-3] + 'Res', sequence, expected_result))
            if name == 'CSRoomMatchStartAllocReq':
                self.assertNotIn('client_group', reply.fields)

    def test_match_handoff_points_only_to_an_active_loopback_probe(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 2}
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('ds_probe_test', 'separate-test-password')['session']
            probe = SimpleNamespace(listening=True, port=47993)
            request = b'ABCD' + codec.encode('CSRoomMatchStartAllocReq', {
                'mode_infos': [mode], 'is_add_member': False, 'group_id': 0},
                sequence=17)
            frame = _candidate_local_match_alloc_response(
                request, key, header_word4=12, header_word9=17,
                game_server_probe=probe)
            response = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(response.fields['result'], 0)
            frame = _candidate_local_match_join_probe(
                backend, token, mode, probe, key,
                header_word4=12, header_word9=18)
            notice = parse_business_envelope(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(notice.header['name'], 'CSPlayerJoinMatchNtf')
            self.assertEqual(notice.header['service'], 'matchroom')
            self.assertIn(b'127.0.0.1', notice.body)
            self.assertIn(b'\x4a\x09localhost', notice.body)  # top-level DS domain
            self.assertIn(b'\x18\xf9\xf6\x02', notice.body)  # field 3, port 47993
            self.assertIn(b'\x58\x02', notice.body)  # field 11, requested mode
            self.assertIn(
                b'\x62\x1c\x0a\x09localhost\x12\x0f\x0a\x09' + b'127.0.0.1' +
                b'\x10\xf9\xf6\x02', notice.body)  # field 12: HostInfo/DsIpInfo
            self.assertIn(b'\x28\x99\x11', notice.body)  # field 5, selected map 2201
            # Decode the two negotiated-encryption fields independently of
            # byte matching, including protobuf's unknown-field skipping.
            from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
            definition = descriptor_pb2.FileDescriptorProto(name='probe_join_contract.proto')
            message = definition.message_type.add(name='JoinEncryptionContract')
            for field_name, number, field_type in (('enc_flag', 14, 13),
                                                    ('secret_key', 19, 9)):
                message.field.add(name=field_name, number=number, type=field_type, label=1)
            pool = descriptor_pool.DescriptorPool()
            pool.Add(definition)
            contract = message_factory.GetMessageClass(
                pool.FindMessageTypeByName('JoinEncryptionContract'))()
            contract.ParseFromString(notice.body)
            self.assertEqual(contract.enc_flag, 0)
            self.assertFalse(contract.HasField('secret_key'))
            with patch.dict('os.environ', {'DF_LOCAL_DS_MAP_ID': '1901'}):
                with self.assertRaisesRegex(ValueError, 'differs from the selected map'):
                    _candidate_local_match_join_probe(
                        backend, token, mode, probe, key,
                        header_word4=12, header_word9=19)
            probe.listening = False
            with self.assertRaises(ValueError):
                _candidate_local_match_join_probe(backend, token, mode, probe, key,
                                                  header_word4=12, header_word9=19)

    def test_world_map_rejects_placeholder_and_safehouse_mode_ids(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        probe = SimpleNamespace(listening=True, port=47993)
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('bad_mode_test', 'separate-test-password')['session']
            for mode_id in (1, 31100003):
                mode = {'game_mode': 1, 'game_rule': 4, 'sub_mode': 10,
                        'map_id': 2201, 'match_mode_id': mode_id}
                request = b'ABCD' + codec.encode('CSRoomMatchStartAllocReq', {
                    'mode_infos': [mode], 'is_add_member': False, 'group_id': 0},
                    sequence=17)
                frame = _candidate_local_match_alloc_response(
                    request, key, header_word4=12, header_word9=17,
                    game_server_probe=probe)
                response = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual(response.fields['result'], 1)
                with self.assertRaises(ValueError):
                    _candidate_local_match_prepare_probe(
                        backend, token, mode, key,
                        header_word4=12, header_word9=18)
                with self.assertRaises(ValueError):
                    _candidate_local_match_join_probe(
                        backend, token, mode, probe, key,
                        header_word4=12, header_word9=18)

    def test_solo_room_team_contains_selected_unlocked_operator(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('room_hero_test', 'separate-test-password')['session']
            backend.set_native_selected_hero(token, 88000000047)
            player_id = int(backend.native_identity(token)['native_id'])
            request = b'ABCD' + codec.encode('CSMatchRoomGetSolRoomTeamTReq',
                                             {'room_id': player_id}, sequence=20)
            mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 2}
            with patch('dfserver.handshake_diagnostic.time.time',
                       return_value=1790748343.75):
                frame = _candidate_local_solo_room_team_response(
                    request, backend, token, mode, key,
                    header_word4=12, header_word9=20)
            reply = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(reply.fields['result'], 0)
            self.assertEqual(int(reply.fields['room_id']), player_id)
            self.assertEqual(int(reply.fields['room_start_time']), 1790748343)
            # Reproduce the native panel's deadline subtraction, rather
            # than only checking that the serialized times are positive.
            self.assertEqual(int(reply.fields['stage_end_time']) - 8 -
                             int(reply.fields['room_start_time']), 10)
            self.assertEqual(len(reply.fields['player_info_array']), 1)
            player = reply.fields['player_info_array'][0]
            self.assertEqual(int(player['player_id']), player_id)
            self.assertEqual(int(player['hero_info']['hero_id']), 88000000047)
            self.assertEqual(int(player['pre_selected_hero_id']), 88000000047)
            self.assertTrue(player['hero_info']['can_use'])
            self.assertTrue(player['hero_info']['is_unlock'])
            for bad_mode in (None, {'game_mode': 1, 'match_mode_id': 31100003}):
                denied = _candidate_local_solo_room_team_response(
                    request, backend, token, bad_mode, key,
                    header_word4=12, header_word9=21)
                decoded = codec.decode(decode_data_frame(
                    denied, key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual(decoded.fields['result'], 1)

    def test_lobby_sol_selection_is_the_room_operator_even_after_mp_selection(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('lobby_room_link', 'separate-test-password')['session']
            for sequence, mode, hero_id in ((10, 1, 88000000035),
                                            (11, 2, 88000000047)):
                request = b'ABCD' + codec.encode('CSHeroSelectHeroReq',
                    {'hero_id': hero_id, 'mode': mode}, sequence=sequence)
                frame = _candidate_local_hero_select_response(
                    request, backend, token, key,
                    header_word4=12, header_word9=sequence)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client',
                    compression_method=1, max_output=1024 * 1024).messages[0])
                self.assertEqual(reply.fields['result'], 0)
            profile = backend.native_lobby_profile(token)
            self.assertEqual(profile['selected_hero_id'], 88000000035)
            self.assertEqual(profile['selected_mp_hero_id'], 88000000047)
            load = b'ABCD' + codec.encode('CSHeroLoadHeroListReq', {}, sequence=12)
            frame = _candidate_local_hero_response(
                load, backend, token, key, header_word4=12, header_word9=12)
            loaded = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1, max_output=1024 * 1024).messages[0])
            self.assertEqual(int(loaded.fields['sol_hero_selected']), 88000000035)
            self.assertEqual(int(loaded.fields['mp_hero_selected']), 88000000047)
            player_id = int(backend.native_identity(token)['native_id'])
            room = b'ABCD' + codec.encode('CSMatchRoomGetSolRoomTeamTReq',
                {'room_id': player_id}, sequence=13)
            frame = _candidate_local_solo_room_team_response(
                room, backend, token,
                {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 2}, key,
                header_word4=12, header_word9=13)
            reply = codec.decode(decode_data_frame(
                frame, key, direction='server_to_client',
                compression_method=1, max_output=1024 * 1024).messages[0])
            self.assertEqual(int(reply.fields['player_info_array'][0]
                                  ['hero_info']['hero_id']), 88000000035)

    def test_room_hero_selection_updates_lobby_and_room_notice(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('room_change_link', 'separate-test-password')['session']
            backend.set_native_selected_hero(token, 88000000035)
            player_id = int(backend.native_identity(token)['native_id'])
            mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 2}
            preview = b'ABCD' + codec.encode('CSMatchRoomSetPreSelectedHeroTReq',
                {'room_id': player_id, 'pre_selected_hero_id': 88000000047},
                sequence=30)
            response, notification = _candidate_local_solo_room_hero_response(
                preview, backend, token, mode, key, header_word4=12, header_word9=30)
            decoded = codec.decode(decode_data_frame(
                response, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(decoded.fields['result'], 0)
            self.assertEqual(backend.native_lobby_profile(token)['selected_hero_id'],
                             88000000035)
            notice = codec.decode(decode_data_frame(
                notification, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(int(notice.fields['pre_selected_hero_id']), 88000000047)
            self.assertEqual(int(notice.fields['hero_info']['hero_id']), 88000000035)
            clear_preview = b'ABCD' + codec.encode(
                'CSMatchRoomSetPreSelectedHeroTReq',
                {'room_id': player_id, 'pre_selected_hero_id': 0}, sequence=30)
            clear_response, clear_notice = _candidate_local_solo_room_hero_response(
                clear_preview, backend, token, mode, key,
                header_word4=12, header_word9=30)
            self.assertEqual(codec.decode(decode_data_frame(
                clear_response, key, direction='server_to_client',
                compression_method=1).messages[0]).fields['result'], 0)
            self.assertEqual(int(codec.decode(decode_data_frame(
                clear_notice, key, direction='server_to_client',
                compression_method=1).messages[0]).fields['pre_selected_hero_id']), 0)
            select = b'ABCD' + codec.encode('CSMatchRoomSetSolRoomHeroTReq',
                {'room_id': player_id, 'hero_id': 88000000047}, sequence=31)
            response, notification = _candidate_local_solo_room_hero_response(
                select, backend, token, mode, key, header_word4=12, header_word9=31)
            decoded = codec.decode(decode_data_frame(
                response, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(decoded.fields['result'], 0)
            self.assertEqual(backend.native_lobby_profile(token)['selected_hero_id'],
                             88000000047)
            notice = codec.decode(decode_data_frame(
                notification, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(int(notice.fields['hero_info']['hero_id']), 88000000047)
            lock = b'ABCD' + codec.encode('CSMatchRoomLockSelectedHeroTReq',
                {'room_id': player_id, 'hero_id': 88000000047,
                 'random_hero': False}, sequence=32)
            response, notification = _candidate_local_solo_room_hero_response(
                lock, backend, token, mode, key, header_word4=12, header_word9=32)
            decoded = codec.decode(decode_data_frame(
                response, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(decoded.fields['result'], 0)
            ready = codec.decode(decode_data_frame(
                notification, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(ready.name, 'CSMatchRoomSolReadyNtf')
            self.assertEqual(int(ready.fields['player_id']), player_id)
            auto = b'ABCD' + codec.encode('CSMatchRoomSetSolRoomHeroTReq',
                {'room_id': player_id, 'hero_id': 0, 'random_hero': True},
                sequence=33)
            response, notification = _candidate_local_solo_room_hero_response(
                auto, backend, token, mode, key, header_word4=12, header_word9=33)
            decoded = codec.decode(decode_data_frame(
                response, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(decoded.fields['result'], 0)
            self.assertEqual(backend.native_lobby_profile(token)['selected_hero_id'],
                             88000000047)
            response, notification = _candidate_local_solo_room_hero_response(
                select, backend, token,
                {'game_mode': 1, 'match_mode_id': 31100003}, key,
                header_word4=12, header_word9=32)
            decoded = codec.decode(decode_data_frame(
                response, key, direction='server_to_client',
                compression_method=1).messages[0])
            self.assertEqual(decoded.fields['result'], 1)
            self.assertIsNone(notification)

    def test_solo_panel_ready_acknowledges_only_the_allocated_room(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('solo_ready', 'separate-test-password')['session']
            player_id = int(backend.native_identity(token)['native_id'])
            mode = {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 142201103}
            for room_id, requested_mode, expected in (
                    (player_id, mode, 0), (player_id + 1, mode, 1),
                    (player_id, None, 1),
                    (player_id, {'game_mode': 1, 'map_id': 2201, 'match_mode_id': 31100003}, 1)):
                request = b'ABCD' + codec.encode('CSMatchRoomSolReadyTReq',
                                                 {'room_id': room_id}, sequence=40)
                frame, notice = _candidate_local_solo_room_ready_response(
                    request, backend, token, requested_mode, key,
                    header_word4=12, header_word9=50)
                reply = codec.decode(decode_data_frame(
                    frame, key, direction='server_to_client',
                    compression_method=1).messages[0])
                self.assertEqual((reply.name, reply.sequence, reply.fields['result']),
                                 ('CSMatchRoomSolReadyTRes', 40, expected))
                if expected:
                    self.assertIsNone(notice)
                else:
                    ready = codec.decode(decode_data_frame(
                        notice, key, direction='server_to_client',
                        compression_method=1).messages[0])
                    self.assertEqual(ready.name, 'CSMatchRoomSolReadyNtf')
                    self.assertEqual(int(ready.fields['room_id']), player_id)
                    self.assertEqual(int(ready.fields['player_id']), player_id)
                    self.assertEqual(notice.header_word9, frame.header_word9 + 1)

    def test_map_selection_rank_gate_has_a_matching_response(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        request = b'ABCD' + codec.encode('CSMatchGateIsRankEnableReq', {
            'mode_info': {'game_mode': 1, 'game_rule': 4, 'sub_mode': 10,
                          'team_mode': 3, 'map_id': 1, 'match_mode_id': 1},
        }, sequence=43)
        frame = _candidate_local_match_rank_response(
            request, key, header_word4=12, header_word9=43)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual((reply.name, reply.sequence),
                         ('CSMatchGateIsRankEnableRes', 43))
        self.assertEqual(reply.fields['result'], 0)
        self.assertTrue(reply.fields['is_rank_enable'])

    def test_candidate_state_reply_keeps_local_player_online_for_entry(self):
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
        # Independent client predicate: common_pb declares Online=1, and
        # AccountServer.IsInIdle uses State & Online before StartMatch invokes
        # the preparation flow event. A successful reply with State=0 regresses
        # the local player to Offline even while the authenticated socket lives.
        self.assertTrue(reply.fields['State'] & 1)
        self.assertFalse(reply.fields['State'] & 2)  # No active gameplay session yet.

    def test_heartbeat_clock_and_room_deadline_share_unix_seconds(self):
        codec = _candidate_codec()
        key = b'0123456789abcdef'
        request = codec.encode('CSOnlineHeartbeatReq', {'padding': 23}, sequence=10)
        with patch('dfserver.handshake_diagnostic.time.time',
                   return_value=1790748343.75), \
                patch('dfserver.handshake_diagnostic.time.monotonic',
                      return_value=12096.078):
            frame = _candidate_local_heartbeat_response(
                b'ABCD' + request, key, header_word4=12, header_word9=7)
        reply = codec.decode(decode_data_frame(
            frame, key, direction='server_to_client',
            compression_method=1).messages[0])
        server_time = int(reply.fields['tick_count'])
        self.assertEqual(server_time, 1790748343)
        # Actual normal-client stage deadline from the Zero Dam trace:
        # ClockManager consumes tick_count without a unit conversion.
        self.assertEqual(1790748361 - 8 - server_time, 10)

    def test_native_solo_ready_handoff_follows_the_countdown_request_once(self):
        codec = _candidate_codec()
        root = Path(__file__).resolve().parent.parent
        key = hashlib.md5(b'\x12').digest()
        with tempfile.TemporaryDirectory() as temporary, patch.dict('os.environ', {
                'DF_LOCAL_DS_JOIN_PROBE_AFTER_READY': '1',
                'DF_LOCAL_DS_JOIN_PROBE_AFTER_HERO_LOCK': '0',
                'DF_LOCAL_DS_MAP_ID': '2201'}):
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('ready_wire', 'separate-test-password')['session']
            backend.register_game_nick(token, 'ReadyPilot')
            identity = dict(backend.native_identity(token), token=token)
            player_id = int(identity['native_id'])
            client, server = socket.socketpair()
            results, progress = [], []
            probe = SimpleNamespace(listening=True, port=47993)
            worker = threading.Thread(target=lambda: results.append(
                inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                                 expected_identity=identity, response_probe=True,
                                 ready_probe=True, auth_identity_probe=True,
                                 business_login_probe=True, business_bootstrap_probe=True,
                                 backend=backend, local_session=token,
                                 game_server_probe=probe,
                                 progress_callback=lambda **values: progress.append(values))))
            decoder, pending = StreamDecoder(), []
            def receive():
                while not pending:
                    pending.extend(decoder.feed(client.recv(4096)))
                return pending.pop(0)
            def decoded(frame):
                message = decode_data_frame(frame, key, direction='server_to_client',
                                            compression_method=1).messages[0]
                envelope = parse_business_envelope(message)
                return envelope.header['name'], message
            def send(name, fields, sequence):
                request = (sequence + 2).to_bytes(4, 'big') + codec.encode(
                    name, fields, sequence=sequence)
                client.sendall(encode_data_frame(
                    (request,), key, direction='client_to_server',
                    header_word4=12, header_word9=sequence + 2).encode())
            try:
                client.settimeout(3)
                worker.start()
                client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                     b'\x03\x00\x01\x12' + bytes(64) + b'\x03', b'').encode())
                receive()
                auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
                client.sendall(Frame(11, 12, 0x2001, 0, 2, b'',
                                     encrypt_body(auth.encode(), key)).encode())
                receive(); receive()
                send('CSAccountLoginReq', {}, 1)
                self.assertEqual(decoded(receive())[0], 'CSAccountLoginRes')
                send('CSStateGetInfoReq', {}, 2)
                self.assertEqual(decoded(receive())[0], 'CSStateGetInfoRes')
                mode = {'game_mode': 1, 'game_rule': 4, 'sub_mode': 10,
                        'team_mode': 3, 'map_id': 2201, 'match_mode_id': 142201103}
                send('CSRoomMatchStartAllocReq', {'mode_infos': [mode]}, 3)
                self.assertEqual(decoded(receive())[0], 'CSRoomMatchStartAllocRes')
                send('CSMatchCheckTReq', {'node_id': ''}, 4)
                self.assertEqual([decoded(receive())[0] for _ in range(2)],
                                 ['CSMatchCheckTRes', 'CSPrepareJoinMatchNtf'])
                send('CSMatchRoomSolReadyTReq', {'room_id': player_id + 1}, 5)
                name, message = decoded(receive())
                self.assertEqual(name, 'CSMatchRoomSolReadyTRes')
                self.assertEqual(codec.decode(message).fields['result'], 1)
                send('CSMatchRoomSolReadyTReq', {'room_id': player_id}, 6)
                frames = [receive() for _ in range(3)]
                self.assertEqual([decoded(frame)[0] for frame in frames],
                                 ['CSMatchRoomSolReadyTRes', 'CSMatchRoomSolReadyNtf',
                                  'CSPlayerJoinMatchNtf'])
                self.assertEqual([frame.header_word9 for frame in frames],
                                 list(range(frames[0].header_word9,
                                            frames[0].header_word9 + 3)))
                # Repeating ready must not start another DS connection.
                send('CSMatchRoomSolReadyTReq', {'room_id': player_id}, 7)
                self.assertEqual([decoded(receive())[0] for _ in range(2)],
                                 ['CSMatchRoomSolReadyTRes', 'CSMatchRoomSolReadyNtf'])
                send('CSOnlineHeartbeatReq', {'padding': 11}, 8)
                self.assertEqual(decoded(receive())[0], 'CSOnlineHeartbeatRes')
                client.shutdown(socket.SHUT_WR)
                worker.join(4)
                self.assertFalse(worker.is_alive())
                entries = results[0]['bounded_business_continuation']
                self.assertEqual(sum(bool(row.get('local_game_server_join_probe_sent'))
                                     for row in entries), 1)
                self.assertEqual(progress[-1]['latest_match_handoff']['trigger_request'],
                                 'CSMatchRoomSolReadyTReq')
                self.assertEqual(progress[-1]['latest_match_handoff']['map_id'], 2201)
            finally:
                client.close(); server.close(); worker.join(4)

    def test_reconnected_guide_first_flow_can_allocate_and_join_the_local_match(self):
        codec = _candidate_codec()
        root = Path(__file__).resolve().parent.parent
        key = hashlib.md5(b'\x12').digest()
        with tempfile.TemporaryDirectory() as temporary, patch.dict('os.environ', {
                'DF_LOCAL_DS_JOIN_PROBE_AFTER_READY': '1',
                'DF_LOCAL_DS_JOIN_PROBE_AFTER_HERO_LOCK': '0',
                'DF_LOCAL_DS_MAP_ID': '2201'}):
            backend = Backend(Path(temporary) / 'save.sqlite3', root / 'definitions.json')
            token = backend.register('reconnect_wire', 'separate-test-password')['session']
            backend.register_game_nick(token, 'ReconnectPilot')
            identity = dict(backend.native_identity(token), token=token)
            client, server = socket.socketpair()
            results, progress = [], []
            worker = threading.Thread(target=lambda: results.append(
                inspect_exchange(server, timeout=3, diagnostic_exponent_one=True,
                                 expected_identity=identity, response_probe=True,
                                 ready_probe=True, auth_identity_probe=True,
                                 business_login_probe=True, business_bootstrap_probe=True,
                                 backend=backend, local_session=token,
                                 game_server_probe=SimpleNamespace(listening=True, port=47993),
                                 progress_callback=lambda **values: progress.append(values))))
            decoder, pending = StreamDecoder(), []
            def receive():
                while not pending:
                    chunk = client.recv(4096)
                    self.assertTrue(chunk, 'Connection closed before a reply')
                    pending.extend(decoder.feed(chunk))
                return pending.pop(0)
            def send(name, fields, sequence):
                message = (sequence+2).to_bytes(4, 'big') + codec.encode(name, fields, sequence=sequence)
                client.sendall(encode_data_frame((message,), key, direction='client_to_server',
                                                header_word4=12, header_word9=sequence+2).encode())
            def reply():
                return codec.decode(decode_data_frame(receive(), key, direction='server_to_client',
                                                     compression_method=1).messages[0])
            try:
                client.settimeout(3)
                worker.start()
                client.sendall(Frame(11, 12, 0x1001, 0, 1,
                                     b'\x03\x00\x01\x12'+bytes(64)+b'\x03', b'').encode())
                self.assertEqual(receive().command, 0x1002)
                auth = AuthRequest(0x1000, b'QQ', token.encode(), b'')
                client.sendall(Frame(11, 12, 0x2001, 0, 2, b'', encrypt_body(auth.encode(), key)).encode())
                self.assertEqual([receive().command, receive().command], [0x2002, 0x6002])
                # This is the observed reconnect's first request; no fresh LoginReq follows.
                send('CSGuideSetDataReq', {}, 1)
                guide = reply()
                self.assertEqual((guide.name, guide.fields['result']),
                                 ('CSGuideSetDataRes', 0))
                send('CSOnlineHeartbeatReq', {'padding': 9}, 2)
                self.assertEqual(reply().name, 'CSOnlineHeartbeatRes')
                mode = {'game_mode': 1, 'game_rule': 4, 'sub_mode': 10,
                        'team_mode': 3, 'map_id': 2201, 'match_mode_id': 142201103}
                send('CSRoomMatchStartAllocReq', {'mode_infos': [mode]}, 3)
                allocated = reply()
                self.assertEqual((allocated.name, allocated.fields['result']), ('CSRoomMatchStartAllocRes', 0))
                send('CSMatchCheckTReq', {'node_id': ''}, 4)
                self.assertEqual([reply().name, reply().name], ['CSMatchCheckTRes', 'CSPrepareJoinMatchNtf'])
                send('CSMatchRoomSolReadyTReq', {'room_id': identity['native_id']}, 5)
                notices = [parse_business_envelope(decode_data_frame(
                    receive(), key, direction='server_to_client',
                    compression_method=1).messages[0]).header['name'] for _ in range(3)]
                self.assertEqual(notices,
                                 ['CSMatchRoomSolReadyTRes', 'CSMatchRoomSolReadyNtf', 'CSPlayerJoinMatchNtf'])
                client.shutdown(socket.SHUT_WR)
                worker.join(4)
                self.assertFalse(worker.is_alive())
                self.assertEqual(results[0]['business_login_probe_result'], 'authenticated_followup_without_login')
                self.assertEqual(sum(bool(row.get('local_game_server_join_probe_sent'))
                                     for row in results[0]['registration_continuation']), 1)
                self.assertEqual(progress[-1]['latest_match_handoff']['map_id'], 2201)
                self.assertNotIn(token, str(results))
            finally:
                client.close(); server.close(); worker.join(4)


if __name__ == '__main__':
    unittest.main()
