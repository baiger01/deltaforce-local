import struct
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dfserver import handshake_diagnostic as wire
from dfserver.client_errors import error_code
from dfserver.gcp_data import decode_data_frame
from dfserver.core import Backend


class NativeActivityWireTests(unittest.TestCase):
    def fixture(self, *, production=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        backend = Backend(Path(directory.name) / 'save.sqlite3', Path(__file__).resolve().parent.parent / 'definitions.json')
        token = backend.register('activity', 'local-password-123')['session']
        backend.set_native_lobby_profile(token, level=60 if production else 1, currencies={}, props=[
            {'gid': 7001, 'template_id': 15020010028, 'quantity': 3, 'grid_page_id': 2,
             'x': 0, 'y': 0, 'length': 1, 'width': 1},
            {'gid': 7002, 'template_id': 15080050023, 'quantity': 1, 'grid_page_id': 2,
             'x': 1, 'y': 0, 'length': 1, 'width': 1}] if production else [])
        if production:
            backend.set_native_lobby_devices(token, {1007: 1})
        from types import SimpleNamespace
        return SimpleNamespace(backend=backend, token=token, codec=wire._candidate_codec())

    def transact(self, fixture, name, fields):
        key = bytes(range(16))
        request = struct.pack('<I', 0) + fixture.codec.encode(name, fields, sequence=451)
        entry = {}
        response = wire._candidate_local_activity_response(request, fixture.backend, fixture.token, key,
            header_word4=17, header_word9=81, diagnostic_entry=entry)
        frames = wire._candidate_local_activity_response_frames(response, key, entry)
        decoded = [fixture.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                                                         compression_method=1, max_output=1024 * 1024).messages[0])
                   for frame in frames]
        self.assertEqual([frame.header_word9 for frame in frames], list(range(81, 81 + len(frames))))
        self.assertEqual(decoded[-1].sequence, 451)
        self.assertNotIn('_local_activity_changes', entry)
        return decoded, entry

    def reward_frames(self, changes, *, result=0):
        codec, key = wire._candidate_codec(), bytes(range(16))
        callback = codec.encode('CSQuestGetRewardRes', {
            'result': result, 'quest_id': 11001, 'quest_state': 7}, sequence=451)
        response = wire.encode_data_frame((callback,), key, direction='server_to_client',
            opaque_flag=64, header_word4=17, header_word9=81)
        entry = {'_local_activity_changes': changes}
        frames = wire._candidate_local_activity_response_frames(response, key, entry)
        messages = [codec.decode(decode_data_frame(frame, key, direction='server_to_client',
            compression_method=1).messages[0]) for frame in frames]
        self.assertEqual([frame.header_word9 for frame in frames], list(range(81, 81 + len(frames))))
        self.assertEqual([message.sequence for message in messages], [0] * (len(messages) - 1) + [451])
        self.assertNotIn('_local_activity_changes', entry)
        return messages

    def test_quest_notification_precedes_accept_callback_and_reconnect_restores(self):
        fixture = self.fixture()
        messages, entry = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 11001})
        self.assertEqual([message.name for message in messages], ['CSQuestDataChangeNtf', 'CSQuestAcceptRes'])
        self.assertEqual(int(messages[0].fields['player_quests'][0]['quest_state']), 3)
        self.assertEqual(entry['local_activity_request'], {'quest_id': 11001})
        messages, _ = self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        saved = next(row for row in messages[0].fields['player_quests'] if int(row['quest_id']) == 11001)
        self.assertEqual(int(saved['quest_state']), 3)

    def test_source_quest_experience_levels_profile_and_notification_together(self):
        fixture = self.fixture()
        from dfserver import native_safehouse_progress as facilities
        costs = facilities._pairs(facilities.UPGRADES[(1010, 2)]['ItemList'])
        props = []
        for ident, count in costs.items():
            metadata = facilities.ITEMS[str(ident)]
            if metadata['is_currency']:
                continue
            for _ in range(count):
                index = len(props)
                props.append({'gid': 8000 + index, 'template_id': ident, 'quantity': 1,
                    'grid_page_id': 2, 'x': (index % 3) * 3, 'y': (index // 3) * 3,
                    'length': metadata['length'], 'width': metadata['width']})
        fixture.backend.set_native_lobby_profile(fixture.token, level=1,
            currencies={17020000010: 1000000}, props=props)
        submitted, _ = self.transact(fixture, 'CSSafehouseSubmitUpgradePropReq', {'device_id': 1010,
            'submit_prop_list': [{'id': row['template_id'], 'gid': row['gid'], 'num': 1, 'position': 2}
                                 for row in props]})
        self.assertEqual(int(submitted[-1].fields['result']), 0)
        path = fixture.backend.database.parent / 'completion.json'
        path.write_text(json.dumps({'enabled': True, 'complete_all': False,
            'complete_quest_ids': [11001, 21001, 49001, 11002, 11003, 21002]}), encoding='utf-8')
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json', quest_completion_config=path)
        self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        expected = [(11001, 1, 1200, 2000), (21001, 2, 400, 2500), (49001, 3, 300, 3100),
                    (11002, 3, 1600, 3100), (11003, 3, 2900, 3100), (21002, 4, 1000, 3700)]
        for quest_id, level, exp, next_exp in expected:
            messages, entry = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': quest_id})
            self.assertEqual(int(messages[-1].fields['result']), 0)
            notification = next(message.fields for message in messages
                                if message.name == 'CSAccountExpChangeNtf')
            self.assertEqual(int(notification['source']), 0)
            self.assertNotIn('account_change', notification)
            current = notification['change']
            self.assertEqual(tuple(int(current[name]) for name in ('level', 'exp', 'next_level_exp')),
                             (level, exp, next_exp))
            self.assertEqual(fixture.backend.native_lobby_profile(fixture.token)['level'], level)
            identity = fixture.backend.native_identity(fixture.token)
            self.assertEqual(int(notification['player_id']), identity['native_id'])
            request = struct.pack('<I', 0) + fixture.codec.encode('CSAccountGetPlayerProfileReq', {}, sequence=33)
            frame = wire._candidate_local_account_state_response(request, fixture.backend, fixture.token,
                identity, bytes(range(16)), header_word4=17, header_word9=81)
            profile = fixture.codec.decode(decode_data_frame(frame, bytes(range(16)),
                direction='server_to_client', compression_method=1).messages[0]).fields
            self.assertEqual(tuple(int(profile[name]) for name in ('level', 'exp', 'next_level_exp')),
                             (level, exp, next_exp))
            self.assertEqual((int(profile['account_level']), int(profile['blast_level'])), (1, 1))
            if quest_id == 49001:
                rejected, _ = self.transact(fixture, 'CSSafehouseUpgradeReq', {'device_id': 1010})
                self.assertEqual(int(rejected[-1].fields['result']), error_code('SafehouseSeasonLevelConditionFail'))
        fixture.backend = Backend(fixture.backend.database, Path(__file__).resolve().parent.parent / 'definitions.json')
        repeated, _ = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': 49001})
        self.assertEqual(len(repeated), 1)
        self.assertNotEqual(int(repeated[0].fields['result']), 0)
        with fixture.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT earned_exp FROM native_lobby_action_progress').fetchone()[0], 8600)
        with patch.object(facilities.time, 'time', return_value=10000000):
            upgraded, _ = self.transact(fixture, 'CSSafehouseUpgradeReq', {'device_id': 1010})
        self.assertEqual(int(upgraded[-1].fields['result']), 0)
        with fixture.backend.connection() as connection:
            upgrade = connection.execute('SELECT * FROM native_lobby_safehouse_upgrades WHERE device_id=1010').fetchone()
            self.assertEqual((upgrade['target_level'], upgrade['end_time'] - upgrade['start_time']), (2, 1))


    def test_actual_watch_reward_notifies_collection_and_hero_before_claim_callback(self):
        fixture = self.fixture()
        path = fixture.backend.database.parent / 'completion.json'
        path.write_text(json.dumps({'enabled': True, 'complete_all': False,
                                  'complete_quest_ids': [41907]}), encoding='utf-8')
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json', quest_completion_config=path)
        self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        messages, entry = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': 41907})
        names = [message.name for message in messages]
        self.assertEqual(names[-2:], ['CSQuestDataChangeNtf', 'CSQuestGetRewardRes'])
        self.assertIn('CSCollectionPropChangeNtf', names)
        self.assertIn('CSHeroUnlockNtf', names)
        self.assertEqual(int(messages[-1].fields['result']), 0)
        heroes = next(message.fields['heros'] for message in messages if message.name == 'CSHeroUnlockNtf')
        self.assertTrue(heroes)
        for hero in heroes:
            watch = next(row for row in hero['accessories'] if int(row['item']['prop_id']) == 38070040001)
            self.assertTrue(watch['is_unlock'])
        repeated, _ = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': 41907})
        self.assertEqual(len(repeated), 1)
        self.assertNotEqual(int(repeated[0].fields['result']), 0)

    def test_production_consumption_notification_and_query_use_same_persisted_line(self):
        fixture = self.fixture(production=True)
        with patch('dfserver.native_safehouse.time.time', return_value=10000000):
            messages, entry = self.transact(fixture, 'CSSafehouseProduceReq', {
                'device_id': 1007, 'formula_id': 372830001, 'mobile_push_token': 'must-not-be-logged'})
        self.assertEqual([message.name for message in messages], ['CSDepositChangeNtf', 'CSSafehouseProduceRes'])
        self.assertEqual(entry['local_activity_request'], {'device_id': 1007, 'formula_id': 372830001})
        self.assertEqual(len(messages[0].fields['deposit_change']['prop_changes']), 2)
        queried, _ = self.transact(fixture, 'CSSafehouseGetInfoReq', {})
        self.assertEqual(queried[0].fields['devices'][0]['produce_line'], messages[1].fields['produce_info'])

    def test_failed_acceptance_sends_no_success_notification(self):
        fixture = self.fixture()
        messages, entry = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 90001})
        self.assertEqual(len(messages), 1)
        self.assertNotEqual(int(messages[0].fields['result']), 0)
        self.assertEqual(entry['local_activity_result'], int(messages[0].fields['result']))
        self.assertTrue(entry['local_activity_error']['code'].startswith('Quest'))
        self.assertTrue(entry['local_activity_error']['message'])

    def test_map_preparation_queries_the_saved_accepted_mission(self):
        fixture = self.fixture()
        self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 11001})
        messages, entry = self.transact(fixture, 'CSQuestGetAcceptedQuestsReq', {
            'hero_id': 88000000025})
        self.assertEqual([message.name for message in messages], ['CSQuestGetAcceptedQuestsRes'])
        self.assertEqual(int(messages[0].fields['result']), 0)
        accepted = messages[0].fields['accepted_quests']
        self.assertEqual([int(row['quest_id']) for row in accepted], [11001])
        self.assertEqual(int(accepted[0]['quest_state']), 3)
        self.assertTrue(accepted[0]['quest_objectives'])
        self.assertEqual(entry['local_activity_result'], 0)
        self.assertEqual(entry['local_activity_accepted_quest_count'], 1)

    def test_department_branch_notification_and_map_preparation_share_saved_data(self):
        fixture = self.fixture(production=True)
        messages, entry = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 49001})
        self.assertEqual([message.name for message in messages], ['CSQuestDataChangeNtf', 'CSQuestAcceptRes'])
        self.assertEqual(entry['local_activity_result'], 0)
        saved = messages[0].fields['player_quests'][0]
        self.assertEqual(int(saved['quest_id']), 49001)
        self.assertEqual(int(saved['quest_state']), 3)
        self.assertEqual([int(row['quest_objective_id']) for row in saved['quest_objectives']], [4900101])
        messages, entry = self.transact(fixture, 'CSQuestGetAcceptedQuestsReq', {'hero_id': 88000000025})
        self.assertEqual([message.name for message in messages], ['CSQuestGetAcceptedQuestsRes'])
        self.assertEqual(messages[0].fields['accepted_quests'], [saved])
        self.assertEqual(entry['local_activity_result'], 0)
        self.assertEqual(entry['local_activity_accepted_quest_count'], 1)

    def test_wallet_condition_notifies_completion_without_currency_consumption(self):
        fixture = self.fixture(production=True)
        fixture.backend.set_native_lobby_profile(fixture.token, level=60,
            currencies={17020000010: 600000}, props=[])
        accepted, _ = self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 49001})
        self.assertEqual([message.name for message in accepted], ['CSQuestDataChangeNtf', 'CSQuestAcceptRes'])
        self.assertEqual(int(accepted[-1].fields['quest_state']), 6)
        objective = accepted[0].fields['player_quests'][0]['quest_objectives'][0]
        self.assertEqual(int(objective['value']), 600000)
        self.assertTrue(objective['has_completed'])
        fields = {'quest_id': 49001, 'submit_list': [{'obj_id': 4900101,
                  'submit_props': [{'id': 17020000010, 'num': 500000}]}]}
        messages, entry = self.transact(fixture, 'CSQuestSubmitPropReq', fields)
        self.assertEqual([message.name for message in messages], ['CSQuestSubmitPropRes'])
        self.assertNotEqual(entry['local_activity_result'], 0)
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json')
        with fixture.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE currency_id=17020000010').fetchone()[0], 600000)
        repeated, _ = self.transact(fixture, 'CSQuestSubmitPropReq', fields)
        self.assertEqual([message.name for message in repeated], ['CSQuestSubmitPropRes'])
        self.assertNotEqual(int(repeated[0].fields['result']), 0)

    def test_committed_wallet_change_refreshes_cash_before_nonquest_callback(self):
        from dfserver.premium_shop import currency_change
        fixture = self.fixture(production=True)
        fixture.backend.set_native_lobby_profile(fixture.token, level=60,
            currencies={17020000010: 499999}, props=[])
        self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 49001})
        with fixture.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            player_id = fixture.backend._authorize(connection, fixture.token)
            currency_change(connection, player_id, 17020000010, 1)
            connection.commit()
        key = bytes(range(16))
        callback = fixture.codec.encode('CSGetCurrencyRes', {'result': 0}, sequence=451)
        response = wire.encode_data_frame((callback,), key, direction='server_to_client',
            opaque_flag=64, header_word4=17, header_word9=81)
        entry = {}
        wire._candidate_local_wallet_quest_changes(response, key, fixture.backend, fixture.token,
                                                   entry, 'CSGetCurrencyReq')
        frames = wire._candidate_local_activity_response_frames(response, key, entry)
        messages = [fixture.codec.decode(decode_data_frame(frame, key,
            direction='server_to_client', compression_method=1).messages[0]) for frame in frames]
        self.assertEqual([row.name for row in messages], ['CSQuestDataChangeNtf', 'CSGetCurrencyRes'])
        self.assertEqual(int(messages[0].fields['player_quests'][0]['quest_state']), 6)
        self.assertEqual(int(messages[0].fields['quest_data_pre'][0]['quest_state']), 3)
        self.assertEqual(entry['local_wallet_quest_refresh_count'], 1)
        self.assertEqual([frame.header_word9 for frame in frames], [81, 82])
        with fixture.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies').fetchone()[0], 500000)
        entry = {}
        wire._candidate_local_wallet_quest_changes(response, key, fixture.backend, fixture.token,
                                                   entry, 'CSGetCurrencyReq')
        self.assertEqual(entry, {})

    def test_wallet_hook_does_not_decode_unrelated_activity_empty_protocol(self):
        from dfserver.business_envelope import parse_business_envelope
        fixture = self.fixture()
        key = bytes(range(16))
        request = b'ABCD' + fixture.codec.encode('CSActivityGetReq', {}, sequence=451)
        response = wire._candidate_local_lobby_critical_response(request, key,
            header_word4=17, header_word9=81)
        message = decode_data_frame(response, key, direction='server_to_client', compression_method=1).messages[0]
        decoded = fixture.codec.decode(message)
        self.assertEqual(decoded.name, 'CSActivityGetRes')
        self.assertEqual(int(decoded.fields['result']), 0)
        entry = {}
        with patch.object(wire, 'decode_data_frame', side_effect=AssertionError('Unrelated wallet decode')):
            wire._candidate_local_wallet_quest_changes(response, key, fixture.backend,
                                                       fixture.token, entry, 'CSActivityGetReq')
        self.assertEqual(entry, {})
        self.assertEqual(wire._candidate_local_activity_response_frames(response, key, entry), (response,))
        self.assertEqual(parse_business_envelope(message).header['name'], 'CSActivityGetRes')

    def test_wallet_hook_inspection_failure_keeps_committed_response_deliverable(self):
        fixture = self.fixture()
        with patch.object(wire, 'decode_data_frame', side_effect=ValueError('invalid response fixture')):
            entry = {}
            wire._candidate_local_wallet_quest_changes(None, bytes(range(16)), fixture.backend,
                                                       fixture.token, entry, 'CSGetCurrencyReq')
        self.assertEqual(entry['local_wallet_quest_error']['code'], 'ValueError')
        self.assertNotIn('_local_activity_changes', entry)

    def test_give_up_uses_native_res_field_and_clears_standing_without_spending(self):
        fixture = self.fixture(production=True)
        fixture.backend.set_native_lobby_profile(fixture.token, level=60,
            currencies={17020000010: 400000}, props=[])
        self.transact(fixture, 'CSQuestAcceptReq', {'quest_id': 49001})
        messages, entry = self.transact(fixture, 'CSQuestGiveUpReq', {'remove_quest_id': 49001})
        self.assertEqual([message.name for message in messages], ['CSQuestDataChangeNtf', 'CSQuestGiveUpRes'])
        self.assertEqual(messages[-1].fields, {'res': 0, 'remove_quest_id': '49001'})
        self.assertEqual(entry['local_activity_result'], 0)
        self.assertEqual(entry['local_activity_request'], {'remove_quest_id': 49001})
        reset = messages[0].fields['player_quests'][0]
        self.assertEqual(int(reset['quest_state']), 2)
        self.assertEqual(int(reset['quest_accept_time']), 0)
        self.assertEqual(int(reset['quest_objectives'][0]['value']), 0)
        self.assertFalse(reset['quest_objectives'][0]['has_completed'])
        with fixture.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT amount FROM native_lobby_currencies '
                'WHERE currency_id=17020000010').fetchone()[0], 400000)
        repeated, entry = self.transact(fixture, 'CSQuestGiveUpReq', {'remove_quest_id': 49001})
        self.assertEqual([message.name for message in repeated], ['CSQuestGiveUpRes'])
        self.assertNotEqual(int(repeated[0].fields['res']), 0)
        self.assertEqual(entry['local_activity_result'], int(repeated[0].fields['res']))
        unknown, _ = self.transact(fixture, 'CSQuestGiveUpReq', {'remove_quest_id': 2**64 - 1})
        self.assertNotEqual(int(unknown[0].fields['res']), 0)

    def test_committed_reward_changes_update_each_native_listener_before_callback(self):
        fixture = self.fixture(production=True)
        player_id = fixture.backend.native_identity(fixture.token)['native_id']
        prop = {**fixture.backend.native_lobby_profile(fixture.token)['props'][0],
                'bind_type': 0, 'bind_player': player_id}
        currency = {'currency_id': 17020000010, 'delta': 100, 'current_num': 200}
        collection = {'change_type': 1, 'delta': 1,
                      'prop': {'id': 28101250003, 'gid': 0, 'num': 2}}
        # Values exercise the wire contract; they do not define a reputation curve.
        quality = {'quality_id': 100002, 'old_rep_val': 0, 'old_rep_lvl': 1,
                   'new_rep_val': 1, 'new_rep_lvl': 1}
        messages = self.reward_frames({'inventory_moves': [{'before': None, 'after': prop}],
            'currency_changes': [currency], 'prop_changes': [collection],
            'quality_changes': [quality], 'quest_notification': {
                'player_quests': [{'quest_id': 11001, 'quest_state': 7}]}})
        self.assertEqual([message.name for message in messages], ['CSDepositChangeNtf',
            'CSCollectionPropChangeNtf', 'CSAttrQualityValueChangeNtf',
            'CSQuestDataChangeNtf', 'CSQuestGetRewardRes'])
        deposit = messages[0].fields['deposit_change']
        self.assertEqual(int(deposit['currency_changes'][0]['current_num']), currency['current_num'])
        self.assertEqual(int(deposit['prop_changes'][0]['prop']['bind_player']), player_id)
        changed = messages[1].fields['data_change'][0]
        self.assertEqual((int(changed['delta_num']), int(changed['after_num'])), (1, 2))
        self.assertEqual(int(changed['prop']['id']), collection['prop']['id'])
        self.assertEqual({name: int(messages[2].fields['change_list'][0][name])
                          for name in quality}, quality)

    def test_failed_callback_discards_any_staged_success_changes(self):
        messages = self.reward_frames({
            'currency_changes': [{'currency_id': 17020000010, 'delta': 100, 'current_num': 200}],
            'quest_notification': {'player_quests': [{'quest_id': 11001, 'quest_state': 7}]}},
            result=error_code('QuestNotCompleted'))
        self.assertEqual([message.name for message in messages], ['CSQuestGetRewardRes'])
        self.assertNotEqual(int(messages[0].fields['result']), 0)

    def test_department_queries_use_authenticated_activity_routing_and_nonempty_curve(self):
        from dfserver import native_department_queries as queries
        from test_native_departments import synthetic_curve_rows
        fixture = self.fixture()
        curve = queries.RepLevelCurve(synthetic_curve_rows())
        with patch.object(queries, 'reputation_curve', return_value=curve, create=True):
            messages, entry = self.transact(fixture, 'CSAttributeGetConfigReq', {})
            self.assertEqual([message.name for message in messages], ['CSAttributeGetConfigRes'])
            self.assertEqual(int(messages[0].fields['result']), 0)
            self.assertEqual(len(messages[0].fields['rep_level_configs']), curve.max_level)
            self.assertEqual(entry['local_department_max_level'], curve.max_level)
            messages, _ = self.transact(fixture, 'CSAttrGetAllQualityReq', {})
            self.assertEqual(len(messages[0].fields['all_quality']), 5)
            self.assertTrue(all(int(row['level']) == 1 for row in messages[0].fields['all_quality']))
            messages, _ = self.transact(fixture, 'CSGetRoleQualityConfigReq', {})
            self.assertEqual(len(messages[0].fields['configs']), 5)

    def test_safehouse_capability_query_requires_an_earned_source_level(self):
        fixture = self.fixture()
        fixture.backend.set_native_lobby_devices(fixture.token, {1011: 1})
        messages, entry = self.transact(fixture, 'CSSafehouseFuncIsUnlockReq', {'unlock_id': 15})
        self.assertEqual([message.name for message in messages], ['CSSafehouseFuncIsUnlockRes'])
        self.assertEqual(int(messages[0].fields['result']), 0)
        self.assertEqual(messages[0].fields.get('params', []), [])
        fixture.backend.set_native_lobby_devices(fixture.token, {1011: 2})
        messages, _ = self.transact(fixture, 'CSSafehouseFuncIsUnlockReq', {'unlock_id': 15})
        self.assertEqual(messages[0].fields['params'], [{'unlock_id': '15', 'params': ['2']}])
        messages, _ = self.transact(fixture, 'CSSafehouseFuncIsUnlockReq', {'unlock_id': 321})
        self.assertEqual(messages[0].fields.get('params', []), [])

    def test_actual_reward_notifies_quality_levels_and_requery_matches_after_restart(self):
        fixture = self.fixture(production=True)
        path = fixture.backend.database.parent / 'completion.json'
        path.write_text(json.dumps({'enabled': True, 'complete_all': False,
                                  'complete_quest_ids': [11001]}), encoding='utf-8')
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json', quest_completion_config=path)
        self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        with fixture.backend.connection() as connection:
            player_id = fixture.backend._authorize(connection, fixture.token)
            connection.execute('INSERT INTO native_lobby_department_values VALUES (?,?,?)',
                               (player_id, 100002, 19))
            connection.commit()
        messages, entry = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': 11001})
        quality = next(message for message in messages if message.name == 'CSAttrQualityValueChangeNtf')
        change = {key: int(value) for key, value in quality.fields['change_list'][0].items()}
        self.assertEqual(change, {'quality_id': 100002, 'old_rep_val': 19, 'old_rep_lvl': 1,
                                  'new_rep_val': 20, 'new_rep_lvl': 2})
        self.assertEqual(entry['local_activity_quality_changes'], [change])
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json')
        queried, _ = self.transact(fixture, 'CSAttrGetAllQualityReq', {})
        owned = next(row for row in queried[0].fields['all_quality'] if int(row['card_id']) == 100002)
        self.assertEqual((int(owned['level']), int(owned['quality_value'])), (2, 20))
        repeated, _ = self.transact(fixture, 'CSQuestGetRewardReq', {'quest_id': 11001})
        self.assertEqual(len(repeated), 1)
        self.assertNotEqual(int(repeated[0].fields['result']), 0)

    def test_initial_warehouse_projection_preserves_explicit_item_binding(self):
        fixture = self.fixture(production=True)
        fixture.backend.ensure_native_lobby_melee_collection(fixture.token)
        fixture.backend.ensure_native_lobby_safe_boxes(fixture.token)
        state = fixture.backend.native_lobby_profile(fixture.token)
        player_id = fixture.backend.native_identity(fixture.token)['native_id']
        state['props'][0].update({'bind_type': 0, 'bind_player': player_id})
        key = bytes(range(16))
        request = struct.pack('<I', 0) + fixture.codec.encode('CSDepositGetPropsReq', {}, sequence=451)
        with patch.object(fixture.backend, 'native_lobby_profile', return_value=state):
            response = wire._candidate_local_deposit_response(request, fixture.backend,
                fixture.token, key, header_word4=17, header_word9=81)
        decoded = fixture.codec.decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1).messages[0])
        prop = next(row for row in decoded.fields['grid_pages'][0]['props'] if int(row['gid']) == 7001)
        self.assertIn('bind_type', prop)
        self.assertIn('bind_player', prop)
        self.assertEqual(int(prop['bind_type']), 0)
        self.assertEqual(int(prop['bind_player']), player_id)
        unbound = next(row for row in decoded.fields['grid_pages'][0]['props'] if int(row['gid']) == 7002)
        self.assertNotIn('bind_player', unbound)

    def test_equipment_move_projection_preserves_explicit_item_binding(self):
        fixture = self.fixture(production=True)
        player_id = fixture.backend.native_identity(fixture.token)['native_id']
        before = {**fixture.backend.native_lobby_profile(fixture.token)['props'][0],
                  'bind_type': 0, 'bind_player': player_id}
        after = {**before, 'grid_page_id': wire.POCKET_POSITION, 'x': 1, 'y': 0}
        key = bytes(range(16))
        request = struct.pack('<I', 0) + fixture.codec.encode('CSDepositEquipPropReq', {
            'cmds': [{'prop_id': before['template_id'], 'prop_gid': before['gid'],
                      'target_pos': wire.POCKET_POSITION}]}, sequence=451)
        def move_props(token, commands, *, receipt):
            receipt['extension_pos_order'] = []
            return [{'before': before, 'after': after}]

        with patch.object(fixture.backend, 'native_lobby_move_props', side_effect=move_props):
            response = wire._candidate_local_equip_response(request, fixture.backend,
                fixture.token, key, header_word4=17, header_word9=81)
        decoded = fixture.codec.decode(decode_data_frame(response, key,
            direction='server_to_client', compression_method=1).messages[0])
        prop = decoded.fields['deposit_change']['prop_changes'][0]['prop']
        self.assertIn('bind_type', prop)
        self.assertIn('bind_player', prop)
        self.assertEqual((int(prop['bind_type']), int(prop['bind_player'])), (0, player_id))

    def test_configured_completion_notifies_once_before_query_and_records_count(self):
        fixture = self.fixture()
        config = fixture.backend.database.parent / 'completion.json'
        config.write_text(json.dumps({'enabled': True, 'complete_all': False,
                                     'complete_quest_ids': [11001]}), encoding='utf-8')
        fixture.backend = Backend(fixture.backend.database,
            Path(__file__).resolve().parent.parent / 'definitions.json', quest_completion_config=config)
        messages, entry = self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        self.assertEqual([message.name for message in messages], ['CSQuestDataChangeNtf', 'CSQuestGetPlayerDataRes'])
        completed = messages[0].fields['player_quests'][0]
        self.assertEqual(int(completed['quest_state']), 6)
        self.assertEqual(int(completed['quest_objectives'][0]['value']), 5)
        self.assertEqual(entry['local_activity_completion_override_count'], 1)
        messages, entry = self.transact(fixture, 'CSQuestGetPlayerDataReq', {})
        self.assertEqual([message.name for message in messages], ['CSQuestGetPlayerDataRes'])
        self.assertNotIn('local_activity_completion_override_count', entry)


if __name__ == '__main__':
    unittest.main()
