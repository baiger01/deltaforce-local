from pathlib import Path
import inspect
import json
import tempfile
import unittest
from unittest.mock import patch

from dfserver import native_safehouse
from dfserver.core import Backend
from dfserver.handshake_diagnostic import _candidate_codec


ROOT = Path(__file__).resolve().parent.parent


class SafehouseUpgradeContractTests(unittest.TestCase):
    def test_original_upgrade_and_material_submission_requests_have_handlers(self):
        self.assertTrue({'CSSafehouseUpgradeReq', 'CSSafehouseSubmitUpgradePropReq',
                         'CSSafehouseFuncIsUnlockReq'} <=
                        native_safehouse.SUPPORTED_REQUESTS)

    def test_failed_requests_accept_a_safe_diagnostic_sink(self):
        self.assertIn('diagnostic', inspect.signature(native_safehouse.response_fields).parameters)


class SafehouseProgressTests(unittest.TestCase):
    def setUp(self):
        from dfserver import native_safehouse_progress
        self.progress = native_safehouse_progress
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.backend = Backend(Path(self.directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('build-progress', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(self.token, level=60,
                                             currencies={17020000010: 1000000}, props=[])
        self.codec = _candidate_codec()
        with self.backend.connection() as connection:
            self.player_id = self.backend._authorize(connection, self.token)

    def request(self, name, fields=None, changes=None, *, now=10000000, curve=None, diagnostic=None):
        request = self.codec.decode(self.codec.encode(name, fields or {}, sequence=77))
        with patch.object(self.progress.time, 'time', return_value=now):
            result = native_safehouse.response_fields(request, self.backend, self.token,
                                                      changes=changes, curve=curve, diagnostic=diagnostic)
        self.assertIsNotNone(result, 'Original safehouse request has no account-backed handler')
        self.codec.decode(self.codec.response(request, result))
        return result

    def state(self):
        with self.backend.connection() as connection:
            return {table: [tuple(row) for row in connection.execute('SELECT * FROM ' + table +
                    ' WHERE player_id=? ORDER BY 1,2', (self.player_id,))]
                    for table in ('native_lobby_devices', 'native_lobby_currencies', 'native_lobby_props',
                                  'native_lobby_safehouse_accounts', 'native_lobby_safehouse_materials',
                                  'native_lobby_safehouse_upgrades', 'native_lobby_safehouse_upgrade_history',
                                  'native_lobby_safehouse_migrations')}

    def costs(self, device_id, level):
        row = self.progress.UPGRADES[(device_id, level)]
        props = []
        for ident, count in self.progress._pairs(row['ItemList']).items():
            metadata = native_safehouse.ITEMS[str(ident)]
            if metadata['is_currency']:
                continue
            for _ in range(count):
                index = len(props)
                props.append({'gid': 8000 + index, 'template_id': ident, 'quantity': 1,
                              'grid_page_id': 2, 'x': (index % 3) * 3, 'y': (index // 3) * 3,
                              'length': metadata['length'], 'width': metadata['width']})
        self.backend.set_native_lobby_profile(self.token, level=60,
                                             currencies={17020000010: 1000000}, props=props)
        return row, [{'id': prop['template_id'], 'gid': prop['gid'], 'num': prop['quantity'],
                      'position': prop['grid_page_id']} for prop in props]

    def submit_costs(self, device_id, level):
        row, entries = self.costs(device_id, level)
        if entries:
            result = self.request('CSSafehouseSubmitUpgradePropReq',
                                  {'device_id': device_id, 'submit_prop_list': entries})
            self.assertEqual(result['result'], 0)
        return row

    def test_fresh_profile_does_not_claim_original_intermediate_repair_unlock(self):
        changes = {}
        result = self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15}, changes)
        self.assertEqual(result, {'result': 0, 'params': []})
        self.assertEqual(changes, {})
        levels = {row[1]: row[2] for row in self.state()['native_lobby_devices']}
        self.assertEqual(levels, self.progress.initial_levels())
        self.assertNotIn(1011, levels)

    def test_original_repair_unlock_is_earned_only_after_durable_upgrade_finishes(self):
        self.backend.set_native_lobby_devices(self.token, {1011: 1})
        row = self.submit_costs(1011, 2)
        self.assertEqual(row['UnlockSystemList'], '21:2;15:2')
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1011})['result'], 0)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15},
                                     now=10000000 + row['Time'] - 1)['params'], [])
        result = self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15},
                              now=10000000 + row['Time'])
        self.assertEqual(result, {'result': 0, 'params': [{'unlock_id': 15, 'params': [2]}]})
        self.assertEqual(len(self.state()['native_lobby_safehouse_upgrade_history']), 1)
        self.assertEqual(self.state()['native_lobby_safehouse_upgrades'], [])
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15},
                                     now=10000001 + row['Time']), result)
        response = self.codec.decode(self.codec.encode('CSSafehouseFuncIsUnlockRes', result, sequence=77))
        self.assertEqual(response.fields['params'], [{'unlock_id': '15', 'params': ['2']}])

    def test_original_compound_and_earlier_level_grants_keep_source_parameter_tuples(self):
        self.backend.set_native_lobby_devices(self.token, {1001: 3, 1004: 1, 1013: 1})
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 1}),
                         {'result': 0, 'params': [{'unlock_id': 1, 'params': [1]}]})
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 14}),
                         {'result': 0, 'params': [{'unlock_id': 14, 'params': [2]},
                                                  {'unlock_id': 14, 'params': [4]}]})
        expected = [{'unlock_id': 8, 'params': value} for value in
                    ([5, 200410501], [1, 200410301], [2, 200410401],
                     [3, 200410231], [4, 200410241])]
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 8}),
                         {'result': 0, 'params': expected})

    def test_unknown_unlock_ids_do_not_echo_a_capability_or_change_saved_state(self):
        self.request('CSSafehouseGetInfoReq')
        before = self.state()
        for unlock_id in (0, -1, 321, 2**63 - 1):
            with self.subTest(unlock_id=unlock_id):
                changes = {}
                self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': unlock_id}, changes),
                                 {'result': 0, 'params': []})
                self.assertEqual(changes, {})
                self.assertEqual(self.state(), before)

    def test_unlocks_use_only_the_authorized_accounts_actual_device_levels(self):
        self.backend.set_native_lobby_devices(self.token, {1011: 2})
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15})['params'],
                         [{'unlock_id': 15, 'params': [2]}])
        self.token = self.backend.register('other-unlock-account', 'local-password-123')['session']
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 15})['params'], [])

    def test_unlock_query_does_not_interpret_an_out_of_range_saved_level(self):
        self.backend.set_native_lobby_devices(self.token, {1003: 7})
        before = self.state()
        self.assertEqual(self.request('CSSafehouseFuncIsUnlockReq', {'unlock_id': 13})['result'], 118079)
        self.assertEqual(self.state(), before)

    def test_fresh_profile_builds_only_original_free_immediate_first_rows(self):
        result = self.request('CSSafehouseGetInfoReq')
        self.assertEqual(result['result'], 0)
        levels = {row['device_id']: row['level'] for row in result['devices']}
        self.assertEqual(set(levels), self.progress.DEVICE_IDS)
        self.assertEqual({ident: level for ident, level in levels.items() if level}, self.progress.initial_levels())
        self.assertEqual((levels[1007], levels[1003], levels[1021]), (0, 0, 0))
        self.assertEqual((levels[1001], levels[1010], levels[1013]), (1, 1, 1))
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        self.assertEqual(self.request('CSSafehouseGetInfoReq'), result)

    def test_existing_profile_is_preserved_until_an_explicit_upgrade_or_migration(self):
        self.backend.set_native_lobby_devices(self.token, {1007: 2})
        self.assertEqual([(row['device_id'], row['level']) for row in
                          self.request('CSSafehouseGetInfoReq')['devices']], [(1007, 2)])
        self.assertEqual(self.state()['native_lobby_safehouse_accounts'], [])

    def test_partial_material_submit_persists_and_pays_currency_only_when_starting(self):
        row, entries = self.costs(1007, 1)
        changes = {}
        partial = self.request('CSSafehouseSubmitUpgradePropReq',
                               {'device_id': 1007, 'submit_prop_list': entries[:1]}, changes)
        self.assertEqual(partial['result'], 0)
        self.assertEqual(sum(item['curr_count'] for item in partial['upgrade_prop_list']), 1)
        self.assertEqual(changes['currency_changes'], [])
        self.assertEqual(len(changes['inventory_moves']), 1)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        queried = self.request('CSSafehouseGetInfoReq', {'device_id': 1007})['devices'][0]
        self.assertEqual(queried['upgrade_prop_list'], partial['upgrade_prop_list'])
        self.assertEqual(queried['level'], 0)
        before = self.state()
        failed_changes = {}
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007}, failed_changes)['result'], 118009)
        self.assertEqual(self.state(), before)
        self.assertEqual(failed_changes, {})
        self.assertEqual(self.request('CSSafehouseSubmitUpgradePropReq',
            {'device_id': 1007, 'submit_prop_list': entries[1:]})['result'], 0)
        changes = {}
        started = self.request('CSSafehouseUpgradeReq', {'device_id': 1007}, changes)
        self.assertEqual(started['result'], 0)
        self.assertEqual((started['device']['level'], started['device']['upgrade_level'],
                          started['device']['upgrade_end_time']), (0, 1, 10000000 + row['Time']))
        self.assertEqual(changes['currency_changes'],
                         [{'currency_id': 17020000010, 'delta': -4000, 'current_num': 996000}])
        before = self.state()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007})['result'], 118019)
        self.assertEqual(self.state(), before)
        self.backend = Backend(self.backend.database, ROOT / 'definitions.json')
        completed = self.request('CSSafehouseGetInfoReq', {'device_id': 1007}, now=10000001)['devices'][0]
        self.assertEqual((completed['level'], completed['upgrade_end_time']), (1, 0))
        self.assertEqual(len(self.state()['native_lobby_safehouse_upgrade_history']), 1)
        final = self.state()
        self.request('CSSafehouseGetInfoReq', {'device_id': 1007}, now=10000002)
        self.assertEqual(self.state(), final)

    def test_duplicate_wrong_currency_overcount_and_foreign_instances_roll_back(self):
        _, entries = self.costs(1007, 1)
        other = self.backend.register('other-build-progress', 'local-password-123')['session']
        self.backend.set_native_lobby_profile(other, level=60, currencies={}, props=[
            {'gid': 9901, 'template_id': entries[0]['id'], 'quantity': 1, 'grid_page_id': 2,
             'x': 0, 'y': 0, 'length': 1, 'width': 1}])
        cases = ([entries[0], entries[0]], [{**entries[0], 'num': 2}],
                 [{**entries[0], 'id': entries[1]['id']}], [{**entries[0], 'gid': 9901}],
                 [{**entries[0], 'gid': 2**64 - 1}],
                 [{'id': 17020000010, 'gid': 0, 'num': 4000}])
        for entries_case in cases:
            with self.subTest(entries=entries_case):
                before, changes = self.state(), {}
                self.assertNotEqual(self.request('CSSafehouseSubmitUpgradePropReq',
                    {'device_id': 1007, 'submit_prop_list': entries_case}, changes)['result'], 0)
                self.assertEqual(self.state(), before)
                self.assertEqual(changes, {})

    def test_submit_database_failure_restores_materials_and_publishes_no_changes(self):
        _, entries = self.costs(1007, 1)
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER reject_submit BEFORE INSERT ON native_lobby_safehouse_materials "
                               "BEGIN SELECT RAISE(ABORT, 'diagnostic write failure'); END")
            connection.commit()
        before, changes, diagnostic = self.state(), {}, {}
        self.assertEqual(self.request('CSSafehouseSubmitUpgradePropReq',
            {'device_id': 1007, 'submit_prop_list': entries}, changes, diagnostic=diagnostic)['result'], 118002)
        self.assertEqual(self.state(), before)
        self.assertEqual(changes, {})
        self.assertEqual(diagnostic['local_activity_error']['code'], 'SafehouseSaveDBFail')
        self.assertNotIn('diagnostic write failure', json.dumps(diagnostic))

    def test_failed_safehouse_and_upgrade_diagnostics_omit_native_tokens_and_request_bodies(self):
        diagnostic = {}
        result = self.request('CSSafehouseProduceReq', {'device_id': 1007, 'formula_id': 372830001,
            'mobile_push_token': 'secret-native-push-token'}, diagnostic=diagnostic)
        self.assertEqual(result['result'], 118013)
        self.assertEqual(diagnostic['local_activity_error']['code'], 'SafehouseDeviceInfoNotFound')
        self.assertNotIn('secret-native-push-token', json.dumps(diagnostic))
        diagnostic = {}
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 99999},
                                     diagnostic=diagnostic)['result'], 118003)
        self.assertEqual(diagnostic['local_activity_error']['code'], 'SafehouseDeviceNotFound')
        self.assertNotIn('99999', json.dumps(diagnostic))

    def test_original_material_binding_predicate_accepts_bound_and_unbound_owned_instances(self):
        from dfserver import native_prop_bindings
        _, entries = self.costs(1007, 1)
        with self.backend.connection() as connection:
            native_prop_bindings.set_binding(connection, entries[0]['gid'], 0)
            native_prop_bindings.set_binding(connection, entries[1]['gid'], 1)
            connection.commit()
        result = self.request('CSSafehouseSubmitUpgradePropReq',
                              {'device_id': 1007, 'submit_prop_list': entries})
        self.assertEqual(result['result'], 0)
        with self.backend.connection() as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM native_lobby_prop_bindings').fetchone()[0], 0)

    def test_existing_production_survives_upgrade_start_and_pending_timer(self):
        self.backend.set_native_lobby_devices(self.token, {1007: 1})
        self.submit_costs(1007, 2)
        products = [{'prop_id': 37280300001, 'num': 180, 'bind_type': 0}]
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_safehouse_production VALUES (?,?,?,?,?,?,?)',
                               (self.player_id, 1007, 372830001, 10000000, 10027000,
                                json.dumps(products), '[]'))
            connection.commit()
        started = self.request('CSSafehouseUpgradeReq', {'device_id': 1007})
        self.assertEqual(started['result'], 0)
        self.assertEqual(started['device']['produce_line']['products'], products)
        queried = self.request('CSSafehouseGetInfoReq', {'device_id': 1007})['devices'][0]
        self.assertEqual(queried['produce_line'], started['device']['produce_line'])
        self.assertEqual(queried['upgrade_level'], 2)

    def test_original_current_level_production_can_start_during_an_independent_upgrade(self):
        self.backend.set_native_lobby_devices(self.token, {1007: 1})
        self.submit_costs(1007, 2)
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007})['result'], 0)
        self.backend.set_native_lobby_profile(self.token, level=60, currencies={}, props=[
            {'gid': 9901, 'template_id': 15020010028, 'quantity': 3, 'grid_page_id': 2,
             'x': 0, 'y': 0, 'length': 1, 'width': 1},
            {'gid': 9902, 'template_id': 15080050023, 'quantity': 1, 'grid_page_id': 2,
             'x': 1, 'y': 0, 'length': 1, 'width': 1}])
        produced = self.request('CSSafehouseProduceReq', {'device_id': 1007, 'formula_id': 372830001})
        self.assertEqual(produced['result'], 0)
        queried = self.request('CSSafehouseGetInfoReq', {'device_id': 1007})['devices'][0]
        self.assertEqual(queried['produce_line'], produced['produce_info'])
        self.assertEqual(queried['upgrade_level'], 2)

    def test_original_action_level_and_saved_balance_gate_do_not_lose_submitted_costs(self):
        self.submit_costs(1007, 1)
        for level, currency, code in ((14, 1000000, 118026), (15, 3999, 118009)):
            self.backend.set_native_lobby_profile(self.token, level=level,
                                                 currencies={17020000010: currency}, props=[])
            before, changes = self.state(), {}
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007}, changes)['result'], code)
            self.assertEqual(self.state(), before)
            self.assertEqual(changes, {})

    def test_original_warehouse_second_level_requires_action_level_materials_and_money(self):
        self.backend.set_native_lobby_devices(self.token, {1010: 1})
        row = self.submit_costs(1010, 2)
        self.assertEqual((row['SeasonLevel'], row['Time']), (4, 1))
        for level, funds, code in ((3, 1000000, 118026), (4, 4999, 118009)):
            self.backend.set_native_lobby_profile(self.token, level=level,
                                                 currencies={17020000010: funds}, props=[])
            before, changes = self.state(), {}
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1010}, changes)['result'], code)
            self.assertEqual(self.state(), before)
            self.assertEqual(changes, {})
        self.backend.set_native_lobby_profile(self.token, level=4,
                                             currencies={17020000010: 5000}, props=[])
        changes = {}
        started = self.request('CSSafehouseUpgradeReq', {'device_id': 1010}, changes)
        self.assertEqual(started['result'], 0)
        self.assertEqual(started['device']['level'], 1)
        self.assertEqual(started['device']['upgrade_level'], 2)
        self.assertEqual(changes['currency_changes'],
                         [{'currency_id': 17020000010, 'delta': -5000, 'current_num': 0}])
        finished = self.request('CSSafehouseGetInfoReq', {'device_id': 1010},
                                now=10000000 + row['Time'])['devices'][0]
        self.assertEqual(finished['level'], 2)

    def test_original_warehouse_eighth_level_keeps_action_facility_and_reputation_gates(self):
        from dfserver.client_errors import error_code
        from dfserver.native_department_queries import RepLevelCurve
        curve = RepLevelCurve([{'level': 1, 'score': 7}, {'level': 2, 'score': 11},
                               {'level': 3, 'score': 13}, {'level': 4, 'score': None}])
        self.backend.set_native_lobby_devices(self.token, {1010: 7, 1002: 3})
        row = self.submit_costs(1010, 8)
        self.assertEqual((row['SeasonLevel'], row['DeviceList'], row['QualityList']),
                         (42, '1002:3', '100003:3'))
        cases = [(41, 3, 18, 'SafehouseSeasonLevelConditionFail'),
                 (42, 2, 18, 'SafehouseDeviceConditionIneligible'),
                 (42, 3, 17, 'SafehousePlayerQualityConditionFail')]
        for level, facility_level, reputation_value, code in cases:
            self.backend.set_native_lobby_profile(self.token, level=level,
                                                 currencies={17020000010: 1000000}, props=[])
            self.backend.set_native_lobby_devices(self.token, {1010: 7, 1002: facility_level})
            with self.backend.connection() as connection:
                connection.execute('INSERT INTO native_lobby_department_values VALUES (?,?,?) '
                    'ON CONFLICT(player_id,quality_id) DO UPDATE SET value=excluded.value',
                    (self.player_id, 100003, reputation_value))
                connection.commit()
            before, changes = self.state(), {}
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1010},
                changes, curve=curve)['result'], error_code(code))
            self.assertEqual(self.state(), before)
            self.assertEqual(changes, {})
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_department_values SET value=18 '
                               'WHERE player_id=? AND quality_id=100003', (self.player_id,))
            connection.commit()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1010}, curve=curve)['result'], 0)

    def test_start_database_failure_restores_currency_and_submitted_slots(self):
        self.submit_costs(1007, 1)
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER reject_start BEFORE INSERT ON native_lobby_safehouse_upgrades "
                               "BEGIN SELECT RAISE(ABORT, 'diagnostic start failure'); END")
            connection.commit()
        before, changes = self.state(), {}
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007}, changes)['result'], 118002)
        self.assertEqual(self.state(), before)
        self.assertEqual(changes, {})

    def test_inventory_and_currency_notifications_precede_original_upgrade_callbacks(self):
        from dfserver import handshake_diagnostic as wire
        from dfserver.gcp_data import decode_data_frame

        def transact(name, fields):
            key, entry = bytes(range(16)), {}
            request = b'\0' * 4 + self.codec.encode(name, fields, sequence=451)
            with patch.object(self.progress.time, 'time', return_value=10000000):
                response = wire._candidate_local_activity_response(request, self.backend, self.token, key,
                    header_word4=17, header_word9=81, diagnostic_entry=entry)
            frames = wire._candidate_local_activity_response_frames(response, key, entry)
            decoded = [self.codec.decode(decode_data_frame(frame, key, direction='server_to_client',
                compression_method=1, max_output=1024 * 1024).messages[0]) for frame in frames]
            self.assertEqual([frame.header_word9 for frame in frames], list(range(81, 81 + len(frames))))
            self.assertEqual(decoded[-1].sequence, 451)
            return decoded

        _, entries = self.costs(1007, 1)
        submitted = transact('CSSafehouseSubmitUpgradePropReq', {'device_id': 1007, 'submit_prop_list': entries})
        self.assertEqual([row.name for row in submitted], ['CSDepositChangeNtf', 'CSSafehouseSubmitUpgradePropRes'])
        self.assertEqual(len(submitted[0].fields['deposit_change']['prop_changes']), len(entries))
        started = transact('CSSafehouseUpgradeReq', {'device_id': 1007})
        self.assertEqual([row.name for row in started], ['CSDepositChangeNtf', 'CSSafehouseUpgradeRes'])
        currency = started[0].fields['deposit_change']['currency_changes'][0]
        self.assertEqual((int(currency['currency_id']), int(currency['delta']), int(currency['current_num'])),
                         (17020000010, -4000, 996000))
        repeated = transact('CSSafehouseUpgradeReq', {'device_id': 1007})
        self.assertEqual(len(repeated), 1)
        self.assertEqual(int(repeated[0].fields['result']), 118019)

    def test_original_out_of_range_saved_level_is_not_silently_clamped_or_upgraded(self):
        self.backend.set_native_lobby_devices(self.token, {1003: 7})
        self.assertEqual(self.progress.MAX_LEVELS[1003], 3)
        before = self.state()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1003})['result'], 118079)
        self.assertEqual(self.state(), before)

    def test_reputation_and_facility_conditions_use_original_ids_and_cumulative_curve(self):
        from dfserver.native_department_queries import RepLevelCurve
        curve = RepLevelCurve([{'level': 1, 'score': 10}, {'level': 2, 'score': 20},
                               {'level': 3, 'score': None}])
        self.backend.set_native_lobby_devices(self.token, {1001: 5, 1007: 2})
        row = self.submit_costs(1001, 6)
        self.assertEqual((row['QualityList'], row['DeviceList']), ('100002:3', '1007:3'))
        before = self.state()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1001}, curve=curve)['result'], 118016)
        self.assertEqual(self.state(), before)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_devices SET level=3 WHERE player_id=? AND device_id=1007',
                               (self.player_id,))
            connection.execute('INSERT INTO native_lobby_department_values VALUES (?,?,?)',
                               (self.player_id, 100002, 29))
            connection.commit()
        before = self.state()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1001}, curve=curve)['result'], 118070)
        self.assertEqual(self.state(), before)
        with self.backend.connection() as connection:
            connection.execute('UPDATE native_lobby_department_values SET value=30 WHERE player_id=? AND quality_id=100002',
                               (self.player_id,))
            connection.commit()
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1001}, curve=curve)['result'], 0)

    def test_synthetic_task_condition_requires_persisted_completed_quest(self):
        from dfserver import native_quests
        self.backend.set_native_lobby_devices(self.token, {1001: 1})
        row = self.submit_costs(1001, 2)
        quest_id = next(iter(native_quests.QUESTS))
        with patch.dict(row, {'TaskList': str(quest_id)}):
            before = self.state()
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1001})['result'], 118024)
            self.assertEqual(self.state(), before)
            with self.backend.connection() as connection:
                connection.execute('INSERT INTO native_lobby_quest_progress(player_id,quest_id,state) VALUES (?,?,?)',
                                   (self.player_id, quest_id, native_quests.COMPLETED))
                connection.commit()
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1001})['result'], 0)

    def test_maximum_and_unknown_devices_fail_without_mutation(self):
        self.backend.set_native_lobby_devices(self.token, {1007: 3})
        for device_id, code in ((1007, 118014), (99999, 118003)):
            before, changes = self.state(), {}
            self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': device_id}, changes)['result'], code)
            self.assertEqual(self.state(), before)
            self.assertEqual(changes, {})

    def test_due_upgrade_database_failure_keeps_pending_timer_and_currency(self):
        self.submit_costs(1007, 1)
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007})['result'], 0)
        with self.backend.connection() as connection:
            connection.execute("CREATE TRIGGER reject_history BEFORE INSERT ON native_lobby_safehouse_upgrade_history "
                               "BEGIN SELECT RAISE(ABORT, 'diagnostic completion failure'); END")
            connection.commit()
        before = self.state()
        self.assertNotEqual(self.request('CSSafehouseGetInfoReq', {'device_id': 1007}, now=10000001)['result'], 0)
        self.assertEqual(self.state(), before)

    def test_exact_legacy_profile_migration_is_audited_once_without_touching_inventory(self):
        self.backend.set_native_lobby_devices(self.token, dict(self.progress.LEGACY_MAX_SIGNATURE))
        self.costs(1007, 1)
        before = self.state()
        with self.backend.connection() as connection:
            preview = self.progress.migration_preview(connection, self.player_id)
            self.assertTrue(preview['eligible'])
            self.assertEqual(self.state(), before)
            connection.execute('BEGIN IMMEDIATE')
            result = self.progress.migrate_legacy_max_profile(connection, self.player_id, 10000000)
            connection.commit()
        self.assertTrue(result['eligible'])
        after = self.state()
        self.assertEqual(after['native_lobby_props'], before['native_lobby_props'])
        self.assertEqual(after['native_lobby_currencies'], before['native_lobby_currencies'])
        self.assertEqual({row[1]: row[2] for row in after['native_lobby_devices']}, self.progress.initial_levels())
        audit = after['native_lobby_safehouse_migrations'][0]
        self.assertEqual(json.loads(audit[3])['before'], {str(k): v for k, v in self.progress.LEGACY_MAX_SIGNATURE.items()})
        with self.backend.connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            self.assertEqual(self.progress.migrate_legacy_max_profile(connection, self.player_id, 10000001)['reason'],
                             'already_migrated')
            connection.commit()
        self.assertEqual(self.state(), after)

    def test_migration_refuses_legitimate_different_profile_and_active_production(self):
        for devices in ({1007: 2}, {**self.progress.LEGACY_MAX_SIGNATURE, 1003: 3}):
            self.backend.set_native_lobby_devices(self.token, devices)
            before = self.state()
            with self.backend.connection() as connection:
                connection.execute('BEGIN IMMEDIATE')
                self.assertFalse(self.progress.migrate_legacy_max_profile(connection, self.player_id, 10000000)['eligible'])
                connection.commit()
            self.assertEqual(self.state(), before)
        self.backend.set_native_lobby_devices(self.token, dict(self.progress.LEGACY_MAX_SIGNATURE))
        with self.backend.connection() as connection:
            connection.execute('INSERT INTO native_lobby_safehouse_production VALUES (?,?,?,?,?,?,?)',
                               (self.player_id, 1007, 372830001, 1, 2, '[]', '[]'))
            connection.commit()
            connection.execute('BEGIN IMMEDIATE')
            self.assertEqual(self.progress.migrate_legacy_max_profile(connection, self.player_id, 10000000)['reason'],
                             'preserve_saved_production_or_upgrade_progress')
            connection.commit()
            self.assertEqual(connection.execute('SELECT count(*) FROM native_lobby_safehouse_production').fetchone()[0], 1)

    def test_other_account_cannot_see_submissions_or_finish_another_accounts_upgrade(self):
        self.submit_costs(1007, 1)
        self.assertEqual(self.request('CSSafehouseUpgradeReq', {'device_id': 1007})['result'], 0)
        self.token = self.backend.register('other-build-account', 'local-password-123')['session']
        other = self.request('CSSafehouseGetInfoReq', {'device_id': 1007}, now=10000001)['devices'][0]
        self.assertEqual((other['level'], other['upgrade_end_time']), (0, 0))
        self.assertTrue(all(row['curr_count'] == 0 for row in other['upgrade_prop_list']))
        self.assertEqual(len(self.state()['native_lobby_safehouse_upgrades']), 1)


if __name__ == '__main__':
    unittest.main()
