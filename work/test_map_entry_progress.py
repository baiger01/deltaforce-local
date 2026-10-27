"""Validate sanitized stage evidence using synthetic native logs."""
import json
from pathlib import Path
import tempfile
import unittest

from collect_map_entry_progress import inspect_entry, XOR_TABLE


class MapEntryEvidenceTests(unittest.TestCase):
    def inspect_text(self, text, probe=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client.log'
            path.write_bytes(b'\xef\xbb\xbf' + text.encode().translate(XOR_TABLE))
            probe_path = None
            if probe is not None:
                probe_path = Path(directory) / 'probe.json'
                probe_path.write_text(json.dumps(probe), encoding='utf-8')
            return inspect_entry(path, probe_path)

    def test_handoff_and_url_evidence_omit_session_contents(self):
        text = (
            '[2026.09.30-18.07.04:866][826]LuaSMatch: Warning: '
            '[GetLevelUrlAsync] url = , 127.0.0.1:47993?PlayerId=private-player'
            '?Cookie=private-ticket?MapId=2201\n'
            '[2026.09.30-18.07.04:867][826]LogGPGameFlow: Display: '
            'UGameFlowGraph::OnLuaGameFlowEvent() MdlName = Preparation, '
            'EventName = flowEvtPreparationStartMatchSuccess, ArgStr = '
            '127.0.0.1:47993?Cookie=private-ticket?SecretKey=private-key\n')
        report = self.inspect_text(text)
        self.assertEqual(report['native_game_flow_handoffs'][0]['module'], 'Preparation')
        self.assertEqual(report['connection_url_parameter_lengths'],
                         [{'PlayerId': 14, 'Cookie': 14, 'MapId': 4}])
        serialized = json.dumps(report)
        for private_value in ('private-player', 'private-ticket', 'private-key'):
            self.assertNotIn(private_value, serialized)

    def test_resource_ready_does_not_infer_a_connection(self):
        report = self.inspect_text(
            '[2026.09.30-18.07.03:334][701]LogGPGameLoading: bLevelStreamingReady!\n')
        self.assertEqual(report['first_stage_events'][0]['name'], 'level_streaming_ready')
        self.assertEqual(report['native_game_flow_handoffs'], [])
        self.assertEqual(report['playability_conclusion'],
                         'Not inferred from loading or connection events')

    def test_actual_cvar_state_overrides_requested_launch_setting(self):
        report = self.inspect_text(
            '[2026.09.30-18.06.41:497][700]LuaSMatch: '
            'CheckIsEnableSeamless , true, DeviceDisableDeviceSeamless, false\n')
        self.assertTrue(report['effective_entry_states'][0]['seamless_enabled'])
        self.assertFalse(report['effective_entry_states'][0]['device_seamless_disabled'])

    def test_native_network_timeout_is_recorded_without_connection_identifiers(self):
        report = self.inspect_text(
            '[2026.10.05-00.29.00:005][100]LogNet: Warning: '
            'UNetConnection::Tick: Connection TIMED OUT. Closing connection.. '
            '[UNetConnection] RemoteAddr: 127.0.0.1:61908, '
            'PC: NULL, Owner: NULL, UniqueId: INVALID\n'
            '[2026.10.05-00.29.00:006][100]LogNet: Warning: '
            'Connection TIMED OUT. Cookie=private-ticket\n')
        events = report['first_stage_events']
        self.assertEqual([event['name'] for event in events], ['native_connection_timeout'])
        self.assertEqual(events[0]['wall_time'], '2026.10.05-00.29.00:005')
        self.assertEqual(report['connection_failure_states'], [{
            'wall_time': '2026.10.05-00.29.00:005',
            'player_controller_missing': True,
            'owner_missing': True,
            'unique_id_invalid': True,
        }])
        serialized = json.dumps(report)
        self.assertNotIn('private-ticket', serialized)
        self.assertNotIn('61908', serialized)

    def test_one_timeout_is_not_counted_again_from_failure_and_rollback_logs(self):
        message = 'UNetConnection::Tick: Connection TIMED OUT. PC: NULL, Owner: NULL, UniqueId: INVALID'
        report = self.inspect_text(
            '[2026.10.05-00.29.00:005][100]LogNet: Warning: ' + message + '\n'
            '[2026.10.05-00.29.00:005][100]LogNet: Error: UEngine::BroadcastNetworkFailure: ' + message + '\n'
            '[2026.10.05-00.29.00:006][100]LogSeamlessEnter: Error: OnLoadingFlowFinished: ' + message + '\n')
        self.assertEqual(len(report['connection_failure_states']), 1)

    def test_join_without_actor_delivery_is_reported_without_private_records(self):
        probe = {
            'address': '127.0.0.1', 'port': 61908, 'listening': False,
            'records': [{'cookie': 'private-ticket', 'payload': 'private-bytes'}],
            'gameplay_server_implemented': False,
            'initial_actor_open_datagrams_sent': 0,
            'initial_actor_bootstrap': {
                'configured_map_profiles': 0, 'registered_sets': 0, 'waiting_for_join': 0,
                'native_spawn_verified': False,
            },
            'handshake_probe': {'native_control_probe': {
                'enabled': True, 'hello_consumed_peers': 1, 'login_authorized_peers': 1,
                'client_load_map_join_observed_count': 2,
                'initial_actor_channels_queued': 0, 'initial_actor_delivery_acks': 0,
                'initial_actor_channels_pending': 0,
                'local_match_admissions': {'private': 'private-account'},
            }},
        }
        report = self.inspect_text('', probe)
        progress = report['local_ds_probe']['transport_progress']
        self.assertEqual(progress['client_load_map_join_observed_count'], 2)
        self.assertEqual(progress['initial_actor_channels_queued'], 0)
        self.assertEqual(progress['initial_actor_open_datagrams_sent'], 0)
        self.assertEqual(progress['initial_actor_delivery_acks'], 0)
        self.assertEqual(progress['configured_map_profiles'], 0)
        self.assertFalse(progress['native_spawn_verified'])
        self.assertEqual(len(report['local_ds_probe']['report_sha256']), 64)
        for secret in ('private-ticket', 'private-bytes', 'private-account'):
            self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(report['playability_conclusion'],
                         'Not inferred from loading or connection events')

    def test_missing_legacy_actor_fields_are_unknown_not_zero(self):
        report = self.inspect_text('', {
            'address': '127.0.0.1', 'port': 18888, 'listening': False,
            'records': [], 'gameplay_server_implemented': False,
        })
        progress = report['local_ds_probe']['transport_progress']
        self.assertIsNone(progress['control_enabled'])
        self.assertIsNone(progress['client_load_map_join_observed_count'])
        self.assertIsNone(progress['initial_actor_open_datagrams_sent'])
        self.assertIsNone(progress['configured_map_profiles'])
        self.assertIsNone(progress['native_spawn_verified'])

    def test_invalid_probe_counter_types_do_not_become_observations(self):
        report = self.inspect_text('', {
            'address': '127.0.0.1', 'port': 18888, 'listening': False,
            'records': [], 'gameplay_server_implemented': False,
            'initial_actor_open_datagrams_sent': True,
            'initial_actor_bootstrap': {'configured_map_profiles': -1,
                                        'native_spawn_verified': 'true'},
            'handshake_probe': {'native_control_probe': {
                'enabled': 'true', 'client_load_map_join_observed_count': '2',
            }},
        })
        progress = report['local_ds_probe']['transport_progress']
        self.assertIsNone(progress['control_enabled'])
        self.assertIsNone(progress['client_load_map_join_observed_count'])
        self.assertIsNone(progress['initial_actor_open_datagrams_sent'])
        self.assertIsNone(progress['configured_map_profiles'])
        self.assertIsNone(progress['native_spawn_verified'])

    def test_binding_stages_distinguish_allowed_and_base_calls_without_actor_names(self):
        report = self.inspect_text(
            '[2026.10.06-00.01.01:000][100]LogGPNet: Log: '
            'UGPNetConnection::HandleClientPlayer\n'
            '[2026.10.06-00.01.01:001][100]LogGPNet: Log: '
            'IGPSeamlessConnectionInterface::HandleClientPlayer\n'
            '[2026.10.06-00.01.01:002][100]LogGPNet: Log: '
            'IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel with NetActorRemapping\n'
            '[2026.10.06-00.01.01:003][100]LogGPNet: Log: '
            'UGPNetConnection::HandleClientPlayer  Super\n'
            '[2026.10.06-00.01.01:004][100]LogNet: VeryVerbose: '
            'private-controller setplayer private-local-player\n'
            '[2026.10.06-00.01.01:005][100]LogNet: VeryVerbose: '
            'Client received PlayerController=private-controller. Num child connections=0.\n')
        stages = {event['name']: event for event in report['client_player_binding_events']}
        self.assertEqual(stages['connection_handle_client_player']['count'], 1)
        self.assertEqual(stages['connection_base_binding_called']['count'], 1)
        self.assertEqual(stages['seamless_binding_allowed_with_remapping']['count'], 1)
        self.assertEqual(stages['base_player_association_logged']['count'], 1)
        self.assertEqual(stages['controller_actor_open_logged']['count'], 1)
        self.assertEqual(stages['controller_actor_open_logged']['first_wall_time'],
                         '2026.10.06-00.01.01:005')
        self.assertNotIn('private-controller', json.dumps(report))
        self.assertNotIn('private-local-player', json.dumps(report))
        self.assertEqual(report['playability_conclusion'],
                         'Not inferred from loading or connection events')

    def test_unprinted_binding_stages_remain_unknown_and_urls_are_not_log_events(self):
        report = self.inspect_text(
            '[2026.10.06-00.01.01:000][100]LogGPGameFlow: Display: '
            'ArgStr = private-ticket?Marker=UGPNetConnection::HandleClientPlayer\n')
        self.assertEqual(report['client_player_binding_events'], [])
        self.assertIn('Absence', report['client_player_binding_qualification'])
        self.assertNotIn('private-ticket', json.dumps(report))

    def test_binding_repeat_counts_do_not_duplicate_generic_entry_for_super_logs(self):
        report = self.inspect_text(
            '[2026.10.06-00.01.01:000][100]LogGPNet: Log: '
            'IGPSeamlessConnectionInterface::HandleClientPlayer  Super\n'
            '[2026.10.06-00.01.01:001][100]LogGPNet: Log: '
            'IGPSeamlessConnectionInterface::HandleClientPlayer  Super\n'
            '[2026.10.06-00.01.01:002][100]LogGPNet: Log: '
            'IGPSeamlessConnectionInterface::HandleClientPlayer  SeamlessTravel\n')
        self.assertEqual([event['name'] for event in report['client_player_binding_events']],
                         ['seamless_base_binding_allowed', 'seamless_binding_allowed'])
        self.assertEqual(report['client_player_binding_events'][0]['count'], 2)


if __name__ == '__main__':
    unittest.main()
