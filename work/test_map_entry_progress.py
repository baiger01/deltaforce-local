"""Validate sanitized stage evidence using synthetic native logs."""
import json
from pathlib import Path
import tempfile
import unittest

from collect_map_entry_progress import inspect_entry, XOR_TABLE


class MapEntryEvidenceTests(unittest.TestCase):
    def inspect_text(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client.log'
            path.write_bytes(b'\xef\xbb\xbf' + text.encode().translate(XOR_TABLE))
            return inspect_entry(path)

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


if __name__ == '__main__':
    unittest.main()
