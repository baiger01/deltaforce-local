import json
import unittest

from watch_official_ds_evidence import SymbolEvidence


class OfficialEvidenceWatchTests(unittest.TestCase):
    def test_keeps_loading_names_and_paths_without_accounts_or_tickets(self):
        evidence = SymbolEvidence()
        evidence.consume('[LogStreaming:] ULevelStreaming::RequestLevel /Game/Maps/Dam/Cell private-player')
        evidence.consume('LogPlayer: APlayerController::OnPossess PlayerId=private-player Cookie=private-cookie')
        evidence.consume('LogGPGameFlow: SecretKey=private-key')
        output = json.dumps(evidence.summary())
        self.assertIn('/Game/Maps/Dam/Cell', output)
        self.assertIn('APlayerController::OnPossess', output)
        for private in ('private-player', 'private-cookie', 'private-key'):
            self.assertNotIn(private, output)
        self.assertFalse(evidence.summary()['actor_property_schemas_recovered'])
        self.assertFalse(evidence.summary()['server_ai_implementation_recovered'])

    def test_unique_symbol_growth_is_bounded(self):
        evidence = SymbolEvidence()
        for index in range(1000):
            evidence.consume(f'LogStreaming: /Game/Maps/Dam/Cell{index}')
        result = evidence.summary()['groups']['scene_loading']
        self.assertEqual(result['matching_lines'], 1000)
        self.assertEqual(len(result['asset_paths']), 200)
