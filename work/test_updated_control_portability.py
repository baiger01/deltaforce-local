"""Moving a checkout or game folder must not alter wire qualification data."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import build_updated_control_profile as builder


class UpdatedControlPortabilityTests(unittest.TestCase):
    def test_configured_shadow_location_does_not_change_generated_profile(self):
        evidence = json.loads(builder.EVIDENCE.read_bytes())
        source = evidence['current_packaged_map_sources']
        maps = evidence['control_welcome_maps']['2201']
        with patch.object(builder, 'current_tables', return_value=(maps, source)):
            first = builder.derive(Path('machine-one/shadow'))
            second = builder.derive(Path('machine-two/shadow'))
        self.assertEqual(first, second)
        for doc in first:
            raw = builder.serialized(doc).decode('ascii')
            self.assertNotRegex(raw, r'[A-Za-z]:[\\/]')

    def test_only_provenance_locations_change_not_source_hashes_or_rows(self):
        source = json.loads(builder.EVIDENCE.read_bytes())['current_packaged_map_sources']
        original = copy.deepcopy(source)
        result = builder.portable_source_locations(source)
        self.assertEqual(source, original)
        self.assertEqual(result['map_config'], original['map_config'])
        self.assertEqual(result['subworld_config'], original['subworld_config'])
        for before, after in zip(original['archive_reports'], result['archive_reports']):
            self.assertEqual(before['validation']['decoded_index_sha256'],
                             after['validation']['decoded_index_sha256'])
            self.assertEqual(before['selected_entries'], after['selected_entries'])
            self.assertEqual(after['path'], 'DeltaForce/Content/Paks/'+after['archive'])
            self.assertEqual(after['validation']['pak'], after['path'])


if __name__ == '__main__':
    unittest.main()
