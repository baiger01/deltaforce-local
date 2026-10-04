import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'work'))
import extract_weapon_components_catalog as extractor


class WeaponComponentExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.presets = {
            '10010000019': 18010000010,
            '10020000005': 18020000003,
            '10050000007': 18050000005,
            '10070000022': 18070000004,
            '10040000900': 18040000001,
        }
        self.items = {}
        self.records = []
        for index, (preset, receiver) in enumerate(self.presets.items()):
            self.items[preset] = {'name_key': preset + '_Name',
                'initial_guide_price': 60793, 'is_model_only': False,
                'is_currency': False, 'length': 0 if index == 4 else 4,
                'width': 0 if index == 4 else 2}
            self.items[str(receiver)] = {'length': 5, 'width': 2}
            self.records.append((100 + index, None, {
                0x7471: int(preset), 0x747c: receiver, 0x7479: 1,
                0x7482: 0, 0x7483: 0, 0x746d: 0, 0x7487: 0}, None))

    def extract(self):
        (self.directory / 'weapon_preset_catalog.json').write_text(json.dumps({
            'default_preset_to_receiver': self.presets}), encoding='utf-8')
        (self.directory / 'game_item_catalog.json').write_text(json.dumps({
            'rows': self.items}), encoding='utf-8')
        source = self.directory / 'source.uexp'
        source.write_bytes(b'source fixture')
        target = self.directory / 'weapon_component_catalog.json'
        with patch.object(extractor, 'TARGET', target), \
                patch.object(extractor, 'SOURCE', source), \
                patch.object(extractor, 'rows', return_value=iter(self.records)), \
                contextlib.redirect_stdout(io.StringIO()):
            extractor.main()
        return json.loads(target.read_text(encoding='utf-8'))

    def test_abstract_preset_uses_real_receiver_dimensions(self):
        report = self.extract()
        self.assertIn('18040000001', report['rows'])
        tree = report['rows']['18040000001']
        self.assertEqual(tree['preset_id'], 10040000900)
        self.assertEqual((tree['prop']['length'], tree['prop']['width']), (5, 2))
        self.assertEqual(tree['node_offsets'], {'1': 104})

    def test_tree_recovery_is_independent_of_sale_price_and_flags(self):
        self.items['10040000900'].update(initial_guide_price=0,
            is_model_only=True, is_currency=True)
        report = self.extract()
        self.assertIn('18040000001', report['rows'])

    def test_missing_source_tree_is_reported_without_fabricating_parts(self):
        self.presets['10300000002'] = 18300000001
        report = self.extract()
        self.assertNotIn('18300000001', report['rows'])
        self.assertIn('unavailable_presets', report)
        self.assertEqual(report['unavailable_presets']['10300000002'], {
            'receiver_id': 18300000001,
            'reason': 'No source component nodes', 'row_offsets': []})

    def test_unmatched_socket_is_reported_without_accepting_bad_tree(self):
        self.records[-1][2].update({0x746d: 2, 0x7487: 1})
        self.items['13030000139'] = {'length': 1, 'width': 1}
        self.records.append((105, None, {
            0x7471: 10040000900, 0x747c: 13030000139, 0x7479: 2,
            0x7482: 1, 0x7483: 2, 0x746d: 0, 0x7487: 0}, None))
        report = self.extract()
        self.assertNotIn('18040000001', report['rows'])
        self.assertIn('unavailable_presets', report)
        self.assertEqual(report['unavailable_presets']['10040000900'], {
            'receiver_id': 18040000001,
            'reason': 'Unmatched socket edge in preset 10040000900',
            'row_offsets': [104, 105]})


if __name__ == '__main__':
    unittest.main()
