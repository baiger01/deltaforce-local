import json
from pathlib import Path
import unittest
from unittest.mock import patch

from dfserver import weapon_ammo
from dfserver.weapon_components import default_components


ROOT = Path(__file__).resolve().parent.parent


class WeaponAmmoCapacityTests(unittest.TestCase):
    def test_default_lmg_magazines_use_their_actual_base_capacity(self):
        for receiver in (18040000003, 18040000004):
            with self.subTest(receiver=receiver):
                self.assertEqual(weapon_ammo.magazine_capacity(default_components(receiver), receiver), 125)

    def test_source_default_firearms_have_only_the_two_missing_attribute_rows_unknown(self):
        source = json.loads((ROOT / 'protocol/weapon_preset_catalog.json').read_text(encoding='utf-8'))
        receivers = [int(k) for k, row in source['rows'].items()
                     if row['is_base_weapon'] and row['default_preset_id']
                     and int(k) // 10000000 % 100 in range(1, 8)]
        unknown = {r for r in receivers if weapon_ammo.magazine_capacity(default_components(r), r) is None}
        self.assertEqual(unknown, {18050000033, 18010000049})

    def test_unrecovered_magazine_effect_is_not_replaced_with_a_guessed_base(self):
        catalogue = {**weapon_ammo.CATALOG,
                     'magazines': {k: v for k, v in weapon_ammo.CATALOG['magazines'].items()
                                   if k != '13120000309'}}
        with patch.object(weapon_ammo, 'CATALOG', catalogue):
            self.assertIsNone(weapon_ammo.magazine_capacity(default_components(18040000003), 18040000003))

    def test_source_barrel_capacity_addition_is_counted_once(self):
        source = weapon_ammo.CATALOG.get('capacity_additions', {}).get('13020000453')
        self.assertIsNotNone(source)
        self.assertEqual(source['capacity'], 2)
        # This tests the native capacity consumer, not attachment compatibility.
        parts = [{'slot': 0, 'prop_data': {'id': 13020000453, 'components': []}}]
        base = weapon_ammo.CATALOG['weapons']['18040000003']['base_capacity']
        self.assertEqual(weapon_ammo.magazine_capacity(parts, 18040000003), base + 2)

    def test_unknown_receiver_attribute_is_not_filled_by_no_override_magazine(self):
        self.assertIsNone(weapon_ammo.magazine_capacity(default_components(18010000049), 18010000049))


if __name__ == '__main__':
    unittest.main()
