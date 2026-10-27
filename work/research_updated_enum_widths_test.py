"""Pure enum MAX and network-width boundary tests."""
import unittest

from research_updated_enum_widths import width_candidates


class EnumWidthTests(unittest.TestCase):
    def test_existing_role_max_is_not_appended_again(self):
        result=width_candidates('ENetRole',0,[('ROLE_None',0),('ROLE_Authority',3),('ROLE_MAX',4)])
        self.assertEqual(result['possible_maxima'],[4])
        self.assertEqual(result['byte_property_bit_widths'],[2])

    def test_game_mode_width_is_stable_across_max_generation_and_archive_version(self):
        result=width_candidates('Mode',2,[('Mode::None',0),('Mode::Last',9)])
        self.assertEqual(result['possible_maxima'],[9,10])
        self.assertEqual(result['enum_property_all_version_bit_widths'],[4])

    def test_power_boundary_retains_version_uncertainty(self):
        result=width_candidates('Mode',2,[('Mode::None',0),('Mode::MAX',4)])
        self.assertEqual(result['possible_maxima'],[4])
        self.assertEqual(result['enum_property_all_version_bit_widths'],[2,3])

    def test_wrong_cpp_form_duplicate_and_out_of_byte_values_fail_closed(self):
        for form,values in ((3,[('X',1)]),(0,[('X',1),('X',2)]),(0,[('X',256)])):
            with self.assertRaises(ValueError): width_candidates('Mode',form,values)


if __name__=='__main__':
    unittest.main()
