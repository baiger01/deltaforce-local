"""Native string-CRC input representation tests."""
import unittest

from research_updated_minimum_cpp_checksums import fold,property_checksum


class MinimumChecksumTests(unittest.TestCase):
    def test_ascii_lowercase_and_four_byte_character_processing(self):
        self.assertEqual(fold(0,'A'),0xa2de4f7a)
        self.assertEqual(fold(0,'1'),0x69d340d8)
        self.assertEqual(fold(0,'A'),fold(0,'a'))

    def test_seeded_fold_is_composable_and_dimensions_are_separate_input(self):
        self.assertEqual(fold(fold(0,'ab'),'cd'),fold(0,'abcd'))
        self.assertEqual(property_checksum('Pawn','APawn*',1),
            fold(fold(fold(0,'pawn'),'apawn*'),'1'))
        self.assertNotEqual(property_checksum('Pawn','APawn*',1),property_checksum('Pawn','APawn*',2))

    def test_unqualified_name_domain_and_dimensions_fail_closed(self):
        for value in ('A\0B','\u4e2d'):
            with self.assertRaises(ValueError): fold(0,value)
        with self.assertRaises(ValueError): property_checksum('A','int64',0)


if __name__=='__main__':
    unittest.main()
