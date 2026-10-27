import unittest
from unittest.mock import patch

import probe_live_storehot_metadata as tool


class StoreHotAdapterModeTests(unittest.TestCase):
    def test_default_keeps_metadata_reader_and_contract(self):
        with patch.object(tool.metadata, 'load_contract', return_value='metadata') as load:
            with patch.object(tool.image_rows, 'load_contract') as image_load:
                reader, contract = tool.reader_contract()
        self.assertIs(reader, tool.metadata)
        self.assertEqual(contract, 'metadata')
        load.assert_called_once_with()
        image_load.assert_not_called()

    def test_explicit_image_rows_loads_independent_contract(self):
        with patch.object(tool.image_rows, 'load_contract', return_value='rows') as load:
            with patch.object(tool.metadata, 'load_contract') as metadata_load:
                reader, contract = tool.reader_contract(True)
        self.assertIs(reader, tool.image_rows)
        self.assertEqual(contract, 'rows')
        load.assert_called_once_with()
        metadata_load.assert_not_called()

    def test_explicit_original_pe_reaches_the_image_source_gate(self):
        with patch.object(tool.image_rows, 'load_contract', return_value='rows') as load:
            reader, contract = tool.reader_contract(True, 'exact-original.exe')
        self.assertIs(reader, tool.image_rows)
        self.assertEqual(contract, 'rows')
        load.assert_called_once_with(source_pe='exact-original.exe')

    def test_contract_failure_propagates_before_adapter_process_access(self):
        with patch.object(tool.image_rows, 'load_contract', side_effect=ValueError('owner pin changed')):
            with self.assertRaisesRegex(ValueError, 'owner pin changed'):
                tool.reader_contract(True)

    def test_non_boolean_mode_is_not_a_selector(self):
        for value in (None, 0, 1, 'rows'):
            with self.subTest(value=value):
                with patch.object(tool.image_rows, 'load_contract') as image_load:
                    with patch.object(tool.metadata, 'load_contract') as metadata_load:
                        with self.assertRaisesRegex(ValueError, 'explicit_boolean'):
                            tool.reader_contract(value)
                image_load.assert_not_called()
                metadata_load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
