"""Bounded synthetic cooked Function stream tests."""
import struct
import unittest

from research_updated_cooked_functions import parse_function


class CookedFunctionTests(unittest.TestCase):
    def fixture(self, flags=0, script=b'\x04\x0b\x53'):
        pkg = dict(serialized_names=['None'], imports=[], exports=[dict(name='Synthetic')],
            custom_versions=[dict(guid_bytes_hex='3f74fccf8044b043df14919373201d17',value=36),
                dict(guid_bytes_hex='3cc15e37fb48e406f08400b57e712a26',value=4)])
        row = dict(name='Synthetic', index=1, super_index=0)
        raw = struct.pack('<6i',0,0,0,0,len(script),len(script))+script+struct.pack('<I',flags)
        if flags&0x40:
            raw += struct.pack('<H',12)
        return raw+struct.pack('<2i',0,0), pkg, row

    def test_bytecode_is_bounded_separately_from_function_flags(self):
        raw,pkg,row=self.fixture(0x8000000)
        result=parse_function(raw,pkg,row)
        self.assertEqual(result['function_flags'],'0x8000000')
        self.assertFalse(result['net_flag'])
        self.assertEqual(result['stored_bytecode_bytes'],3)

    def test_net_flag_requires_current_native_conditional_rpc_id(self):
        raw,pkg,row=self.fixture(0x40)
        result=parse_function(raw,pkg,row)
        self.assertTrue(result['net_flag'])
        self.assertEqual(result['legacy_rpc_id'],12)
        with self.assertRaises(ValueError): parse_function(raw[:-2],pkg,row)

    def test_trailing_bytes_wrong_super_and_duplicate_versions_fail_closed(self):
        raw,pkg,row=self.fixture()
        with self.assertRaises(ValueError): parse_function(raw+b'\0',pkg,row)
        with self.assertRaises(ValueError): parse_function(raw,pkg,dict(row,super_index=1))
        pkg['custom_versions'].append(pkg['custom_versions'][0])
        with self.assertRaises(ValueError): parse_function(raw,pkg,row)

    def test_negative_and_oversized_bytecode_extent_fail_closed(self):
        raw,pkg,row=self.fixture()
        for size in (-1,1000000):
            changed=bytearray(raw); struct.pack_into('<i',changed,20,size)
            with self.assertRaises(ValueError): parse_function(bytes(changed),pkg,row)


if __name__=='__main__':
    unittest.main()
