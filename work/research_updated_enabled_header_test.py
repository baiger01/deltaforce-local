import struct
import unittest

from research_updated_metadata_roots import decoder
from research_updated_enabled_header import hook_states, coalesce_cells, hook_dispatch_calls


class EnabledHeaderTests(unittest.TestCase):
    def instructions(self, *, key=7, argument=7, immediate=0):
        first, cell = 0x1000, 0x2000+key
        raw = b'\x80\x3d'+struct.pack('<i',cell-(first+7))+bytes([immediate])
        raw += b'\xb9'+struct.pack('<I',argument)+b'\xe8\x00\x00\x00\x00\xc3'
        return list(decoder().disasm(raw,first))

    def test_each_hook_cell_is_bound_to_its_native_dispatch_key(self):
        rows = hook_states(self.instructions(),0x2000,32)
        self.assertEqual(rows[0]['rva'],'0x2007')
        self.assertEqual(rows[0]['dispatch_key'],7)
        with self.assertRaises(ValueError):
            hook_states(self.instructions(argument=8),0x2000,32)

    def test_nonzero_only_postcheck_does_not_qualify_a_disabled_hook(self):
        with self.assertRaises(ValueError):
            hook_states(self.instructions(immediate=2),0x2000,32)

    def test_exact_ranges_never_bridge_unqualified_bytes(self):
        self.assertEqual(coalesce_cells([0x2009,0x2007,0x2008,0x200d]),
            [dict(rva='0x2007',bytes=3),dict(rva='0x200d',bytes=1)])
        with self.assertRaises(ValueError):
            coalesce_cells([0x2007,0x2007])
        with self.assertRaises(ValueError):
            coalesce_cells(list(range(129)))

    def test_dispatch_calls_require_the_current_ecx_key_argument(self):
        self.assertEqual(len(hook_dispatch_calls(self.instructions(),{7})),1)
        raw = bytes.fromhex('b9070000004889d9e800000000c3')
        overwritten = list(decoder().disasm(raw,0x1000))
        self.assertEqual(hook_dispatch_calls(overwritten,{7}),[])

    def test_register_zero_comparison_is_not_omitted(self):
        raw = b'\x31\xc0\x38\x05'+struct.pack('<i',0x2007-0x1008)
        raw += b'\xb9\x07\x00\x00\x00\xe8\x00\x00\x00\x00\xc3'
        rows = hook_states(list(decoder().disasm(raw,0x1000)),0x2000,32)
        self.assertEqual(rows[0]['dispatch_key'],7)
        self.assertEqual(rows[0]['guards'][0]['compared_value'],0)


if __name__ == '__main__':
    unittest.main()
