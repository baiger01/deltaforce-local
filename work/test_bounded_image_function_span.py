"""Verify contiguous unwind chains without widening native read permissions."""

from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from read_named_ds_transport_code import bounded_image_function_span


class UnwindBoundaryTests(unittest.TestCase):
    def span(self, *, foreign_chain=False, oversized=False):
        root = (0x100, 0x120, 0x400)
        first = (0x120, 0x140, 0x420)
        second = (0x140, 0x2201 if oversized else 0x160, 0x440)
        raw = bytearray(0x500)
        for index, entry in enumerate((root, first, second)):
            struct.pack_into('<III', raw, 0x20 + index * 12, *entry)
        struct.pack_into('<4B', raw, root[2], 1, 0, 0, 0)
        for entry, parent in ((first, root), (second, first)):
            struct.pack_into('<4B', raw, entry[2], 0x21, 0, 0, 0)
            if foreign_chain and entry == second:
                parent = (0x80, 0x100, 0x460)
            struct.pack_into('<III', raw, entry[2] + 4, *parent)
        pe = SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=[None] * 3 + [
                SimpleNamespace(VirtualAddress=0x20, Size=36)]),
            sections=[SimpleNamespace(Characteristics=0x20000000,
                                      VirtualAddress=0x100, Misc_VirtualSize=0x3000)],
            get_offset_from_rva=lambda rva: rva,
        )
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'unwind-fixture.bin'
            executable.write_bytes(raw)
            with patch('read_named_ds_transport_code.pefile.PE', return_value=pe):
                return bounded_image_function_span(executable, 0x100)

    def test_continuation_can_chain_to_an_already_verified_continuation(self):
        self.assertEqual(self.span(), (0x100, 0x60,
                                      [(0x100, 0x120), (0x120, 0x140), (0x140, 0x160)]))

    def test_unrelated_chain_does_not_extend_the_read(self):
        self.assertEqual(self.span(foreign_chain=True)[1], 0x40)

    def test_transitive_chain_still_enforces_the_byte_budget(self):
        with self.assertRaisesRegex(ValueError, 'code budget'):
            self.span(oversized=True)


if __name__ == '__main__':
    unittest.main()
