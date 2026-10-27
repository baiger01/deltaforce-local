"""The split export/body helper must preserve the historical combined bytes."""
import hashlib
import unittest

from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import (
    DefaultSubobjectUpdate, default_subobject_followup_parts, write_default_subobjects_followup,
)


class DefaultSubobjectCompatibilityTests(unittest.TestCase):
    def test_small_combined_followups_match_pre_split_reference_vectors(self):
        # Reproduced from the archived pre-split codec, without runtime state.
        cases = ((1, 221, '308184af11f2d1bede7fbde86beacf63cc974a88928a576eb31788cb9f3beb46'),
                 (2, 385, '0e4504241d9535228927a82117d024f6b4e0237329c62474f9b622644b38f5a6'))
        for count, bits, digest in cases:
            with self.subTest(component_count=count):
                updates = tuple(DefaultSubobjectUpdate(2, 6+index*2,
                    'CharMoveComp' if index == 0 else 'Inventory', 'a'*64, b'\x00', 1)
                    for index in range(count))
                combined = BitWriter(maximum_bits=8192)
                write_default_subobjects_followup(combined, updates, (), (2, 4))
                self.assertEqual(combined.bit_count, bits)
                self.assertEqual(hashlib.sha256(combined.to_bytes()).hexdigest(), digest)
                split = BitWriter(maximum_bits=8192)
                for raw, size in default_subobject_followup_parts(updates, (), (2, 4)):
                    split.write_payload(raw, size)
                self.assertEqual((split.to_bytes(), split.bit_count),
                                 (combined.to_bytes(), combined.bit_count))


if __name__ == '__main__':
    unittest.main()
