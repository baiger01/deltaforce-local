"""Pure value/content grammar tests; no process, channel, mapping, or socket."""
import unittest
from unittest.mock import patch

from dfserver.legacy_ds_bit_archive import BitReader
from dfserver.legacy_ds_scalar_serializers import NativeScalarBinding, SHIPPING_SHA256
from dfserver import legacy_ds_player_state_human_appearance_content as codec


class HumanPlayerStateContentTests(unittest.TestCase):
    def bindings(self):
        return tuple(NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286c000, table)
                     for table in codec.PROPERTY_TABLES)

    def build(self, **changes):
        args = dict(hero_id=-1, same_team_avatar_id=0, diff_team_avatar_id=(1 << 64) - 1,
            bindings=self.bindings(), no_byteswap=True, normal_actor_receive_contract=True)
        args.update(changes)
        return codec.build_player_state_human_appearance_content(**args)

    def test_exact_unaligned_three_handles_raw_values_and_single_terminal(self):
        block = self.build()
        self.assertTrue(block.has_rep_layout); self.assertEqual(block.payload_bit_count, 249)
        self.assertEqual(len(block.payload), 32)
        reader = BitReader(block.payload, bit_count=block.payload_bit_count)
        self.assertFalse(reader.read_bool())
        for handle, value, signed in ((140, -1, True), (142, 0, False), (143, (1 << 64) - 1, False)):
            self.assertEqual(reader.read_packed_int(), handle)
            self.assertEqual(reader.position % 8, 1)
            self.assertEqual(int.from_bytes(reader.read_bytes(8), 'little', signed=signed), value)
        self.assertEqual(reader.read_packed_int(), 0); self.assertEqual(reader.remaining, 0)
        # Independently construct the known packed units and shift once for the
        # leading zero option. There is no per-property length, FName or RPC bit.
        aligned = bytes.fromhex('1902') + bytes([255]) * 8 + bytes.fromhex('1d02') + bytes(8) + bytes.fromhex('1f02') + bytes([255]) * 8 + b'\0'
        expected = (int.from_bytes(aligned, 'little') << 1).to_bytes(32, 'little')
        self.assertEqual(block.payload, expected)

    def test_integer_extrema_keep_all_64_bits(self):
        for hero in (-(1 << 63), (1 << 63) - 1):
            block = self.build(hero_id=hero, same_team_avatar_id=(1 << 64) - 1, diff_team_avatar_id=0)
            reader = BitReader(block.payload, bit_count=249); reader.read_bool(); reader.read_packed_int()
            self.assertEqual(int.from_bytes(reader.read_bytes(8), 'little', signed=True), hero)

    def test_wrong_table_hook_or_build_never_allocates_writer(self):
        wrong = [NativeScalarBinding('0' * 64, 0x10e5ce20, 0x286c000, 0x15a86560),
            NativeScalarBinding(SHIPPING_SHA256, 0x10e8ed20, 0x286c000, 0x15a86560),
            NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286bf70, 0x15a86560),
            NativeScalarBinding(SHIPPING_SHA256, 0x10e5ce20, 0x286c000, 0x1ab60db0)]
        for binding in wrong:
            with patch.object(codec, 'BitWriter') as writer, self.assertRaises(ValueError):
                self.build(bindings=(binding,) + self.bindings()[1:])
            writer.assert_not_called()
        for bindings in (self.bindings()[:2], list(self.bindings()), (), self.bindings()[::-1]):
            with self.assertRaises(ValueError): self.build(bindings=bindings)

    def test_truthy_contracts_and_invalid_values_refuse_before_writer(self):
        invalid = [dict(no_byteswap=x) for x in (False, None, 1, 'true')]
        invalid += [dict(normal_actor_receive_contract=x) for x in (False, None, 1, 'true')]
        invalid += [dict(hero_id=x) for x in (True, None, -1 - (1 << 63), 1 << 63, '25')]
        for field in ('same_team_avatar_id', 'diff_team_avatar_id'):
            invalid += [{field: x} for x in (True, None, -1, 1 << 64, '25')]
        for changes in invalid:
            with patch.object(codec, 'BitWriter') as writer, self.assertRaises(ValueError): self.build(**changes)
            writer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
