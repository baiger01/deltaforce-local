"""Offline medical parameter boundary tests; no native game methods or transport."""
import importlib
import importlib.util
import unittest


class MedicalCancelCodecTests(unittest.TestCase):
    def codec(self):
        name = 'medical_cancel_codec_20261020'
        self.assertIsNotNone(importlib.util.find_spec(name), 'Source-qualified cancellation codec is missing')
        return importlib.import_module(name)

    def test_native_none_has_absent_and_explicit_present_forms(self):
        codec = self.codec()
        for raw, bits, present in ((b'\0', 1, False), (b'\1', 6, True)):
            with self.subTest(bits=bits):
                result = codec.decode_cancel(raw, bits)
                self.assertEqual((result.reason, result.reason_present), (0, present))
                self.assertEqual(codec.encode_cancel(0, reason_present=present), (raw, bits))

    def test_installed_combat_interrupt_fixtures(self):
        codec = self.codec()
        for reason, raw in ((1, b'\x03'), (2, b'\x05'), (5, b'\x0b'), (14, b'\x1d'), (21, b'\x2b')):
            with self.subTest(reason=reason):
                self.assertEqual(codec.encode_cancel(reason), (raw, 6))
                self.assertEqual(codec.decode_cancel(raw, 6).reason, reason)

    def test_every_declared_reason_roundtrips(self):
        codec = self.codec()
        for reason in range(22):
            raw, bits = codec.encode_cancel(reason)
            result = codec.decode_cancel(raw, bits)
            self.assertEqual((result.reason, result.reason_present), (reason, True))

    def test_truncation_extra_bits_padding_and_storage_are_refused(self):
        codec = self.codec()
        for raw, bits in ((b'', 0), (b'\1', 1), (b'\x03', 5), (b'\0', 2),
                          (b'\x43', 6), (b'\0\0', 1), (b'\x03', 7)):
            with self.subTest(raw=raw, bits=bits), self.assertRaises(ValueError):
                codec.decode_cancel(raw, bits)

    def test_local_subset_rejects_unknown_values_and_nonzero_absent_reason(self):
        codec = self.codec()
        for value in (-1, 22, 31, True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                codec.encode_cancel(value)
        with self.assertRaises(ValueError):
            codec.encode_cancel(1, reason_present=False)
        with self.assertRaises(ValueError):
            codec.decode_cancel(b'\x3f', 6)

    def test_schema_retains_source_and_acceptance_boundaries(self):
        schema = self.codec().source_schema()
        self.assertEqual(schema['reason_width_bits'], 5)
        self.assertEqual(schema['reason_default_when_absent'], 0)
        self.assertEqual(schema['parameter_presence_bits'], 1)
        self.assertTrue(schema['source_equivalent_parameter_grammar_closed'])
        self.assertFalse(schema['captured_medical_request_replayed'])
        self.assertFalse(schema['native_handler_or_medical_success_verified'])


if __name__ == '__main__':
    unittest.main()
