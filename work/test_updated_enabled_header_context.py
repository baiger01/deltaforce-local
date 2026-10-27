import importlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch


try:
    enabled = importlib.import_module('updated_enabled_header_context')
except ModuleNotFoundError:
    enabled = None

ROOT = Path(__file__).resolve().parents[1]
PROOF_PATH = 'work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json'
CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
TOP = (('global_hook_enable', 0x1de36180), ('alternate_actor_channel', 0x1e322935))
TOP_GUARDS = ((0x4e24db6, bytes.fromhex('803dc313011900488bd97423')),
              (0x4977e22, bytes.fromhex('803d0cab9a1900488bd7488bcb740b488b03ff9050030000eb05e8ef96ee0d')))


class Fixture:
    def __init__(self, top=(1, 1)):
        self.base = 0x140000000
        self.proof = json.loads((ROOT / PROOF_PATH).read_bytes())
        self.cells = self.proof['hook_gate_scope']['required_quiet_cells']
        self.ranges = tuple((int(r['rva'], 16), r['bytes'])
                            for r in self.proof['hook_gate_scope']['exact_read_ranges'])
        guards = dict(TOP_GUARDS)
        for cell in self.cells:
            for guard in cell['guards']:
                guards[int(guard['rva'], 16)] = bytes.fromhex(guard['bytes_hex'])
                zero = guard['zero_register_source']
                if zero is not None:
                    guards[int(zero['rva'], 16)] = bytes.fromhex(zero['bytes_hex'])
        for guard in self.proof['exact_instruction_witnesses']:
            guards[int(guard['rva'], 16)] = bytes.fromhex(guard['bytes_hex'])
        self.guards = tuple(sorted(guards.items()))
        self.data = {(self.base + rva, len(raw)): raw for rva, raw in self.guards}
        self.data.update({(self.base + rva, 1): bytes((value,)) for (_, rva), value in zip(TOP, top)})
        self.data.update({(self.base + rva, size): bytes(size) for rva, size in self.ranges})
        self.calls, self.after_read = [], None
        self.backend = self.read

    def hook(self, rva, value):
        if type(rva) is str:
            rva = int(rva, 16)
        start, size = next((first, count) for first, count in self.ranges if first <= rva < first + count)
        key = self.base + start, size
        raw = bytearray(self.data[key])
        raw[rva - start] = value
        self.data[key] = bytes(raw)

    def read(self, address, size):
        self.calls.append((address, size))
        raw = self.data[address, size]
        if self.after_read is not None:
            self.after_read(address, size)
        return raw

    def read_exact(self, address, size):
        return self.backend(address, size)


class EnabledHeaderContextTests(unittest.TestCase):
    def observe(self, fixture, **changes):
        self.assertIsNotNone(enabled, 'The callback-only enabled header reader is missing')
        return enabled.read_enabled_header_context(fixture.read_exact,
            changes.get('module_base', fixture.base), client_sha256=changes.get('client_sha256', CLIENT_SHA))

    def test_actual_one_one_and_all_37_zero_hooks_qualify_only_source_native_route(self):
        fixture = Fixture()
        result = self.observe(fixture)
        self.assertEqual(result['top_level_values'], {'global_hook_enable': 1, 'alternate_actor_channel': 1})
        self.assertEqual(result['hook_values'], {cell['rva']: 0 for cell in fixture.cells})
        self.assertTrue(result['native_receiver_route_qualified'])
        self.assertTrue(result['source_instructions_rechecked'])
        self.assertFalse(result['native_gameplay_qualified'])
        self.assertFalse(result['process_identity_verified'])
        self.assertFalse(result['atomic_snapshot'])
        self.assertFalse(result['native_function_called'])
        self.assertEqual(set(fixture.calls), set(fixture.data))
        self.assertEqual((len(fixture.guards), len(fixture.ranges)), (88, 13))
        self.assertEqual((result['read_calls'], result['read_bytes']), (309, 1944))
        self.assertEqual(len(fixture.calls), 309)

    def test_every_nonzero_hook_is_captured_and_refuses_the_native_route(self):
        fixture = Fixture()
        for cell, value in zip(fixture.cells, (1, 2, 255) * 13):
            with self.subTest(rva=cell['rva'], value=value):
                fixture = Fixture()
                fixture.hook(cell['rva'], value)
                result = self.observe(fixture)
                self.assertEqual(result['hook_values'][cell['rva']], value)
                self.assertFalse(result['native_receiver_route_qualified'])
                self.assertEqual(result['status'], 'observed_nonzero_hook_refused')
                self.assertEqual(sum(v != 0 for v in result['hook_values'].values()), 1)

    def test_other_top_level_flags_are_observed_without_assuming_zero_or_one(self):
        for top in ((0, 0), (1, 0), (0, 1), (2, 255)):
            with self.subTest(top=top):
                result = self.observe(Fixture(top))
                self.assertEqual(tuple(result['top_level_values'].values()), top)
                self.assertFalse(result['native_receiver_route_qualified'])
                self.assertEqual(result['status'], 'observed_top_level_context_refused')

    def test_invalid_identity_and_base_refuse_before_any_process_callback(self):
        for base in (True, 0, 0x140000001, (1 << 47) - 0x10000):
            fixture = Fixture()
            with self.assertRaises(ValueError):
                self.observe(fixture, module_base=base)
            self.assertEqual(fixture.calls, [])
        fixture = Fixture()
        with self.assertRaises(ValueError):
            self.observe(fixture, client_sha256='0' * 64)
        self.assertEqual(fixture.calls, [])

    def test_changed_incomplete_and_mutable_guard_buffers_refuse_before_state_reads(self):
        for index in (0, 40, 87):
            for kind in ('changed', 'short', 'mutable'):
                fixture = Fixture()
                rva, raw = fixture.guards[index]
                wrong = (bytes((raw[0] ^ 1,)) + raw[1:] if kind == 'changed' else
                         raw[:-1] if kind == 'short' else bytearray(raw))
                fixture.data[fixture.base + rva, len(raw)] = wrong
                with self.assertRaises(ValueError):
                    self.observe(fixture)
                self.assertFalse(any((address, size) in {(fixture.base + first, count) for first, count in fixture.ranges}
                                     for address, size in fixture.calls))

    def test_short_long_and_mutable_sparse_ranges_are_refused(self):
        for wrong in (b'', bytes(11), bytearray(10), None):
            fixture = Fixture()
            rva, size = fixture.ranges[0]
            fixture.data[fixture.base + rva, size] = wrong
            with self.assertRaises(ValueError):
                self.observe(fixture)

    def test_widened_missing_and_duplicate_read_ranges_refuse_before_callback(self):
        self.assertIsNotNone(enabled)
        original = enabled.HOOK_RANGES
        bad_ranges = (original[:-1], original + (original[0],),
                      ((original[0][0], original[0][1] + 1),) + original[1:])
        for ranges in bad_ranges:
            fixture = Fixture()
            with patch.object(enabled, 'HOOK_RANGES', ranges):
                with self.assertRaisesRegex(ValueError, 'range'):
                    self.observe(fixture)
            self.assertEqual(fixture.calls, [])

    def test_code_hook_and_top_flag_changes_during_rechecks_are_refused(self):
        for kind in ('guard', 'hook', 'top'):
            fixture = Fixture()
            changed = False
            def mutate(address, size):
                nonlocal changed
                if changed or (address, size) != (fixture.base + fixture.ranges[-1][0], 1):
                    return
                changed = True
                if kind == 'guard':
                    rva, raw = fixture.guards[0]
                    fixture.data[fixture.base + rva, len(raw)] = bytes((raw[0] ^ 1,)) + raw[1:]
                elif kind == 'hook':
                    fixture.hook(fixture.cells[0]['rva'], 1)
                else:
                    fixture.data[fixture.base + TOP[0][1], 1] = b'\0'
            fixture.after_read = mutate
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'changed|guard'):
                    self.observe(fixture)

    def test_base_and_nested_backend_replacements_are_not_published(self):
        for kind in ('base', 'backend', 'method'):
            fixture = Fixture()
            def mutate(address, size):
                if kind == 'base':
                    fixture.base += 0x10000
                elif kind == 'backend':
                    fixture.backend = lambda address, size: bytes(size)
                else:
                    fixture.read_exact = lambda address, size: bytes(size)
            fixture.after_read = mutate
            with self.assertRaisesRegex(ValueError, 'identity|base|backend'):
                self.observe(fixture)

    def test_session_adapter_preserves_the_fixed_scope_and_underlying_base_identity(self):
        fixture = Fixture()
        class Session:
            def __init__(self):
                self.backend = fixture.read_exact
            def read(self, address, size):
                return self.backend(address, size)
        session = Session()
        self.assertIsNotNone(enabled)
        result = enabled.read_enabled_header_context(session.read, fixture.base, client_sha256=CLIENT_SHA)
        self.assertTrue(result['native_receiver_route_qualified'])
        fixture.after_read = lambda address, size: setattr(fixture, 'base', fixture.base + 0x10000)
        with self.assertRaisesRegex(ValueError, 'identity|base|backend'):
            enabled.read_enabled_header_context(session.read, 0x140000000, client_sha256=CLIENT_SHA)

    def test_proof_producer_and_reused_helper_pins_are_exact_and_checked_before_callback(self):
        self.assertIsNotNone(enabled)
        pins = enabled.source_pins()
        self.assertIn(PROOF_PATH, pins)
        self.assertIn('work/updated_enabled_header_context.py', pins)
        self.assertEqual(pins['work/updated_header_context.py'],
            '95d4337e2b46016ce0efc09e75ba7bfe9bbba14c83ed2259005aec45b7fe1fe1')
        self.assertIn('work/research_updated_enabled_header.py', pins)
        for constant in ('PROOF_SHA256', 'IDENTITY_HELPER_SHA256'):
            fixture = Fixture()
            with patch.object(enabled, constant, '0' * 64):
                with self.assertRaisesRegex(ValueError, 'source|proof|helper'):
                    self.observe(fixture)
            self.assertEqual(fixture.calls, [])

    def test_callback_attribute_side_effects_cannot_widen_sparse_read_ranges(self):
        fixture = Fixture()
        self.assertIsNotNone(enabled)
        original = enabled.HOOK_RANGES
        class Callback:
            changed = False
            def __getattribute__(self, name):
                if name == '__self__' and not object.__getattribute__(self, 'changed'):
                    self.changed = True
                    enabled.HOOK_RANGES = ((0x10000, 65536),)
                return object.__getattribute__(self, name)
            def __call__(self, address, size):
                return fixture.read(address, size)
        try:
            try:
                enabled.read_enabled_header_context(Callback(), fixture.base, client_sha256=CLIENT_SHA)
            except ValueError:
                pass
            self.assertLessEqual(set(fixture.calls), set(fixture.data))
        finally:
            enabled.HOOK_RANGES = original

    def test_source_pin_callback_changes_during_capture_are_refused(self):
        fixture = Fixture()
        self.assertIsNotNone(enabled)
        original = enabled.source_pins
        fixture.after_read = lambda address, size: setattr(enabled, 'source_pins', lambda: {})
        try:
            with self.assertRaisesRegex(ValueError, 'source'):
                self.observe(fixture)
        finally:
            enabled.source_pins = original


if __name__ == '__main__':
    unittest.main()
