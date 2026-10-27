"""Only sealed instruction spans and two current header-gate bytes are read."""
import importlib
import unittest
from unittest.mock import patch


try:
    header = importlib.import_module('updated_header_context')
except ModuleNotFoundError:
    header = None

CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
CELLS = (0x1de36180, 0x1e322935)
GUARDS = ((0x4e24db6, bytes.fromhex('803dc313011900488bd97423')),
          (0x4977e22, bytes.fromhex('803d0cab9a1900488bd7488bcb740b488b03ff9050030000eb05e8ef96ee0d')))


class Fixture:
    def __init__(self, values=(0, 0)):
        self.base = 0x140000000
        self.data = {self.base + rva: raw for rva, raw in GUARDS}
        self.data.update({self.base + rva: bytes((value,)) for rva, value in zip(CELLS, values)})
        self.calls = []
        self.after_read = None
        self.backend = self.read

    def read(self, address, size):
        self.calls.append((address, size))
        raw = self.data[address]
        if len(raw) != size:
            raise AssertionError('An unqualified span was requested')
        if self.after_read is not None:
            self.after_read(address, size)
        return raw

    def read_exact(self, address, size):
        return self.backend(address, size)


class HeaderContextTests(unittest.TestCase):
    def observe(self, fixture, **changes):
        self.assertIsNotNone(header, 'The callback-only current header gate reader is missing')
        return header.read_header_context(fixture.read_exact, changes.get('module_base', fixture.base),
            client_sha256=changes.get('client_sha256', CLIENT_SHA))

    def test_zero_values_are_observed_and_only_the_four_exact_spans_are_read(self):
        fixture = Fixture()
        result = self.observe(fixture)
        self.assertEqual(result['values'], {'global_hook_enable': 0, 'alternate_actor_channel': 0})
        self.assertTrue(result['zero_gate_qualified'])
        self.assertTrue(result['source_instructions_rechecked'])
        self.assertFalse(result['native_gameplay_qualified'])
        self.assertFalse(result['native_function_called'])
        self.assertFalse(result['atomic_snapshot'])
        expected = {(fixture.base + rva, len(raw)) for rva, raw in GUARDS}
        expected.update((fixture.base + rva, 1) for rva in CELLS)
        self.assertEqual(set(fixture.calls), expected)
        self.assertEqual(len(fixture.calls), 12)
        self.assertEqual(result['read_calls'], 12)
        self.assertEqual(result['read_bytes'], 135)
        self.assertNotIn((fixture.base + 0x1de39d25, 1), fixture.calls)

    def test_nonzero_values_are_preserved_and_refuse_zero_gate_qualification(self):
        for values in ((1, 0), (0, 1), (2, 255)):
            with self.subTest(values=values):
                result = self.observe(Fixture(values))
                self.assertEqual(tuple(result['values'].values()), values)
                self.assertFalse(result['zero_gate_qualified'])
                self.assertEqual(result['status'], 'observed_nonzero_gate_refused')

    def test_exact_current_identity_and_valid_aligned_user_mode_base_are_required(self):
        for base in (None, True, 0, 0xffff, 0x140000001, (1 << 47) - 0x10000):
            fixture = Fixture()
            with self.subTest(base=base):
                with self.assertRaises(ValueError):
                    self.observe(fixture, module_base=base)
                self.assertEqual(fixture.calls, [])
        for sha in ('0' * 64, CLIENT_SHA.upper(), None):
            fixture = Fixture()
            with self.assertRaises(ValueError):
                self.observe(fixture, client_sha256=sha)
            self.assertEqual(fixture.calls, [])

    def test_wrong_or_incomplete_instruction_guards_fail_before_mutable_cell_reads(self):
        for rva, raw in GUARDS:
            for wrong in (raw[:-1], bytes((raw[0] ^ 1,)) + raw[1:], bytearray(raw), None):
                fixture = Fixture()
                fixture.data[fixture.base + rva] = wrong
                with self.subTest(rva=hex(rva), wrong_type=type(wrong).__name__):
                    with self.assertRaises(ValueError):
                        self.observe(fixture)
                    self.assertFalse(any(address in (fixture.base + cell for cell in CELLS)
                                         for address, size in fixture.calls))

    def test_incomplete_mutable_cell_reads_and_callback_exceptions_fail_closed(self):
        for wrong in (b'', b'\0\0', bytearray(b'\0'), None):
            fixture = Fixture()
            fixture.data[fixture.base + CELLS[0]] = wrong
            with self.assertRaises(ValueError):
                self.observe(fixture)
        fixture = Fixture()
        def unavailable(address, size):
            raise OSError('fixture unavailable')
        fixture.backend = unavailable
        with self.assertRaises(ValueError):
            self.observe(fixture)

    def test_cell_and_code_changes_after_a_later_callback_are_not_published(self):
        for target in (CELLS[0], GUARDS[0][0]):
            fixture = Fixture()
            changed = False
            def mutate(address, size):
                nonlocal changed
                if not changed and address == fixture.base + CELLS[1]:
                    changed = True
                    old = fixture.data[fixture.base + target]
                    fixture.data[fixture.base + target] = bytes((old[0] ^ 1,)) + old[1:]
            fixture.after_read = mutate
            with self.assertRaisesRegex(ValueError, 'changed|guard'):
                self.observe(fixture)

    def test_callback_owner_base_backend_and_method_replacement_are_rechecked(self):
        for kind in ('base', 'backend', 'method'):
            fixture = Fixture()
            changed = False
            def mutate(address, size):
                nonlocal changed
                if changed:
                    return
                changed = True
                if kind == 'base':
                    fixture.base += 0x10000
                elif kind == 'backend':
                    fixture.backend = lambda address, size: b'\0' * size
                else:
                    fixture.read_exact = lambda address, size: b'\0' * size
            fixture.after_read = mutate
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'identity|base|backend'):
                    self.observe(fixture)

    def test_nested_session_backend_identity_is_rechecked(self):
        fixture = Fixture()
        class Session:
            def __init__(self):
                self.backend = fixture.read_exact
            def read(self, address, size):
                return self.backend(address, size)
        session = Session()
        fixture.after_read = lambda address, size: setattr(fixture, 'base', fixture.base + 0x10000)
        self.assertIsNotNone(header)
        with self.assertRaisesRegex(ValueError, 'identity|base|backend'):
            header.read_header_context(session.read, 0x140000000, client_sha256=CLIENT_SHA)

    def test_plain_callback_is_supported_without_inventing_process_identity(self):
        fixture = Fixture()
        self.assertIsNotNone(header)
        result = header.read_header_context(lambda address, size: fixture.read(address, size),
                                            fixture.base, client_sha256=CLIENT_SHA)
        self.assertTrue(result['zero_gate_qualified'])
        self.assertFalse(result['process_identity_verified'])

    def test_source_pins_cover_exact_proofs_and_module_and_refuse_changed_sources_before_reads(self):
        self.assertIsNotNone(header)
        pins = header.source_pins()
        self.assertEqual(set(pins), {'work/updated_header_context.py',
            'work/research_updated_header_context_79fb7b10_v1.json',
            'work/research_updated_header_cells_79fb7b10_v3.json'})
        for name in ('HEADER_CONTEXT_SHA256', 'HEADER_CELLS_SHA256'):
            fixture = Fixture()
            with patch.object(header, name, '0' * 64):
                with self.assertRaisesRegex(ValueError, 'proof|source'):
                    self.observe(fixture)
            self.assertEqual(fixture.calls, [])

    def test_source_pin_function_changes_during_callback_are_refused(self):
        fixture = Fixture()
        self.assertIsNotNone(header)
        original = header.source_pins
        def mutate(address, size):
            header.source_pins = lambda: {}
        fixture.after_read = mutate
        try:
            with self.assertRaisesRegex(ValueError, 'source'):
                self.observe(fixture)
        finally:
            header.source_pins = original

    def test_callback_attribute_side_effects_cannot_expand_the_fixed_read_allowlist(self):
        fixture = Fixture()
        self.assertIsNotNone(header)
        original_cells = header.CELLS
        class Callback:
            changed = False
            def __getattribute__(self, name):
                if name == '__self__' and not object.__getattribute__(self, 'changed'):
                    self.changed = True
                    header.CELLS = (('global_hook_enable', 0x20000000), ('alternate_actor_channel', CELLS[1]))
                return object.__getattribute__(self, name)
            def __call__(self, address, size):
                return fixture.read(address, size)
        try:
            try:
                header.read_header_context(Callback(), fixture.base, client_sha256=CLIENT_SHA)
            except ValueError:
                pass
            expected = {(fixture.base + rva, len(raw)) for rva, raw in GUARDS}
            expected.update((fixture.base + rva, 1) for rva in CELLS)
            self.assertLessEqual(set(fixture.calls), expected)
        finally:
            header.CELLS = original_cells


if __name__ == '__main__':
    unittest.main()
