"""The current collector binds header observations to the complete class scan."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import observe_updated_client_metadata as collector
from updated_header_context import SOURCE_SHA256


class Reader:
    module_base = 0x140000000
    closed = False

    def __init__(self, *args, **kwargs):
        pass

    def read_exact(self, address, size):
        raise AssertionError('This integration fixture must not read process memory')

    def verify_identity(self):
        pass

    def close(self):
        self.closed = True


class Session:
    calls = bytes_read = 0

    def __init__(self, backend):
        self.backend = backend

    def read(self, address, size):
        return self.backend(address, size)


class Metadata:
    def __init__(self, backend, base):
        self.backend, self.base = backend, base


class HeaderCollectionTests(unittest.TestCase):
    def collect(self, values, hooks=(0, 0)):
        observations = [dict(values=value, zero_gate_qualified=not any(value.values()),
            native_gameplay_qualified=False) for value in values]
        enabled = [dict(top_level_values=value, hook_values={'0x1de39d25': state},
            native_receiver_route_qualified=state == 0, native_gameplay_qualified=False)
            for value, state in zip(values, hooks)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root/'work/native-client-tests/observation'
            folder.parent.mkdir(parents=True)
            saved = []
            with patch.object(collector, 'ROOT', root), \
                    patch.object(collector, 'source_pins', return_value={'fixed': 'proof'}), \
                    patch.object(collector.image, 'validate_plan', return_value={'fixed': 'image'}), \
                    patch.object(collector.image.bounded, 'qualified_shadow_root'), \
                    patch.object(collector.image.bounded, 'verified_pids', return_value=[123]), \
                    patch.object(collector.image.bounded, 'save_json',
                        side_effect=lambda path, value: saved.append(copy.deepcopy(value))), \
                    patch('export_native_replication_metadata.Win32MetadataReader', Reader), \
                    patch('native_replication_metadata_core.MetadataSession', Session), \
                    patch.object(collector, 'UpdatedMetadata', Metadata), \
                    patch.object(collector, 'observe_classes', return_value={'selected_class_count': 0}), \
                    patch('updated_header_context.read_header_context', side_effect=observations) as observed, \
                    patch('updated_enabled_header_context.read_enabled_header_context',
                        side_effect=enabled) as observed_enabled:
                result = collector.collect(root/'game', folder, 123, 456)
            self.assertEqual(observed.call_count, 2)
            self.assertEqual(observed_enabled.call_count, 2)
            self.assertEqual([call.kwargs['client_sha256'] for call in observed.call_args_list],
                             [SOURCE_SHA256, SOURCE_SHA256])
            self.assertEqual(saved, [result])
            return result

    def test_stable_nonzero_branch_is_reported_without_enabling_gameplay(self):
        values = {'global_hook_enable': 1, 'alternate_actor_channel': 0}
        result = self.collect([values, values])
        self.assertTrue(result['complete'])
        self.assertEqual(result['header_context']['values'], values)
        self.assertFalse(result['header_context']['zero_gate_qualified'])
        self.assertFalse(result['header_context']['native_gameplay_qualified'])

    def test_branch_change_across_class_scan_refuses_combined_observation(self):
        result = self.collect([{'global_hook_enable': 0, 'alternate_actor_channel': 0},
                               {'global_hook_enable': 1, 'alternate_actor_channel': 0}])
        self.assertFalse(result['complete'])
        self.assertIn('Header context changed', result['error_reason'])

    def test_enabled_hook_values_are_bound_to_the_complete_class_scan(self):
        value = {'global_hook_enable': 1, 'alternate_actor_channel': 1}
        result = self.collect([value, value])
        self.assertTrue(result['complete'])
        self.assertTrue(result['enabled_header_context']['native_receiver_route_qualified'])
        self.assertFalse(result['enabled_header_context']['native_gameplay_qualified'])

    def test_changed_enabled_hook_state_refuses_combined_observation(self):
        value = {'global_hook_enable': 1, 'alternate_actor_channel': 1}
        result = self.collect([value, value], hooks=(0, 1))
        self.assertFalse(result['complete'])
        self.assertIn('Enabled header context changed', result['error_reason'])


if __name__ == '__main__':
    unittest.main()
