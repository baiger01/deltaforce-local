"""Opt-in interface observation stays scoped through discovery and UAC."""
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

import export_native_replication_metadata as export
import native_actor_interface_metadata as interface
import test_export_native_replication_metadata as fixtures


class InterfaceModeTests(unittest.TestCase):
    def roots(self):
        candidate = {'class_name': 'BP_DFMCharacter_C', 'class_address': 200, 'address': 300}
        klass = {'address': 200}
        return {'named_template_candidates': [candidate], 'classes': [klass]}

    def test_only_selected_pawn_is_observed_without_driver_export(self):
        roots = self.roots()
        roots['named_template_candidates'].append({'class_name': 'BP_GameState_PVPVE_C'})
        session = object()
        with patch.object(export, 'discover_roots', return_value=roots), \
             patch.object(interface, 'observe_actor_interface', return_value={'status': 'observed'}) as observe, \
             patch.object(export, 'export_existing_driver_class') as driver:
            result = export.export_actor_interface_metadata(session, 100)
        observe.assert_called_once_with(session, 100, roots['named_template_candidates'][0], roots['classes'][0])
        driver.assert_not_called()
        self.assertFalse(result['driver_tables_read'])
        self.assertFalse(result['player_property_values_read'])
        self.assertEqual(result['class_cache_exports'], 0)
        self.assertEqual(result['replication_layout_exports'], 0)

    def test_missing_or_ambiguous_template_or_class_refuses_before_interface_read(self):
        variants = []
        missing = self.roots()
        missing['named_template_candidates'] = []
        variants.append(missing)
        duplicate = self.roots()
        duplicate['named_template_candidates'] *= 2
        variants.append(duplicate)
        wrong_class = self.roots()
        wrong_class['classes'][0]['address'] = 201
        variants.append(wrong_class)
        for roots in variants:
            with self.subTest(roots=roots), patch.object(export, 'discover_roots', return_value=roots), \
                 patch.object(interface, 'observe_actor_interface') as observe:
                with self.assertRaises(ValueError):
                    export.export_actor_interface_metadata(object(), 100)
                observe.assert_not_called()

    def test_collect_mode_skips_cvar_and_full_export_and_discards_stale_process_results(self):
        fixture = fixtures.Fixture()
        for stale in (False, True):
            reader = SimpleNamespace(read_exact=fixture.memory.read, module_base=fixture.base,
                verify_identity=Mock(side_effect=ValueError('stale process') if stale else None),
                find_module=Mock(return_value=fixture.base), close=Mock())
            result = {'actor_interface_observations': [{'status': 'observed'}],
                      'class_cache_exports': 0, 'replication_layout_exports': 0}
            with self.subTest(stale=stale), \
                 patch.object(export, 'validate_source', return_value=(Path('fake.exe'), 0x20000000)), \
                 patch.object(export, 'Win32MetadataReader', return_value=reader), \
                 patch.object(export, 'export_actor_interface_metadata', return_value=result) as observe, \
                 patch.object(export, 'export_metadata') as full, \
                 patch.object(export, 'observe_dynamic_address_switch_cvar') as cvar, \
                 patch.object(export, 'save'):
                report = export.collect('fake-root', 'fake-output', pid=123, created_at=5000.0,
                                        actor_interface_only=True)
            observe.assert_called_once()
            full.assert_not_called()
            cvar.assert_not_called()
            reader.close.assert_called_once()
            self.assertFalse(report['playable_map_verified'])
            self.assertFalse(report['process_memory_written'])
            if stale:
                self.assertEqual(report['status'], 'metadata_export_refused')
                self.assertNotIn('actor_interface_observations', report)
            else:
                self.assertEqual(report['status'], 'metadata_export_complete')
                self.assertEqual(len(report['actor_interface_observations']), 1)

    def test_uac_preserves_mode_and_worker_pins_the_added_reader(self):
        parent = fixtures.ElevationTests()
        with parent.mocked_parent() as env:
            env.args.actor_interface_only = True
            export.request_read_only_elevation(env.args)
        argv = parent.split_windows_arguments(env.capture['parameters'])
        self.assertEqual(argv[-1], '--actor-interface-only')
        base_pins = export.source_pins()
        mode_pins = export.source_pins(actor_interface_only=True)
        self.assertEqual(set(mode_pins) - set(base_pins), {'work/native_actor_interface_metadata.py'})
        argv = parent.worker_arguments(extra=('--actor-interface-only',))
        with patch.object(export.sys, 'argv', argv), \
             patch.object(export.C, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=Mock(return_value=True)))), \
             patch.object(export, 'source_pins', return_value={'fixed-source': 'a'*64}) as pins, \
             patch.object(export, 'collect', return_value={'status': 'metadata_export_complete'}) as collect, \
             redirect_stdout(io.StringIO()):
            export.main()
        pins.assert_called_once_with(actor_interface_only=True)
        collect.assert_called_once_with(Path('mock game 目录'), Path(argv[4]), pid=123,
                                        created_at=5000.125, actor_interface_only=True)

    def test_worker_pin_change_is_recorded_before_exit_without_reading_process(self):
        parent = fixtures.ElevationTests()
        argv = parent.worker_arguments(extra=('--actor-interface-only',))
        with patch.object(export.sys, 'argv', argv), \
             patch.object(export.C, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=Mock(return_value=True)))), \
             patch.object(export, 'source_pins', return_value={'changed-source': 'b'*64}), \
             patch.object(export, 'collect') as collect, \
             patch.object(export, 'save') as save, \
             patch.object(export.sys, 'stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                export.main()
        collect.assert_not_called()
        report = save.call_args.args[1]
        self.assertEqual(report['status'], 'metadata_reader_preflight_refused')
        self.assertIn('source identity changed', report['reason'])
        self.assertFalse(report['process_memory_read'])


if __name__ == '__main__':
    unittest.main()
