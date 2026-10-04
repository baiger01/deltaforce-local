"""Offline loading compensation with actual registry/name discovery fixtures."""
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import export_native_replication_metadata as export
import native_metadata_objects as objects
from native_replication_metadata_core import MetadataSession
from test_export_native_replication_metadata import Fixture
from test_native_metadata_archetypes import add_candidate


class LoadingFixture(Fixture):
    def hide_initial_targets(self):
        # These remain valid Class objects, but have a different literal name.
        # Their existing instances may still use them without invalid pointers.
        for address in (self.pc, self.gs):
            self.describe(address, 'Actor', self.blueprint_type, self.actor_type,
                          outer=self.packages['/Game/Test/PC' if address == self.pc else '/Game/Test/GS'])

    def append_class(self, name):
        package = self.packages['/Game/Test/PC' if name == 'BP_DFMPlayerController_C' else '/Game/Test/GS']
        address = self.allocate()
        self.describe(address, name, self.blueprint_type, self.actor_type, outer=package)
        self.memory.write(self.base + objects.COUNT_RVA, struct.pack('<i', len(self.rows)))
        return address

    def append_ordinary_actor(self):
        address = self.allocate()
        self.describe(address, 'Actor', self.actor_type, 0)
        self.memory.write(self.base + objects.COUNT_RVA, struct.pack('<i', len(self.rows)))
        return address


class LoadingCompensationTests(unittest.TestCase):
    def growth_iterator(self, fixture, additions, *, templates=False):
        original = export.iter_object_records
        calls, new_addresses = [], []

        def iterator(*args, **kwargs):
            calls.append(kwargs)
            records = original(*args, **kwargs)
            first = next(records)
            # The real iterator already captured and verified its initial batch.
            # Appended records are outside that batch and its fixed index range.
            plan = additions[len(calls)-1] if len(calls) <= len(additions) else ()
            for name in plan:
                address = fixture.append_class(name) if name else fixture.append_ordinary_actor()
                new_addresses.append(address)
                if templates and name:
                    package = fixture.packages['/Game/Test/PC' if name == 'BP_DFMPlayerController_C' else '/Game/Test/GS']
                    add_candidate(fixture, address, name, package, len(new_addresses))
            yield first
            yield from records

        return iterator, calls, new_addresses

    def collect_fixture(self, fixture, iterator, *, verify_effect=None, backend=None):
        reader = SimpleNamespace(read_exact=backend or fixture.memory.read, module_base=fixture.base,
            verify_identity=Mock(side_effect=verify_effect),
            find_module=Mock(return_value=fixture.base), close=Mock(),
            deadline=export.time.monotonic() + export.MAX_DURATION_SECONDS)
        with patch.object(export, 'validate_source', return_value=(Path('fake-client.exe'), 0x20000000)), \
             patch.object(export, 'Win32MetadataReader', return_value=reader) as opened, \
             patch.object(export, 'iter_object_records', side_effect=iterator), \
             patch.object(export, 'export_existing_driver_class', side_effect=fixture.cache_result) as tables, \
             patch.object(export, 'save') as saved:
            report = export.collect('fake-root', 'fake-output', pid=123, created_at=5000.0)
        opened.assert_called_once_with(Path('fake-client.exe'), 0x20000000, 123, 5000.0)
        reader.close.assert_called_once()
        saved.assert_called_once_with('fake-output', report)
        return report, reader, tables

    def test_appended_targets_are_found_by_one_frozen_tail(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        initial_count = len(fixture.rows)
        iterator, calls, new_addresses = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])
        report, reader, tables = self.collect_fixture(fixture, iterator)
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertEqual(len(calls), 2)
        roots = report['roots']
        self.assertEqual(roots['missing_target_classes'], [])
        self.assertEqual({row['address'] for row in roots['classes']}, {fixture.pawn, *new_addresses})
        self.assertEqual([row['address'] for row in roots['drivers']], [fixture.driver])
        self.assertEqual(tables.call_count, 3)  # No first-pass table exports.
        self.assertEqual(reader.verify_identity.call_count, 2)  # Before retry and final.
        diagnostics = report['loading_compensation']
        self.assertEqual(diagnostics['selected_attempt'], 1)
        self.assertTrue(diagnostics['additional_scan_attempted'])
        first, second = diagnostics['attempts']
        self.assertEqual(first['registry_scan']['initial_index_range'], [0, initial_count])
        self.assertEqual(first['registry_scan']['final_observed_count'], initial_count + 2)
        self.assertEqual(second['registry_scan']['initial_index_range'], [initial_count, initial_count + 2])
        self.assertEqual(calls[1]['start_index'], initial_count)
        self.assertEqual(calls[1]['stop_index'], initial_count + 2)
        self.assertEqual(second['pass_records_scanned'], 2)
        self.assertEqual(first['selected_class_count'], 1)
        self.assertEqual(second['selected_class_count'], 3)
        self.assertFalse(roots['complete_global_inventory'])
        self.assertTrue(roots['selected_roots_rechecked'])
        self.assertNotIn('classes', first)  # Diagnostics never expose continuation state.

    def test_tail_does_not_claim_to_rescan_a_previously_empty_old_slot(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        index = fixture.rows.index(fixture.false_target)
        fixture.memory.entry(index, 0, 0)
        iterator, calls, _ = self.growth_iterator(fixture, [('BP_GameState_PVPVE_C',)])

        def fill_old_slot():
            fixture.memory.entry(index, fixture.false_target, 8001)
            fixture.describe(fixture.false_target, 'BP_DFMPlayerController_C',
                fixture.blueprint_type, fixture.actor_type, outer=fixture.packages['/Game/Test/PC'])

        with patch.object(export, 'iter_object_records', side_effect=iterator):
            roots = export.discover_roots_with_loading_compensation(
                fixture.session(), fixture.base, before_rescan=fill_old_slot,
                remaining_time=lambda: 1000.0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(roots['missing_target_classes'], ['BP_DFMPlayerController_C'])
        self.assertNotIn(fixture.false_target, {row['address'] for row in roots['classes']})
        self.assertFalse(roots['complete_global_inventory'])

    def test_old_address_classification_is_not_merged_after_generation_change(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])

        def replace_old_pawn_metadata():
            fixture.serial(fixture.pawn, 9001)
            fixture.describe(fixture.pawn, 'Actor', fixture.blueprint_type, fixture.actor_type,
                             outer=fixture.packages['/Game/Test/Pawn'])

        with patch.object(export, 'iter_object_records', side_effect=iterator):
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                export.discover_roots_with_loading_compensation(
                    fixture.session(), fixture.base, before_rescan=replace_old_pawn_metadata,
                    remaining_time=lambda: 1000.0)
        self.assertEqual(len(calls), 1)  # Refused before any tail slot is read.

    def test_further_growth_and_missing_target_never_causes_third_scan(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C',), ('BP_GameState_PVPVE_C',)])
        report, _, tables = self.collect_fixture(fixture, iterator)
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertEqual(len(calls), 2)
        roots = report['roots']
        self.assertEqual(roots['missing_target_classes'], ['BP_GameState_PVPVE_C'])
        self.assertGreater(roots['registry_scan']['final_observed_count'], roots['registry_scan']['initial_count'])
        self.assertEqual(tables.call_count, 2)
        self.assertEqual(report['loading_compensation']['maximum_additional_scans'], 1)

    def test_missing_targets_without_growth_do_not_rescan(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [])
        report, reader, _ = self.collect_fixture(fixture, iterator)
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertEqual(len(calls), 1)
        self.assertEqual(reader.verify_identity.call_count, 1)
        self.assertFalse(report['loading_compensation']['additional_scan_attempted'])

    def test_growth_without_missing_targets_does_not_rescan(self):
        fixture = LoadingFixture()
        for ordinal, (klass, name, package) in enumerate((
            (fixture.pawn, 'BP_DFMCharacter_C', '/Game/Test/Pawn'),
            (fixture.pc, 'BP_DFMPlayerController_C', '/Game/Test/PC'),
            (fixture.gs, 'BP_GameState_PVPVE_C', '/Game/Test/GS'))):
            add_candidate(fixture, klass, name, fixture.packages[package], ordinal)
        iterator, calls, _ = self.growth_iterator(fixture, [(None,)])
        report, _, _ = self.collect_fixture(fixture, iterator)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['roots']['missing_target_classes'], [])
        self.assertGreater(report['roots']['registry_scan']['final_observed_count'],
                           report['roots']['registry_scan']['initial_count'])
        self.assertEqual(report['loading_compensation']['selected_attempt'], 0)

    def test_appended_templates_are_found_even_when_all_classes_were_already_selected(self):
        fixture = LoadingFixture()
        add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C', fixture.packages['/Game/Test/Pawn'])
        initial = len(fixture.rows)
        original, calls = export.iter_object_records, []
        def append_after_initial_snapshot(*args, **kwargs):
            calls.append(kwargs)
            records = original(*args, **kwargs)
            first = next(records)
            if len(calls) == 1:
                add_candidate(fixture, fixture.pc, 'BP_DFMPlayerController_C', fixture.packages['/Game/Test/PC'], 1)
                add_candidate(fixture, fixture.gs, 'BP_GameState_PVPVE_C', fixture.packages['/Game/Test/GS'], 2)
            yield first
            yield from records
        report, _, _ = self.collect_fixture(fixture, append_after_initial_snapshot)
        self.assertEqual(report['status'], 'metadata_export_complete')
        roots = report['roots']
        self.assertEqual(roots['missing_target_classes'], [])
        self.assertEqual(roots['missing_named_templates'], [])
        self.assertEqual(roots['pass_records_scanned'], 2)
        diagnostics = report['loading_compensation']
        self.assertEqual(diagnostics['attempts'][0]['missing_target_classes'], [])
        self.assertEqual(len(diagnostics['attempts'][0]['missing_named_templates']), 2)
        self.assertTrue(diagnostics['additional_scan_attempted'])
        self.assertEqual(calls[1]['start_index'], initial)
        self.assertEqual(calls[1]['stop_index'], initial+2)

    def test_second_scan_failure_cannot_commit_first_pawn_or_export_tables(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])

        def break_second_backreference():
            fixture.memory.write(fixture.pawn + objects.OBJECT_INDEX_OFFSET, struct.pack('<i', 999))

        report, _, tables = self.collect_fixture(fixture, iterator, verify_effect=break_second_backreference)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(len(calls), 1)
        self.assertIn('object_', report['reason'])
        self.assertNotIn('roots', report)
        self.assertNotIn('driver_class_exports', report)
        self.assertFalse(report['runtime_class_cache_recovered'])
        tables.assert_not_called()
        diagnostics = report['loading_compensation']
        self.assertTrue(diagnostics['additional_scan_attempted'])
        self.assertIsNone(diagnostics['selected_attempt'])
        self.assertEqual(len(diagnostics['attempts']), 1)

    def test_identity_change_before_second_pass_refuses_without_fallback(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])
        report, _, tables = self.collect_fixture(fixture, iterator,
            verify_effect=ValueError('Client process identity changed'))
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(len(calls), 1)
        self.assertNotIn('roots', report)
        tables.assert_not_called()
        self.assertIsNone(report['loading_compensation']['selected_attempt'])

    def test_read_call_and_byte_budgets_are_shared_not_reset(self):
        for budget in ('calls', 'bytes'):
            with self.subTest(budget=budget):
                fixture = LoadingFixture()
                fixture.hide_initial_targets()
                iterator, calls, _ = self.growth_iterator(fixture, [
                    ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])
                session = fixture.session()
                spent = []

                def constrain_remaining_budget():
                    spent.append((session.calls, session.bytes_read))
                    if budget == 'calls':
                        session.max_calls = session.calls + 1
                    else:
                        session.max_bytes = session.bytes_read + 4

                diagnostics = {}
                with patch.object(export, 'iter_object_records', side_effect=iterator):
                    with self.assertRaisesRegex(ValueError, 'read budget exhausted'):
                        export.discover_roots_with_loading_compensation(session, fixture.base,
                            diagnostics=diagnostics, before_rescan=constrain_remaining_budget,
                            remaining_time=lambda: 1000.0)
                self.assertEqual(len(calls), 1)  # Root recheck shares the exhausted budget.
                self.assertGreater(spent[0][0], 0)
                self.assertEqual((session.calls, session.bytes_read), (spent[0][0]+1, spent[0][1]+4))
                self.assertIsNone(diagnostics['selected_attempt'])

    def test_existing_backend_deadline_is_not_extended_for_second_pass(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])
        clock = {'now': 1.0, 'deadline': 2.0}

        def backend(address, size):
            if clock['now'] > clock['deadline']:
                raise ValueError('Metadata collection time budget exhausted')
            return fixture.memory.read(address, size)

        def expire_original_deadline():
            clock['now'] = 3.0

        report, _, tables = self.collect_fixture(fixture, iterator,
            backend=backend, verify_effect=expire_original_deadline)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertIn('time budget exhausted', report['reason'])
        self.assertEqual(clock['deadline'], 2.0)
        self.assertEqual(len(calls), 1)
        self.assertNotIn('roots', report)
        tables.assert_not_called()

    def test_initial_refusal_does_not_start_compensation(self):
        fixture = LoadingFixture()
        diagnostics = {}
        with patch.object(export, 'discover_roots', side_effect=ValueError('initial refusal')) as discover:
            with self.assertRaisesRegex(ValueError, 'initial refusal'):
                export.discover_roots_with_loading_compensation(
                    fixture.session(), fixture.base, diagnostics=diagnostics)
        discover.assert_called_once()
        self.assertFalse(diagnostics['additional_scan_attempted'])
        self.assertEqual(diagnostics['attempts'], [])
        self.assertIsNone(diagnostics['selected_attempt'])

    def policy_roots(self, *, initial=10, final=20):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        roots = export.discover_roots(fixture.session(), fixture.base)
        roots['registry_scan'].update(initial_count=initial, final_observed_count=final,
                                      initial_index_range=[0, initial])
        return fixture, roots

    def test_actual_trial_count_ratio_skips_unstarted_scan_with_checked_first_roots(self):
        fixture, first = self.policy_roots(initial=121202, final=286994)
        remaining = Mock(return_value=68.363)
        check = Mock()
        with patch.object(export, 'discover_roots', return_value=first) as discover, \
             patch.object(export.time, 'monotonic', side_effect=(0.0, 51.637)):
            roots = export.discover_roots_with_loading_compensation(
                fixture.session(), fixture.base, remaining_time=remaining, before_rescan=check)
        discover.assert_called_once()
        check.assert_not_called()
        remaining.assert_called_once()
        self.assertIs(roots, first)
        diagnostics = roots['loading_compensation']
        self.assertEqual(diagnostics['first_duration_seconds'], 51.637)
        self.assertAlmostEqual(diagnostics['estimated_additional_required_seconds'], 93.292700, places=6)
        self.assertEqual(diagnostics['export_reserve_seconds'], 5.0)
        self.assertFalse(diagnostics['estimate_is_deadline_guarantee'])
        self.assertFalse(diagnostics['additional_scan_attempted'])
        self.assertEqual(diagnostics['selected_attempt'], 0)
        self.assertEqual(diagnostics['additional_scan_skip_reason'],
                         'insufficient_remaining_time_for_estimated_scan_and_export')
        self.assertEqual(roots['missing_target_classes'],
                         ['BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C'])

    def test_enough_budget_at_reserved_boundary_starts_one_second_pass(self):
        fixture, first = self.policy_roots()
        second = export.discover_roots(fixture.session(), fixture.base)
        remaining = Mock(return_value=30.0)  # 20s * ((20-10)/10) * 1.25 +5s.
        check = Mock()
        with patch.object(export, 'discover_roots', side_effect=(first, second)) as discover, \
             patch.object(export.time, 'monotonic', side_effect=(0.0, 20.0, 20.0, 24.0)):
            roots = export.discover_roots_with_loading_compensation(
                fixture.session(), fixture.base, remaining_time=remaining, before_rescan=check)
        self.assertEqual(discover.call_count, 2)
        check.assert_called_once_with()
        self.assertEqual(remaining.call_count, 2)
        self.assertIs(roots, second)
        diagnostics = roots['loading_compensation']
        self.assertEqual(diagnostics['estimated_additional_required_seconds'], 30.0)
        self.assertEqual(diagnostics['attempts'][1]['duration_seconds'], 4.0)
        self.assertTrue(diagnostics['additional_scan_attempted'])
        self.assertNotIn('additional_scan_skip_reason', diagnostics)

    def test_identity_check_time_is_charged_before_second_scan(self):
        fixture, first = self.policy_roots()
        remaining = Mock(side_effect=(18.0, 17.0))  # Required:10s *1 *1.25 +5s=17.5s.
        check = Mock()
        with patch.object(export, 'discover_roots', return_value=first) as discover, \
             patch.object(export.time, 'monotonic', side_effect=(0.0, 10.0)):
            roots = export.discover_roots_with_loading_compensation(
                fixture.session(), fixture.base, remaining_time=remaining, before_rescan=check)
        discover.assert_called_once()
        check.assert_called_once_with()
        diagnostics = roots['loading_compensation']
        self.assertFalse(diagnostics['additional_scan_attempted'])
        self.assertEqual(diagnostics['remaining_time_after_identity_check_seconds'], 17.0)
        self.assertEqual(diagnostics['additional_scan_skip_reason'],
                         'insufficient_remaining_time_after_identity_check')
        self.assertEqual(diagnostics['selected_attempt'], 0)

    def test_unknown_remaining_time_skips_instead_of_starting_unbudgeted_pass(self):
        fixture, first = self.policy_roots()
        with patch.object(export, 'discover_roots', return_value=first) as discover:
            roots = export.discover_roots_with_loading_compensation(fixture.session(), fixture.base)
        discover.assert_called_once()
        self.assertEqual(roots['loading_compensation']['additional_scan_skip_reason'],
                         'remaining_time_unavailable')
        self.assertFalse(roots['loading_compensation']['additional_scan_attempted'])

    def test_unmeasurable_first_cost_skips_and_invalid_budget_refuses(self):
        for initial, duration in ((0, 10.0), (10, 0.0)):
            with self.subTest(initial=initial, duration=duration):
                fixture, first = self.policy_roots(initial=initial)
                with patch.object(export, 'discover_roots', return_value=first) as discover, \
                     patch.object(export.time, 'monotonic', side_effect=(0.0, duration)):
                    roots = export.discover_roots_with_loading_compensation(
                        fixture.session(), fixture.base, remaining_time=lambda: 1000.0)
                discover.assert_called_once()
                self.assertEqual(roots['loading_compensation']['additional_scan_skip_reason'],
                                 'additional_scan_cost_unestimated')
        for value in (True, float('nan'), float('inf'), '120'):
            with self.subTest(value=value):
                fixture, first = self.policy_roots()
                with patch.object(export, 'discover_roots', return_value=first) as discover, \
                     patch.object(export.time, 'monotonic', side_effect=(0.0, 10.0)):
                    with self.assertRaisesRegex(ValueError, 'finite seconds'):
                        export.discover_roots_with_loading_compensation(
                            fixture.session(), fixture.base, remaining_time=lambda: value)
                discover.assert_called_once()

    def test_collect_keeps_original_deadline_and_fits_a_small_tail(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        iterator, calls, _ = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')])
        original = export.discover_roots
        clock = {'now': 0.0}

        def delayed_discovery(*args, **kwargs):
            roots = original(*args, **kwargs)
            clock['now'] = 51.637
            return roots

        with patch.object(export.time, 'monotonic', side_effect=lambda: clock['now']), \
             patch.object(export, 'discover_roots', side_effect=delayed_discovery):
            report, reader, tables = self.collect_fixture(fixture, iterator)
        self.assertEqual(reader.deadline, 120.0)
        self.assertEqual(report['status'], 'metadata_export_complete')
        self.assertEqual(len(calls), 2)
        self.assertEqual(tables.call_count, 3)
        self.assertEqual(report['roots']['missing_target_classes'], [])
        self.assertTrue(report['roots']['selected_roots_rechecked'])
        self.assertFalse(report['roots']['complete_global_inventory'])
        self.assertEqual(report['loading_compensation']['remaining_time_before_additional_scan_seconds'], 68.363)
        self.assertTrue(report['loading_compensation']['additional_scan_attempted'])
        self.assertNotIn('additional_scan_skip_reason', report['loading_compensation'])

    def test_tail_recovers_both_class_and_default_template_with_old_pawn_retained(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        pawn_template = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C',
                                      fixture.packages['/Game/Test/Pawn'])
        first_count = len(fixture.rows)
        iterator, calls, new_addresses = self.growth_iterator(fixture, [
            ('BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C')], templates=True)
        report, _, tables = self.collect_fixture(fixture, iterator)
        self.assertEqual(report['status'], 'metadata_export_complete')
        roots = report['roots']
        self.assertEqual(roots['missing_target_classes'], [])
        self.assertEqual(roots['missing_named_templates'], [])
        self.assertEqual({row['class_address'] for row in roots['named_template_candidates']},
                         {fixture.pawn, *new_addresses})
        self.assertIn(pawn_template, {row['address'] for row in roots['named_template_candidates']})
        self.assertEqual(calls[1]['start_index'], first_count)
        self.assertEqual(calls[1]['stop_index'], first_count+4)
        self.assertEqual(roots['pass_records_scanned'], 4)
        self.assertEqual(tables.call_count, 3)

    def test_old_name_or_outer_change_before_tail_cannot_commit_roots(self):
        for change in ('name', 'outer'):
            with self.subTest(change=change):
                fixture = LoadingFixture()
                fixture.hide_initial_targets()
                iterator, calls, _ = self.growth_iterator(fixture, [('BP_DFMPlayerController_C',)])
                def mutate():
                    if change == 'name':
                        fixture.memory.write(fixture.pawn+0x1c, fixture.tokens['Actor'])
                    else:
                        fixture.memory.write(fixture.pawn+0x10, struct.pack('<Q', fixture.packages['/Game/Test/GS']))
                report, _, tables = self.collect_fixture(fixture, iterator, verify_effect=mutate)
                self.assertEqual(report['status'], 'metadata_export_refused')
                self.assertNotIn('roots', report)
                self.assertEqual(len(calls), 1)
                tables.assert_not_called()

    def test_old_template_change_during_tail_is_rechecked_after_tail(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        template = add_candidate(fixture, fixture.pawn, 'BP_DFMCharacter_C',
                                 fixture.packages['/Game/Test/Pawn'])
        iterator, calls, _ = self.growth_iterator(fixture, [('BP_DFMPlayerController_C',)])
        def changing(*args, **kwargs):
            for row in iterator(*args, **kwargs):
                if len(calls) == 2:
                    fixture.memory.write(template+0x10, struct.pack('<Q', fixture.packages['/Game/Test/PC']))
                yield row
        report, _, tables = self.collect_fixture(fixture, changing)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(len(calls), 2)
        self.assertIn('template candidate binding changed', report['reason'])
        self.assertNotIn('roots', report)
        tables.assert_not_called()

    def test_real_trial_tail_estimate_fits_original_remaining_budget(self):
        fixture, first = self.policy_roots(initial=119720, final=209153)
        second = export.discover_roots(fixture.session(), fixture.base)
        with patch.object(export, 'discover_roots', side_effect=(first, second)) as discover, \
             patch.object(export.time, 'monotonic', side_effect=(0.0, 54.141924, 54.141924, 94.0)):
            roots = export.discover_roots_with_loading_compensation(fixture.session(), fixture.base,
                before_rescan=lambda: None, remaining_time=lambda: 65.628161)
        diagnostics = roots['loading_compensation']
        self.assertTrue(diagnostics['additional_scan_attempted'])
        self.assertEqual(diagnostics['frozen_tail_index_range'], [119720, 209153])
        self.assertAlmostEqual(diagnostics['estimated_additional_required_seconds'], 55.556243, places=5)
        self.assertEqual(discover.call_args.kwargs['start_index'], 119720)
        self.assertEqual(discover.call_args.kwargs['stop_index'], 209153)

    def test_total_unique_descriptor_bound_is_not_reset_when_cache_is_trimmed(self):
        fixture = LoadingFixture()
        fixture.hide_initial_targets()
        session, state = fixture.session(), {}
        first = export.discover_roots(session, fixture.base, _state=state)
        initial = len(fixture.rows)
        fixture.append_class('BP_DFMPlayerController_C')
        with patch.object(export, 'MAX_CLASS_DESCRIPTORS', first['unique_class_descriptors_read']):
            with self.assertRaisesRegex(ValueError, 'descriptor discovery exceeds local bound'):
                export.discover_roots(session, fixture.base, _state=state,
                                      start_index=initial, stop_index=len(fixture.rows))

    def test_tail_without_checked_private_state_is_refused(self):
        fixture = LoadingFixture()
        fixture.memory.reads.clear()
        with self.assertRaisesRegex(ValueError, 'requires checked first-pass state'):
            export.discover_roots(fixture.session(), fixture.base, start_index=1, stop_index=2)
        self.assertEqual(fixture.memory.reads, [])

    def test_collect_preserves_registry_change_context_without_accepting_partial_roots(self):
        fixture = LoadingFixture()
        original, changed = fixture.memory.read, False
        def changing(address, size):
            nonlocal changed
            data = original(address, size)
            if not changed and address == fixture.memory.chunk0 and size > objects.ENTRY_SIZE:
                changed = True
                fixture.serial(fixture.pawn, 9001)
            return data
        report, _, tables = self.collect_fixture(fixture, export.iter_object_records, backend=changing)
        self.assertEqual(report['status'], 'metadata_export_refused')
        self.assertEqual(report['reason'], 'object_slot_changed_during_metadata_read')
        self.assertEqual(report['failure_context']['phase'], 'registry_batch_recheck')
        self.assertEqual(report['failure_context']['first_changed_object_index'], fixture.rows.index(fixture.pawn))
        self.assertNotIn('roots', report)
        self.assertFalse(report['runtime_class_cache_recovered'])
        self.assertFalse(report['runtime_replication_layout_recovered'])
        tables.assert_not_called()


if __name__ == '__main__':
    unittest.main()
