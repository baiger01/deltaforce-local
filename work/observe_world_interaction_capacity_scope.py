"""Read current World.Levels with separate element and allocation limits.

The original owned reader rejected 476 live elements because its allocated
capacity was 584. This isolated diagnostic keeps reads at 512 references and
allows capacity up to 1024 only for the exact reflected World.Levels field.
It never changes trial sources, calls native methods, or sends packets.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import threading

import observe_world_interaction_lifecycle as original


ORIGINAL_SHA256 = 'fb2e4d33a5fdeea0826cdae0d1c27ea8ddd3c71683b82e647bfe1cc5ffa1be4d'
MAX_LEVEL_COUNT = 512
MAX_LEVEL_CAPACITY = 1024
_LOCK = threading.Lock()


def source_pins():
    pins = original.sources()
    if pins['work/observe_world_interaction_lifecycle.py'] != ORIGINAL_SHA256:
        raise ValueError('The original owned world reader changed')
    relative = 'work/observe_world_interaction_capacity_scope.py'
    pins[relative] = hashlib.sha256((original.ROOT / relative).read_bytes()).hexdigest()
    return pins


def world_levels_header(raw):
    data, count, capacity = original.array_header(raw, 8, MAX_LEVEL_CAPACITY)
    if count > MAX_LEVEL_COUNT:
        raise ValueError('The actual world level count exceeds 512 references')
    return data, count, capacity


def observe(game_root, trial_report):
    pins = source_pins()
    if not _LOCK.acquire(blocking=False):
        raise ValueError('One isolated world capacity observer is required')
    old_reference = original.Fields.reference_array
    old_array = original.array_header
    context = []

    def array(raw, stride, limit=512):
        if context and stride == 8 and limit == 512:
            data, count, capacity = old_array(raw, stride, MAX_LEVEL_CAPACITY)
            if count > MAX_LEVEL_COUNT:
                raise ValueError('The actual world level count exceeds 512 references')
            return data, count, capacity
        return old_array(raw, stride, limit)

    def reference(fields, pointer, klass, name, expected_class):
        if (name, expected_class) != ('Levels', 'Level'):
            return old_reference(fields, pointer, klass, name, expected_class)
        owner = fields.identity(pointer, 'World')
        field = fields.one(klass, name)
        if (field['declaring_class'], field['name'], field['storage_offset'],
                field['element_bytes'], field['field_vtable_rva']) != (
                'World', 'Levels', 344, 16, 0x1ab5b730):
            raise ValueError('The actual World.Levels declaration changed')
        context.append(owner)
        try:
            return old_reference(fields, pointer, klass, name, expected_class)
        finally:
            context.pop()

    try:
        original.array_header = array
        original.Fields.reference_array = reference
        result = original.observe(game_root, trial_report)
        if source_pins() != pins:
            raise ValueError('The capacity observer source changed during observation')
        result.update(source_pins=pins, world_levels_diagnostic_limits=dict(
            maximum_live_count=MAX_LEVEL_COUNT, maximum_allocated_capacity=MAX_LEVEL_CAPACITY,
            maximum_reference_payload_bytes=MAX_LEVEL_COUNT * 8,
            original_element_read_bound_preserved=True,
            capacity_policy_applies_only_to_exact_reflected_world_levels=True))
        return result
    finally:
        original.Fields.reference_array = old_reference
        original.array_header = old_array
        _LOCK.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(original.ROOT / 'work'):
        parser.error('Use one exclusive new project work output')
    original.owned_trial_identity(json.loads(args.trial_report.read_bytes()), args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        original.request_elevation(['-B', str(Path(__file__).resolve()), '--game-root',
            str(args.game_root.resolve()), '--trial-report', str(args.trial_report.resolve()),
            '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False,
                native_layouts_constructed=False, packets_sent=False, code_sampled=False,
                historical_process_pointers_reused=False)
        original.write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
