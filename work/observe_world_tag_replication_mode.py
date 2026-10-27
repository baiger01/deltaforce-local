"""Read the exact GameplayTag serializer's current singleton mode, without calls.

The installed native body loads module+1e4d2750 and tests manager+181 before
choosing network-index or ordinary FName serialization. The singleton must be
a current typed GameplayTagsManager; null is uninitialized, never nonfast.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (owned_trial_identity, address,
    BindingObservation, write_exclusive_report)
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, request_elevation)
from native_metadata_paths import object_path

SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-tag-serialize-and-end-delegate-v1.json'
SOURCE_SHA = '5afd0921a60808438512a7357eab70c77eca704c11d98ffe9a1a90f564e7405f'
SINGLETON_RVA = 0x1e4d2750
MODE_OFFSET = 0x181


def source_pins():
    raw = (ROOT / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('The exact native GameplayTag mode consumer changed')
    document = json.loads(raw)
    rows = {(row['rva'], row['mnemonic'], row['operands'])
        for function in document['functions'] for row in function['instructions']}
    if (document['client_sha256'] != SHIPPING_SHA256 or document['process_access'] is not False or
            not {('0x1242795a', 'mov', 'rdi, qword ptr [rip + 0xc0aadef]'),
                 ('0x1242797e', 'cmp', 'byte ptr [rdi + 0x181], 0'),
                 ('0x1242798d', 'je', '0x12427e69'),
                 ('0x12427e72', 'call', 'qword ptr [rax + 0x50]')} <= rows):
        raise ValueError('The actual nonfast FName serialization branch changed')
    pins = {SOURCE: SOURCE_SHA}
    for relative in ('work/observe_world_tag_replication_mode.py',
            'work/observe_owned_gameplay_metadata.py', 'work/observe_portable_map_runtime.py',
            'work/export_native_replication_metadata.py', 'work/native_metadata_paths.py'):
        pins[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    return pins


def interpret_mode(raw):
    if type(raw) is not bytes or len(raw) != 1 or raw[0] not in (0, 1):
        raise ValueError('One actual zero-or-one native GameplayTagsManager mode byte is required')
    return dict(fast_replication=bool(raw[0]), nonfast_replication_confirmed=raw == b'\0')


def observe(game_root, trial_report):
    trial_raw = trial_report.read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
        observed = [row for row in roots['connection_binding_observations']['player_controllers']
            if row.get('status') == 'observed' and row.get('identity_and_fields_rechecked') is True and
            row.get('driver_primary_matches_original_connection') is True and row.get('local_player_index_field') == 0]
        if len(observed) != 1:
            raise ValueError('The exact current owned primary connection is required')
        observation = BindingObservation(session, base, sink['callback'], None)
        pointer_raw = session.stable(base + SINGLETON_RVA, 8)
        pointer, = struct.unpack('<Q', pointer_raw)
        if not pointer:
            raise ValueError('The actual native GameplayTagsManager singleton is uninitialized')
        pointer = address(pointer)
        identity = observation.identify(pointer, 'GameplayTagsManager')
        if identity['is_cdo']:
            raise ValueError('The native tag serializer singleton must not be a class default object')
        path = object_path(session.read, base, pointer)
        raw = session.stable(pointer + MODE_OFFSET, 1)
        mode = interpret_mode(raw)
        observation.finish()
        if (session.stable(base + SINGLETON_RVA, 8) != pointer_raw or
                session.stable(pointer + MODE_OFFSET, 1) != raw or
                object_path(session.read, base, pointer) != path):
            raise ValueError('The actual current native GameplayTag singleton or mode changed')
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('The native tag mode source or owned process changed')
        return dict(kind='owned_current_native_gameplaytag_replication_mode_observation', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            singleton_identity=identity, singleton_object_path=path, raw_mode_hex=raw.hex(), **mode,
            current_identity_mode_and_owned_roots_rechecked=True,
            process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            read_calls=session.calls, read_bytes=session.bytes_read, snapshot_atomic=False)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / 'work'):
        parser.error('Use one exclusive project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()), args.game_root)
    source_pins()
    if args.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(args.game_root.resolve()),
            '--trial-report', str(args.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(args.game_root, args.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
                packets_sent=False, code_sampled=False, historical_process_pointers_reused=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
