"""Observe current loaded EmptyHand ancestry/interfaces and existing CDO only.

No native call, executable-byte read, class construction, write or packet is used.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import owned_trial_identity, write_exclusive_report
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, request_elevation)
from native_actor_interface_metadata import _Observation, SOURCE_PINS
from native_metadata_names import resolve_name
from native_metadata_paths import object_path
from native_replication_metadata_core import span

TARGETS = {
    'BP_EmptyHand_C': '/Game/BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_EmptyHand.BP_EmptyHand_C',
    'WeaponBase': '/Script/GPGameplay.WeaponBase',
}


class ClassObservation(_Observation):
    """Local bounded policy includes qualified paths for every ancestor/interface."""
    def read(self, address, size):
        span(address, size)
        if self.calls >= 32768 or self.bytes_read+size > 8*1024*1024:
            raise ValueError('EmptyHand class metadata observation budget exhausted')
        self.calls += 1
        self.bytes_read += size
        raw = self.session.read(address, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('Incomplete EmptyHand class metadata')
        return raw


def source_pins():
    pins = {}
    for relative, expected in SOURCE_PINS.values():
        if not (ROOT/relative).exists():
            continue
        digest = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
        if digest != expected:
            raise ValueError('Interface source proof changed: '+relative)
        pins[relative] = digest
    for relative in ('work/observe_owned_emptyhand_class_metadata.py',
            'work/observe_owned_gameplay_metadata.py', 'work/observe_portable_map_runtime.py',
            'work/export_native_replication_metadata.py', 'work/native_actor_interface_metadata.py',
            'work/native_metadata_objects.py', 'work/native_metadata_names.py',
            'work/native_metadata_paths.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def observe(game_root, trial_report):
    raw = Path(trial_report).read_bytes()
    pid, created = owned_trial_identity(json.loads(raw), game_root)
    pins = source_pins()
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        previous = exporter.TARGET_CLASSES
        try:
            exporter.TARGET_CLASSES = previous | frozenset(TARGETS)
            roots = discover_roots(session, base, connection_binding_only=True,
                first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        finally:
            exporter.TARGET_CLASSES = previous
        identity = sink['callback']
        ob = ClassObservation(session, base)
        selected, identities = [], []
        for name, expected_path in TARGETS.items():
            rows = [r for r in roots['classes'] if r['name'] == name]
            if len(rows) != 1:
                raise ValueError('One current loaded class is required: '+name)
            klass = rows[0]['address']
            before = identity(klass, 'Class')
            identities.append((klass, 'Class', before))
            if object_path(ob.read, base, klass) != expected_path:
                raise ValueError('Current loaded class path differs: '+name)
            chain, seen, total, cursor = [], set(), 0, klass
            while cursor:
                if cursor in seen or len(seen) >= 32:
                    raise ValueError('Class ancestry cycle or bound')
                seen.add(cursor)
                desc = ob.class_identity(cursor)
                data, count = struct.unpack('<Qi', ob.keep(cursor+0x200, 12))
                if not 0 <= count <= 128 or total+count > 128:
                    raise ValueError('Implemented interface count bound')
                total += count
                entries = ob.keep(data, count*16) if count else b''
                interfaces = []
                for index in range(count):
                    interface, adjustment = struct.unpack_from('<Qi', entries, index*16)
                    flag = entries[index*16+12]
                    actual = ob.class_identity(interface)
                    interfaces.append(dict(name=actual['name'],
                        class_path=object_path(ob.read, base, interface),
                        pointer_adjustment=adjustment, implemented_by_script_byte=flag))
                chain.append(dict(name=desc['name'], class_path=object_path(ob.read, base, cursor),
                    implemented_interfaces=interfaces))
                cursor = desc['parent']
            cdo = ob.ptr(klass+0x140)
            cdo_result = dict(status='missing_existing_pointer', class_field_offset='0x140',
                native_get_default_object_called=False)
            if cdo:
                # The instance-binding callback intentionally rejects CDOs.
                # Validate this named metadata object through its registry slot.
                ob.record(cdo)
                flags = struct.unpack('<I', ob.keep(cdo+0x18, 4))[0]
                actual_class = ob.ptr(cdo+8)
                cdo_name = resolve_name(ob.read, base, ob.keep(cdo+0x1c, 8)).display_text
                if actual_class != klass or cdo_name != 'Default__'+name or not flags & 0x10:
                    raise ValueError('Existing CDO class/name/flags qualification failed')
                table = ob.ptr(cdo)
                if not base <= table < base+size:
                    raise ValueError('Existing CDO vtable outside qualified image')
                hook = ob.ptr(table+0x3d8)
                if not base <= hook < base+size:
                    raise ValueError('Existing CDO open-channel hook outside qualified image')
                cdo_result = dict(status='existing_cdo_identity_verified',
                    class_field_offset='0x140', name=cdo_name,
                    object_path=object_path(ob.read, base, cdo),
                    outer_path=object_path(ob.read, base, ob.ptr(cdo+0x10)),
                    flags=hex(flags), required_class_default_object_flag='0x10',
                    class_matches_selected=True, vtable_rva=hex(table-base),
                    actor_channel_open_slot='0x3d8', actor_channel_open_target_rva=hex(hook-base),
                    native_get_default_object_called=False)
            selected.append(dict(name=name, class_path=expected_path, ancestors=chain,
                net_rep_actor_interface_matches=[dict(declaring_class=c['class_path'], **i)
                    for c in chain for i in c['implemented_interfaces']
                    if i['name'] == 'NetRepActorInterface'], existing_cdo=cdo_result))
        ob.finish()
        for pointer, base_class, before in identities:
            if identity(pointer, base_class) != before:
                raise ValueError('Selected class or CDO identity changed')
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != base or source_pins() != pins:
            raise ValueError('Source module or helper pins changed')
        return dict(kind='owned_emptyhand_class_interface_cdo_metadata', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),
            source_pins=pins, trial_report_sha256=hashlib.sha256(raw).hexdigest(),
            unavailable_legacy_native_archive_pins={relative: expected
                for relative, expected in SOURCE_PINS.values() if not (ROOT/relative).exists()},
            implemented_interface_array_class_offset='0x200', interface_entry_bytes=16,
            selected_classes=selected, read_calls=session.calls, read_bytes=session.bytes_read,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True,
            process_identity_rechecked=True, process_memory_written=False,
            native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            current_process_session_closed_by_finally=True)
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    opts = parser.parse_args()
    output = opts.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Output must be an exclusive new project work file')
    owned_trial_identity(json.loads(opts.trial_report.read_bytes()), opts.game_root)
    source_pins()
    if opts.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(opts.game_root.resolve()),
            '--trial-report', str(opts.trial_report.resolve()), '--output', str(output)], output)
        report = json.loads(output.read_bytes())
    else:
        try:
            report = observe(opts.game_root, opts.trial_report)
        except Exception as error:
            report = dict(status='refused', reason=str(error), error_type=type(error).__name__,
                process_memory_written=False, native_methods_invoked=False,
                native_layouts_constructed=False, packets_sent=False, code_sampled=False,
                historical_process_pointers_reused=False)
        write_exclusive_report(output, report)
    print(json.dumps(dict(status=report['status'], reason=report.get('reason'), output=str(output))))


if __name__ == '__main__':
    main()
