"""Read-only code observation for one exact updated build, not runtime approval.

Only the independent shadow's existing executable image may be read. The
historical sender samples are comparisons; they do not qualify new layouts.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import math
import mmap
import os
from pathlib import Path

import pefile

import snapshot_native_image_code as bounded


ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE_RELATIVE = bounded.EXECUTABLE_RELATIVE
SOURCE_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
HEADER_SHA = '1b6ec697ef232836ca6acccb8dc070d797bf5ee3846474043c8d221e4c9903e0'
FILE_BYTES, IMAGE_SIZE, HEADER_BYTES = 514154112, 536408064, 1536
SECTIONS = (
    (0, 0x1000, 349183323, 349183488, 1536,
     '42be2f9bae05033b52b143bdd19aba902ba68255b46daaa9b9d45e91cf8bfde4'),
    (8, 0x1f4aa000, 11300864, 379392, 513645568,
     '8047acb0c98752be745e4ad0b860d2e7cc924a937c9a9a83f94b28a8e0c6890a'),
)


def plan_from_image(raw):
    if len(raw) != FILE_BYTES or hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('Updated executable size/SHA mismatch')
    pe = pefile.PE(data=raw, fast_load=True)
    try:
        if (pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b or
                pe.OPTIONAL_HEADER.SizeOfImage != IMAGE_SIZE or
                pe.OPTIONAL_HEADER.SizeOfHeaders != HEADER_BYTES or
                hashlib.sha256(raw[:HEADER_BYTES]).hexdigest() != HEADER_SHA):
            raise ValueError('Updated PE header identity mismatch')
        if [i for i, s in enumerate(pe.sections) if s.Characteristics & 0x20000000] != [0, 8]:
            raise ValueError('Updated executable section set mismatch')
        rows = []
        for index, rva, virtual, backing, offset, expected in SECTIONS:
            section = pe.sections[index]
            length = min(virtual, backing)
            if ((section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData,
                    section.PointerToRawData, section.Characteristics, section.Name.rstrip(b'\0')) !=
                    (rva, virtual, backing, offset, 0x60000020, b'.std') or
                    not 0 <= offset < offset + length <= len(raw) or
                    hashlib.sha256(raw[offset:offset+length]).hexdigest() != expected):
                raise ValueError('Updated executable section bounds/SHA mismatch')
            rows.append(dict(index=index, name='.std', rva=hex(rva),
                file_backed_code_bytes=length, virtual_size=virtual, raw_size=backing,
                raw_backed_sha256=expected, excluded_virtual_only_bytes=max(0, virtual-backing)))
    finally:
        pe.close()
    return dict(kind='fixed_updated_client_code_observation_plan', client_sha256=SOURCE_SHA,
        client_relative_to_game_root=EXECUTABLE_RELATIVE.as_posix(),
        immutable_image_size_bytes=IMAGE_SIZE, sections=rows,
        maximum_code_bytes=sum(row['file_backed_code_bytes'] for row in rows),
        maximum_region_split_RPM_count=sum((row['file_backed_code_bytes']+4095)//4096 for row in rows),
        maximum_RPM_bytes=1048576, private_cache_only=True, whole_executable_dump=False,
        live_data_object_read=False, reconstructed_executable=False,
        native_protocol_compatibility_verified=False,
        historical_comparison_scope='comparison_only_not_current_layout_qualification')


def validate_plan(game_root):
    with (Path(game_root)/EXECUTABLE_RELATIVE).open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            return plan_from_image(raw)


def source_pins():
    return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
        ('work/snapshot_updated_client_code.py', 'work/snapshot_native_image_code.py',
         'work/local_game_paths.py')}


def qualify_launch(args, game_root, shadow_root):
    code = getattr(args, 'updated_client_code_observation', False)
    metadata = getattr(args, 'updated_client_metadata_observation', False)
    transport = getattr(args, 'updated_client_transport_observation', False)
    map_metadata = (metadata is True and transport is True and code is False
                    and getattr(args, 'ds_control_probe', False) is True)
    if (any(type(value) is not bool for value in (code, metadata, transport)) or
            sum((code, metadata, transport)) > 1 and not map_metadata):
        raise ValueError('One explicit updated observation mode is required')
    if not code and not metadata and not transport:
        return None
    if (getattr(args, 'entry', None) != 'shipping' or
            Path(game_root).resolve() != Path(shadow_root).resolve() or
            not getattr(args, 'wire_business_bootstrap_probe', False)):
        raise ValueError('Updated observation requires the shipping shadow lobby only')
    conflicts = ('game_server_probe', 'replication_metadata_export', 'bootstrap_template_observation',
        'portable_map_bootstrap', 'entry_code_probe', 'stop_after_code_collection',
        'disable_device_seamless', 'disable_dynamic_address_switch', 'enable_sol_map_entry_loading',
        'use_qualified_subworld', 'map_board_catalog')
    transport_options = {'game_server_probe', 'ds_handshake_probe', 'ds_packet_ack_probe',
                         'ds_join_after_ready', 'ds_map_id'} if transport else set()
    control = transport and getattr(args, 'ds_control_probe', False)
    if control:
        # The UAC wrapper seals these CLI values into the worker environment;
        # the inner runner intentionally has no duplicate map/handoff parser.
        join_after_ready = getattr(args, 'ds_join_after_ready',
            os.environ.get('DF_LOCAL_DS_JOIN_PROBE_AFTER_READY') == '1')
        selected_map = getattr(args, 'ds_map_id', os.environ.get('DF_LOCAL_DS_MAP_ID'))
        if (type(selected_map) is str and selected_map.isascii() and
                selected_map.isdecimal() and len(selected_map) <= 10):
            selected_map = int(selected_map)
        if (control is not True or not getattr(args, 'ds_control_profile', None) or
                join_after_ready is not True or type(selected_map) is not int or selected_map != 2201 or
                getattr(args, 'disable_device_seamless', False) is not True):
            raise ValueError('Updated control requires its current profile and explicit ordinary map handoff')
        transport_options.update(('ds_control_probe', 'ds_control_profile',
            'disable_device_seamless', 'disable_dynamic_address_switch', 'enable_sol_map_entry_loading'))
    if transport and not all(getattr(args, name, False) is True for name in
                             ('game_server_probe', 'ds_handshake_probe', 'ds_packet_ack_probe')):
        raise ValueError('Updated transport observation requires explicit handshake and packet layers')
    for name, value in vars(args).items():
        if (name not in transport_options and (name in conflicts or name.startswith(('ds_', 'connection_')))
                and value not in (False, None)):
            raise ValueError('Updated code observation refuses unqualified gameplay/read features: '+name)
    if any(os.environ.get(key) == '1' for key in ('DF_LOCAL_SOCKET_EVIDENCE', 'DF_LOCAL_RESOURCE_EVIDENCE')):
        raise ValueError('Updated code observation refuses historical auxiliary readers')
    pins = source_pins()
    if metadata:
        from observe_updated_client_metadata import source_pins as metadata_pins
        pins.update(metadata_pins())
    if transport:
        from updated_transport_observation import source_pins as transport_pins
        pins.update(transport_pins(control_profile=args.ds_control_profile if control else None,
                                   shadow=shadow_root))
    return dict(client_sha256=SOURCE_SHA, plan=validate_plan(game_root), source_pins=pins,
        mode=('updated_control_metadata_capture' if map_metadata else
              'updated_control_capture' if control else 'updated_transport_capture' if transport else
              'updated_class_metadata' if metadata else 'updated_executable_code'),
        native_protocol_compatibility_verified=False)


def collect(game_root, output_dir, expected_pid, expected_create_time):
    if (type(expected_pid) is not int or expected_pid <= 0 or
            type(expected_create_time) not in (int, float) or
            not math.isfinite(expected_create_time) or expected_create_time <= 0):
        raise ValueError('Exact positive PID/create time required')
    bounded.qualified_shadow_root(game_root)
    folder = bounded.private_output(output_dir)
    plan, pins = validate_plan(game_root), source_pins()
    executable = Path(game_root)/EXECUTABLE_RELATIVE
    if bounded.verified_pids(executable) != [expected_pid]:
        raise RuntimeError('Updated shadow executable process is not unique')
    api = bounded.kernel()
    handle = api.OpenProcess(0x1010, False, expected_pid)
    if not handle:
        raise RuntimeError('Ordinary process read permission unavailable')
    report = dict(kind='private_client_update_code_observation', client_sha256=SOURCE_SHA,
        pid=expected_pid, process_create_time=expected_create_time, plan=plan, source_pins=pins,
        complete=False, status='initializing', sections=[], client_launched=False,
        elevation_requested=False, process_memory_written=False, live_data_object_read=False,
        original_game_modified=False, reconstructed_executable=False,
        native_complete_decode_claimed=False, snapshot_is_atomic=False,
        native_protocol_compatibility_verified=False,
        historical_comparison_scope=plan['historical_comparison_scope'],
        observed_at_utc=datetime.now(timezone.utc).isoformat())
    try:
        check = lambda: bounded.process_identity(api, handle, expected_pid, executable, expected_create_time)
        check()
        base, size = bounded.verified_module(api, expected_pid, executable)
        if size != IMAGE_SIZE or validate_plan(game_root) != plan or source_pins() != pins:
            raise RuntimeError('Updated executable plan or observation sources changed')
        folder.mkdir(parents=True, exist_ok=False)
        bounded.save_json(folder/'manifest.json', report)
        report.update(bounded.snapshot_sections(api, handle, base, plan, folder, check))
        check()
        if (bounded.verified_module(api, expected_pid, executable) != (base, size) or
                validate_plan(game_root) != plan or source_pins() != pins):
            raise RuntimeError('Updated executable or sources changed after observation')
        coverage = report['saved_code_bytes'] == plan['maximum_code_bytes'] and report['unavailable_bytes'] == 0
        report.update(complete=coverage, scope_coverage_complete=coverage,
            status='updated_code_observation_complete' if coverage else 'updated_code_observation_partial')
    except Exception as error:
        report.update(status='updated_code_observation_failed', complete=False,
            error_type=type(error).__name__)
        if isinstance(error, (RuntimeError, ValueError)):
            report['error_reason'] = str(error)
        if not folder.exists():
            raise
    finally:
        api.CloseHandle(handle)
    bounded.save_json(folder/'manifest.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--expected-pid', type=int)
    parser.add_argument('--expected-create-time', type=float)
    args = parser.parse_args()
    if args.collect:
        if any(value is None for value in (args.output_dir, args.expected_pid, args.expected_create_time)):
            parser.error('--collect requires output directory and exact PID/create time')
        result = collect(args.game_root, args.output_dir, args.expected_pid, args.expected_create_time)
        print(result['status'])
        raise SystemExit(0 if result['complete'] else 1)
    if any(value is not None for value in (args.output_dir, args.expected_pid, args.expected_create_time)):
        parser.error('Live arguments require explicit --collect')
    plan = validate_plan(args.game_root)
    print('Updated offline plan validated: '+str(plan['maximum_code_bytes'])+' code bytes; no process access.')
