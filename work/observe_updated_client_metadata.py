"""Read selected class descriptors in an owned updated-build lobby process.

No instance payloads, native calls, writes, account fields or old reflection
offsets are used. A complete registry scan and final identity checks are required.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

import snapshot_updated_client_code as image
from updated_client_metadata import UpdatedMetadata, qualification_pins

ROOT = Path(__file__).resolve().parents[1]
CLASS_PATHS = {'/Script/CoreUObject.Class', '/Script/Engine.BlueprintGeneratedClass',
               '/Script/UMG.WidgetBlueprintGeneratedClass', '/Script/Engine.AnimBlueprintGeneratedClass'}
METACLASS_NAMES = frozenset(path.rsplit('.', 1)[1] for path in CLASS_PATHS)
SELECTED_NAMES = frozenset({'Class', 'Actor', 'Pawn', 'Character', 'PlayerController',
    'PlayerState', 'GameStateBase', 'NetDriver', 'IpNetDriver', 'GPNetDriver',
    'Function',
    'GPPlayerController', 'GPPlayerState', 'GPCharacter', 'GPCharacterMovementComponent',
    'GPWeapon', 'GPWeaponModular', 'GPWeaponMelee', 'GPWeaponManagerComponent',
    'GPAbilitySystemComponent', 'GPInventoryComponent', 'GPInteractComponent',
    'BP_PlayerController_C', 'BP_WeaponModular_C', 'BP_WeaponMelee_C',
    'BP_DFMCharacter_C', 'BP_DFMPlayerController_C', 'BP_GameState_PVPVE_C',
    'BP_SOLPlayerState_C', 'DFMPlayerController', 'GameState_SOL', 'GameState_PVPVE',
    'DFMGameState', 'GPGameState', 'BaseGameState', 'GameState', 'SOLPlayerState', 'DFMPlayerState',
    'MapInfoSystem', 'MapInfoComponent', 'BlueprintPlunder', 'MovementReplicationActor',
    'BP_EmptyHandWeapon_C', 'BP_Interactor_SingleItemContainer_HalloweenRaven_C'})


def source_pins():
    pins = qualification_pins()
    from updated_template_metadata import source_pins as template_pins
    pins.update(template_pins())
    from updated_header_context import source_pins as header_pins
    pins.update(header_pins())
    from updated_enabled_header_context import source_pins as enabled_header_pins
    pins.update(enabled_header_pins())
    for name in ('work/observe_updated_client_metadata.py', 'work/snapshot_updated_client_code.py',
                 'work/snapshot_native_image_code.py', 'work/export_native_replication_metadata.py',
                 'work/native_replication_metadata_core.py', 'work/local_game_paths.py'):
        pins[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return pins


def observe_classes(reader, *, progress=None, property_export=None, include_ancestors=False, class_export=None):
    if progress is None:
        progress = {}
    progress['phase'] = 'bounded_registry_scan'
    scan = {}
    records = list(reader.records(include_class_pointer=True, scan_metadata=scan,
                                  unpublished_batch_attempts=2))
    by_address = {row.object_address: row for row in records}
    progress.update(phase='identify_metaclasses', live_registry_records=len(records))
    # Only class-pointer targets have names read. Ordinary objects' own names
    # or instance fields are never needed to identify class descriptors.
    class_root = None
    for address in {row.class_address for row in records}:
        row = by_address.get(address)
        if row is not None and row.class_address == address and str(reader.name(address)) == 'Class':
            if reader.path(address) != '/Script/CoreUObject.Class' or class_root is not None:
                raise ValueError('Updated Class singleton path or uniqueness not established')
            class_root = address
    if class_root is None:
        raise ValueError('Updated Class singleton not found in complete registry scan')
    metaclasses = {class_root}
    for address in {row.class_address for row in records}:
        row = by_address.get(address)
        if (row is not None and row.class_address == class_root
                and str(reader.name(address)) in METACLASS_NAMES and reader.path(address) in CLASS_PATHS):
            metaclasses.add(address)
    selected = []
    progress['phase'] = 'select_named_classes'
    for row in records:
        if row.class_address not in metaclasses:
            continue
        label = str(reader.name(row.object_address))
        if label not in SELECTED_NAMES:
            continue
        path = reader.path(row.object_address)
        selected.append((row, label, path))
        if len(selected) > 256:
            raise ValueError('Updated selected descriptor count exceeds policy bound')
    parent_bindings = {}
    if include_ancestors:
        complete = {row.object_address: (row, label, path) for row, label, path in selected}
        for row, label, path in tuple(selected):
            ancestry = set()
            current = row.object_address
            while current:
                if current in ancestry or len(ancestry) >= 64:
                    raise ValueError('Updated selected class ancestry cycle or policy bound')
                ancestry.add(current)
                parent = reader.superclass(current)
                if current in parent_bindings and parent_bindings[current] != parent:
                    raise ValueError('Updated selected superclass changed during ancestry export')
                parent_bindings[current] = parent
                if parent:
                    descriptor = by_address.get(parent)
                    if (descriptor is None or descriptor.class_address not in metaclasses or
                            reader.class_pointer(parent) != descriptor.class_address):
                        raise ValueError('Updated superclass is not a current class descriptor')
                    if parent not in complete:
                        complete[parent] = descriptor, str(reader.name(parent)), reader.path(parent)
                        if len(complete) > 384:
                            raise ValueError('Updated ancestor descriptor count exceeds policy bound')
                current = parent
        selected = list(complete.values())
    for row, label, path in selected:
        if (reader.record(row.object_address).index != row.index or
                reader.record(row.object_address).serial != row.serial or
                reader.class_pointer(row.object_address) != row.class_address or
                str(reader.name(row.object_address)) != label or reader.path(row.object_address) != path):
            raise ValueError('Updated selected class metadata changed during observation')
    for address in metaclasses:
        if (reader.record(address).index != by_address[address].index or
                reader.record(address).serial != by_address[address].serial or
                reader.class_pointer(address) != by_address[address].class_address):
            raise ValueError('Updated metaclass identity changed after complete scan')
    progress['phase'] = 'selected_metadata_rechecked'
    exported = []
    for row, label, path in selected:
        value = dict(index=row.index, name=label, path=path,
                     metaclass_path=reader.path(row.class_address))
        if property_export is not None:
            value['own_properties'] = property_export(row.object_address)
        if include_ancestors:
            parent = reader.superclass(row.object_address)
            value['superclass_path'] = reader.path(parent) if parent else None
        if class_export is not None:
            value.update(class_export(row.object_address))
        exported.append(value)
    # Individual readers use fresh baselines. Bind all of their outputs back to
    # the original complete scan, including callbacks that ran after the first
    # selection recheck. A recycled class cannot keep an earlier label/schema.
    for row, label, path in selected:
        record = reader.record(row.object_address)
        if ((record.index, record.serial) != (row.index, row.serial) or
                reader.class_pointer(row.object_address) != row.class_address or
                str(reader.name(row.object_address)) != label or reader.path(row.object_address) != path or
                include_ancestors and reader.superclass(row.object_address) != parent_bindings[row.object_address]):
            raise ValueError('Updated selected class binding changed during metadata export')
    for address in metaclasses:
        record = reader.record(address)
        if ((record.index, record.serial) != (by_address[address].index, by_address[address].serial) or
                reader.class_pointer(address) != by_address[address].class_address):
            raise ValueError('Updated metaclass binding changed during metadata export')
    return dict(registry_scan=scan, selected_classes=exported,
        selected_class_count=len(selected), metaclass_count=len(metaclasses),
        class_fields_exported=property_export is not None, replication_handles_exported=False,
        class_fields_or_replication_handles_exported=property_export is not None,
        native_protocol_compatibility_verified=False)


def collect(game_root, folder, expected_pid, expected_create_time):
    from export_native_replication_metadata import Win32MetadataReader
    from native_replication_metadata_core import MetadataSession
    image.bounded.qualified_shadow_root(game_root)
    plan, pins = image.validate_plan(game_root), source_pins()
    folder = Path(folder).resolve()
    if (folder.parent != (ROOT / 'work/native-client-tests').resolve() or folder.exists()):
        raise ValueError('Updated metadata output must be a new private trial directory')
    executable = Path(game_root) / image.EXECUTABLE_RELATIVE
    if image.bounded.verified_pids(executable) != [expected_pid]:
        raise ValueError('Updated metadata process is not unique')
    report = dict(kind='updated_client_class_metadata_observation', client_sha256=image.SOURCE_SHA,
        pid=expected_pid, process_create_time=expected_create_time, source_pins=pins,
        observed_at_utc=datetime.now(timezone.utc).isoformat(), complete=False,
        native_protocol_compatibility_verified=False, process_memory_written=False,
        native_function_called=False, account_data_read=False)
    reader = session = None
    progress = {}
    start = time.monotonic()
    try:
        reader = Win32MetadataReader(executable, image.IMAGE_SIZE, expected_pid,
                                     expected_create_time, maximum_seconds=240)
        session = MetadataSession(reader.read_exact)
        metadata = UpdatedMetadata(session.read, reader.module_base)
        from updated_header_context import read_header_context
        from updated_enabled_header_context import read_enabled_header_context
        header_before = read_header_context(session.read, reader.module_base,
            client_sha256=image.SOURCE_SHA)
        report['header_context_before_class_scan'] = header_before
        enabled_before = read_enabled_header_context(session.read, reader.module_base,
            client_sha256=image.SOURCE_SHA)
        report['enabled_header_context_before_class_scan'] = enabled_before
        if enabled_before['top_level_values'] != header_before['values']:
            raise ValueError('Header context changed before the current class scan')
        from updated_template_metadata import SUPPORTED_CLASS_PATHS, observe_template_metadata
        def class_metadata(at):
            value = dict(setup_metadata=metadata.class_setup(at),
                         own_net_functions=metadata.functions(at))
            if metadata.path(at) in SUPPORTED_CLASS_PATHS.values():
                value['template_metadata'] = observe_template_metadata(metadata, at)
            return value
        result = observe_classes(metadata, progress=progress,
            property_export=lambda at: metadata.fields(at, virtual_methods=True), include_ancestors=True,
            class_export=class_metadata)
        header_after = read_header_context(session.read, reader.module_base,
            client_sha256=image.SOURCE_SHA)
        report['header_context'] = header_after
        enabled_after = read_enabled_header_context(session.read, reader.module_base,
            client_sha256=image.SOURCE_SHA)
        report['enabled_header_context'] = enabled_after
        if header_after['values'] != header_before['values']:
            raise ValueError('Header context changed across the current class scan')
        if (enabled_after['top_level_values'] != header_after['values'] or
                enabled_after['top_level_values'] != enabled_before['top_level_values'] or
                enabled_after['hook_values'] != enabled_before['hook_values']):
            raise ValueError('Enabled header context changed across the current class scan')
        reader.verify_identity()
        if image.validate_plan(game_root) != plan or source_pins() != pins:
            raise ValueError('Updated metadata image or sources changed')
        report.update(result, complete=True, status='updated_class_metadata_observed',
                      read_calls=session.calls, read_bytes=session.bytes_read)
    except (OSError, RuntimeError, ValueError) as error:
        report.update(status='updated_class_metadata_refused', error_type=type(error).__name__,
                      error_reason=str(error))
    finally:
        report['diagnostic_progress'] = progress
        if session is not None:
            report.update(read_calls=session.calls, read_bytes=session.bytes_read)
        if reader is not None:
            reader.close()
    report['elapsed_seconds'] = round(time.monotonic() - start, 3)
    folder.mkdir(parents=True, exist_ok=False)
    image.bounded.save_json(folder / 'updated-class-metadata.json', report)
    return report
