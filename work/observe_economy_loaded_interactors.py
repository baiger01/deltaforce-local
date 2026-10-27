"""Read only four source-pinned exact actors in the current owned shadow trial.

Uses published UObject metadata and typed component references. No code reads,
native calls, layout creation, GUID allocation, packets, or process writes.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import export_native_replication_metadata as exporter
from observe_owned_gameplay_metadata import (address, owned_trial_identity,
    typed_declarations, BindingObservation, write_exclusive_report, label_existing)
from observe_portable_map_runtime import (ROOT, SHIPPING_SHA256, Win32MetadataReader,
    MetadataSession, validate_source, discover_roots, observe_first_player_state,
    object_name, request_elevation)
from native_metadata_objects import validate_object_record
from native_metadata_paths import object_path

CATALOG = 'work/evidence/map-system-audit-20261018/native-economy-loaded-level1-container-door-catalog-v2.json'
CATALOG_SHA = 'd0b9dd3a71225f6cb5aab029658a6a852eb75378a89a99746ac0bfc5d4ed9bdc'
MAX_CLASS_NAMES = 25000
MAX_COMPONENTS = 80
NOOP_SOURCE = 'work/evidence/map-system-audit-20261018/native-economy-box-actor-channel-open-noop.json'
NOOP_SHA = '3db5677b10afc0ae8b5e35ff9888904a1fbc6abb6026d38889e3ef8426f741c5'
OPEN_SLOT = 0x3d8
NOOP_RVA = 0xd5f350


def actor_open_hook(session, base, size, pointer):
    table_raw = session.stable(pointer, 8)
    table = struct.unpack('<Q', table_raw)[0]
    if not base <= table < base+size-OPEN_SLOT-8:
        raise ValueError('The selected Actor vtable is outside its pinned image')
    target_raw = session.stable(table+OPEN_SLOT, 8)
    target = struct.unpack('<Q', target_raw)[0]
    if not base <= target < base+size:
        raise ValueError('The selected Actor open hook is outside its pinned image')
    if session.stable(pointer, 8) != table_raw or session.stable(table+OPEN_SLOT, 8) != target_raw:
        raise ValueError('The selected Actor open hook changed')
    return dict(slot=OPEN_SLOT, target_rva=target-base, inside_pinned_image=True,
        source_qualified_no_extra_fields=target-base == NOOP_RVA, native_method_invoked=False)


def sources():
    raw = (ROOT/CATALOG).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_SHA:
        raise ValueError('The exact source actor catalog changed')
    catalog = json.loads(raw)
    if catalog['counts'] != dict(packages=3, actors=4, components=65, failures=0):
        raise ValueError('The bounded actor catalog scope changed')
    noop_raw = (ROOT/NOOP_SOURCE).read_bytes()
    if hashlib.sha256(noop_raw).hexdigest() != NOOP_SHA:
        raise ValueError('The source-qualified Actor open no-op changed')
    noop = json.loads(noop_raw)
    instructions = noop['functions'][0]['instructions']
    if (noop.get('client_sha256') != SHIPPING_SHA256 or noop.get('process_access') is not False or
            not instructions or instructions[0] !=
            dict(rva='0xd5f350', bytes='c20000', mnemonic='ret', operands='0')):
        raise ValueError('The Actor open source is outside the qualified return-only branch')
    pins = {CATALOG: CATALOG_SHA, NOOP_SOURCE: NOOP_SHA}
    for relative in ('work/observe_economy_loaded_interactors.py', 'work/observe_owned_gameplay_metadata.py',
            'work/observe_portable_map_runtime.py', 'work/observe_map_component_sources.py',
            'work/export_native_replication_metadata.py', 'work/native_metadata_objects.py',
            'work/native_metadata_paths.py', 'work/native_metadata_names.py',
            'work/native_replication_metadata_core.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return catalog, pins


def observe(game_root, trial_report):
    trial_raw = trial_report.read_bytes()
    pid, created = owned_trial_identity(json.loads(trial_raw), game_root)
    catalog, pins = sources()
    targets = {row['actor_name']: row for row in catalog['actors']}
    class_names = {row['class_import'].rsplit('.', 1)[-1] for row in targets.values()}
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=150)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink, candidates, class_cache = reader.module_base, {}, [], {}
        original_iterator, original_classes = exporter.iter_object_records, exporter.TARGET_CLASSES

        def exact_candidates(read, module_base, **options):
            for record in original_iterator(read, module_base, **options):
                if record.class_address is None:
                    raise ValueError('A checked published Class pointer is required')
                klass = record.class_address
                if klass not in class_cache:
                    if len(class_cache) >= MAX_CLASS_NAMES:
                        raise ValueError('Class-name metadata scope exceeds its bound')
                    before = validate_object_record(session.read, base, klass)
                    name = object_name(session.read, base, klass).display_text
                    if validate_object_record(session.read, base, klass) != before:
                        raise ValueError('Class identity changed while selecting exact actors')
                    class_cache[klass] = name
                if class_cache[klass] in class_names:
                    name = object_name(session.read, base, record.object_address).display_text
                    if name in targets:
                        if len(candidates) >= 8:
                            raise ValueError('Exact actor candidates exceed their bound')
                        candidates.append(dict(address=record.object_address, object_index=record.index,
                            serial=record.serial, class_address=klass, name=name))
                yield record

        try:
            exporter.iter_object_records = exact_candidates
            exporter.TARGET_CLASSES = original_classes | class_names
            roots = discover_roots(session, base, connection_binding_only=True,
                first_player_state=True, _binding_identity_sink=sink, unpublished_batch_retry=True)
        finally:
            exporter.iter_object_records, exporter.TARGET_CLASSES = original_iterator, original_classes
        identity = sink['callback']
        pcs = [pc for pc in roots['connection_binding_observations']['player_controllers']
               if pc.get('status') == 'observed' and pc.get('identity_and_fields_rechecked') is True
               and pc.get('driver_primary_matches_original_connection') is True
               and pc.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = pcs[0]
        binding = observe_first_player_state(session, base, driver_address=address(pc['driver']),
            connection_address=address(pc['connection']), pc_address=address(pc['address']), object_identity=identity)
        pawn = binding['pc_pawn_reference']
        if binding.get('status') != 'observed' or pawn.get('status') != 'typed_existing_reference':
            raise ValueError('The current owned Pawn binding is unavailable')
        actor_counts = {name: sum(r['name'] == name for r in candidates) for name in targets}
        if any(count > 1 for count in actor_counts.values()):
            raise ValueError('An exact observed actor name has multiple live instances')
        declarations, checked, actors = {}, [], []

        def metadata(pointer, expected):
            value = identity(pointer, expected)
            klass = address(value['class_address'])
            if klass not in declarations:
                declarations[klass] = dict(declarations=typed_declarations(session, base, klass, identity),
                    existing_driver_class=label_existing(session, base, address(pc['driver']), klass))
            return declarations[klass]

        observation = BindingObservation(session, base, identity, metadata)

        def describe(pointer, expected):
            value = observation.identify(pointer, expected)
            path = object_path(session.read, base, pointer)
            if object_path(session.read, base, pointer) != path:
                raise ValueError('Selected actor path changed')
            checked.append((pointer, expected, value, path))
            return dict(identity=value, object_path=path,
                        class_path=object_path(session.read, base, address(value['class_address'])))

        for candidate in candidates:
            source = targets[candidate['name']]
            pointer = candidate['address']
            actor = describe(pointer, 'Actor')
            actor['existing_driver_class'] = metadata(pointer, 'Actor')['existing_driver_class']
            actor['actor_open_hook'] = actor_open_hook(session, base, size, pointer)
            if (actor['identity']['name'] != candidate['name'] or
                    actor['identity']['class_ancestry'][0] not in class_names):
                raise ValueError('Exact actor binding changed after the registry scan')
            level_pointer = address(actor['identity']['outer_address'])
            level = describe(level_pointer, 'Level')
            world = describe(address(level['identity']['outer_address']), 'World')
            package = describe(address(world['identity']['outer_address']), 'Package')
            wanted = {row['name'] for row in source['components']}
            fields = [dict(field, declaring_class=cls['class_name'])
                      for cls in metadata(pointer, 'Actor')['declarations'] for field in cls['fields']
                      if field['name'] in wanted]
            if len(fields) > MAX_COMPONENTS or len({f['name'] for f in fields}) != len(fields):
                raise ValueError('Named actor component declarations are ambiguous')
            components = []
            for field in fields:
                link = observation.reference(pointer, field, expected_base='ActorComponent')
                if link['status'] == 'typed_existing_reference':
                    component = describe(address(link['identity']['address']), 'ActorComponent')
                    component['existing_driver_class'] = metadata(address(link['identity']['address']),
                        'ActorComponent')['existing_driver_class']
                    link.update(component)
                    link['name_matches_cooked_component'] = component['identity']['name'] == field['name']
                components.append(link)
            actor.update(level=level, world=world, package=package, components=components,
                source_catalog_export=source['export'], source_catalog_package=source['package_path'],
                source_catalog_actor_name=source['actor_name'],
                source_component_names=sorted(wanted),
                missing_component_declarations=sorted(wanted-{f['name'] for f in fields}),
                current_world_membership_beyond_observed_outer_chain_verified=False)
            actors.append(actor)
        observation.finish()
        for pointer, expected, before, path in checked:
            if identity(pointer, expected) != before or object_path(session.read, base, pointer) != path:
                raise ValueError('A selected object identity or path changed before publishing')
        for actor in actors:
            if actor_open_hook(session, base, size, address(actor['identity']['address'])) != actor['actor_open_hook']:
                raise ValueError('The qualified Actor open hook changed before publishing')
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != base:
            raise ValueError('Pinned module identity changed')
        if sources()[1] != pins:
            raise ValueError('A helper/source changed during observation')
        return dict(kind='owned_current_exact_dam_interactor_metadata_observation', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding,
            current_pawn=describe(pawn['address'], 'Pawn'), exact_actor_counts=actor_counts,
            registry_scan=roots['registry_scan'], actors=actors,
            read_calls=session.calls, read_bytes=session.bytes_read, source_identity_rechecked=True,
            process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            snapshot_atomic=False)
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
    if output.exists() or not output.is_relative_to(ROOT/'work'):
        parser.error('Use an exclusive new project work output')
    owned_trial_identity(json.loads(args.trial_report.read_bytes()), args.game_root)
    sources()
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
