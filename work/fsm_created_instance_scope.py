"""Observe one planned FSM creation through the current connection GUID cache.

There is no resolver, allocator, process API, native call, or property encoder.
Only exact GUIDs selected by the owned trial allocation are looked up. The
existing Pawn and current component-selected class must match before the new
instance can be followed, including when component.R_Instance remains null.
"""
from pathlib import Path
import hashlib
import struct

from dfserver.legacy_ds_dynamic_object_creation import DynamicObjectCreation, preflight_creation
from native_guid_object_metadata import (_Read, _lookup, _existing_weak,
    LOOKUP_TARGET_RVA, IMAGE_BYTES)
from native_replication_metadata_core import span


ROOT = Path(__file__).resolve().parent.parent
REFERENCE_STATUSES = ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized')
PINS = {
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-lookup.json':
        '467917bcf328517641977770aa7351ae9a290b453166de5ca43b5bb4db7f6627',
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-hash-lookup.json':
        'e704b5ccb521f7a2571b359b7ea881d5a410504f8dec43ab677fa3be6e27842d',
}


def source_pins():
    from portable_map_fsm_instance import source_pins as creation_pins
    from fsm_readonly_scope import sealed
    for relative, digest in PINS.items():
        sealed(relative, digest)
    result = dict(PINS, **creation_pins())
    for relative in ('work/fsm_created_instance_scope.py', 'work/native_guid_object_metadata.py'):
        result[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return result


def creation_from_trial(trial):
    """Select the explicit current owned plan allocation, with no fixed GUID IDs."""
    if type(trial) is not dict or type(trial.get('portable_map_bootstrap', {})) is not dict:
        raise ValueError('The current owned trial bootstrap summary is required')
    allocation = trial.get('portable_map_bootstrap', {}).get('fsm_instance_creation')
    if allocation is None:
        return None, ()
    keys = {'actor_guid', 'guid', 'class_guid', 'class_path', 'source_sha256', 'allocated_guids'}
    if (type(allocation) is not dict or set(allocation) != keys or
            type(allocation['allocated_guids']) is not list):
        raise ValueError('One exact owned FSM creation allocation is required')
    namespace = tuple(allocation['allocated_guids'])
    creation = DynamicObjectCreation(**{key: allocation[key] for key in keys-{'allocated_guids'}})
    preflight_creation(creation, actor_guids=(creation.actor_guid,),
        exported_class_bindings=((creation.class_guid, creation.class_path),), allocated_guids=namespace)
    return creation, namespace


def _address(value):
    return int(value, 16) if type(value) is str else value


def observe_created_instance(session, module_base, *, driver, connection, pawn, selected_class,
        creation, allocated_guids, identity, recheck_binding):
    """Return an existing typed object only after exact current dependency checks."""
    preflight_creation(creation, actor_guids=(creation.actor_guid,),
        exported_class_bindings=((creation.class_guid, creation.class_path),),
        allocated_guids=allocated_guids)
    if not callable(identity) or not callable(recheck_binding):
        raise ValueError('Original current typed identity and binding callbacks are required')
    for pointer in (module_base, driver, connection, pawn, selected_class):
        span(pointer, 1)
    recheck_binding()
    read, identities = _Read(session), {}

    def typed(pointer, expected):
        value = identity(pointer, expected)
        key = pointer, expected
        if key in identities and identities[key] != value:
            raise ValueError('The current created FSM typed identity changed')
        identities[key] = value
        return value

    typed(driver, 'NetDriver')
    typed(connection, 'NetConnection')
    typed(pawn, 'Pawn')
    typed(selected_class, 'Class')
    if read.pointer(driver+0x98) != connection or read.pointer(connection+0x58) != driver:
        raise ValueError('The created FSM GUID scope requires its current primary connection')
    package_map = read.pointer(connection+0x68)
    typed(package_map, 'PackageMapClient')
    if read.pointer(package_map+0x130) != connection:
        raise ValueError('The created FSM PackageMap backlink changed')
    table = read.pointer(package_map)
    if (not module_base <= table <= module_base+IMAGE_BYTES-0x2d0 or
            read.pointer(table+0x2c8) != module_base+LOOKUP_TARGET_RVA):
        raise ValueError('The created FSM GUID lookup target is not source-qualified')
    cache = read.pointer(package_map+0x310)
    if read.fact(cache+0x152, 1) != b'\0' or read.fact(connection+0xb4, 1)[0] & 1:
        raise ValueError('The created FSM GUID scope requires the ordinary reference profile')
    header = read.fact(cache, 0x50)
    mappings = []
    for guid in (creation.actor_guid, creation.class_guid, creation.guid):
        found = _lookup(read, cache, header, guid)
        mapped = (dict(status='mapping_missing', object_address=None) if found is None else
            _existing_weak(read, module_base, found[1]))
        mappings.append(dict(guid=guid, map_slot_index=None if found is None else found[0], **mapped))
    actor_row, class_row, instance_row = mappings
    for row, pointer, expected in ((actor_row, pawn, 'Pawn'), (class_row, selected_class, 'Class')):
        if row['status'] == 'existing_object_observed':
            if row['object_address'] != pointer:
                raise ValueError('The exact created FSM '+expected+' GUID maps to a different current object')
            known = typed(pointer, expected)
            if known.get('serial') != row['serial'] or known.get('object_index') != row['object_index']:
                raise ValueError('The current created FSM dependency GUID generation differs')
    result = dict(status=instance_row['status'], guid=creation.guid, class_guid=creation.class_guid,
        actor_guid=creation.actor_guid, expected_class_path=creation.class_path,
        reference_origin='current_connection_exact_creation_guid', mappings=mappings,
        guid_cache_address=cache, package_map_address=package_map,
        component_R_Instance_bound_inferred=False, gameplay_initialization_verified=False,
        native_methods_invoked=False, missing_references_resolved=False, native_objects_created=False)
    if all(row['status'] == 'existing_object_observed' for row in mappings):
        pointer = instance_row['object_address']
        current = typed(pointer, 'SMInstance')
        if (current.get('is_cdo') is not False or _address(current.get('address')) != pointer or
                _address(current.get('class_address')) != selected_class or
                _address(current.get('outer_address')) != pawn or
                current.get('serial') != instance_row['serial'] or
                current.get('object_index') != instance_row['object_index']):
            raise ValueError('The created FSM lacks its exact current class/Pawn Outer/weak identity')
        result.update(status='typed_existing_reference', identity=current,
            outer_is_current_pawn=True, selected_class_matches_current_main_fsm=True)
    elif instance_row['status'] == 'existing_object_observed':
        result.update(status='dependencies_unresolved', instance_value_published=False)
    recheck_binding()
    for (pointer, expected), before in identities.items():
        if identity(pointer, expected) != before:
            raise ValueError('The created FSM typed identity changed before final recheck')
    read.recheck()
    result.update(read_calls=read.calls, read_bytes=read.bytes,
        primary_connection_and_metadata_rechecked=True)
    return result


def select_instance_reference(component_reference, created_reference):
    if created_reference and created_reference.get('status') in REFERENCE_STATUSES:
        if (component_reference and component_reference.get('status') in REFERENCE_STATUSES and
                component_reference['identity']['address'] != created_reference['identity']['address']):
            raise ValueError('The current component and exact creation GUID reference different FSM instances')
        return created_reference
    return component_reference
