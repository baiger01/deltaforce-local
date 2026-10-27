"""Read the owned Pawn's declared sprint, stamina, skill, and health objects.

Current reflected fields, existing scalar RepLayouts, and pinned getter values are read.
Missing layouts remain missing; no native method, writer, packet or launch API.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, BindingObservation,
    address, owned_trial_identity, source_pins as gameplay_source_pins, typed_declarations,
    label_existing, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, read_declared_scalar_fields, request_elevation,
    observed_virtual_method, recheck_virtual_method)
from native_metadata_paths import object_path
from runtime_declaration_supplement import source_pins as runtime_source_pins
from vitals_readonly_field_scope import (attribute_current_fields, read_skill_state,
    read_health_display_base, local_reference_fields, read_attribute_state,
    component_lifecycle_declaration, sprint_input_reference_fields,
    local_ability_array_field, local_ability_array_header,
    DECLARATION_SOURCE, DECLARATION_SHA256,
    BINDING_DECLARATION_SOURCE, BINDING_DECLARATION_SHA256,
    SPRINT_DECLARATION_SOURCE, SPRINT_DECLARATION_SHA256)

PAWN_FIELDS = {
    'SprintComp': 'GPSprintComponent', 'GPStaminaDataComp': 'GPStaminaDataComponent',
    'DFMSkillComponent': 'DFMSkillComponent', 'GPSkillReplicateComponent': 'GPSkillReplicateComponent',
    'DFMHealthDataComponent': 'DFMHealthDataComponent', 'SOLHealthDataComponent': 'SOLHealthDataComponent',
    'GPCharacterMovement': 'GPCharacterMovementComponent',
}
SCALAR_TERMS = ('stamina', 'stanina', 'health', 'sprint', 'skill', 'waitingstart')
FORMATS = frozenset((4, 5, 6, 20, 21))
GETTER_FIELDS = {
    'GPAttributeSetSpeed': {'GetStaninaValue': 0x118, 'GetMaxStaninaValue': 0x128},
    'GPAttributeSetHealth': {'GetHealth': 0x30, 'GetHealthMAX': 0x48},
}
SPRINT_GATE_FIELDS = {
    'GPSprintComponent': {'bSprintingIgnoreStamina': 0x100},
    'GPStaminaDataComponent': {'bTiredStateAllowSprint': 0x1e8},
}
GETTER_PINS = {
    DECLARATION_SOURCE: DECLARATION_SHA256,
    BINDING_DECLARATION_SOURCE: BINDING_DECLARATION_SHA256,
    SPRINT_DECLARATION_SOURCE: SPRINT_DECLARATION_SHA256,
    'work/evidence/model-init-chain-20261018/native-lazy-weak-serial-allocation-v1.json':
        '46472c683408ece336601e03ec59e8532b9b92dae15c2143272baf02ed0aaa99',
    'work/evidence/model-init-chain-20261018/native-actor-component-init-beginplay-register-flags-v1.json':
        '6cf0cfb64b33a419771e22a91bf59260917f344fcc076e997dd07a7ec304305f',
    'work/evidence/model-init-chain-20261018/native-component-register-world-and-initialize-callers-v1.json':
        '4a11681c5d529509e1fc64ae6979d2591ac5f405aea07f5dd057529e45bd7f42',
    'work/evidence/model-init-chain-20261018/native-component-created-registered-and-dfm-skill-init-v1.json':
        '21a9416efbf6607360bb5cb82fe5c6e9413e6d6e147b5a90143df9890ff280fa',
    'work/evidence/map-system-audit-20261018/native-default-subobject-flags.json':
        '2a02b44011001d41dbe3d2f66a633066db9c227a9e467721062d44602e3ca9bc',
    'work/evidence/model-init-chain-20261018/native-vitals-skill-detail-info-struct-fields.json':
        'd8459c79a67dea155d2e208da926a77c1f9e45494ac4ef4db9c081c12bb3a99a',
    'work/evidence/model-init-chain-20261018/native-vitals-skill-detail-onrep-and-set-expert.json':
        '3c167521d9dec59ac4bb6bbc7dac4f1609a3d694b3179fedde96de6fcde93953',
    'work/evidence/model-init-chain-20261018/native-vitals-health-max-attribute-base-current-getters.json':
        '38aac5b025a8246ff58aa0b13aa63ff42614d67357359167845eabf87fcf95f5',
    'work/evidence/model-init-chain-20261018/native-vitals-health-bar-segment-and-update-bodies.json':
        '3757c684e4e5071c795391187bdc96d8772028515bbc323b3a278563fde010c8',
    'work/evidence/model-init-chain-20261018/native-vitals-getter-dispatch.json':
        'f9b03c08a35e82c51644e17027342e6dabf5209f1290a8a38a466c2811db5abc',
    'work/evidence/model-init-chain-20261018/native-vitals-getter-bodies.json':
        '3919c4d74cd381b673d6bea829165aa272b24d55dd33a45d88fcf666445c903b',
    'work/evidence/model-init-chain-20261018/native-vitals-attribute-types.json':
        '04546572b6f1a3a09acbec65f4c96835cebb369ad690690a7d554f6b2eca3e94',
    'work/evidence/model-init-chain-20261018/native-gp-sprint-actual-ability-gates.json':
        'f7a9081da31e06c6395542be56a3dc867897c1c188dd36188991c21da219ca1d',
    'work/native-client-tests/1792314937287546900/owned-vitals-metadata.json':
        'b9a0c833779649e650517f2322c8e0207b06a5401a4cb0e403d4b33051ba7ed3',
    'work/evidence/model-init-chain-20261018/native-current-sprint-blackboard-1c8-field-v1.json':
        '65e723e97bdb8b24b7e3bdda805537dec7bbc2563cf0689381278628d2c5351b',
    'work/evidence/model-init-chain-20261018/native-blackboard-sprint-component-class-getter-v1.json':
        'a4fca42d400f239a30db107460d8eff2a8c58063b0d5db1c9ff8113c4bc5c5d9',
    'work/evidence/model-init-chain-20261018/native-blackboard-sprint-component-class-registration-v1.json':
        '0c711c865733aca1fc41c35fd89edaef505ade8e9341ab5a734ef99ba34d86ae',
    'work/evidence/model-init-chain-20261018/native-sprint-input-dispatch-and-callers.json':
        '55ba01b690b455d35d87bfdddc1f724539c6a8757ae53c2d250472f03c14d5f9',
}


def source_pins():
    result = gameplay_source_pins()
    result.update(runtime_source_pins())
    for relative in ('work/observe_owned_vitals_metadata.py', 'work/vitals_readonly_field_scope.py'):
        result[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    for relative, expected in GETTER_PINS.items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('The fixed native vitals getter source changed')
        result[relative] = expected
    return result


def selected_fields(declarations, expected):
    result = []
    for name, declared in expected.items():
        matches = [dict(f, declaring_class=d['class_name']) for d in declarations for f in d['fields']
                   if f['name'] == name]
        if len(matches) != 1 or matches[0].get('declared_native_class') != declared:
            raise ValueError('The scoped current object declaration changed: ' + name)
        result.append(matches[0])
    return result


class VitalsBindingObservation(BindingObservation):
    """Retain typed serial-zero metadata without promoting it to a weak identity."""
    def reference(self, owner, field, *, expected_base='Object'):
        result = super().reference(owner, field, expected_base=expected_base)
        if 'property_flags' in field:
            result['property_flags'] = field['property_flags']
            result['is_net_property'] = bool(int(field['property_flags'], 16) & 0x20)
        if 'declared_native_class_path' in field:
            result['declared_native_class_path'] = field['declared_native_class_path']
        if result['status'] == 'typed_existing_reference':
            initialized = result['identity']['serial'] != 0
            result['weak_identity_initialized'] = initialized
            if not initialized:
                result['status'] = 'typed_reference_weak_identity_uninitialized'
        return result


def follow_fields(declarations, expected, role):
    """Follow fixed declarations, including both Movement references."""
    follow = ({'StaminaData': 'GPStaminaDataComponent'} if role == 'SprintComp' else
        {'MovementLimitConfig': 'GPCharacterMovementLimitDataAsset'}
            if expected == 'GPCharacterMovementComponent' else
        {'PlayerController': 'GPPlayerController'}
            if expected in ('GPInputManager', 'GPInputMovementLogic') else
        {'GPActor': 'Actor', 'GPCharacter': 'GPCharacter', 'DFMCharacter': 'DFMCharacter'}
            if expected == 'DFMSkillComponent' else {})
    return selected_fields(declarations, follow) + local_reference_fields(declarations, expected)


def input_scope_refusal(declarations, name, error):
    actual = [dict(f, declaring_class=d['class_name']) for d in declarations
              for f in d['fields'] if f['name'] == name]
    return dict(status='refused', name=name, reason=str(error), actual_declarations=actual,
        instance_value_published=False)


def sprint_input_bindings(observation, pointer, record, expected):
    try:
        fields = sprint_input_reference_fields(record['declarations'], expected,
            runtime_root_class_path=record.get('class_path'))
    except ValueError as error:
        name = 'Blackboard' if expected == 'Pawn' else 'SprintComponent'
        return [input_scope_refusal(record['declarations'], name, error)]
    return [observation.reference(pointer, field, expected_base='ActorComponent') for field in fields]


def read_sprint_input_scope(session, pointer, record, expected, reads):
    if expected == 'GPBlackboardComponent':
        return dict(status='refused', name='native_input_bit_array_guard',
            reason='The +0xd98 bit-array owner path and field declaration are not qualified.',
            native_consumer_rvas=['0x4ef083a', '0x4ef083f'],
            instance_value_published=False, storage_read=False)
    if expected != 'DFMSkillComponent':
        return None
    try:
        field = local_ability_array_field(record['declarations'])
    except ValueError as error:
        return input_scope_refusal(record['declarations'], 'LocalAbilityInstances', error)
    at, size = pointer+field['storage_offset'], field['element_bytes']
    raw = session.stable(at, size)
    if (at, size) in reads and reads[(at, size)] != raw:
        raise ValueError('Current Sprint input scope bytes changed')
    reads[(at, size)] = raw
    try:
        header = local_ability_array_header(raw, field)
    except ValueError as error:
        return input_scope_refusal(record['declarations'], 'LocalAbilityInstances', error)
    return dict(status='observed', local_ability_instances=header,
        ability_instances_initialized_inferred=False, snapshot_atomic=False)


def object_metadata(session, pointer, identity, observation, reads):
    """Record flags and a typed Outer; neither proves native name stability."""
    raw = session.stable(pointer + 0x18, 4)
    if (pointer + 0x18, 4) in reads and reads[(pointer + 0x18, 4)] != raw:
        raise ValueError('Current vitals object flags changed between metadata visits')
    reads[(pointer + 0x18, 4)] = raw
    flags, = struct.unpack('<I', raw)
    outer_at = int(identity['outer_address'], 16)
    if outer_at:
        outer_identity = observation.identify(address(outer_at), 'Object')
        initialized = outer_identity['serial'] != 0
        outer = dict(status='typed_existing_reference' if initialized else
            'typed_reference_weak_identity_uninitialized', identity=outer_identity,
            weak_identity_initialized=initialized)
    else:
        outer = dict(status='null_reference')
    return dict(typed_name=identity['name'], object_flags=hex(flags), flags_storage_offset=0x18,
        default_subobject_flag_present=bool(flags & 0x40000),
        class_default_object_flag_present=bool(flags & 0x10),
        weak_identity_initialized=identity['serial'] != 0, outer=outer,
        name_stability_inferred=False)


def serial_zero_attribute_scope(record, expected, pawn, role):
    """Allow only current typed Pawn-owned Health/Speed storage without a weak key."""
    if expected not in ('GPAttributeSetHealth', 'GPAttributeSetSpeed'):
        return None
    required_binding = 'HealthSet' if expected == 'GPAttributeSetHealth' else 'AttributeSetSpeed'
    info, identity = record['object_metadata'], record['identity']
    outer = info.get('outer', {})
    outer_identity = outer.get('identity', {})
    if (role.rpartition('.')[2] != required_binding or
            record['class_path'] != '/Script/GPGameplay.' + expected or
            not identity.get('name') or identity['name'] != info['typed_name'] or
            not identity.get('class_ancestry') or identity['class_ancestry'][0] != expected or
            identity.get('serial') != 0 or identity.get('key') is not None or
            info['weak_identity_initialized'] is not False or
            info['class_default_object_flag_present'] is not False or
            int(info['object_flags'], 16) & 0x10 or
            int(identity['outer_address'], 16) != pawn or
            outer.get('status') != 'typed_existing_reference' or
            int(outer_identity.get('address', '0'), 16) != pawn or
            outer_identity.get('serial', 0) <= 0 or
            'Pawn' not in outer_identity.get('class_ancestry', [])):
        raise ValueError('Serial-zero attribute lacks its exact current typed Pawn binding')
    return dict(snapshot_atomic=False, weak_identity_initialized=False,
        native_serial_continuity_proved=False, weak_key_created=False,
        current_typed_binding_required=True, object_identity_rechecked=True,
        attribute_bytes_rechecked=True, native_methods_invoked=False,
        native_serial_allocation_rva='0x10ea1680')


class RecheckedAttributeValues:
    """Keep bounded source-selected value bytes for the final publication check."""
    def __init__(self, session, reads):
        self.session, self.reads = session, reads

    def read(self, pointer, size):
        if size not in (16, 24):
            raise ValueError('Serial-zero attribute read exceeds its declared storage scope')
        raw = self.session.stable(pointer, size)
        if (pointer, size) in self.reads and self.reads[(pointer, size)] != raw:
            raise ValueError('Current serial-zero attribute bytes changed')
        self.reads[(pointer, size)] = raw
        return raw


def read_serial_zero_attributes(session, pointer, record, expected, pawn, role, observation, reads):
    policy = serial_zero_attribute_scope(record, expected, pawn, role)
    if policy is None:
        return None, []
    if observation.identify(pointer, expected) != record['identity']:
        raise ValueError('Serial-zero attribute identity changed before its value read')
    attributes = read_attribute_state(RecheckedAttributeValues(session, reads), pointer,
        record['declarations'], expected)
    if observation.identify(pointer, expected) != record['identity']:
        raise ValueError('Serial-zero attribute identity changed after its value read')
    return policy, attributes


def read_component_lifecycle(session, pointer, declarations, expected, pawn, observation, reads):
    creation = component_lifecycle_declaration(declarations, expected)
    if creation is None:
        return None

    def stable(at, size):
        raw = session.stable(at, size)
        if (at, size) in reads and reads[(at, size)] != raw:
            raise ValueError('Current native component lifecycle bytes changed')
        reads[(at, size)] = raw
        return raw

    registered = stable(pointer+0xc8, 1)[0]
    lifecycle = stable(pointer+0xcc, 1)[0]
    creation_value = stable(pointer+0xce, 1)[0]
    owner_at, = struct.unpack('<Q', stable(pointer+0xe8, 8))
    owner = dict(status='null_reference')
    if owner_at:
        owner_at = address(owner_at)
        identity = observation.identify(owner_at, 'Actor')
        owner = dict(status='typed_existing_reference' if identity['serial'] else
            'typed_reference_weak_identity_uninitialized', identity=identity,
            is_current_pawn=owner_at == pawn, storage_offset=0xe8,
            native_consumer_rva='0x4531107')
        if owner_at == pawn:
            raw = stable(owner_at+0x94, 2)
            owner['native_dispatch_guards'] = dict(raw=raw.hex(), storage_offset=0x94,
                initialize_dispatch_bit_set=bool(raw[0] & 4),
                beginplay_dispatch_state_mask=raw[1] & 0x18,
                native_consumer_rvas=['0x1270ccf9', '0x1270cd0e'])
    return dict(raw_registered_byte=hex(registered), registered_byte_offset=0xc8,
        raw_lifecycle_byte=hex(lifecycle), lifecycle_byte_offset=0xcc,
        registered=bool(registered & 1), wants_initialize_component=bool(lifecycle & 2),
        native_created_flag_set=bool(lifecycle & 8), native_initialize_flag_set=bool(lifecycle & 0x10),
        native_beginplay_flag_set=bool(lifecycle & 0x20),
        creation_method=dict(field=creation, raw=hex(creation_value)), owner_private=owner,
        derived_initialization_success_inferred=False, native_methods_invoked=False,
        snapshot_atomic=False)


def enrich_existing_layout(session, base, record, hooks, reads):
    """Keep every existing command/parent and add descriptor-only serializer facts."""
    commands = record.get('layout', {}).get('commands', [])
    if len(commands) > 4096:
        raise ValueError('The scoped existing vitals command count exceeds its local bound')
    for command in commands:
        descriptor = command['descriptor_address']
        if not descriptor:
            continue
        descriptor = address(descriptor)
        raw = session.stable(descriptor, 0x60)
        if (descriptor, 0x60) in reads and reads[(descriptor, 0x60)] != raw:
            raise ValueError('Current vitals property metadata changed between layout visits')
        reads[(descriptor, 0x60)] = raw
        command['current_property_declaration'] = dict(
            array_dimension=struct.unpack_from('<i', raw, 0x3c)[0],
            element_bytes=struct.unpack_from('<i', raw, 0x40)[0],
            storage_offset=struct.unpack_from('<i', raw, 0x54)[0],
            property_flags=hex(struct.unpack_from('<Q', raw, 0x48)[0]))
        for slot, key in ((0x90, 'property_serializer_hook'), (0x88, 'property_scalar_leaf_hook')):
            command[key] = observed_virtual_method(session, base, descriptor, slot)
            hooks.append((descriptor, command[key]))


def scalar_request(metadata):
    layout = metadata.get('layout', {})
    parents, requests = layout.get('parents', []), {}
    for command in layout.get('commands', []):
        name, opcode = command.get('descriptor_name'), command.get('dispatch_opcode')
        parent = command.get('parent_index')
        if (not isinstance(name, str) or not any(t in name.lower() for t in SCALAR_TERMS) or
                opcode not in FORMATS or type(parent) is not int or not 0 <= parent < len(parents) or
                parents[parent].get('descriptor_address') != command.get('descriptor_address')):
            continue
        if name in requests or len(requests) >= 16:
            raise ValueError('The scoped existing scalar declarations are ambiguous or over bound')
        requests[name] = opcode
    return requests


def getter_attribute_fields(declarations, expected):
    result = []
    for getter, offset in GETTER_FIELDS.get(expected, {}).items():
        fields = [dict(f, declaring_class=d['class_name']) for d in declarations for f in d['fields']
                  if f['storage_offset'] == offset]
        if (len(fields) != 1 or fields[0]['element_bytes'] < 16 or
                fields[0]['array_dimension'] != 1):
            raise ValueError('The current declared native getter attribute changed: ' + getter)
        result.append((getter, fields[0]))
    return result


def sprint_gate_fields(declarations, expected):
    result = []
    for name, offset in SPRINT_GATE_FIELDS.get(expected, {}).items():
        fields = [dict(f, declaring_class=d['class_name']) for d in declarations for f in d['fields']
                  if f['name'] == name]
        if (len(fields) != 1 or fields[0]['storage_offset'] != offset or
                fields[0]['element_bytes'] != 1 or fields[0]['array_dimension'] != 1):
            raise ValueError('The current declared native sprint gate changed: ' + name)
        result.append(fields[0])
    return result


def observe(game_root, trial_report):
    trial_raw = Path(trial_report).read_bytes()
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
        identity = sink['callback']
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
               if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True and
               p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=identity)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current owned PC/Pawn binding could not be rechecked')
        pawn = address(binding['pc_pawn_reference']['address'])
        classes, values, metadata_reads, attribute_reads, hooks = {}, {}, {}, {}, []

        def metadata(pointer, expected):
            before = observation.identify(pointer, expected)
            klass = address(before['class_address'])
            if klass not in classes:
                existing = label_existing(session, base, driver, klass)
                enrich_existing_layout(session, base, existing, hooks, metadata_reads)
                classes[klass] = dict(identity=identity(klass, 'Class'),
                    declarations=typed_declarations(session, base, klass, identity),
                    class_path=object_path(session.read, base, klass),
                    existing_driver_class=existing)
            record = dict(classes[klass], identity=before,
                object_metadata=object_metadata(session, pointer, before, observation, metadata_reads))
            values[pointer] = record
            return record

        observation = VitalsBindingObservation(session, base, identity, metadata)
        pawn_record = metadata(pawn, 'Pawn')
        if not pawn_record['object_metadata']['weak_identity_initialized']:
            raise ValueError('Current owned Pawn weak identity is uninitialized')
        fields = selected_fields(pawn_record['declarations'], PAWN_FIELDS)
        links = [observation.reference(pawn, f) for f in fields]
        controller_record = metadata(pc_at, 'PlayerController')
        if not controller_record['object_metadata']['weak_identity_initialized']:
            raise ValueError('Current owned controller weak identity is uninitialized')
        controller_fields = selected_fields(controller_record['declarations'], {'GPInputManager': 'GPInputManager'})
        controller_links = [observation.reference(pc_at, f) for f in controller_fields]
        pending = [(pawn, 'Pawn', 'current_pawn'), (pc_at, 'PlayerController', 'current_controller')]
        pending += [(address(r['identity']['address']), r['declared_native_class'], r['field_name'])
                    for r in links + controller_links if r['status'] in
                    ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized')]
        objects, seen = [], set()
        while pending:
            pointer, expected, role = pending.pop(0)
            if pointer in seen:
                continue
            if len(seen) >= 16:
                raise ValueError('The fixed vitals object count bound was exceeded')
            seen.add(pointer)
            record = metadata(pointer, expected)
            object_links = links if pointer == pawn else controller_links if pointer == pc_at else []
            if not record['object_metadata']['weak_identity_initialized']:
                policy, attribute_state = read_serial_zero_attributes(session, pointer, record,
                    expected, pawn, role, observation, attribute_reads)
                objects.append(dict(**record, scope=role, bound_references=object_links,
                    instance_values_status=('read_rechecked_typed_attribute_without_weak_identity'
                        if policy else 'not_read_uninitialized_native_weak_identity'),
                    instance_value_read_contract=policy,
                    existing_layout_scalars={}, native_getter_attribute_values=[],
                    native_attribute_storage_values=attribute_state, scoped_skill_state=None,
                    native_sprint_gate_values=[], native_movement_override=None,
                    scoped_attribute_current_values=[], native_health_display_base=None,
                    scoped_sprint_input_state=dict(status='not_read_uninitialized_native_weak_identity')))
                continue
            lifecycle_state = read_component_lifecycle(session, pointer, record['declarations'],
                expected, pawn, observation, metadata_reads)
            if expected == 'GPInputManager':
                movement_fields = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
                    for f in d['fields'] if f.get('declared_native_class') == 'GPInputMovementLogic']
                if len(movement_fields) > 1:
                    raise ValueError('The current declared movement input logic is ambiguous')
                for field in movement_fields:
                    result = observation.reference(pointer, field)
                    object_links.append(result)
                    if result['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
                        pending.append((address(result['identity']['address']), 'GPInputMovementLogic', field['name']))
            for field in follow_fields(record['declarations'], expected, role):
                result = observation.reference(pointer, field)
                object_links.append(result)
                if result['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
                    pending.append((address(result['identity']['address']), field['declared_native_class'],
                        role + '.' + field['name']))
            input_links = sprint_input_bindings(observation, pointer, record, expected)
            object_links.extend(input_links)
            for result in input_links:
                if result['status'] in ('typed_existing_reference', 'typed_reference_weak_identity_uninitialized'):
                    pending.append((address(result['identity']['address']), result['declared_native_class'],
                        role+'.'+result['field_name']))
            input_state = read_sprint_input_scope(session, pointer, record, expected, metadata_reads)
            request = scalar_request(record['existing_driver_class'])
            scalars = read_declared_scalar_fields(session, pointer, record['existing_driver_class'], request)
            attributes = []
            for getter, field in getter_attribute_fields(record['declarations'], expected):
                # Each pinned actual getter selects this declared attribute; 2fe60a0 reads its float at +c.
                raw = session.read(pointer + field['storage_offset'] + 12, 4)
                value, = struct.unpack('<f', raw)
                if not math.isfinite(value):
                    raise ValueError('A scoped current native getter attribute is not finite')
                attributes.append(dict(getter=getter, field=field, value=value, raw=raw.hex(),
                    scalar_reader_rva='0x2fe60a0', attribute_value_member_offset=12,
                    native_getter_invoked=False))
            scoped_attributes = []
            for field in attribute_current_fields(record['declarations'], expected):
                raw = session.read(pointer+field['storage_offset']+12, 4)
                value, = struct.unpack('<f', raw)
                if not math.isfinite(value):
                    raise ValueError('A scoped native attribute current value is not finite')
                scoped_attributes.append(dict(field=field, value=value, raw=raw.hex(),
                    scalar_reader_rva='0x2fe60a0', attribute_value_member_offset=12,
                    native_getter_invoked=False, initialization_success_inferred=False))
            skill_state = read_skill_state(session, pointer, record['declarations'], expected)
            attribute_state = read_attribute_state(session, pointer, record['declarations'], expected)
            health_display_base = read_health_display_base(session, pointer,
                record['declarations']) if pointer == pawn else None
            gates = []
            for field in sprint_gate_fields(record['declarations'], expected):
                # 44c1f7d and 44c1fd3 read these exact full bytes, without a packed-bool mask.
                raw = session.read(pointer + field['storage_offset'], 1)
                if raw[0] not in (0, 1):
                    raise ValueError('A scoped native sprint gate is not a canonical bool')
                gates.append(dict(field=field, value=bool(raw[0]), raw=raw.hex(),
                    native_consumer_rva='0x44c1a70'))
            if expected == 'GPCharacterMovementLimitDataAsset':
                fields = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
                    for f in d['fields'] if f['storage_offset'] == 0x36]
                if (len(fields) != 1 or fields[0]['element_bytes'] != 1 or
                        fields[0]['array_dimension'] != 1 or fields[0]['field_vtable_rva'] != 0x15a868a0):
                    raise ValueError('The current native MovementLimitConfig sprint bool changed')
                raw = session.read(pointer + 0x36, 1)
                if raw[0] not in (0, 1):
                    raise ValueError('The current movement limit sprint gate is not a canonical bool')
                gates.append(dict(field=fields[0], value=bool(raw[0]), raw=raw.hex(),
                    native_consumer_rva='0x44c3af7', nonzero_clears_can_sprint=True))
            override = None
            if pointer == pawn:
                fields = [dict(f, declaring_class=d['class_name']) for d in record['declarations']
                    for f in d['fields'] if f['name'] == 'CurrentOverrideMovementInfo']
                if (len(fields) != 1 or fields[0]['storage_offset'] != 0x16f0 or
                        fields[0]['element_bytes'] != 2 or fields[0]['array_dimension'] != 1):
                    raise ValueError('The current native movement override declaration changed')
                raw = session.read(pointer + 0x16f0, 2)
                override = dict(field=fields[0], raw=raw.hex(), first_byte=raw[0], second_byte=raw[1],
                    native_consumer_rvas=['0x44c245f', '0x44c28e0'],
                    nonzero_first_and_second_below_three_clears_stamina_gate=bool(raw[0] and raw[1] < 3))
            objects.append(dict(**record, scope=role, bound_references=object_links,
                instance_values_status='read_rechecked_typed_current_object',
                existing_layout_scalars=scalars, native_getter_attribute_values=attributes,
                native_attribute_storage_values=attribute_state,
                native_sprint_gate_values=gates, native_movement_override=override,
                scoped_attribute_current_values=scoped_attributes, scoped_skill_state=skill_state,
                native_health_display_base=health_display_base,
                native_component_lifecycle=lifecycle_state, scoped_sprint_input_state=input_state))
        for descriptor, hook in hooks:
            recheck_virtual_method(session, base, descriptor, hook)
        if any(session.stable(at, size) != raw for (at, size), raw in metadata_reads.items()):
            raise ValueError('Current vitals object flags or property metadata changed')
        if any(session.stable(at, size) != raw for (at, size), raw in attribute_reads.items()):
            raise ValueError('Current serial-zero attribute bytes changed before publication')
        for klass, before in classes.items():
            if (identity(klass, 'Class') != before['identity'] or
                    typed_declarations(session, base, klass, identity) != before['declarations']):
                raise ValueError('Vitals declaration identity changed during observation')
        observation.finish()
        sink['recheck_roots']()
        reader.verify_identity()
        if reader.find_module() != base or pins != source_pins():
            raise ValueError('The fixed vitals observation source or module changed')
        return dict(kind='owned_vitals_existing_metadata_observation', status='observed',
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding, objects=objects,
            read_calls=session.calls, read_bytes=session.bytes_read, identities_and_fields_rechecked=True,
            process_memory_written=False, native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            snapshot_atomic=False, gameplay_initialization_verified=False)
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    opts = parser.parse_args()
    if opts.output.exists() or not opts.output.resolve().is_relative_to(ROOT / 'work'):
        parser.error('Use a new project work output')
    owned_trial_identity(json.loads(opts.trial_report.read_bytes()), opts.game_root)
    source_pins()
    if opts.request_uac and not ctypes.windll.shell32.IsUserAnAdmin():
        request_elevation(['-B', str(Path(__file__).resolve()), '--game-root', str(opts.game_root.resolve()),
            '--trial-report', str(opts.trial_report.resolve()), '--output', str(opts.output.resolve())], opts.output)
        result = json.loads(opts.output.read_bytes())
    else:
        try:
            result = observe(opts.game_root, opts.trial_report)
        except Exception as error:
            result = dict(status='refused', error_type=type(error).__name__, reason=str(error),
                process_memory_written=False, native_methods_invoked=False, packets_sent=False)
        write_exclusive_report(opts.output, result)
    print(json.dumps(dict(status=result['status'], reason=result.get('reason'), output=str(opts.output))))
