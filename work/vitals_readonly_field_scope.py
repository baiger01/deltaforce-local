"""Bounded fields from rechecked same-build declarations, never wire defaults."""
import math
import struct
from runtime_declaration_supplement import exact_runtime_variant

DECLARATION_SOURCE = 'work/native-client-tests/1792297548603201600/owned-vitals-input-owner-metadata.json'
DECLARATION_SHA256 = 'ae64c8d0b1e63355a60dd4d86e81373ea9fd598000eff7988107fc0fbf533e02'
BINDING_DECLARATION_SOURCE = 'work/native-client-tests/1792297548603201600/owned-vitals-attributes-metadata.json'
BINDING_DECLARATION_SHA256 = '3d59a171c18f6a953502fe48e41beac2ea56576056da20cabbe5f0173abef64f'
SPRINT_DECLARATION_SOURCE = 'work/native-client-tests/1792311694804456800/owned-vitals-metadata.json'
SPRINT_DECLARATION_SHA256 = '0b9b7b84aeb27ebc33ab6caab0c9f8f6cc2508ed790fdb56f0868c0b3872b7c1'
SPRINT_INPUT_REFERENCES = {
    'Pawn': ('Blackboard', 0x1020, 'GPCharacterBase', 'GPBlackboardComponent',
        0x1c0000000a001d),
    'GPBlackboardComponent': ('SprintComponent', 0x1c8, 'GPBlackboardComponent',
        'GPSprintComponent', 0x1400000008001c),
}
LOCAL_REFERENCES = {
    'GPSprintComponent': {'GPOwner': (0x128, 'GPCharacter',
        0x1ab613b0, 'FEncryptedObjectProperty', 0x2c080000000000)},
    'DFMSkillComponent': {'SkillDataFlow': (0x220, 'GPSkillDataFlow',
        0x15a86b80, 'FObjectProperty', 0x18001040000200)},
    'DFMHealthDataComponent': {'HealthSet': (0x280, 'GPAttributeSetHealth',
        0x1ab613b0, 'FEncryptedObjectProperty', 0x1c000000000014)},
    'GPStaminaDataComponent': {'AttributeSetSpeed': (0x1e0, 'GPAttributeSetSpeed',
        0x15a86b80, 'FObjectProperty', 0x28081040000200)},
    'GPCharacterMovementComponent': {'AttributeSetSpeed': (0xd10, 'GPAttributeSetSpeed',
        0x15a86b80, 'FObjectProperty', 0x28081040000200)},
}
ATTRIBUTE_CURRENT = {
    'GPAttributeSetSpeed': {'Speed': 0x30, 'RuntimeMaxSpeed': 0x48,
        'StandBasicSpeed': 0x58, 'SprintBasicSpeed': 0x68,
        'Moveable': 0xd8, 'LockSprint': 0xe8, 'EnableSprint': 0x1f8},
    'GPAttributeSetHealth': {'ShieldHealth': 0xb8, 'MaxShieldHealth': 0xd0},
}
SKILL_SCALARS = {'GMExpertID': (0x4288, 8, 0x15a86560, '<q'),
                 'SkillPlayerIndex': (0x218, 4, 0x15a863c0, '<i')}
SKILL_ARRAYS = {'ReplicatedAbilityInstances': 0xf8, 'StaticSkillIDs': 0x1e0,
                'PendingGiveSkillIDs': 0x480}
ATTRIBUTE_STORAGE = {
    'GPAttributeSetSpeed': {**{name: (offset, 16) for name, offset in
        ATTRIBUTE_CURRENT['GPAttributeSetSpeed'].items()},
        'Stamina': (0x118, 16), 'MaxStamina': (0x128, 16)},
    'GPAttributeSetHealth': {'Health': (0x30, 24), 'MaxHealth': (0x48, 16),
        'ShieldHealth': (0xb8, 24), 'MaxShieldHealth': (0xd0, 16)},
}
LIFECYCLE_COMPONENTS = frozenset(('GPSprintComponent', 'GPStaminaDataComponent',
    'DFMSkillComponent', 'GPSkillReplicateComponent', 'DFMHealthDataComponent',
    'SOLHealthDataComponent', 'GPCharacterMovementComponent'))


def _field(declarations, name, offset, size, table):
    fields = [dict(f, declaring_class=d['class_name']) for d in declarations
        for f in d['fields'] if f['name'] == name]
    if (len(fields) != 1 or fields[0]['storage_offset'] != offset or
            fields[0]['element_bytes'] != size or fields[0]['array_dimension'] != 1 or
            fields[0]['field_vtable_rva'] != table):
        raise ValueError('Scoped current vitals declaration differs: '+name)
    return fields[0]


def attribute_current_fields(declarations, expected):
    return [_field(declarations, name, offset, 24 if name == 'ShieldHealth' else 16, 0x15a86f40)
        for name, offset in ATTRIBUTE_CURRENT.get(expected, {}).items()]


def local_reference_fields(declarations, expected):
    """Select sealed non-Net object references, never infer a property handle."""
    if expected == 'SOLHealthDataComponent':
        expected = 'DFMHealthDataComponent'
    result = []
    for name, (offset, target, table, kind, flags) in LOCAL_REFERENCES.get(expected, {}).items():
        field = _field(declarations, name, offset, 8, table)
        if (field.get('declared_native_class') != target or
                field.get('native_property_type') != kind or
                int(field.get('property_flags', '0'), 16) != flags or flags & 0x20):
            raise ValueError('Scoped current local vitals binding differs: ' + name)
        result.append(field)
    return result


def sprint_input_reference_fields(declarations, expected, *, runtime_root_class_path=None):
    """Only the current Pawn Blackboard and its exact native Sprint binding."""
    if expected not in SPRINT_INPUT_REFERENCES:
        return []
    name, offset, owner, target, flags = SPRINT_INPUT_REFERENCES[expected]
    field = _field(declarations, name, offset, 8, 0x1ab613b0)
    if (field['declaring_class'] != owner or field.get('declared_native_class') != target or
            field.get('declared_native_class_path') != '/Script/GPGameplay.'+target or
            field.get('native_property_type') != 'FEncryptedObjectProperty' or
            (int(field.get('property_flags', '0'), 16) != flags and not
                exact_runtime_variant('sprint_input_reference', runtime_root_class_path, field)) or flags & 0x20):
        raise ValueError('Scoped current Sprint input binding differs: '+name)
    return [field]


def local_ability_array_field(declarations):
    field = _field(declarations, 'LocalAbilityInstances', 0x108, 16, 0x1ab5b730)
    if (field['declaring_class'] != 'GPSkillComponentBase' or
            int(field.get('property_flags', '0'), 16) != 0x10000000000200):
        raise ValueError('Scoped current LocalAbilityInstances array declaration differs')
    return field


def local_ability_array_header(raw, field):
    if type(raw) is not bytes or len(raw) != 16:
        raise ValueError('The local ability array requires its exact bounded header')
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= 4096 or capacity and not data or
            data and (not 0x10000 <= data < 1 << 47 or data & 7)):
        raise ValueError('Scoped current LocalAbilityInstances array header is invalid')
    return dict(field=field, raw=raw.hex(), count=count, capacity=capacity,
        data_pointer_nonnull=bool(data), elements_read=False,
        network_serialization_inferred=False, initialization_success_inferred=False)


def component_lifecycle_declaration(declarations, expected):
    if expected not in LIFECYCLE_COMPONENTS:
        return None
    actor = [d for d in declarations if d['class_name'] == 'ActorComponent']
    if len(actor) != 1:
        raise ValueError('The current vitals component lacks its exact ActorComponent declaration')
    creation = _field(actor, 'CreationMethod', 0xce, 1, 0x15a87070)
    if int(creation.get('property_flags', '0'), 16) != 0x18001040000200:
        raise ValueError('The current native component CreationMethod flags differ')
    return creation


def read_attribute_state(session, pointer, declarations, expected):
    """Capture the entire declared attribute plus its proven Base/Current floats."""
    fields = [_field(declarations, name, offset, size, 0x15a86f40)
        for name, (offset, size) in ATTRIBUTE_STORAGE.get(expected, {}).items()]
    result = []
    for field in fields:
        raw = session.read(pointer + field['storage_offset'], field['element_bytes'])
        base, current = struct.unpack_from('<ff', raw, 8)
        if not math.isfinite(base) or not math.isfinite(current):
            raise ValueError('A scoped native attribute Base/Current value is not finite')
        result.append(dict(field=field, raw=raw.hex(), base_value=base, current_value=current,
            base_value_member_offset=8, current_value_member_offset=12,
            network_serialization_inferred=False, initialization_success_inferred=False))
    return result


def read_health_display_base(session, pointer, declarations):
    """Native Update8affb89 reads this Pawn float, independently of MaxHealth."""
    field = _field(declarations, 'MaxHealthBase', 0x1ff0, 4, 0x15a86700)
    raw = session.read(pointer+0x1ff0, 4)
    value, = struct.unpack('<f', raw)
    if not math.isfinite(value):
        raise ValueError('The native health display base is not finite')
    return dict(field=field, raw=raw.hex(), value=value, native_consumer_rva='0x8affb89',
        same_as_health_set_maximum_assumed=False)


def read_skill_state(session, pointer, declarations, expected):
    """Read two scalar values, three TArray headers and one opaque eight-byte struct.

    Array contents and opaque struct targets are never dereferenced. These values
    are source observations only; no ability ID or initialization is inferred.
    """
    if expected != 'DFMSkillComponent':
        return None
    scalar_fields = [(name, _field(declarations, name, offset, size, table), fmt)
        for name, (offset, size, table, fmt) in SKILL_SCALARS.items()]
    arrays = [(name, _field(declarations, name, offset, 16, 0x1ab5b730))
        for name, offset in SKILL_ARRAYS.items()]
    info = _field(declarations, 'SkillDetailInfo', 0x210, 8, 0x15a86f40)
    scalars, counts = {}, {}
    for name, field, fmt in scalar_fields:
        raw = session.read(pointer+field['storage_offset'], field['element_bytes'])
        scalars[name] = dict(value=struct.unpack(fmt, raw)[0], raw=raw.hex(), field=field)
    for name, field in arrays:
        raw = session.read(pointer+field['storage_offset'], 16)
        data, count, capacity = struct.unpack('<Qii', raw)
        if not 0 <= count <= capacity <= 4096 or count and not 0x10000 <= data < 1 << 47:
            raise ValueError('Scoped current skill array header is invalid: '+name)
        counts[name] = dict(count=count, capacity=capacity, data_pointer_nonnull=bool(data),
            field=field, elements_read=False)
    raw = session.read(pointer+info['storage_offset'], 8)
    if raw[4] not in (0, 1):
        raise ValueError('The native SkillDetailInfo bool is not canonical')
    expert, = struct.unpack_from('<i', raw)
    return dict(scalars=scalars, arrays=counts,
        skill_detail_info=dict(field=info, raw=raw.hex(), storage_is_zero=not any(raw),
            expert_id=expert, can_sliding_tackle=bool(raw[4]),
            native_struct_semantics_qualified=True, network_serialization_inferred=False,
            sliding_rule_comparison_matches=(bool(raw[4]) == (expert == 10007)),
            target_dereferenced=False))
