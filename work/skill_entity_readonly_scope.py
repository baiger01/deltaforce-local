"""Bounded readers for the current typed Skill component's primary entities.

No process API, native call, allocation, packet, layout construction or writer.
The caller retains its original current-Pawn and identity recheck callbacks.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = 'work/native-client-tests/1792328560808149500/owned-vitals-metadata.json'
CAPTURE_SHA256 = 'f3bcb54f0ea117e894069294a39cf4732ce757e86c7b6f63eb6a7f22dded321f'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
PINS = {
    CAPTURE: CAPTURE_SHA256,
    'work/evidence/model-init-chain-20261018/native-skill-entity-map-int32-layout-v1.json':
        '7e807e167ca0cc9d622acd2cc3bcdb1c149e12e0f505d05035b30cd40a693326',
    'work/evidence/model-init-chain-20261018/native-skill-slotmap-byte-key-layout-v1.json':
        '7e37afaae6f5cdecf6304c8196d839c1da775eba3b5b005b9353ffe5e156d7f2',
    'work/evidence/model-init-chain-20261018/native-skill-slotmap-byte-key-lookup-insert-v1.json':
        'df268503a9455e0a41c3e937e9ca35a8c3599ddd0a6995bc6c0efa5babbdbf22',
    'work/evidence/model-init-chain-20261018/native-skill-existing-weak-and-gs-thunks-v1.json':
        'de52eff159c00d169a668592ddd6c2e32a6ae6643ca78e120564776ce89e01ac',
    'work/evidence/model-init-chain-20261018/native-dfm-skill-manager-and-entity-instance-create-v1.json':
        '812f3acc38a884c0b0ecd2b8b8c317f076c8bde3773d1881a455112936a9ca9a',
    'work/evidence/model-init-chain-20261018/native-dfm-skill-authority-create-ability-v1.json':
        'c96c2916bdf9702a24c806324432ce060a5203bb806cbb07e143f719ecc5dd23',
    'work/evidence/model-init-chain-20261018/native-skill-entity-data-struct-declarations-v1.json':
        '7817b1a26f192cfefef67c2c7910b274060e95d03280639667fd68eef5c2e7f9',
    'work/evidence/model-init-chain-20261018/native-skill-subsystem-class-declarations-v1.json':
        'd7efa6b6f6496f6f12691219356774869144904f2c77fda2e627e1de4ee8bbe0',
    'work/evidence/model-init-chain-20261018/native-skill-subsystem-class-registration-v1.json':
        '26e590ab20d1ec744ad9bce47c6b1bd50af7661562afbde896f7931d1989723f',
    'work/evidence/model-init-chain-20261018/native-skill-entity-weak-class-registrations-v1.json':
        '2e5c8e3f7d7ea659a0268339b71bd5e8b69b48fd7128689885a6985c71598999',
    'work/evidence/model-init-chain-20261018/native-skill-data-system-and-gs-declarations-v1.json':
        '2bd63bfdf82315e84cb9352bc3a1b3006c2c31cd3ce60a83c364483ae80524d5',
    'work/evidence/model-init-chain-20261018/native-skill-state-struct-declarations-v1.json':
        '1b26769c606ea2a73ed2b4d2cbc6c847564b775da2eed2a2155b74bde6f2facd',
    'work/evidence/model-init-chain-20261018/native-skill-state-items-and-map-quest-structs-v1.json':
        'f1bd87af6027f897995bedbb863af6061d3cd09e345eb3df5770869ba5f8469e',
    'work/evidence/model-init-chain-20261018/native-skill-state-base-fields-v1.json':
        'f49e3dc575dcfff78f0b1d593e8a6f49cb93b97491db7e9fdf839cf0c1a9c6d0',
    'work/evidence/model-init-chain-20261018/native-skill-state-client-add-and-reconcile-v1.json':
        '9c8cb467278aebada486165fced6df75b8836ec3074aad1edf15cf49278eba2c',
    'work/evidence/model-init-chain-20261018/native-skill-gs-entity-registration-bridge-v1.json':
        '93282aaf6ae805a836fe6aa4d3525ca503a1d13f60006f7df36b4471bc1ae6ab',
}
FIELD_KEYS = ('name', 'storage_offset', 'element_bytes', 'array_dimension',
    'property_flags', 'field_vtable_rva')
MAX_SLOTS, MAX_BUCKETS, MAX_CONTEXTS = 256, 512, 32


def source_pins():
    for path, digest in PINS.items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest() != digest:
            raise ValueError('The primary skill source changed: '+path)
    return dict(PINS, **{'work/skill_entity_readonly_scope.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


def source_skill_fields():
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA256:
        raise ValueError('The current primary skill declaration source changed')
    obj, = [o for o in json.loads(raw)['objects'] if o['class_path'] ==
        '/Script/DFMGameplay.DFMSkillComponent' and o['identity']['name'] == 'DFMSkill']
    names = {'SkillSystem', 'SkillEntityMap', 'SkillEntitySlotMap'}
    result = {f['name']: dict({k: f[k] for k in FIELD_KEYS}, declaring_class=d['class_name'])
        for d in obj['declarations'] for f in d['fields'] if f['name'] in names}
    if set(result) != names or any(f['declaring_class'] != 'GPSkillComponent' for f in result.values()):
        raise ValueError('The sealed current Skill declarations are incomplete')
    return result


def qualified_skill_fields(declarations):
    result = {}
    for name, expected in source_skill_fields().items():
        rows = [dict(f, declaring_class=d['class_name']) for d in declarations
            for f in d['fields'] if f['name'] == name]
        if len(rows) != 1 or any(rows[0].get(k) != v for k, v in expected.items()):
            raise ValueError('The current primary skill declaration differs: '+name)
        result[name] = rows[0]
    return result


def qualified_state_fields(declarations):
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA256:
        raise ValueError('The sealed SkillState declaration source changed')
    obj, = [o for o in json.loads(raw)['objects'] if o['class_path'] ==
        '/Script/DFMGameplay.DFMSkillComponent']
    result = {}
    for name in ('SkillState', 'SkillState3P'):
        expected, = [dict({k: f[k] for k in FIELD_KEYS}, declaring_class=d['class_name'])
            for d in obj['declarations'] for f in d['fields'] if f['name'] == name]
        actual = [dict(f, declaring_class=d['class_name']) for d in declarations
            for f in d['fields'] if f['name'] == name]
        if len(actual) != 1 or any(actual[0].get(k) != v for k, v in expected.items()):
            raise ValueError('The current primary SkillState declaration differs: '+name)
        result[name] = actual[0]
    return result


def _array_header(fact, at, stride, maximum):
    _span(at, 16, 8)
    raw = fact(at, 16)
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= maximum or capacity and not data or
            data and (data & 7 or not 0x10000 <= data < data+max(1, count)*stride < 1 << 47)):
        raise ValueError('The current SkillState array exceeds its source-qualified bound')
    return dict(header_hex=raw.hex(), count=count, capacity=capacity), data


def read_replicated_states(fact, skill, declarations):
    """Actual reflected initial state, separate from primary runtime entities."""
    fields, result = qualified_state_fields(declarations), {}
    for name in ('SkillState', 'SkillState3P'):
        field = fields[name]
        header, data = _array_header(fact, skill+field['storage_offset'], 40, 256)
        rows = []
        for index in range(header['count']):
            raw = fact(data+index*40, 40)
            execute_header, _ = _array_header(lambda at, size, p=data+index*40, r=raw:
                r[at-p:at-p+size], data+index*40+16, 48, 256)
            rows.append(dict(array_index=index, skill_id=struct.unpack_from('<i', raw)[0],
                skill_entity_unique_id=struct.unpack_from('<i', raw, 4)[0], using_ability_raw=raw[8],
                execute_id=struct.unpack_from('<i', raw, 32)[0],
                execute_data_header=execute_header,
                not_switch_weapon_raw=raw[36] if name == 'SkillState' else None,
                raw_hex=raw.hex(), execute_elements_read=False))
        result[name] = dict(field={k: field[k] for k in FIELD_KEYS},
            **header, entries=rows, native_element_bytes=40)
    header, data = _array_header(fact, skill+fields['SkillState']['storage_offset']+16, 4, 256)
    indices = list(struct.unpack('<'+'i'*header['count'], fact(data, header['count']*4))) if header['count'] else []
    result['UpdateIndexArray'] = dict(**header, values=indices)
    result['bCheckSkillLeave_raw'] = fact(skill+fields['SkillState']['storage_offset']+32, 1).hex()
    return result


def _span(at, size, alignment=1):
    if (type(at) is not int or type(size) is not int or not 0 < size <= 256*1024 or
            not 0x10000 <= at < at+size <= 1 << 47 or at % alignment):
        raise ValueError('The primary skill read span is invalid or over bound')


def read_map(fact, at, *, byte_key):
    """Enumerate actual native hash chains; no SparseArray allocator assumption.

    107cad0 and2311880 choose inline hash+38 or heap+40, bucket count+48,
    then follow live16B slots with next+8. Slot-key comparison differs.
    """
    if type(byte_key) is not bool:
        raise ValueError('The source-qualified map key type is required')
    _span(at, 80, 8)
    raw = fact(at, 80)
    data, count, capacity = struct.unpack_from('<Qii', raw)
    free = struct.unpack_from('<i', raw, 0x34)[0]
    if not 0 <= free <= count <= capacity <= MAX_SLOTS:
        raise ValueError('The primary skill map exceeds its slot bound')
    result = dict(header_hex=raw.hex(), slot_count=count, capacity=capacity,
        free_count=free, live_count=count-free, key_type='uint8' if byte_key else 'int32', entries=[])
    if count == free:
        return result
    _span(data, count*16, 8)
    buckets = struct.unpack_from('<i', raw, 0x48)[0]
    heap = struct.unpack_from('<Q', raw, 0x40)[0]
    if not 1 <= buckets <= MAX_BUCKETS or buckets & (buckets-1):
        raise ValueError('The primary skill hash bucket count is invalid')
    if not heap and buckets > 2:
        raise ValueError('The primary skill hash exceeds native inline storage')
    storage = heap or at+0x38
    _span(storage, buckets*4, 4)
    heads = struct.unpack('<'+'i'*buckets, fact(storage, buckets*4))
    seen, keys = set(), set()
    for bucket, index in enumerate(heads):
        while index != -1:
            if index in seen or not 0 <= index < count or len(seen) >= MAX_SLOTS:
                raise ValueError('The primary skill hash chain is cyclic or out of bounds')
            seen.add(index)
            slot = fact(data+index*16, 16)
            key = slot[0] if byte_key else struct.unpack_from('<i', slot)[0]
            value, following = struct.unpack_from('<ii', slot, 4)
            if key in keys or key & (buckets-1) != bucket:
                raise ValueError('The primary skill hash key or bucket is inconsistent')
            keys.add(key)
            result['entries'].append(dict(slot_index=index, bucket_index=bucket,
                key=key, value=value, raw_hex=slot.hex()))
            index = following
    if len(seen) != count-free:
        raise ValueError('The primary skill live count differs from its complete hash chains')
    result['entries'].sort(key=lambda x: x['slot_index'])
    return result


def read_contexts(fact, subsystem, entries):
    """31e58e0 stores entity+80 in both maps;34ce080 indexes the3f0-byte list."""
    if type(entries) is not list or len(entries) > MAX_CONTEXTS:
        raise ValueError('The current primary entity selection exceeds its bound')
    _span(subsystem+0x378, 16, 8)
    raw = fact(subsystem+0x378, 16)
    data, count, capacity = struct.unpack('<Qii', raw)
    if not 0 <= count <= capacity <= 16384 or capacity and not data:
        raise ValueError('The actual subsystem entity list header is invalid')
    if data:
        _span(data, max(1, count)*0x3f0 if count <= 256 else 1, 8)
    result = dict(header_hex=raw.hex(), count=count, capacity=capacity,
        native_element_bytes=0x3f0, entries=[], unselected_entities_read=False)
    selected = set()
    for item in entries:
        skill_id, index = item['key'], item['value']
        if type(index) is not int or not 0 <= index < count or index in selected:
            raise ValueError('The actual SkillEntityMap index is out of range or duplicated')
        selected.add(index)
        _span(data+index*0x3f0, 0x3f0, 8)
        entity = fact(data+index*0x3f0, 0x3f0)
        observed_skill, entity_id, observed_index = struct.unpack_from('<iii', entity, 0x78)
        if observed_skill != skill_id or observed_index != index:
            raise ValueError('The actual entity context does not match its primary component map')
        result['entries'].append(dict(skill_id=observed_skill, entity_id=entity_id,
            entity_index=observed_index, owner_uin=struct.unpack_from('<Q', entity, 0x88)[0],
            skill_state_type_raw=entity[0x90], skill_slot_raw=entity[0x126],
            ability_spawn_state_raw=entity[0x20],
            ability_instance_weak_hex=entity[0x10:0x18].hex(),
            ability_template_weak_hex=entity[0x18:0x20].hex(),
            context_sha256=hashlib.sha256(entity).hexdigest(),
            native_state_enum_meanings_inferred=False))
    return result
