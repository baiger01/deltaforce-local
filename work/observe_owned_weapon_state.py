"""Read bounded weapon state in an already owned, source-sealed shadow trial.

Only current typed Pawn components, their bounded WeaponList references and
this trial's actual EmptyHand GUID are selected. No client launch, native
method, resolver, layout construction, executable-byte read, process write,
account lookup or packet is used.
"""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from observe_owned_gameplay_metadata import (ROOT, SHIPPING_SHA256, BindingObservation,
    address, owned_trial_identity, source_pins as gameplay_source_pins, typed_declarations,
    label_existing, write_exclusive_report)
from observe_portable_map_runtime import (Win32MetadataReader, MetadataSession, validate_source,
    discover_roots, observe_first_player_state, request_elevation, observed_virtual_method,
    recheck_virtual_method, direct_root_reference, object_name)
from native_metadata_names import resolve_name
from native_metadata_paths import object_path
from native_guid_object_metadata import _Read, _lookup, _existing_weak, LOOKUP_TARGET_RVA, IMAGE_BYTES
from owned_weapon_values_codec import actor_schema_binding, ACTOR_SCHEMA_PATH, ACTOR_SCHEMA_SHA256
from portable_native_code_cache import CodeCache

PROFILE = 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'
CAPTURE = 'work/native-client-tests/1792304896147723900/owned-gameplay-metadata.json'
CAPTURE_SHA256 = '71a25ea64f873ba51b68a28b412755c92252d361498916eb0e5618e0add92827'
EMPTY_HAND_CLASS = '/Game/BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_EmptyHand.BP_EmptyHand_C'
MODULAR_CLASS = '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponModular.BP_WeaponModular_C'
MANIFEST_SHA256 = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
EXTRA_PINS = {
    'work/evidence/map-system-audit-20261018/native-owning-weapon-bool-property-mask-v1.json':
        'f9b0cb0b567d06fe183a74f1ea549b4a54706d389661cd71cc407d85f93fb616',
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-lookup.json':
        '467917bcf328517641977770aa7351ae9a290b453166de5ca43b5bb4db7f6627',
    'work/evidence/model-init-chain-20261018/native-map-marker-guid-hash-lookup.json':
        'e704b5ccb521f7a2571b359b7ea881d5a410504f8dec43ab677fa3be6e27842d',
}
SCOPE_NAMES = {
    'pawn': ('WeaponManagerComponent', 'WeaponReplicateComponent'),
    'manager': ('CharacterOwner', 'EmptyHandOverrideID', 'bUseEmptyHandOverride',
        'WeaponList', 'WeaponIdentityList', 'WeaponIDList', 'WeaponSlot', 'EmptyHandWeapon'),
    'replicate': ('CharacterOwner', 'CurrActiveWeapInfoArr', 'WeapInfoArray'),
    'actor': ('Owner', 'WeaponID', 'WeaponGuid', 'WeaponEquipPosition', 'WeaponSlot',
        'ServerWeaponIdentity', 'CharacterOwner', 'Role', 'RemoteRole'),
}
COMPONENT_SCOPES = (
    ('manager', 'WeaponManagerComponent', 'WeaponManager', 'WeaponManagerComponent',
        '/Script/GPGameplay.MultiWeaponManagerComponent'),
    ('replicate', 'WeaponReplicateComponent', 'WeaponReplicate', 'WeaponReplicateComponent',
        '/Script/GPGameplay.WeaponReplicateComponent'),
)
FIELD_KEYS = ('name', 'storage_offset', 'element_bytes', 'array_dimension', 'property_flags',
    'field_vtable_rva', 'native_property_type', 'declared_native_class', 'declared_native_class_path')


class WeaponPropertySourceMismatch(ValueError):
    """One selected serializer failed while independent typed metadata remains usable."""


def scoped_fields():
    raw = (ROOT/CAPTURE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CAPTURE_SHA256:
        raise ValueError('The scoped weapon declaration source changed')
    doc = json.loads(raw)
    selected = {
        'pawn': next(x for x in doc['objects'] if x['class_path'].endswith('.BP_DFMCharacter_C')),
        'manager': next(x for x in doc['objects'] if x['identity']['name'] == 'WeaponManager'),
        'replicate': next(x for x in doc['objects'] if x['identity']['name'] == 'WeaponReplicate'),
        'actor': next(x for x in doc['loaded_named_classes'] if x['class_path'] == EMPTY_HAND_CLASS),
    }
    return {scope: [dict({k: f[k] for k in FIELD_KEYS if k in f}, declaring_class=d['class_name'])
        for d in obj['declarations'] for f in d['fields'] if f['name'] in SCOPE_NAMES[scope]]
        for scope, obj in selected.items()}


def select_fields(declarations, scope):
    result = {}
    expected = modular_actor_source()[1] if scope == 'modular_actor' else scoped_fields()[scope]
    names = SCOPE_NAMES['actor'] if scope == 'modular_actor' else SCOPE_NAMES[scope]
    if len(expected) != len(names):
        raise ValueError('The fixed weapon field scope is incomplete')
    for before in expected:
        rows = [dict(f, declaring_class=d['class_name']) for d in declarations for f in d['fields']
            if f['name'] == before['name']]
        if len(rows) != 1 or any(rows[0].get(k) != v for k, v in before.items()):
            raise ValueError('The current scoped weapon declaration changed: '+before['name'])
        result[before['name']] = rows[0]
    return result


def bool_value(storage, masks):
    """10e8ebe0 reads ByteOffset/ByteMask/FieldMask at descriptor+8a/8b/8c."""
    if type(storage) is not bytes or type(masks) is not bytes or len(masks) != 3:
        raise ValueError('Exact bounded bool storage and current metadata are required')
    offset, byte_mask, field_mask = masks
    if (offset >= len(storage) or byte_mask == 0 or byte_mask & (byte_mask-1) or
            field_mask not in (byte_mask, 255)):
        raise ValueError('The current native bool mask is invalid')
    return dict(value=bool(storage[offset] & field_mask), raw_hex=storage.hex(),
        byte_offset=offset, byte_mask=byte_mask, field_mask=field_mask)


def array_header(raw, stride):
    if type(raw) is not bytes or len(raw) != 16 or type(stride) is not int or not 1 <= stride <= 280:
        raise ValueError('A current bounded array header and qualified stride are required')
    data, count, capacity = struct.unpack('<Qii', raw)
    if (not 0 <= count <= capacity <= 32 or data and (not 0x10000 <= data < 1 << 47 or data & 7) or
            capacity and not data or data and data+count*stride >= 1 << 47):
        raise ValueError('The scoped weapon array exceeds its fixed bound')
    return dict(data=data, count=count, capacity=capacity, element_bytes=stride)


def profile_weapon_manifest(plan):
    matches = [m for m in plan.manifests if m.class_path == EMPTY_HAND_CLASS]
    if len(matches) != 1:
        raise ValueError('The current profile must have one exact EmptyHand Actor')
    value = matches[0]
    if (type(value.actor_guid) is not int or not 2 <= value.actor_guid < 1 << 32 or value.actor_guid & 1 or
            value.client_sha256 != SHIPPING_SHA256 or value.references_resolvable is not True or
            value.connection_network_version != 13 or value.archive_network_version != 13 or
            len({m.actor_guid for m in plan.manifests}) != len(plan.manifests)):
        raise ValueError('The current EmptyHand manifest or complete Actor namespace changed')
    return value


def qualify_weapon_actor(identity, class_path, current_pawn_level):
    if (class_path != EMPTY_HAND_CLASS or identity.get('is_cdo') is not False or
            not identity.get('name', '').startswith('BP_EmptyHand_C') or
            'WeaponBase' not in identity.get('class_ancestry', ()) or
            address(identity['outer_address']) != current_pawn_level):
        raise ValueError('The mapped weapon is not this profile class in the current Pawn Level')


def modular_actor_source():
    from portable_modular_weapon_initialization import schema_binding
    from export_portable_modular_weapon_schema import CAPTURE as capture, CAPTURE_SHA256 as digest
    schema = schema_binding()
    if (schema['actor']['class_path'] != MODULAR_CLASS or schema['actor']['cdo_path'] !=
            MODULAR_CLASS.rsplit('.', 1)[0]+'.Default__BP_WeaponModular_C'):
        raise ValueError('The source-qualified Modular class/CDO changed')
    raw = (ROOT/capture).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest or schema['sources'].get(capture) != digest:
        raise ValueError('The actual Modular declaration observation changed')
    records = [r for r in json.loads(raw)['loaded_named_classes'] if r['class_path'] == MODULAR_CLASS]
    if len(records) != 1:
        raise ValueError('One actual source-qualified Modular class is required')
    selected = [dict({k: f[k] for k in FIELD_KEYS if k in f}, declaring_class=d['class_name'])
        for d in records[0]['declarations'] for f in d['fields'] if f['name'] in SCOPE_NAMES['actor']]
    return schema, selected


def read_weapon_actor_state(record, *, scope, pawn_record, observation, fields, facts, state):
    selected = select_fields(record['declarations'], scope)
    pointer, klass = (address(record['identity'][key]) for key in ('address', 'class_address'))
    current = {n: fields.field(klass, f) for n, f in selected.items()}
    for name in ('Owner', 'CharacterOwner'):
        state[name] = observation.reference(pointer, selected[name], expected_base='Actor')
        state[name]['is_current_pawn'] = (state[name].get('identity', {}).get('address') ==
                                        pawn_record['identity']['address'])
    for name, fmt in (('WeaponID', 'q'), ('WeaponGuid', 'Q'), ('WeaponEquipPosition', 'i'), ('WeaponSlot', 'B')):
        field = selected[name]
        raw = facts.fact(pointer+field['storage_offset'], struct.calcsize(fmt))
        state[name] = dict(field=field, value=struct.unpack('<'+fmt, raw)[0], raw_hex=raw.hex())
    state['WeaponSlot']['enum'] = fields.enum(current['WeaponSlot'])
    identity_type = fields.struct_type(current['ServerWeaponIdentity'], 'WeaponIdentity')
    unique = fields.nested(identity_type, 'UniqueId', 0, 4)
    fields.uint32(unique)
    raw = facts.fact(pointer+selected['ServerWeaponIdentity']['storage_offset'], 4)
    state['ServerWeaponIdentity'] = dict(field=selected['ServerWeaponIdentity'],
        unique_id=struct.unpack('<I', raw)[0], raw_hex=raw.hex(), unique_id_field=unique)
    for name in ('Role', 'RemoteRole'):
        field = selected[name]
        state[name] = dict(field=field, value=facts.fact(pointer+field['storage_offset'], 1)[0],
            enum=fields.enum(current[name], expected_name='ENetRole'))


def observe_carried_weapon_actors(entries, *, pawn_record, current_pawn_level,
        observation, fields, facts, metadata, results):
    """Follow only actual manager entries; no manifest, NetGUID or business ID is inferred."""
    from portable_modular_weapon_initialization import SCHEMA_SHA256
    schema, _ = modular_actor_source()
    if type(entries) is not list or len(entries) > 32 or type(results) is not list or results:
        raise ValueError('A bounded actual manager WeaponList and fresh result scope are required')
    selected, pointers = [], set()
    for index, identity in enumerate(entries):
        if identity is None:
            continue
        if type(identity) is not dict:
            raise ValueError('An actual typed manager weapon identity is required')
        pointer = address(identity['address'])
        if pointer in pointers:
            raise ValueError('The actual manager WeaponList contains a duplicate reference')
        pointers.add(pointer)
        selected.append((index, pointer, identity))
    if len(selected) > 4:
        raise ValueError('The carried weapon scope exceeds EmptyHand, two guns and one selected melee')
    if sum('BP_WeaponModular_C' in row[2].get('class_ancestry', ()) for row in selected) > 2:
        raise ValueError('The carried weapon scope exceeds two Modular Actors')
    from portable_melee_weapon import catalog as melee_catalog
    melee_paths = {r['class_path'] for r in melee_catalog()['rows'].values()}
    gun_count, melee_count = 0, 0
    for index, pointer, before in selected:
        identity = observation.identify(pointer, 'WeaponBase')
        if identity != before:
            raise ValueError('The manager-bound weapon identity changed')
        record = metadata(pointer, 'WeaponBase')
        if record['identity'] != identity:
            raise ValueError('The current manager-bound weapon metadata identity changed')
        if record['class_path'] == EMPTY_HAND_CLASS:
            qualify_weapon_actor(identity, record['class_path'], current_pawn_level)
            continue
        row = dict(**record, scope='carried_weapon_actor', manager_list_index=index,
            reference_origin='current_typed_WeaponManager.WeaponList', status='reading')
        results.append(row)
        state = {}
        try:
            is_melee = record['class_path'] in melee_paths
            gun_count += int(not is_melee)
            melee_count += int(is_melee)
            leaf = record['class_path'].rsplit('.', 1)[-1]
            if (record['class_path'] != schema['actor']['class_path'] and not is_melee or
                    identity.get('is_cdo') is not False or
                    not identity.get('name', '').startswith(leaf+'_') or
                    'WeaponBase' not in identity.get('class_ancestry', ()) or
                    address(identity['outer_address']) != current_pawn_level or
                    gun_count > 2 or melee_count > 1):
                raise ValueError('The carried weapon differs from its original class or current Pawn Level')
            row.update(source_cdo_path=(record['class_path'].rsplit('.', 1)[0]+'.Default__'+leaf),
                runtime_cdo_observed=False,
                actor_schema_sha256=SCHEMA_SHA256, outer_is_current_pawn_level=True)
            # Reject declaration/descriptor drift before reading any Actor values.
            read_weapon_actor_state(record, scope='modular_actor', pawn_record=pawn_record,
                observation=observation, fields=fields, facts=facts, state=state)
            row.update(state=state, status='observed')
        except ValueError as error:
            row.update(status='partial' if state else 'refused', reason=str(error))
            if state:
                row['state'] = state
            raise
    return results


class ReadFacts:
    def __init__(self, session):
        self.session, self.reads, self.bytes = session, {}, 0

    def fact(self, at, size):
        if len(self.reads) >= 8192 or not 0 < size <= 65536 or self.bytes+size > 2*1024*1024:
            raise ValueError('The fixed weapon metadata budget was exceeded')
        raw = self.session.stable(at, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('The scoped weapon reader returned incomplete bytes')
        key = at, size
        if key in self.reads and self.reads[key] != raw:
            raise ValueError('Selected weapon state changed during observation')
        if key not in self.reads:
            self.bytes += size
        self.reads[key] = raw
        return raw

    def finish(self):
        if any(self.session.stable(at, size) != raw for (at, size), raw in self.reads.items()):
            raise ValueError('Selected weapon state changed before publication')


def _profile_path(trial):
    bootstrap = trial.get('portable_map_bootstrap', {})
    served = bootstrap.get('source_pins', {})

    def read_profile(relative):
        if (type(relative) is not str or '\\' in relative or
                any(part in ('', '.', '..') for part in relative.split('/')) or
                not relative.startswith('outputs/df-local-server/protocol/portable-map-spawn/profile') or
                not relative.endswith('.json')):
            raise ValueError('The active weapon profile escaped its fixed scope')
        if relative not in served:
            raise ValueError('The active trial profile must be pinned')
        path = (ROOT/relative).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not 0 < path.stat().st_size <= 65536:
            raise ValueError('The active weapon profile escaped its fixed scope')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != served[relative]:
            raise ValueError('The active trial profile changed')
        return path, json.loads(raw)

    # Source pins include profile dependencies as well as the entry profile.
    if 'profile_relative_path' in bootstrap:
        path, doc = read_profile(bootstrap['profile_relative_path'])
        if doc.get('kind') != 'portable_local_map_bootstrap_profile':
            raise ValueError('The active trial entry is not a portable profile')
        return path

    candidates = []
    for relative in served:
        if not relative.startswith('outputs/df-local-server/protocol/portable-map-spawn/profile') or not relative.endswith('.json'):
            continue
        path, doc = read_profile(relative)
        if doc.get('kind') == 'portable_local_map_bootstrap_profile':
            candidates.append(path)
    if len(candidates) != 1:
        raise ValueError('One exact source-sealed active portable profile is required')
    return candidates[0]


def merge_source_pins(*groups):
    result = {}
    for group in groups:
        for relative, expected in group.items():
            if relative in result and result[relative] != expected:
                raise ValueError('Weapon source groups disagree: '+relative)
            result[relative] = expected
    return result


def source_pins(game_root, profile_path=None):
    from portable_map_bootstrap import load_plan
    path = ROOT/PROFILE if profile_path is None else Path(profile_path).resolve()
    plan = load_plan(ROOT, path)
    profile_weapon_manifest(plan)
    schema = actor_schema_binding()
    pins = merge_source_pins(plan.sources, gameplay_source_pins(), schema['sources'],
        {ACTOR_SCHEMA_PATH: ACTOR_SCHEMA_SHA256})
    from export_portable_modular_weapon_schema import OUTPUT as modular_path
    from portable_modular_weapon_initialization import (SCHEMA_SHA256 as modular_digest,
        source_pins as modular_source_pins)
    modular, _ = modular_actor_source()
    pins = merge_source_pins(pins, modular['sources'], modular_source_pins(),
        {modular_path.relative_to(ROOT).as_posix(): modular_digest})
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600', MANIFEST_SHA256, game_root)
    for relative, expected in EXTRA_PINS.items():
        raw = (ROOT/relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('The weapon readonly native source changed: '+relative)
        pins[relative] = expected
        for function in json.loads(raw)['functions']:
            code = cache.read(int(function['span_start'], 16), function['span_bytes'])
            if hashlib.sha256(code).hexdigest() != function['code_sha256']:
                raise ValueError('The current cached readonly weapon source changed')
    pins['work/native-code-cache/1792259162856698600/manifest.json'] = MANIFEST_SHA256
    for relative in ('work/observe_owned_weapon_state.py', 'work/native_guid_object_metadata.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


def selected_guid_mapping(session, base, *, driver, connection, guid, identity, recheck_binding):
    if type(guid) is not int or not 2 <= guid < 1 << 32 or guid & 1:
        raise ValueError('Only the exact current dynamic weapon GUID is supported')
    read = _Read(session)
    recheck_binding()
    if (read.pointer(driver+0x98) != connection or read.pointer(connection+0x58) != driver):
        raise ValueError('The current weapon driver/connection link changed')
    package = read.pointer(connection+0x68)
    package_identity = identity(package, 'PackageMapClient')
    if read.pointer(package+0x130) != connection:
        raise ValueError('The current weapon PackageMap backlink changed')
    table = read.pointer(package)
    if not base <= table <= base+IMAGE_BYTES-0x2d0 or read.pointer(table+0x2c8) != base+LOOKUP_TARGET_RVA:
        raise ValueError('The current GUID lookup differs from the qualified native consumer')
    cache = read.pointer(package+0x310)
    if read.fact(cache+0x152, 1) != b'\0' or read.fact(connection+0xb4, 1)[0] & 1:
        raise ValueError('The weapon lookup is not an ordinary non-export reference')
    header = read.fact(cache, 0x50)
    found = _lookup(read, cache, header, guid)
    result = dict(guid=guid, status='mapping_missing')
    if found is not None:
        index, weak = found
        result.update(_existing_weak(read, base, weak), map_slot_index=index, weak_reference_hex=weak.hex())

    def finish():
        recheck_binding()
        if identity(package, 'PackageMapClient') != package_identity:
            raise ValueError('The current weapon PackageMap identity changed')
        read.recheck()

    finish()
    return result, finish


class WeaponFields:
    def __init__(self, session, base, identity, facts):
        self.session, self.base, self.identity, self.facts = session, base, identity, facts
        self.hooks, self.descriptors = [], {}

    def properties(self, root):
        if root in self.descriptors:
            return self.descriptors[root]
        cursor, classes, nodes, rows = root, set(), set(), []
        while cursor:
            if cursor in classes or len(classes) >= 32:
                raise ValueError('Weapon property declaring-Struct cycle')
            classes.add(cursor)
            owner = self.identity(cursor, 'Struct')
            parent = struct.unpack('<Q', self.facts.fact(cursor+0x48, 8))[0]
            node = struct.unpack('<Q', self.facts.fact(cursor+0x70, 8))[0]
            while node:
                if node in nodes or len(nodes) >= 1024:
                    raise ValueError('Weapon reflected field cycle or count bound')
                nodes.add(node)
                raw = self.facts.fact(node, 0x60)
                following, field_class = struct.unpack_from('<QQ', raw, 0x18)
                mask = struct.unpack('<Q', self.facts.fact(field_class+0x10, 8))[0]
                if mask & 1 and mask & 0x8000:
                    if not raw[0x10] or struct.unpack_from('<Q', raw, 8)[0] != cursor:
                        raise ValueError('The current weapon property has a foreign declaring owner')
                    name = object_name(self.session.read, self.base, node, field_representation=0).display_text
                    rows.append(dict(name=name, declaring_class=owner['name'], descriptor_address=node,
                        storage_offset=struct.unpack_from('<i', raw, 0x54)[0],
                        element_bytes=struct.unpack_from('<i', raw, 0x40)[0],
                        array_dimension=struct.unpack_from('<i', raw, 0x3c)[0],
                        property_flags=hex(struct.unpack_from('<Q', raw, 0x48)[0]),
                        field_vtable_rva=struct.unpack_from('<Q', raw)[0]-self.base))
                node = following
            if self.identity(cursor, 'Struct') != owner:
                raise ValueError('The weapon declaring Struct identity changed')
            cursor = parent
        self.descriptors[root] = rows
        return rows

    def field(self, root, expected):
        matches = [r for r in self.properties(root) if r['name'] == expected['name'] and
            r['declaring_class'] == expected['declaring_class']]
        if len(matches) != 1 or any(matches[0].get(k) != expected[k] for k in
                ('storage_offset', 'element_bytes', 'array_dimension', 'field_vtable_rva', 'property_flags')):
            raise ValueError('The selected current weapon descriptor changed: '+expected['name'])
        return matches[0]

    def nested(self, root, name, offset, size):
        matches = [r for r in self.properties(root) if r['name'] == name]
        if len(matches) != 1 or (matches[0]['storage_offset'], matches[0]['element_bytes'],
                matches[0]['array_dimension']) != (offset, size, 1):
            raise ValueError('The current nested weapon field differs: '+name)
        return matches[0]

    def hook(self, descriptor, target, slot=0x90):
        hook = observed_virtual_method(self.session, self.base, descriptor, slot)
        if hook.get('target_rva') != target or hook.get('inside_pinned_image') is not True:
            raise WeaponPropertySourceMismatch(
                'The scoped property serializer differs from its pinned native source: '
                f'descriptor={hex(descriptor)} slot={hex(slot)} expected={hex(target)} '
                f'observed={hook.get("target_rva")!r}')
        recheck_virtual_method(self.session, self.base, descriptor, hook)
        self.hooks.append((descriptor, hook))
        return hook

    def uint32(self, field):
        # WeaponIdentity.UniqueId UHT generation 6; the numeric NET wrapper
        # delegates to its raw 32-bit archive leaf, not FByteProperty's enum path.
        if field['element_bytes'] != 4:
            raise ValueError('The current weapon uint32 extent changed')
        self.hook(field['descriptor_address'], 0x10e5ce20)
        self.hook(field['descriptor_address'], 0x286bf70, slot=0x88)

    def struct_type(self, field, name):
        at = field['descriptor_address']
        self.hook(at, 0x10e8ee50)
        pointer = address(struct.unpack('<Q', self.facts.fact(at+0x90, 8))[0])
        value = self.identity(pointer, 'ScriptStruct')
        if value['name'] != name:
            raise ValueError('The scoped weapon ScriptStruct type differs')
        return pointer

    def boolean(self, instance, field):
        descriptor = field['descriptor_address']
        self.hook(descriptor, 0x10e8ebe0)
        masks = self.facts.fact(descriptor+0x8a, 3)
        raw = self.facts.fact(instance+field['storage_offset'], field['element_bytes'])
        return dict(field=field, **bool_value(raw, masks))

    def enum(self, field, *, enum_property=False, expected_name=None):
        descriptor = field['descriptor_address']
        self.hook(descriptor, 0x10e29fa0 if enum_property else 0x10e8ec50)
        pointer = struct.unpack('<Q', self.facts.fact(descriptor+(0x98 if enum_property else 0x90), 8))[0]
        if not pointer:
            if expected_name is not None:
                raise ValueError('The scoped native byte enum is missing')
            return dict(status='null_enum_pointer', property_kind='FByteProperty')
        pointer = address(pointer)
        before = self.identity(pointer, 'Enum')
        if expected_name is not None and before['name'] != expected_name:
            raise ValueError('The current weapon enum type changed')
        header = self.facts.fact(pointer+0x40, 12)
        data, count = struct.unpack('<Qi', header)
        if not 1 <= count <= 64:
            raise ValueError('The current weapon enum exceeds its fixed bound')
        address(data)
        raw = self.facts.fact(data, count*16)
        entries = [dict(name=resolve_name(self.session.read, self.base, raw[i:i+8]).display_text,
            value=struct.unpack_from('<q', raw, i+8)[0]) for i in range(0, len(raw), 16)]
        if len({e['name'] for e in entries}) != count or self.identity(pointer, 'Enum') != before:
            raise ValueError('The current weapon enum identity or names changed')
        return dict(status='observed', identity=before, entries=entries)

    def array(self, instance, field, stride, *, kind):
        if field['field_vtable_rva'] != 0x1ab5b730 or field['element_bytes'] != 16:
            raise ValueError('The scoped weapon field is not the actual FArrayProperty')
        descriptor = field['descriptor_address']
        inner = address(struct.unpack('<Q', self.facts.fact(descriptor+0x90, 8))[0])
        raw = self.facts.fact(inner, 0x60)
        if struct.unpack_from('<ii', raw, 0x3c) != (1, stride) or struct.unpack_from('<i', raw, 0x54)[0] != 0:
            raise ValueError('The current weapon array inner extent differs')
        inner_field = dict(descriptor_address=inner, element_bytes=stride)
        if kind == 'object':
            self.hook(inner, 0x10e8ed20)
            declared = address(struct.unpack('<Q', self.facts.fact(inner+0x90, 8))[0])
            declared_identity = self.identity(declared, 'Class')
            if declared_identity['name'] != 'WeaponBase':
                raise ValueError('WeaponList does not contain the actual WeaponBase type')
        elif kind == 'int64':
            self.hook(inner, 0x10e5ce20)
            self.hook(inner, 0x286c000, slot=0x88)
        else:
            self.struct_type(inner_field, 'WeaponIdentity' if kind == 'identity' else 'GPWeaponRepInfoPair')
        header = self.facts.fact(instance+field['storage_offset'], 16)
        info = array_header(header, stride)
        payload = self.facts.fact(info['data'], info['count']*stride) if info['count'] else b''
        return dict(field=field, inner_descriptor_address=inner, header_raw_hex=header.hex(), **info), payload, inner_field

    def pairs(self, instance, field):
        header, raw, inner = self.array(instance, field, 88, kind='pair')
        pair_type = self.struct_type(inner, 'GPWeaponRepInfoPair')
        identity_field = self.nested(pair_type, 'WeaponIdentity', 0x10, 4)
        identity_type = self.struct_type(identity_field, 'WeaponIdentity')
        unique = self.nested(identity_type, 'UniqueId', 0, 4)
        self.uint32(unique)
        slot = self.nested(pair_type, 'WeaponSlot', 0x54, 1)
        switch = self.nested(pair_type, 'SwitchType', 0xd, 1)
        reserve = self.nested(pair_type, 'bShouldReserveLastWeapon', 0xc, 1)
        last = self.nested(pair_type, 'LastActiveFrame', 0x50, 4)
        self.uint32(last)
        slot_enum = self.enum(slot)
        switch_enum = self.enum(switch, enum_property=True, expected_name='EWeaponSwitchType')
        self.hook(reserve['descriptor_address'], 0x10e8ebe0)
        masks = self.facts.fact(reserve['descriptor_address']+0x8a, 3)
        values = []
        for offset in range(0, len(raw), 88):
            row = raw[offset:offset+88]
            values.append(dict(unique_id=struct.unpack_from('<I', row, 0x10)[0], weapon_slot=row[0x54],
                switch_type=row[0xd], last_active_frame=struct.unpack_from('<I', row, 0x50)[0],
                reserve_last=bool_value(row[0xc:0xd], masks),
                weapon_class_path_value_read=False, fast_array_memory_header_read=False))
        return dict(**header, pairs=values, weapon_slot_enum=slot_enum, switch_type_enum=switch_enum,
            selected_fields=[identity_field, unique, slot, switch, reserve, last])

    def finish(self):
        for descriptor, hook in self.hooks:
            recheck_virtual_method(self.session, self.base, descriptor, hook)


def observe(game_root, trial_report):
    from portable_map_bootstrap import load_plan
    trial_raw = Path(trial_report).read_bytes()
    trial = json.loads(trial_raw)
    pid, created = owned_trial_identity(trial, game_root)
    profile_path = _profile_path(trial)
    pins = source_pins(game_root, profile_path)
    plan = load_plan(ROOT, profile_path)
    if plan.sources != trial['portable_map_bootstrap']['source_pins']:
        raise ValueError('The current weapon plan differs from this exact active trial')
    weapon_manifest = profile_weapon_manifest(plan)
    executable, size = validate_source(game_root)
    reader = Win32MetadataReader(executable, size, pid, created, maximum_seconds=120)
    try:
        session = MetadataSession(reader.read_exact)
        session.module_sha256, session.module_size = SHIPPING_SHA256, size
        base, sink = reader.module_base, {}
        roots = discover_roots(session, base, connection_binding_only=True, first_player_state=True,
            _binding_identity_sink=sink, unpublished_batch_retry=True)
        callback = sink['callback']
        pcs = [p for p in roots['connection_binding_observations']['player_controllers']
            if p.get('status') == 'observed' and p.get('identity_and_fields_rechecked') is True and
            p.get('driver_primary_matches_original_connection') is True and p.get('local_player_index_field') == 0]
        if len(pcs) != 1:
            raise ValueError('One current primary owned controller is required')
        pc = pcs[0]
        pc_at, driver, connection = (address(pc[k]) for k in ('address', 'driver', 'connection'))
        binding = observe_first_player_state(session, base, driver_address=driver,
            connection_address=connection, pc_address=pc_at, object_identity=callback)
        if binding.get('status') != 'observed' or binding['pc_pawn_reference'].get('status') != 'typed_existing_reference':
            raise ValueError('The current primary Pawn binding is unavailable')
        pawn = address(binding['pc_pawn_reference']['address'])
        classes = {}

        def metadata(pointer, expected):
            before = callback(pointer, expected)
            klass = address(before['class_address'])
            if klass not in classes:
                classes[klass] = dict(class_identity=callback(klass, 'Class'),
                    class_path=object_path(session.read, base, klass),
                    declarations=typed_declarations(session, base, klass, callback),
                    existing_driver_class=label_existing(session, base, driver, klass))
            return dict(classes[klass], identity=before)

        observation = BindingObservation(session, base, callback, metadata)
        facts = ReadFacts(session)
        fields = WeaponFields(session, base, observation.identify, facts)

        def recheck_binding():
            sink['recheck_roots']()
            now = observe_first_player_state(session, base, driver_address=driver,
                connection_address=connection, pc_address=pc_at, object_identity=callback)
            if now != binding:
                raise ValueError('The current owned weapon PC/Pawn binding changed')

        pawn_record = metadata(pawn, 'Pawn')
        if not pawn_record['class_path'].endswith('.BP_DFMCharacter_C'):
            raise ValueError('The current owned Pawn is outside the qualified weapon profile')
        level = address(pawn_record['identity']['outer_address'])
        observation.identify(level, 'Level')
        refs = [observation.reference(pawn, f) for f in select_fields(pawn_record['declarations'], 'pawn').values()]
        objects, carried_actors = [], []
        carried_scope_error = 'The actual current manager WeaponList was not observed'
        for scope, property_name, name, expected_class, expected_path in COMPONENT_SCOPES:
            link = next(r for r in refs if r['field_name'] == property_name)
            if link['status'] != 'typed_existing_reference':
                objects.append(dict(scope=scope, status=link['status']))
                continue
            pointer = address(link['identity']['address'])
            record = metadata(pointer, expected_class)
            if (record['identity']['name'] != name or record['class_path'] != expected_path or
                    address(record['identity']['outer_address']) != pawn):
                raise ValueError('The current weapon default component name/class/Outer changed')
            selected = select_fields(record['declarations'], scope)
            klass = address(record['identity']['class_address'])
            current = {n: fields.field(klass, f) for n, f in selected.items()}
            owner = observation.reference(pointer, selected['CharacterOwner'], expected_base='GPCharacterBase')
            owner['is_current_pawn'] = (owner.get('identity', {}).get('address') == pawn_record['identity']['address'])
            state = dict(character_owner=owner)
            objects.append(dict(**record, scope=scope, state=state, status='reading'))
            if scope == 'manager':
                slot = selected['WeaponSlot']
                if (slot['storage_offset'], slot['element_bytes']) != (0x1c8, 1):
                    raise ValueError('The current manager WeaponSlot declaration changed')
                state['weapon_slot'] = dict(field=slot,
                    value=facts.fact(pointer+slot['storage_offset'], 1)[0],
                    enum=fields.enum(current['WeaponSlot']))
                state['empty_hand_override'] = dict(field=selected['EmptyHandOverrideID'],
                    value=struct.unpack('<q', facts.fact(pointer+selected['EmptyHandOverrideID']['storage_offset'], 8))[0],
                    is_net_property=False)
                state['use_empty_hand_override'] = fields.boolean(pointer, current['bUseEmptyHandOverride'])
                state['empty_hand_reference'] = observation.reference(pointer, selected['EmptyHandWeapon'], expected_base='WeaponBase')
                arrays = {}
                for name, stride, kind in (('WeaponList', 8, 'object'), ('WeaponIdentityList', 4, 'identity'), ('WeaponIDList', 8, 'int64')):
                    header, payload, inner = fields.array(pointer, current[name], stride, kind=kind)
                    if kind == 'object':
                        entries = []
                        for offset in range(0, len(payload), 8):
                            value = struct.unpack_from('<Q', payload, offset)[0]
                            entries.append(None if not value else observation.identify(address(value), 'WeaponBase'))
                    else:
                        entries = list(struct.unpack('<'+('I' if kind == 'identity' else 'q')*header['count'], payload))
                    arrays[name] = dict(**header, entries=entries)
                state['arrays'] = arrays
                state['parallel_array_counts_match'] = len({a['count'] for a in arrays.values()}) == 1
            else:
                state['current_active'] = fields.pairs(pointer, current['CurrActiveWeapInfoArr'])
                fast_type = fields.struct_type(current['WeapInfoArray'], 'GPWeaponRepInfoPairFastArray')
                items = fields.nested(fast_type, 'Items', 0x108, 16)
                state['weapon_info'] = fields.pairs(pointer+current['WeapInfoArray']['storage_offset'], items)
            objects[-1]['status'] = 'observed'
            if scope == 'manager':
                try:
                    observe_carried_weapon_actors(state['arrays']['WeaponList']['entries'],
                        pawn_record=pawn_record, current_pawn_level=level, observation=observation,
                        fields=fields, facts=facts, metadata=metadata, results=carried_actors)
                    carried_scope_error = None
                except ValueError as error:
                    carried_scope_error = str(error)
        mapping, recheck_mapping = selected_guid_mapping(session, base, driver=driver,
            connection=connection, guid=weapon_manifest.actor_guid, identity=observation.identify,
            recheck_binding=recheck_binding)
        actor = None
        if mapping['status'] == 'existing_object_observed':
            pointer = address(mapping['object_address'])
            observation.identify(pointer, 'WeaponBase')
            record = metadata(pointer, 'WeaponBase')
            qualify_weapon_actor(record['identity'], record['class_path'], level)
            state = {}
            read_weapon_actor_state(record, scope='actor', pawn_record=pawn_record,
                observation=observation, fields=fields, facts=facts, state=state)
            actor = dict(**record, guid=weapon_manifest.actor_guid, state=state, outer_is_current_pawn_level=True)
        observation.finish()
        fields.finish()
        for klass, record in classes.items():
            if (callback(klass, 'Class') != record['class_identity'] or
                    typed_declarations(session, base, klass, callback) != record['declarations']):
                raise ValueError('The selected weapon declarations changed')
        facts.finish()
        recheck_mapping()
        recheck_binding()
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root, profile_path) != pins:
            raise ValueError('The weapon observer source or pinned module changed')
        return dict(kind='owned_weapon_scoped_readonly_state_v1',
            status='partial' if carried_scope_error else 'observed', reason=carried_scope_error,
            client_sha256=SHIPPING_SHA256,
            pid=pid, created_at=created, observed_at_utc=datetime.now(timezone.utc).isoformat(), source_pins=pins,
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(), primary_connection_binding=pc,
            first_player_binding=binding, pawn_component_references=refs, objects=objects,
            current_profile_weapon_guid=weapon_manifest.actor_guid, weapon_guid_mapping=mapping, weapon_actor=actor,
            carried_weapon_actors=carried_actors, carried_weapon_scope_reason=carried_scope_error,
            read_calls=session.calls, read_bytes=session.bytes_read, identities_and_fields_rechecked=True,
            selected_roots_rechecked=True, process_identity_rechecked=True, process_memory_written=False,
            native_methods_invoked=False, native_layouts_constructed=False, packets_sent=False, code_sampled=False,
            historical_process_pointers_reused=False, snapshot_atomic=False, native_weapon_gameplay_verified=False)
    except WeaponPropertySourceMismatch as error:
        # Keep independently rechecked declarations and completed scopes. A
        # serializer mismatch still forbids the failed scope's further reads.
        observation.finish()
        fields.finish()
        for klass, record in classes.items():
            if (callback(klass, 'Class') != record['class_identity'] or
                    typed_declarations(session, base, klass, callback) != record['declarations']):
                raise ValueError('The selected partial weapon declarations changed')
        facts.finish()
        recheck_binding()
        reader.verify_identity()
        if reader.find_module() != base or source_pins(game_root, profile_path) != pins:
            raise ValueError('The partial weapon observer source or pinned module changed')
        if objects and objects[-1].get('status') == 'reading':
            objects[-1].update(status='partial', reason=str(error))
        return dict(kind='owned_weapon_scoped_readonly_state_v1', status='partial', reason=str(error),
            client_sha256=SHIPPING_SHA256, pid=pid, created_at=created, source_pins=pins,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),
            trial_report_sha256=hashlib.sha256(trial_raw).hexdigest(),
            primary_connection_binding=pc, first_player_binding=binding,
            objects=objects, scoped_class_metadata=list(classes.values()), carried_weapon_actors=carried_actors,
            carried_weapon_scope_reason=carried_scope_error,
            identities_and_fields_rechecked=True, selected_roots_rechecked=True,
            process_identity_rechecked=True, process_memory_written=False,
            native_methods_invoked=False, native_layouts_constructed=False,
            packets_sent=False, code_sampled=False, historical_process_pointers_reused=False,
            snapshot_atomic=False, native_weapon_gameplay_verified=False)
    finally:
        reader.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    parser.add_argument('--trial-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--request-uac', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to((ROOT/'work').resolve()):
        parser.error('Use an exclusive new project work output')
    trial = json.loads(args.trial_report.read_bytes())
    owned_trial_identity(trial, args.game_root)
    source_pins(args.game_root, _profile_path(trial))
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
