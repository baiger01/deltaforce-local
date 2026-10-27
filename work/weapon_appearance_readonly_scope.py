"""Bounded native appearance hide reasons from actual weapon-owned components."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

import observe_owned_weapon_state as old
from observe_owned_gameplay_metadata import address
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


ROOT = old.ROOT
BASE = 'work/evidence/map-system-audit-20261018/'
CAPTURE = 'work/native-client-tests/1792385022786009500/owned-weapon-mesh-followup.json'
CAPTURE_SHA = '93ca8ded72dd88e9eec2738d55348872eea3ec2545d09064f39f44a2e3d9255a'
PINS = {
    BASE+'native-weapon-appearance-hidden-fields-v1.json':
        '9869dc71c91fd6441a560e85f452620e0a77deb59d27970086fe8144ee83a89f',
    BASE+'native-weapon-appearance-component-constructor-v1.json':
        '4818aaf9391cca3a49058cf7e541309f085812ff42770e26d0b32e37b91f2a09',
    BASE+'native-weapon-appearance-access-and-state-methods-v1.json':
        '1ecde65488bf6b978cd2444bac85c308e246cf3669ce3c051db8ee5af10a1a35',
    BASE+'native-weapon-normal-hide-tag-writers-v1.json':
        '18bc3444a2fa71552cc2dab1ba6f2015600c2d227f2982d577b6d4847a5c822a',
    BASE+'native-weapon-hide-reason-enum-and-writer-callers-v1.json':
        '68ff50aaa22b3ff3ddf154bd46fe6350ffd2fc015b6ea3f9feef966d63b6a7d5',
    BASE+'native-weapon-hide-inner-callers-and-enum-registration-v1.json':
        '4a0be3f3ad5e6538a70e4ecfa7a561db6ca7da77e4d6b54be25663a4cdd6caff',
    BASE+'native-weapon-isvisible-native-reader-v1.json':
        'e6e1203a67c089cb2aba473c39b5c6513c191b964321ced026687090aa10481b',
    BASE+'native-weapon-isvisible-owner-component-getter-v1.json':
        '5e1a195581dd557d255c3c6b513e7f9e3827e20630c6b30449e4e69775279aa4',
    BASE+'native-weapon-visible-hide-actual-methods-v1.json':
        '5b7be8b61405727ec4661cb37e458201b433d1a48ba357bff652da2564821257',
    CAPTURE: CAPTURE_SHA,
}
REASONS = ('FuncAppearance', 'FireThrowableWeapon', 'FPPInteraction',
    'ThrowableWeaponAnimNotify', 'SocketNotExist')
COMPONENT = 'GPWeaponDataComponentAppearance'
BOOLS = {'bAttachWeaponToCharacter': 0x430, 'bEnableFppMeshDetachOnHidden': 0x4c8}
REFERENCES = {'WeaponMainMeshComp': 0x458, 'WeaponSecondaryMeshComp': 0x460,
    'WeaponBaseMeshComp': 0x468, 'WeaponSecondaryBaseMeshComp': 0x470}


def document(relative):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[relative]:
        raise ValueError('The weapon appearance source changed: '+relative)
    return json.loads(raw)


def source_pins(game_root):
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        old.MANIFEST_SHA256, game_root)
    instructions = {}
    for relative in PINS:
        for function in document(relative).get('functions', ()):
            first, amount = int(function['span_start'], 16), function['span_bytes']
            if type(amount) is not int or not 1 <= amount <= 65536:
                raise ValueError('The appearance native span exceeds its bound')
            raw = b''.join(cache.read(at, min(8192, first+amount-at))
                for at in range(first, first+amount, 8192))
            if hashlib.sha256(raw).hexdigest() != function['code_sha256']:
                raise ValueError('The weapon appearance native code changed')
            instructions.update({i['rva']: i['bytes'] for i in function['instructions']})
    for at, expected in (('0x21907ea', '48c1e304'),
            ('0x2190806', '8b440328'), ('0xd968d0', '488b01'),
            ('0x2201693', '48833b00'), ('0x21ebd37', '480fabc8'),
            ('0x221a8c7', '480fb3c8')):
        if instructions.get(at) != expected:
            raise ValueError('The native map stride, chain, or tag reader changed: '+at)
    executable = Path(game_root)/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with executable.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        record = image.read(0x1caca580, 56)
        if (struct.unpack_from('<Q', record)[0] != image.image_base+0x218b010 or
                struct.unpack_from('<4I', record, 40) != (5, 0x45, 0, 2)):
            raise ValueError('The native EWeaponMeshHideReason registration changed')
        pairs_at = struct.unpack_from('<Q', record, 32)[0]-image.image_base
        entries = []
        for pointer, value in struct.iter_unpack('<Qq', image.read(pairs_at, 5*16)):
            name = image.read(pointer-image.image_base, 128).split(b'\0', 1)[0].decode('ascii')
            entries.append((name, value))
        if entries != [('EWeaponMeshHideReason::'+name, index) for index, name in enumerate(REASONS)]:
            raise ValueError('The source-qualified weapon hide reason names changed')
        if struct.unpack('<Q', image.read(0x1d59de58, 8))[0] != image.image_base+0xd968d0:
            raise ValueError('The native HiddenMap allocator getter changed')
    return {**PINS, 'work/weapon_appearance_readonly_scope.py':
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def view_list_field(record):
    if record.get('class_path') not in (old.MODULAR_CLASS, old.EMPTY_HAND_CLASS):
        raise ValueError('The appearance view list is outside the actual weapon class scope')
    def selected(row):
        return [dict(f, declaring_class=c['class_name']) for c in row['declarations']
            for f in c['fields'] if f['name'] == 'GPWeaponViewComponentList']
    source = next(r for r in document(CAPTURE)['actual_manager_weapon_actors']
        if r['class_path'] == old.MODULAR_CLASS)
    expected, current = selected(source), selected(record)
    if (len(expected) != 1 or len(current) != 1 or
            (expected[0]['declaring_class'], expected[0]['storage_offset'], expected[0]['element_bytes']) !=
                ('WeaponBase', 0xbe8, 16) or
            any(current[0].get(k) != expected[0].get(k) for k in (*old.FIELD_KEYS, 'declaring_class'))):
        raise ValueError('The current actual weapon appearance list declaration changed')
    return current[0]


def read_view_list(actor, field, *, fields, facts):
    if (field['field_vtable_rva'], field['element_bytes'], field['array_dimension']) != (0x1ab5b730, 16, 1):
        raise ValueError('The weapon view list is not the qualified native array')
    descriptor = field['descriptor_address']
    inner = address(struct.unpack('<Q', facts.fact(descriptor+0x90, 8))[0])
    raw = facts.fact(inner, 0x60)
    if struct.unpack_from('<ii', raw, 0x3c) != (1, 8) or struct.unpack_from('<i', raw, 0x54)[0] != 0:
        raise ValueError('The weapon view list has an unqualified inner extent')
    fields.hook(inner, 0x10e8ed20)
    fields.hook(inner, 0x10e95370, slot=0x88)
    declared = address(struct.unpack('<Q', facts.fact(inner+0x90, 8))[0])
    if fields.identity(declared, 'Class')['name'] != 'GPWeaponViewComponentBase':
        raise ValueError('The actual view array does not contain GPWeaponViewComponentBase')
    raw = facts.fact(actor+field['storage_offset'], 16)
    header = old.array_header(raw, 8)
    payload = facts.fact(header['data'], header['count']*8) if header['count'] else b''
    pointers = [address(at) for (at,) in struct.iter_unpack('<Q', payload) if at]
    if len(set(pointers)) != len(pointers):
        raise ValueError('The actual weapon view component list contains duplicate references')
    return dict(**header, field=field, header_hex=raw.hex(),
        inner_descriptor_address=hex(inner), declared_native_class='GPWeaponViewComponentBase'), pointers


def _span(pointer, size, alignment=1):
    if (type(pointer) is not int or type(size) is not int or not 0 < size <= 65536 or
            not 0x10000 <= pointer < pointer+size < 1 << 47 or pointer % alignment):
        raise ValueError('The weapon appearance read exceeds the bounded address scope')


def _pointer_hash(pointer):
    # Same wrapping 32-bit mix as SetWeaponMeshHiddenInner, 21e2252..21e22d1.
    a, b, c = 0, 0, pointer >> 4
    mask = 0xffffffff
    a = (0x9e3779b9-c) & mask
    a ^= (c << 8) & mask
    b = (-(c+a)) & mask
    b ^= a >> 13
    c = (c-a-b) & mask
    c ^= b >> 12
    a = (a-c-b) & mask
    a ^= (c << 16) & mask
    b = (b-a-c) & mask
    b ^= a >> 5
    c = (c-a-b) & mask
    c ^= b >> 3
    a = (a-c-b) & mask
    a ^= (c << 10) & mask
    b = (b-a-c) & mask
    return (b ^ (a >> 15)) & mask


def read_hidden_map(fact, pointer):
    """Follow live 48-byte native hash chains; read only mesh key and tag Value."""
    _span(pointer, 80, 8)
    raw = fact(pointer, 80)
    data, count, capacity = struct.unpack_from('<Qii', raw)
    free = struct.unpack_from('<i', raw, 0x34)[0]
    if not 0 <= free <= count <= capacity <= 32:
        raise ValueError('The actual weapon HiddenMap exceeds its slot bound')
    result = dict(header_hex=raw.hex(), slot_count=count, capacity=capacity,
        free_count=free, live_count=count-free, native_slot_bytes=48, entries=[],
        normal_writer_rva='0x21e1f20', process_memory_written=False)
    if count == free:
        return result
    _span(data, count*48, 8)
    buckets = struct.unpack_from('<i', raw, 0x48)[0]
    heap = struct.unpack_from('<Q', raw, 0x40)[0]
    if not 1 <= buckets <= 64 or buckets & (buckets-1) or not heap and buckets > 2:
        raise ValueError('The native weapon HiddenMap bucket storage is invalid')
    storage = heap or pointer+0x38
    _span(storage, buckets*4, 4)
    heads = struct.unpack('<'+'i'*buckets, fact(storage, buckets*4))
    seen, meshes = set(), set()
    for bucket, index in enumerate(heads):
        while index != -1:
            if index in seen or not 0 <= index < count or len(seen) >= 32:
                raise ValueError('The weapon HiddenMap chain is cyclic or out of bounds')
            seen.add(index)
            mesh, value = struct.unpack('<QQ', fact(data+index*48, 16))
            address(mesh)
            if mesh in meshes or _pointer_hash(mesh) & (buckets-1) != bucket:
                raise ValueError('The weapon HiddenMap key or hash chain is inconsistent')
            meshes.add(mesh)
            unknown = value & ~((1 << len(REASONS))-1)
            result['entries'].append(dict(slot_index=index, bucket_index=bucket,
                mesh_address=hex(mesh), bit_tag_value_hex=hex(value), hidden=bool(value),
                reason_names=[name for bit, name in enumerate(REASONS) if value & (1 << bit)],
                unknown_reason_bits=hex(unknown) if unknown else False))
            index = struct.unpack('<i', fact(data+index*48+40, 4))[0]
    if len(seen) != count-free:
        raise ValueError('The weapon HiddenMap live count differs from the complete hash chains')
    result['entries'].sort(key=lambda row: row['slot_index'])
    return result


def appearance_field(record, name):
    expected_size = 1 if name in BOOLS else 8 if name in REFERENCES else 80
    expected_offset = {**BOOLS, **REFERENCES, 'HiddenMap': 0x4d0}.get(name)
    if expected_offset is None:
        raise ValueError('The appearance field is outside its fixed named scope')
    matches = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
        for f in c['fields'] if c['class_name'] == COMPONENT and f['name'] == name]
    source = next(f for c in document(BASE+'native-weapon-appearance-hidden-fields-v1.json')['classes']
        for f in c['declared_property_records'] if f['name'] == name)
    if (len(matches) != 1 or
            (matches[0]['storage_offset'], matches[0]['element_bytes'], matches[0]['array_dimension']) !=
                (expected_offset, expected_size, 1) or
            matches[0]['property_flags'] != source['property_flags']):
        raise ValueError('The source-qualified current appearance field changed: '+name)
    if name in REFERENCES and matches[0].get('native_property_type') != 'FObjectProperty':
        raise ValueError('The appearance mesh field is not the declared native object reference')
    return matches[0]


def visibility_predicate(record, *, pawn_record, fields, facts, observation, metadata):
    """Observe the actual IsVisible default-body gate without resolving encrypted overrides."""
    actor = address(record['identity']['address'])
    table = struct.unpack('<Q', facts.fact(actor+0x388, 8))[0]
    if table != fields.base+0x16ee9150:
        raise ValueError('The actual DFM visibility interface differs')
    target = struct.unpack('<Q', facts.fact(table+0x6e8, 8))[0]
    primary = address(struct.unpack('<Q', facts.fact(actor, 8))[0])
    implementation = struct.unpack('<Q', facts.fact(primary+0x9e0, 8))[0]
    if target != fields.base+0x58ce5f0 or implementation != fields.base+0x58ae3c0:
        raise ValueError('The current actual IsVisible interface or default implementation differs')
    owner_fields = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
        for f in c['fields'] if c['class_name'] == 'WeaponBase' and f['name'] == 'CharacterOwner']
    if (len(owner_fields) != 1 or
            (owner_fields[0]['storage_offset'], owner_fields[0]['element_bytes'],
             owner_fields[0].get('native_property_type'), owner_fields[0].get('declared_native_class')) !=
                (0xa60, 8, 'FObjectProperty', 'GPCharacterBase')):
        raise ValueError('The actual IsVisible CharacterOwner field differs')
    owner_field = fields.field(address(record['identity']['class_address']), owner_fields[0])
    fields.hook(owner_field['descriptor_address'], 0x10e8ed20)
    fields.hook(owner_field['descriptor_address'], 0x10e95370, slot=0x88)
    owner = observation.reference(actor, owner_field, expected_base='GPCharacterBase')
    if owner.get('status') != 'typed_existing_reference' or owner['identity'] != pawn_record['identity']:
        raise ValueError('The current visibility CharacterOwner is not the selected Pawn')
    pawn = address(owner['identity']['address'])
    selector = facts.fact(pawn+0x1020, 8)
    result = dict(character_owner=owner, native_get_mesh_rva='0x4bcd400',
        native_is_visible_rva='0x58ae3c0', native_mesh_selector_offset=0x1020,
        native_mesh_override_present=bool(struct.unpack('<Q', selector)[0]),
        encrypted_reference_decoded=False, native_method_invoked=False,
        rendering_verified=False, native_instrumentation_override_evaluated=False)
    if result['native_mesh_override_present']:
        return dict(result, status='native_mesh_override_requires_qualified_resolver',
            missing_current_predicate='CharacterOwner.GetMesh selected its native override; resolved component+0x8c8 bit0 is unobserved')
    matches = [dict(f, declaring_class=c['class_name']) for c in pawn_record['declarations']
        for f in c['fields'] if c['class_name'] in ('CHARACTER', 'Character') and f['name'] == 'Mesh']
    if (len(matches) != 1 or
            (matches[0]['storage_offset'], matches[0]['element_bytes'], matches[0].get('native_property_type'),
             matches[0].get('declared_native_class')) != (0x3d0, 8, 'FObjectProperty', 'SkeletalMeshComponent')):
        raise ValueError('The current Character.Mesh fallback is outside its typed native source')
    field = fields.field(address(pawn_record['identity']['class_address']), matches[0])
    fields.hook(field['descriptor_address'], 0x10e8ed20)
    fields.hook(field['descriptor_address'], 0x10e95370, slot=0x88)
    link = observation.reference(pawn, field, expected_base='SkeletalMeshComponent')
    if link.get('status') != 'typed_existing_reference':
        return dict(result, status='native_character_mesh_unavailable', character_mesh=link)
    mesh = address(link['identity']['address'])
    value = facts.fact(mesh+0x8c8, 1)[0]
    return dict(result, status='observed_default_body_predicate', character_mesh=link,
        native_mesh_member_offset=0x8c8, native_mesh_member_mask=1,
        native_mesh_byte_hex=hex(value), native_default_body_visible=bool(value & 1),
        reflected_property_name_inferred=False, net_property=False)


def read_appearance(record, *, actor, fields, facts, observation):
    identity = record['identity']
    if (identity.get('is_cdo') is not False or address(identity['outer_address']) != actor or
            COMPONENT not in identity.get('class_ancestry', ())):
        raise ValueError('The actual weapon appearance component belongs to a different Actor')
    pointer, klass = (address(identity[k]) for k in ('address', 'class_address'))
    result = dict(identity=identity, class_path=record['class_path'], state={}, status='observed',
        reflected_net_state=False, encrypted_cache_decoded=False, native_methods_invoked=False)
    from observe_weapon_initialization_followup import read_field
    for name in (*BOOLS, *REFERENCES, 'HiddenMap'):
        def read(n=name):
            field = fields.field(klass, appearance_field(record, n))
            if n in BOOLS:
                return fields.boolean(pointer, field)
            if n in REFERENCES:
                fields.hook(field['descriptor_address'], 0x10e8ed20)
                fields.hook(field['descriptor_address'], 0x10e95370, slot=0x88)
                return observation.reference(pointer, field, expected_base='SceneComponent')
            result = read_hidden_map(facts.fact, pointer+field['storage_offset'])
            for entry in result['entries']:
                mesh = observation.identify(address(entry['mesh_address']), 'SkeletalMeshComponent')
                if mesh.get('is_cdo') is not False or address(mesh['outer_address']) != actor:
                    raise ValueError('The current hidden-reason mesh belongs to a different Actor')
                entry['mesh_identity'] = mesh
            return result
        read_field(result, name, read)
    return result


def observe_actor(record, *, fields, facts, observation, metadata):
    actor = address(record['identity']['address'])
    field = fields.field(address(record['identity']['class_address']), view_list_field(record))
    header, pointers = read_view_list(actor, field, fields=fields, facts=facts)
    entries, selected = [], []
    for pointer in pointers:
        identity = observation.identify(pointer, 'GPWeaponViewComponentBase')
        if identity.get('is_cdo') is not False or address(identity['outer_address']) != actor:
            raise ValueError('The current view component belongs to a different weapon Actor')
        entries.append(identity)
        if COMPONENT in identity.get('class_ancestry', ()):
            current = metadata(pointer, COMPONENT)
            if current['identity'] != identity:
                raise ValueError('The actual weapon appearance metadata identity changed')
            selected.append(current)
    if len(selected) != 1:
        raise ValueError('One actual Actor-bound GPWeaponDataComponentAppearance is required')
    appearance = read_appearance(selected[0], actor=actor, fields=fields,
        facts=facts, observation=observation)
    return dict(view_component_list=dict(**header, entries=entries),
        appearance=appearance, status=appearance['status'], source='current_typed_GPWeaponViewComponentList',
        historical_pointers_reused=False, encrypted_cache_decoded=False)
