"""Actual Actor-bound normal appearance component state, with no client calls."""
import hashlib
import json
from pathlib import Path
import struct

import observe_owned_weapon_state as old
from observe_owned_gameplay_metadata import address
from portable_native_code_cache import CodeCache


ROOT = old.ROOT
BASE = 'work/evidence/map-system-audit-20261018/'
COMPONENT = 'GPWeaponFuncComponentAppearance'
PINS = {
    'native-owning-weapon-interfaces-and-switch-enum-entries.json':
        '8b8c354cae20627f38658ffa235b1ce3907250177dbfbc3097508ddb61d8160d',
    'native-owning-weapon-native-interface-identities.json':
        '062cacd9e3aab2d9e35e93738a4821bd3eb2f5f7d6ade04bbb87c63e61a772d4',
    'native-weapon-view-component-base-uht-v1.json':
        '5127c150984ab8efaa6aca327c32e238ed92349c86b0e39d4f3328ca62035951',
    'native-weapon-function-appearance-uht-v1.json':
        '7e233dbfe619f6234ac446b4421a26d6fee2c38f6dbc764afd3372f5c0b35cf3',
    'native-weapon-function-appearance-constructor-v1.json':
        '1c74da6ebf0b333b253e961281ffbd717b4402736ba9cb168301cfd55c80d438',
    'native-weapon-function-appearance-attach-guards-v1.json':
        '9651116c154a403862dc53b7f1f6c0920a755836d8f58ff48c9cd9da85eac190',
    'native-weapon-function-appearance-normal-load-bodies-v1.json':
        '4e68f1b07c709899f8ebd035950dd08af5a71ddbf39d4c9560fd8d7ea5a66f02',
    'native-weapon-function-appearance-attach-interface-vslots-v1.json':
        'ee03f2dc530f61012adf665e2f7fc768749bae16338a744895c592f6f2ba648d',
    'native-weapon-function-appearance-normal-attach-bodies-v1.json':
        '47a0bc93b4e0b3bc08c495ba63fa442be7f0b7aafc5bda4cbfa4441beef64676',
    'native-weapon-function-appearance-hide-reason-values-v1.json':
        '408c28ce08662b290f309de9f5afd1bafdfd8fb94cad81218d6a7de9d483dfc0',
}


def document(name):
    raw = (ROOT/BASE/name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('The normal function appearance source changed: '+name)
    return json.loads(raw)


def source_pins(game_root):
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        old.MANIFEST_SHA256, game_root)
    instructions = {}
    for name in PINS:
        for function in document(name).get('functions', ()):
            first, size = int(function['span_start'], 16), function['span_bytes']
            if type(size) is not int or not 1 <= size <= 65536:
                raise ValueError('The normal appearance source span exceeds its bound')
            raw = b''.join(cache.read(at, min(8192, first+size-at))
                for at in range(first, first+size, 8192))
            if hashlib.sha256(raw).hexdigest() != function['code_sha256']:
                raise ValueError('The normal function appearance cached bytes changed')
            instructions.update({row['rva']: row['bytes'] for row in function['instructions']})
    for at, expected in (('0x21e1dd4', '448883c8010000'),
            ('0x21c4583', 'c683c901000000'), ('0x219c163', '88879d010000')):
        if instructions.get(at) != expected:
            raise ValueError('The normal appearance native member writer changed: '+at)
    table = document('native-owning-weapon-interfaces-and-switch-enum-entries.json')['data'][0]
    rows = tuple(struct.iter_unpack('<QiI', bytes.fromhex(table['raw_hex'])))
    if table['rva'] != '0x1682e090' or (0x1423ccf80, 0x708, 0) not in rows:
        raise ValueError('The actual native WeaponObInterface adjustment changed')
    return {**{BASE+name: digest for name, digest in PINS.items()},
        'work/weapon_function_appearance_scope.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def hide_reason(value):
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError('The normal appearance hide reason must be uint8')
    entries = document('native-weapon-function-appearance-hide-reason-values-v1.json')[
        'enums']['FunctionAppearanceHideReason']['entries']
    names = {row['value']: row['name'].split('::', 1)[1] for row in entries}
    return dict(value=value, name=names.get(value), known=value in names)


def observe(record, *, actor, data_identity, fields, facts, observation=None, metadata=None):
    identity = record['identity']
    if (identity.get('is_cdo') is not False or address(identity['outer_address']) != actor or
            COMPONENT not in identity.get('class_ancestry', ())):
        raise ValueError('The normal appearance component belongs to another Actor')
    pointer = address(identity['address'])
    rows = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
        for f in c['fields'] if c['class_name'] == COMPONENT and f['name'] == 'DCAppearance']
    source = next(f for c in document('native-weapon-function-appearance-uht-v1.json')['classes']
        for f in c['declared_property_records'] if f['name'] == 'DCAppearance')
    if (len(rows) != 1 or
            (rows[0]['storage_offset'], rows[0]['element_bytes'], rows[0]['array_dimension'],
             rows[0]['property_flags']) != (0x170, 16, 1, source['property_flags'])):
        raise ValueError('The normal appearance DCAppearance native interface declaration differs')
    fields.field(address(identity['class_address']), rows[0])
    for name, offset in (('GPWeaponProxy', 0x130), ('WeaponObInterface', 0x150)):
        selected = [dict(f, declaring_class=c['class_name']) for c in record['declarations']
            for f in c['fields'] if c['class_name'] == 'GPWeaponViewComponentBase' and f['name'] == name]
        source = next(f for c in document('native-weapon-view-component-base-uht-v1.json')['classes']
            for f in c['declared_property_records'] if f['name'] == name)
        if (len(selected) != 1 or
                (selected[0]['storage_offset'], selected[0]['element_bytes'],
                 selected[0]['array_dimension'], selected[0]['property_flags']) !=
                (offset, 16, 1, source['property_flags'])):
            raise ValueError('The normal appearance base interface declaration differs: '+name)
        fields.field(address(identity['class_address']), selected[0])
    actual_interface = struct.unpack('<Q', facts.fact(pointer+0x160, 8))[0]
    if actual_interface != fields.base+0x159124d8:
        raise ValueError('The actual normal appearance interface differs from its native constructor')
    proxy_object, proxy_interface = struct.unpack('<QQ', facts.fact(pointer+0x130, 16))
    owner_object, owner_interface = struct.unpack('<QQ', facts.fact(pointer+0x150, 16))
    data_object, data_interface = struct.unpack('<QQ', facts.fact(pointer+0x170, 16))
    owner = dict(status='null_interface' if not owner_object and not owner_interface else 'observed',
        matches_selected_weapon=(owner_object, owner_interface) == (actor, actor+0x708),
        source_qualified_native_adjustment=0x708)
    data_at = address(data_identity['address'])
    data = dict(status='null_interface' if not data_object and not data_interface else 'observed',
        matches_actual_data_component=(data_object, data_interface) == (data_at, data_at+0x160))
    proxy = dict(status='null_interface' if not proxy_object and not proxy_interface else 'observed',
        source_field='GPWeaponViewComponentBase.GPWeaponProxy', source_offset=0x130)
    if proxy_object and proxy_interface and observation is not None and metadata is not None:
        proxy_identity = observation.identify(address(proxy_object), 'Object')
        proxy['object_identity'] = proxy_identity
        owned = proxy_object == actor or address(proxy_identity['outer_address']) == actor
        proxy['is_actor_or_actor_owned_object'] = owned
        if owned:
            current = metadata(proxy_object, 'Object')
            if current['identity'] != proxy_identity:
                raise ValueError('The normal appearance typed GPWeaponProxy identity changed')
            proxy['class_path'] = current['class_path']
            proxy['declarations'] = current['declarations']
            table = struct.unpack('<Q', facts.fact(address(proxy_interface), 8))[0]
            if not fields.base <= table <= fields.base+old.IMAGE_BYTES-0x2f0:
                raise ValueError('The actual GPWeaponProxy table is outside the pinned module')
            proxy['native_vtable_rva'] = hex(table-fields.base)
            targets = {}
            for slot in (0x260, 0x280, 0x2e0, 0x2e8):
                target = struct.unpack('<Q', facts.fact(table+slot, 8))[0]
                if not fields.base <= target < fields.base+old.IMAGE_BYTES:
                    raise ValueError('The actual GPWeaponProxy target is outside the pinned module')
                targets[hex(slot)] = hex(target-fields.base)
            proxy['normal_guard_target_rvas'] = targets
    reason = hide_reason(facts.fact(pointer+0x1c8, 1)[0])
    booleans = {}
    for offset in (0x19c, 0x19d, 0x1c9):
        raw = facts.fact(pointer+offset, 1)
        if raw not in (b'\0', b'\1'):
            raise ValueError('The normal appearance cached member is not a canonical bool')
        booleans[hex(offset)] = bool(raw[0])
    return dict(status='observed', identity=identity, class_path=record['class_path'],
        declarations=record['declarations'], weapon_ob_interface=owner,
        proxy_interface=proxy, data_interface=data,
        normal_hide_reason=reason, native_cached_bools=booleans,
        native_cached_bools_are_not_reflected_properties=True,
        native_methods_invoked=False, process_memory_written=False, gameplay_verified=False)
