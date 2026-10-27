"""Frozen melee selection from installed cooked rows and original class paths."""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, tags
from recover_economy_pak_access import installed_name_map
from inspect_owned_weapon_recipe_table import scalar
from portable_map_owned_weapon import _admitted_loadout

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
PINS = {
    'work/evidence/melee-runtime-source-20261021-tables.json':
        'fa7407f2a26a5b59db437ea1b51e27f0a82069e57d0b6d29676b20fa0a6594c9',
    'work/evidence/melee-runtime-source-20261021-classes.json':
        '3107d5fa455b4142a015b1ae22042974432aed6bbf52d7c56ef8023195325728',
    'work/evidence/melee-runtime-source-20261021-nepal-class.json':
        '407503a54547e6793990a6f0f2c2ab0920c917dea50c76a7b7722f5dadd20959',
    BASE+'native-owning-weapon-fast-class-id-resolution.json':
        'ee39e6a30892014c9df525d551846c93e6502312f8d9b2303567e99938629a26',
    BASE+'native-owning-weapon-fastpath-netserialize-core.json':
        'f18eaa755e5ed2f9f6921429abea054cce379b0e170d5e6bb1dc5e8ef4b42eca',
    BASE+'native-owned-weapon-system-type3-class-table-v1.json':
        'bd0a585569056a5d4b89e25a2dfe8c73321af7caa9a038f14ac2cecc8fe9eb65',
}


def _checked(relative, expected):
    path = (ROOT/relative).resolve()
    raw = path.read_bytes()
    if not path.is_relative_to(ROOT) or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Original melee source changed: '+relative)
    return raw


@lru_cache(maxsize=1)
def catalog():
    documents = {p: json.loads(_checked(p, s)) for p, s in PINS.items()}
    sources = dict(PINS)
    assets = {}
    for doc in documents.values():
        for pak in doc.get('paks', ()):
            for asset in pak.get('extracted_assets', ()):
                relative = Path(asset['output']).as_posix()
                sources[relative] = asset['decoded_sha256']
                assets[relative] = _checked(relative, asset['decoded_sha256'])
    stem = ('work/evidence/melee-runtime-source-20261021/pak-0-0-pakchunk2-WindowsClient/'
            'DeltaForce/Content/DataTables/WeaponMelee/WeaponMeleeAttributeTable')
    names, data = installed_name_map(assets[stem+'.uasset']), assets[stem+'.uexp']
    header, offset = tags(data, 0, names, len(data))
    prefix, count = struct.unpack_from('<ii', data, offset)
    if [t['name'] for t in header] != ['RowStruct'] or prefix or not 1 <= count <= 1024:
        raise ValueError('Original melee table header changed')
    offset += 8
    rows = {}
    for _ in range(count):
        start, name = offset, fname(data, offset, names)
        fields, offset = tags(data, offset+8, names, len(data))
        values = {f['name']: scalar(data, f, names) for f in fields}
        item = values['ItemId']
        field = next(f for f in fields if f['name'] == 'BPClass')
        raw = data[field['value_start']:field['end']]
        if field['kind'] != 'SoftObjectProperty' or len(raw) != 12 or raw[8:] != bytes(4):
            raise ValueError('Original melee class path grammar changed')
        path = fname(data, field['value_start'], names)
        if type(item) is not int or item in rows or not path.startswith('/Game/') or not path.endswith('_C'):
            raise ValueError('Duplicate or invalid original melee row')
        rows[item] = dict(name=name, class_path=path, values=values, row_offset=start,
            row_sha256=hashlib.sha256(data[start:offset]).hexdigest())
    if data[offset:] != bytes.fromhex('c1832a9e'):
        raise ValueError('Original melee table has unread bytes')
    instructions = {i['rva']: i for doc in documents.values()
        for function in doc.get('functions', ()) for i in function['instructions']}
    for at, expected in {'0x561a9d4':'3c03', '0x561a9dc':'e84f39ffff',
            '0x561a9e8':'e8d3d8ffff', '0x561a9f8':'488d5878',
            '0x22daa5d':'41b808000000'}.items():
        if instructions.get(at, {}).get('bytes') != expected:
            raise ValueError('Original table class resolver/serializer changed: '+at)
    skin_path = 'outputs/df-local-server/protocol/melee_weapon_catalog.json'
    skin_raw = (ROOT/skin_path).read_bytes()
    skins = json.loads(skin_raw)
    original_skin = next(raw for p, raw in assets.items()
        if p.endswith('/MeleeWeaponSkinDataTable.uexp'))
    if hashlib.sha256(original_skin).hexdigest() != skins['source_uexp_sha256']:
        raise ValueError('Lobby skin mapping differs from original melee skin table')
    sources[skin_path] = hashlib.sha256(skin_raw).hexdigest()
    return dict(rows=rows, skins={s['skin_id']: s['weapon_id'] for s in skins['rows']},
        sources=sources, assets=tuple(assets))


@lru_cache(maxsize=1)
def _source_pins():
    from portable_carried_weapon_selection import source_pins as carried_pins
    pins = dict(catalog()['sources'])
    pins.update(carried_pins())
    from modular_weapon_recipe_codec import source_pins as recipe_pins
    pins.update(recipe_pins())
    from portable_map_hud import required_guid_source_pins
    pins.update(required_guid_source_pins(ROOT))
    for path in ('work/portable_melee_weapon.py', 'work/inspect_owned_weapon_recipe_table.py',
            'work/extract_operator_avatar_catalog.py', 'work/recover_economy_pak_access.py'):
        pins[path] = hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
    return tuple(sorted(pins.items()))


def source_pins():
    return dict(_source_pins())


@dataclass(frozen=True)
class CarriedMeleeSelection:
    weapon_rec_id: int
    inventory_gid: int
    business_position: int
    skin_id: int
    class_path: str
    cdo_path: str
    path_type: int
    path_id: int


def select(ticket):
    from portable_carried_weapon_selection import binding
    from owned_weapon_values_codec import schema_binding
    document = _admitted_loadout(ticket)
    item = document.get('selected_melee')
    if item is None:
        return None
    data = catalog()
    gid, rec = item.get('gid'), item.get('template_id')
    slot = binding()['business_slots']['MeleeWeapon']
    if (type(gid) is not int or not 1 <= gid < 1 << 64 or
            any(p.get('gid') == gid for p in document['props']) or
            type(rec) is not int or rec not in data['rows'] or
            item.get('grid_page_id') != slot or type(item.get('quantity')) is not int or
            item['quantity'] != 1):
        raise ValueError('One exact frozen equipped melee item is required')
    skin = item.get('weapon', {}).get('skin_id')
    if type(skin) is not int or data['skins'].get(skin) != rec:
        raise ValueError('The equipped melee skin and original weapon row disagree')
    path = data['rows'][rec]['class_path']
    ids = schema_binding()['fast_class_path']['ids_to_paths']
    common = [int(k) for k, p in ids.items() if p == path]
    if len(common) > 1:
        raise ValueError('Duplicate original common weapon class')
    return CarriedMeleeSelection(rec, gid, slot, skin, path,
        path.rsplit('.', 1)[0]+'.Default__'+path.rsplit('.', 1)[1],
        1 if common else 3, common[0] if common else rec)


@lru_cache(maxsize=32)
def _class_source(selection):
    from audit_owning_weapon_cooked_defaults import package
    leaf = selection.class_path.rsplit('.', 1)[1]
    candidates = [p for p in catalog()['assets'] if p.endswith('/'+leaf[:-2]+'.uasset')]
    if len(candidates) != 1:
        raise ValueError('The selected original melee blueprint must be recovered exactly')
    document = package((ROOT/candidates[0]).with_suffix(''))
    cls = next(e for e in document['exports'] if e['name'] == leaf)
    cdo = next(e for e in document['exports'] if e['name'] == 'Default__'+leaf)
    parent = '/Game/BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_WeaponBaseMelee.BP_WeaponBaseMelee_C'
    if cls['super_path'] != parent or cdo['class_index'] != cls['index']:
        raise ValueError('The melee blueprint must share the source-qualified native melee parent')
    return document


def actor_probe(ticket, **fields):
    from dataclasses import replace
    from dfserver.legacy_ds_actor_manifest import GuidPathBinding
    from dfserver.legacy_ds_guid_exports import GuidExportNode
    from dfserver.legacy_ds_actor_content import ActorContentBlock
    from dfserver.legacy_ds_bit_archive import BitWriter
    from portable_map_owned_weapon import empty_hand_actor_manifest
    from owned_weapon_values_codec import schema_binding
    selection = select(ticket)
    if selection is None:
        raise ValueError('A frozen equipped melee selection is required')
    _class_source(selection)
    base = empty_hand_actor_manifest(schema_binding(), **fields)
    package_path, class_leaf = selection.class_path.rsplit('.', 1)
    package_guid, class_guid, cdo_guid = (fields[n] for n in
        ('package_guid', 'class_guid', 'archetype_guid'))
    package = GuidExportNode(package_guid, package_path)
    klass = GuidExportNode(class_guid, class_leaf, package)
    cdo = GuidExportNode(cdo_guid, 'Default__'+class_leaf, package)
    manifest = replace(base, class_path=selection.class_path, archetype_path=selection.cdo_path,
        must_be_mapped_guids=(cdo_guid,),
        source_relative_path='work/evidence/melee-runtime-source-20261021-tables.json',
        source_sha256=PINS['work/evidence/melee-runtime-source-20261021-tables.json'],
        exports=(klass, cdo, base.exports[-1]),
        path_bindings=(GuidPathBinding(package_guid, package_path),
            GuidPathBinding(class_guid, selection.class_path, '.'),
            GuidPathBinding(cdo_guid, selection.cdo_path, '.'))+base.path_bindings[3:])
    writer = BitWriter()
    writer.write_bool(False)
    writer.write_packed_int(0)
    return manifest, ActorContentBlock(True, writer.to_bytes(), writer.bit_count)


def initial_content(selection, *, pawn_guid, unique_id, slot):
    """Inherited Actor fields plus original non-modular item and skin attributes."""
    from dfserver.legacy_ds_actor_content import ActorContentBlock
    from dfserver.legacy_ds_bit_archive import BitWriter
    from owned_weapon_values_codec import actor_schema_binding
    from modular_weapon_recipe_codec import RecipeSkin, root_only, write_recipe_fields
    _class_source(selection)
    fields = actor_schema_binding()['actor']['fields']
    writer = BitWriter()
    writer.write_bool(False)
    from weapon_actor_network_role import write_network_role
    write_network_role(writer)
    for name, value, bits in (('Owner', pawn_guid, None),
            ('WeaponID', selection.weapon_rec_id, 64),
            ('WeaponGuid', selection.inventory_gid, 64),
            ('WeaponEquipPosition', selection.business_position, 32),
            ('WeaponSlot', slot, 8)):
        if value is None:
            continue
        writer.write_packed_int(fields[name]['ordinary_handle'])
        writer.write_packed_int(value) if bits is None else writer.write_bits(value, bits)
    # WeaponBase.ModularReplicateInfo handles 36/37/38. A one-node root is
    # required: the client ready gate 590ce90 skips view-mode initialization
    # while WeaponPartNodes is empty, leaving the knife without first person.
    write_recipe_fields(writer, root_only(selection.weapon_rec_id, selection.inventory_gid,
        poor_item_id=selection.weapon_rec_id, skin=RecipeSkin(0, selection.skin_id, 0)))
    writer.write_packed_int(fields['ServerWeaponIdentity']['inner_handle'])
    writer.write_bits(unique_id, 32)
    writer.write_packed_int(fields['CharacterOwner']['ordinary_handle'])
    writer.write_packed_int(pawn_guid)
    writer.write_packed_int(0)
    return ActorContentBlock(True, writer.to_bytes(), writer.bit_count)
