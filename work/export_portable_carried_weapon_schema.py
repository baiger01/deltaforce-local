"""Export the closed receiver-to-Actor-class subset without native pointers."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/evidence/map-system-audit-20261018'
OUTPUT = FOLDER/'carried-weapon-selection-schema-v2.json'
PINS = {
    'outputs/df-local-server/protocol/weapon_preset_catalog.json':
        '66ed0bd86ecfc34be405b1e90f82b7ce2e7f23e3a2ac1dcf9cdeb649001a5626',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-manager-add-recid-source-v1.json':
        '5721081352a2d56c1460243b9f02c0e32b6fdb044ac34d668776096bf1f2e4af',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-receiver-config-class-resolver-v1.json':
        '59332d1f3c06c09f1b4279b4f7cf928d8d4d31a4b5a4c394f200597920b4b421',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-modular-class-cooked-sources-v1.json':
        'e7f56730c8978b380929e94c98bb418e83a0de4ad29bdecc876a681dc0974b49',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-position-global-lua-v1.json':
        'd4b732d24dba5fe646399a2c69916e0dfe9fc6f1cfa3464841c7e3972474ff53',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-actor-init-values-v1.json':
        '088f35191563202e77bfe1de00c3e3ccbed9797ee17fe082b5352a228d497c53',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-interface-init-vslots-v1.json':
        '1d0a9346b836b01e2f326a92c62cb6a80f25dc4b3def998610a667ffe5630f99',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-interface-init-setters-v1.json':
        'eaa37b6fff2ffef384aa41e362d6aa85bb6bbefe60275c0e0dac21bf7b097798',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-base-constructor-v1.json':
        'c8a2cc53326f3b6288247b3e879c0a05cbb78843928e17039b56befe233c084c',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-dfm-class-getter-v1.json':
        '190c7d75d8d4d1c6d0a23d35515ca160567ed24546c1fc09fc29423961e349da',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-dfm-ctor-thunk-v1.json':
        '4890b70d6d7112a61e0f597a50c527e29673957d52274f4079b757b3ee07d542',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-dfm-constructor-v1.json':
        '736e79773c2d2a56ff2efcc045873ea117fc6bfd48c8d1680fd397459c665f7f',
    'work/evidence/map-system-audit-20261018/native-owned-weapon-dfm-open-and-value-vslots-v1.json':
        'bca8bfeb9ea70c49c522fbf79de07e25891e97a206ead3a402c90670b66c8d54',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-actor-open-native-stub-prefix.json':
        '3db5677b10afc0ae8b5e35ff9888904a1fbc6abb6026d38889e3ef8426f741c5',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-emptyhand-initialization-core.json':
        '1a781b8fbb4b0e958fa4bbf9ca8a7538f3990433e7223be237167ac3dd4aaf1f',
    'work/evidence/map-system-audit-20261018/native-owning-weapon-manager-uht-and-vtables.json':
        'c32b8731b5a9fdcd1abbb1de1c6a56c32dfdf70178ca6f6116796821b91c5d21',
    'work/native-client-tests/1792311694804456800/owned-gameplay-metadata.json':
        '407649e4d323bf8ca17f929c86798f2e3b3ca0e9ce585ce00fc1e94b84a1cc24',
}


def checked(relative, digest):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Carried weapon source changed: '+relative)
    return json.loads(raw) if relative.endswith('.json') else raw


def derive():
    docs = {path: checked(path, digest) for path, digest in PINS.items()}
    get = lambda name: docs['work/evidence/map-system-audit-20261018/'+name]
    cooked = get('native-owned-weapon-modular-class-cooked-sources-v1.json')
    if not all(row['compressed_sha1_valid'] for row in cooked['assets']):
        raise ValueError('Modular package payload qualification differs')
    declaration = next(p for p in cooked['receiver_declarations']['properties'] if p['name'] == 'BPClass')
    if declaration['offset_raw36'] != '0x68' or declaration['generation_flags_raw'] != '0xd':
        raise ValueError('Receiver BPClass declaration differs')
    package = next(p for p in cooked['packages'] if any(
        e['name'] == 'BP_WeaponModular_C' for e in p['exports']))
    cls = next(e for e in package['exports'] if e['name'] == 'BP_WeaponModular_C')
    cdo = next(e for e in package['exports'] if e['name'] == 'Default__BP_WeaponModular_C')
    class_path = '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponModular.BP_WeaponModular_C'
    if cls['super_path'] != '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponBase.BP_WeaponBase_C':
        raise ValueError('Modular cooked parent differs')
    if cdo['class_index'] != cls['index']:
        raise ValueError('Modular cooked CDO class differs')
    catalog = docs['outputs/df-local-server/protocol/weapon_preset_catalog.json']
    pins = dict(PINS)
    # Verify original table payloads and recovered cooked asset bytes at runtime.
    stem = ('work/evidence/map-system-audit-20261018/economy-gun-desc-parts-assets/'
        '1.101.37117.36.10_WindowsNoEditor_37127_P/DeltaForce/Content/R13N/Common/Base/'
        'DataTables/WeaponPart/RecFunctionTable')
    for suffix, digest in (('.uasset', catalog['source_uasset_sha256']), ('.uexp', catalog['source_uexp_sha256'])):
        checked(stem+suffix, digest)
        pins[stem+suffix] = digest
    for source in package['source_files']:
        checked(source['relative_path'], source['sha256'])
        pins[source['relative_path']] = source['sha256']
    header_source = next(s for s in package['source_files'] if s['relative_path'].endswith('.uasset'))
    header = checked(header_source['relative_path'], header_source['sha256'])
    cdo_flags = struct.unpack_from('<I', header, cdo['record_offset']+24)[0]
    if not cdo_flags & 0x10:
        raise ValueError('The exact modular archetype lacks the cooked CDO flag')
    native = get('native-owned-weapon-dfm-open-and-value-vslots-v1.json')
    tables = {r['rva']: int(r['qwords'][0], 16)-0x140000000 for r in native['data']}
    if tables != {'0x17db5be0': 0xd5f350, '0x16ee95f0': 0x58f87e0,
            '0x16ee9800': 0x58f86b0, '0x16ee9608': 0x58f6fa0}:
        raise ValueError('DFMWeapon native open/value vslots differ')
    stub = get('native-owning-weapon-actor-open-native-stub-prefix.json')['functions'][0]
    if stub['instructions'][0]['bytes'] != 'c20000':
        raise ValueError('The native ActorOpen handler is no longer the qualified return stub')
    observed = docs['work/native-client-tests/1792311694804456800/owned-gameplay-metadata.json']
    loaded = next(c for c in observed['loaded_named_classes'] if c['class_path'] == class_path)
    ancestry = [d['class_name'] for d in loaded['declarations']]
    if ancestry[:4] != ['BP_WeaponModular_C', 'BP_WeaponBase_C', 'DFMWeapon', 'WeaponBase']:
        raise ValueError('The observed modular native parent differs from cooked/default sources')
    driver = loaded['existing_driver_class']
    if driver['cache_status'] != 'missing' or driver['layout_status'] != 'missing':
        raise ValueError('Requalify the newly available modular layout instead of preserving a probe gap')
    slot_function = next(f for f in get('native-owning-weapon-emptyhand-initialization-core.json')['functions']
        if f['requested_rva'] == '0x564d290')
    instructions = {i['rva']: i['operands'] for i in slot_function['instructions']}
    if (instructions.get('0x564f406') != 'r14, qword ptr [rbp - 0x80]' or
            instructions.get('0x564f4c1') != 'eax, byte ptr [r14 + 0x1c8]' or
            instructions.get('0x564f4d1') != 'byte ptr [rdi + 0x84c], al'):
        raise ValueError('The actual Actor WeaponSlot copy from owning Manager differs')
    lua = get('native-owned-weapon-position-global-lua-v1.json')
    listing = next(s for s in lua['sources'] if s['source_name'] == '@DFMGlobalConst.lua')['functions'][0]['listing']
    slots = {}
    for name in ('MainWeaponLeft', 'MainWeaponRight', 'MeleeWeapon'):
        pos = next(i for i, line in enumerate(listing) if "='"+name+"'" in line)
        number = re.search(r'K[0-9]+=([0-9]+)$', listing[pos+1])
        if not number or 'SETTABLE' not in listing[pos+2]:
            raise ValueError('Business equipment slot literal changed')
        slots[name] = int(number.group(1))
    receivers = {key: dict(weapon_rec_id=row['receiver_id'], class_path=row['bp_class'],
        source_row=key, default_preset_id=row['default_preset_id']) for key, row in catalog['rows'].items()
        if row['bp_class'] == class_path and row['is_base_weapon'] is True}
    return dict(kind='portable_carried_weapon_selection_sources_v2', client_sha256=cooked['client_sha256'],
        sources=pins, receivers=receivers, business_slots=slots,
        modular_actor=dict(class_path=class_path,
            cdo_path=class_path.rsplit('.', 1)[0]+'.'+cdo['name'], super_path=cls['super_path'],
            cdo_flags=hex(cdo_flags), native_class_path='/Script/DFMGameplay.DFMWeapon',
            native_vtable_rva='0x17db5808', actor_channel_open_vslot='0x3d8',
            actor_channel_open_handler_rva='0xd5f350', custom_open_payload_bits=0,
            custom_open_tail_source_qualified=True, actor_open_probe_qualified=True,
            source_default_properties=[p['name'] for e in package['selected_defaults']
                if e['export']['name'] == cdo['name'] for p in e['properties']]),
        native_assignment=dict(receiver_id_origin='ModularWeaponDesc node zero ItemId',
            weapon_guid_origin='ModularWeaponDesc node zero Guid',
            add_desc_rva='0x55e90c0', init_modular_rva='0x58c66f0',
            weapon_slot_origin='owning WeaponManagerComponent.WeaponSlot',
            manager_weapon_slot_offset='0x1c8', actor_weapon_slot_offset='0x84c',
            weapon_id_offset='0x838', weapon_guid_offset='0x840', equip_position_offset='0x848'),
        actor_equip_position_mapping_qualified=False, weapon_slot_origin_qualified=True,
        manager_weapon_slot_current_value_observed=False,
        modular_actor_rep_layout_qualified=False, melee_actor_mapping_qualified=False,
        native_gameplay_verified=False, installed_runtime_override_absence_proven=False)


if __name__ == '__main__':
    raw = (json.dumps(derive(), indent=2, sort_keys=True)+'\n').encode()
    with OUTPUT.open('xb') as output:
        output.write(raw)
    print(json.dumps(dict(path=str(OUTPUT), sha256=hashlib.sha256(raw).hexdigest())))
