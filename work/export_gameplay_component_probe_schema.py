"""Seal cooked default names and the native ordinary empty-content receive route."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import tags
from recover_economy_pak_access import installed_name_map

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
SOURCES = {
    'native-owning-weapon-cooked-character-emptyhand-defaults.json':
        'e935d6eab000430da6933ce6578e2fea6a40e9897849c14597c734bf742dc543',
    'native-default-subobject-name-contract.json':
        '857a8faa379683106df6dcfaf41e13627728ae31f07c3e5069023435cc10f403',
    'native-default-subobject-flags.json':
        '2a02b44011001d41dbe3d2f66a633066db9c227a9e467721062d44602e3ca9bc',
    'native-empty-subobject-replicator-receive-core.json':
        '0a4edae073161f2ed99b076827effeee1e66fde13b32bda818306688f7794419',
    'native-empty-subobject-create-before-read.json':
        '85c0ede3532ac8b52fda38ac26c830242c1600547d883f6e70ed296871143967',
    'native-empty-subobject-layout-cache-creation.json':
        'e85965ca5579239920f44103e2afa5d74ef8756533813db4fa2392f192a00b20',
    'native-empty-subobject-layout-and-replicator-constructors.json':
        '9c350a49987a2b167cc8993bb6e743de34ed3abebc30a428acd65b1d1f92748a',
    'native-empty-subobject-receive-vtable-entries.json':
        'a59658244eeaede51e67c61c57bb7f52bdbe0d9ed6b0b1f87063ca3dfb0c8a28',
    'native-empty-subobject-layout-initializer.json':
        '740e00244f0802c5eabf1c4b21d8175f5c970f8499df721162e0bf486cc8ea63',
    'native-empty-subobject-field-header-eof.json':
        '97fb8d2408fdb0f803c06a64583b624e4903f11d82ae74cc5ffc0ef87ae56d10',
    'native-empty-subobject-actorcomponent-constructor.json':
        'eeb0d09eadf6d34e0afc161e839230bf3640b9d7a8e0566d2cc0673e7950c664',
}
COMPONENTS = (
    ('WeaponManagerComponent', 'WeaponManager', '/Script/GPGameplay.MultiWeaponManagerComponent'),
    ('WeaponReplicateComponent', 'WeaponReplicate', '/Script/GPGameplay.WeaponReplicateComponent'),
    ('CharacterEquipComponent', 'CharacterEquip', '/Script/DFMGameplay.SOLCharacterEquipComponent'),
    ('InventoryManager', 'InventoryManager', '/Script/DFMGameplay.InventoryManager'),
    ('InventoryUseItemManager', 'InventoryUseItemManager', '/Script/DFMGameplay.InventoryUseItemManager'),
    ('InteractorComponent', 'InteractorComponent', '/Script/SOL.SOLInteractorComponent'),
)


def build_schema():
    documents = {}
    for name, expected in SOURCES.items():
        raw = (ROOT/BASE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Changed native gameplay probe source: '+name)
        documents[name] = json.loads(raw)
    instructions = {i['rva']: i for d in documents.values() for f in d.get('functions', [])
                    for i in f['instructions']}
    oracle = {
        '0x10ea7471': '410fbaee12', '0x10e5b086': 'f7411800000c00',
        '0x128619c5': '4c39ada0000000', '0x12861a33': 'e8f81dffff',
        '0x12861a5f': '41ff5228', '0x12853b52': 'ff9028030000',
        '0x12b8d747': 'e814d6cfff', '0x1288ae56': 'e8155e3000',
        '0x12b90d1b': 'e8f0922100', '0x12daa122': 'e8997d0000',
        '0x1289203a': 'e891ba46fe', '0x10cfdb50': 'e84b7a1000',
        '0x128921a0': 'e82b6f5200', '0x12db92b8': 'ff5078',
        '0x12db9368': '744d', '0x12db93b7': 'b001',
        '0x12864c3a': '0f8462060000', '0x12892a83': '40b701',
        '0x126f46a5': '33f6', '0x126f4774': '4088b3ce000000',
    }
    for rva, expected in oracle.items():
        if instructions.get(rva, {}).get('bytes') != expected:
            raise ValueError('Native instruction oracle changed: '+rva)
    pkg = documents['native-owning-weapon-cooked-character-emptyhand-defaults.json']['packages'][0]
    assets = {}
    for source in pkg['source_files']:
        raw = (ROOT/source['relative_path']).read_bytes()
        if len(raw) != source['bytes'] or hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('Changed cooked default source')
        assets[source['relative_path']] = raw
    header = next(raw for path, raw in assets.items() if path.endswith('.uasset'))
    payload = next(raw for path, raw in assets.items() if path.endswith('.uexp'))
    names = installed_name_map(header)
    cdo = next(row for row in pkg['selected_defaults'] if row['export']['index'] == 47)
    rows = []
    for field, name, cls in COMPONENTS:
        export, = [e for e in pkg['exports'] if e['name'] == name]
        prop, = [p for p in cdo['properties'] if p['name'] == field]
        flags, = struct.unpack_from('<I', header, export['record_offset']+24)
        props, after = tags(payload, export['offset'], names, export['offset']+export['size'])
        if (export['class_path'] != cls or export['outer_index'] != 47 or
                export['template_path'] != '/Script/SOL.Default__SOLCharacter.'+name or
                prop['object_index'] != export['index'] or flags != 0x40029 or
                payload[after:export['offset']+export['size']] != b'\0'*4 or
                any(p['name'] == 'CreationMethod' for p in props)):
            raise ValueError('Cooked default component identity changed: '+name+' '+str((
                after, export['offset']+export['size'], [p['name'] for p in props])))
        rows.append(dict(field=field, name=name, class_path=cls,
            export_index=export['index'], export_record_offset=export['record_offset'],
            object_flags=flags, default_subobject_flag=0x40000,
            outer_export_index=47, template_path=export['template_path'],
            cdo_property_tag_offset=prop['start'], cdo_property_value_offset=prop['value_start'],
            cooked_creation_method_override=None))
    return dict(kind='client_source_derived_empty_gameplay_component_probe_schema',
        client_sha256=CLIENT_SHA256, process_access=False, client_launched=False,
        pawn_class_path='/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
        components=rows, sources={BASE+k: v for k, v in SOURCES.items()},
        cooked_sources=pkg['source_files'],
        receive_contract=dict(normal_client_only=True, parent_actor_must_already_exist=True,
            parent_actor_receipt_required=True, name_outer_resolution_required=True,
            content_has_rep_layout=True, payload_hex='0000', payload_bit_count=9,
            option=False, first_and_terminal_handle=0,
            zero_bit_content_is_skipped=True,
            replicator_creation_precedes_property_values=True,
            layout_creation_precedes_property_values=True,
            class_cache_creation_precedes_property_values=True,
            actor_component_constructor_creation_method=0,
            actor_component_stable_name_requires='bNetAddressable or (UObject stable and CreationMethod != 2)',
            runtime_stability_must_not_have_been_overridden=True,
            process_bunch_rva='0x128611e0', find_or_create_replicator_rva='0x12853830',
            init_with_object_rva='0x1288ad60', get_class_layout_rva='0x12b90c70',
            class_layout_factory_rva='0x12daa010', class_layout_initializer_rva='0x12db1ec0',
            received_bunch_rva='0x12891f60', class_cache_lookup_rva='0x10cfdad0',
            receive_properties_rva='0x12db90d0', default_subobject_creator_rva='0x10ea7190',
            is_name_stable_rva='0x10e5b080', instruction_oracle=oracle),
        limitations=['No native field handles or weapon/inventory values are supplied.',
            'Native acceptance and metadata creation must be observed after normal delivery.',
            'This does not establish weapon initialization or client interaction readiness.',
            'Name/Outer exports flags3 are consumer-compatible local policy, not official server bytes.',
            'The current normal receiver and matching Pawn build are required.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = (json.dumps(build_schema(), indent=2, sort_keys=True)+'\n').encode()
    with args.output.open('xb') as output:
        output.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest())))
