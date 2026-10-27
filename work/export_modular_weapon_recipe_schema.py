"""Seal full-node recipe wire commands and installed configuration without pointers."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

from offline_received_packet_xrefs import ImmutableImage
from parse_economy_installed_tables import parse_table
from recover_economy_pak_access import installed_name_map
from extract_operator_avatar_catalog import tags

ROOT = Path(__file__).resolve().parent.parent
BASE = 'work/evidence/map-system-audit-20261018/'
OUTPUT = ROOT/(BASE+'portable-modular-weapon-recipe-schema-v1.json')
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CAPTURE = 'work/native-client-tests/1792328560808149500/owned-gameplay-metadata.json'
PINS = {
    CAPTURE: '18fcdea26eba57403bc94e712e07906aef38e5a641e8a140012d2d4504233a31',
    BASE+'native-owned-weapon-modular-part-node-fields-v1.json': '52f8f99cd7ce0ac734a7cc67d7b2a1f4c62a1127b345328310829e8cf85c20d1',
    BASE+'native-owned-weapon-full-node-from-item-and-config-v1.json': '338ad44db0137b16e6da42fa7ce0f12882bfdfa8d711fd6a4316eae52e0e7f49',
    BASE+'native-owned-weapon-full-node-construction-values-v1.json': '207276c9642bcacb1ff79934e75edde6d98e9dbf67cb2922ba027dfde838a388',
    BASE+'native-owned-weapon-full-node-defaults-and-configuration-v1.json': '9233c18a025436289e81aca6e430b412392b491d753460a1e1eb30cade87f134',
    BASE+'native-owned-weapon-addpart-actual-node-bridge-v1.json': '38cb2a5c39d44d81815d46f1cb089acd5fcab9f05336f66d65f9721da39431cc',
    BASE+'native-owned-weapon-parent-child-socket-link-v1.json': 'cfdee2a36a481ed7171a7b94803171292e4d2de1daf8c31eeea28ccb8a68df25',
    BASE+'native-owned-weapon-parts-mode-select-and-addpart-callers-v1.json': 'c252dbd6fe3561f9b32c05766d0f2967e7b2e0caba108604ee334c832b5a5a96',
    BASE+'native-owned-weapon-node-type-wire-enums-v1.json': 'e47063b6a09f0150bb13dede44209410f94e5e3d761fa9cb90ed9da99fe9c2ee',
    BASE+'native-owned-weapon-node-name-wire-grammar-v1.json': '7ff4f216f1f1b5eb6dd0dfc162cabfddedaa600cb36caa8ef2d355713f513877',
    BASE+'native-owned-weapon-node-name-archive-dispatch-v1.json': 'efbe81cf351ef6f48eb72f435ea7b2164183c1f88122efbbc7b5d2f75761e66a',
    BASE+'native-owned-weapon-skin-info-fields-v1.json': 'a0a08421cb02a7098a7eabdffdea686b871350a4341df39a18de44ef699f6f5f',
    BASE+'native-owned-weapon-skin-native-default-values-v1.json': '7302d641bcfcac05db738fccf79c0b03820c3043c0f448cca5cf164de661ea9a',
    BASE+'native-owned-weapon-skin-default-pendant-and-update-v1.json': 'a1a935cdcee2495c42fac748925936cc7d8d7ceddb1b2302b1c41198b58231a2',
    BASE+'native-owned-weapon-skin-pb-to-native-assignment-v1.json': 'ef61ddd13fbd429e65b518cd446cc0e7054ff9f4a0d01c72aeb1025f7e4d2b3f',
    BASE+'native-owned-weapon-description-registered-exec-bindings-v1.json': 'e3dab154fce9887f551ce979ca82d381694efe126ee6c9b3b3ae4b991f370213',
    BASE+'native-owned-weapon-description-actual-exec-table-registration-v1.json': 'f1250519c7282761d590ae7cc0c27ce37523e009ad3583c79219f4d017bff170',
    BASE+'native-owned-weapon-modular-desc-to-config-components-v1.json': '68c75f3887431041f4c2085cc64e7457da87d2aeb752262e0d5a256080652f53',
    BASE+'native-owned-weapon-item-helper-skin-appearance-policy-v2.json': '0fc0d2d99330363a51734456c9083ed9b23acec3b4f370b125bcd074dc827bd7',
    BASE+'native-owned-weapon-full-recipe-array-handle-grammar-v1.json': '7dce23dcd1363cec1c3ac6476e5fe0ebf1bdb0ec970c8cec0917692ccfd02fe1',
    BASE+'native-owned-weapon-recipe-array-resize-v1.json': 'f7d6c90642c6274b4539d915a404a8cceb7af55bfcd77ed96886e50e2fcdc21b',
    BASE+'native-owned-weapon-recipe-default-tune-and-construct-v1.json': '8a47e91d7659c73db39c854e4918d5d905292f2c728826d93d3d6f4d81a54025',
    BASE+'native-owned-weapon-parts-config-cooked-sources-v1.json': '2b452ea895e6b4bdcfa42a4796a6b8adafb905740aa6d368056b8582ebf29798',
    BASE+'native-owned-weapon-recipe-socket-skin-cooked-sources-v1.json': 'b4febdc61b22ade3596c287cea0d1f4498dfd621aef10c3375a82d33c71e0c91',
}


def _load(relative, expected):
    path = (ROOT/relative).resolve()
    raw = path.read_bytes()
    if not path.is_relative_to(ROOT) or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Changed recipe source: '+relative)
    return json.loads(raw)


def _table(report, basename, pins):
    rows = report['paks'][0]['extracted_assets']
    paths = {}
    for extension in ('.uasset', '.uexp'):
        matches = [r for r in rows if r['path'].endswith('/'+basename+extension)]
        if len(matches) != 1:
            raise ValueError('One exact cooked recipe table is required')
        row = matches[0]
        path = (ROOT/row['output']).resolve()
        if not path.is_relative_to(ROOT) or hashlib.sha256(path.read_bytes()).hexdigest() != row['decoded_sha256']:
            raise ValueError('Changed cooked recipe table')
        paths[extension] = path
        pins[path.relative_to(ROOT).as_posix()] = row['decoded_sha256']
    return parse_table(paths['.uasset'], paths['.uexp'])


def derive():
    pins = dict(PINS)
    documents = {p: _load(p, sha) for p, sha in pins.items()}
    capture = documents[CAPTURE]
    if capture['status'] != 'observed' or capture['client_sha256'] != CLIENT_SHA:
        raise ValueError('An actual observed Modular layout is required')
    klass = next(c for c in capture['loaded_named_classes']
                 if c['class_path'] == '/Game/BluePrints/Weapons/WeaponBP/BP_WeaponModular.BP_WeaponModular_C')
    layout = klass['existing_driver_class']['layout']
    if layout['parents'][26]['descriptor_name'] != 'ModularReplicateInfo':
        raise ValueError('The recipe parent changed')
    commands = layout['commands']
    def tree(start):
        result, cursor = [], start
        while commands[cursor]['dispatch_opcode'] != 1:
            row = commands[cursor]
            cursor += 1
            item = {key: row[key] for key in ('descriptor_name', 'relative_handle', 'data_offset', 'dispatch_opcode')}
            if row['dispatch_opcode'] == 0:
                item['children'], cursor = tree(cursor)
            result.append(item)
        return result, cursor+1
    node, end = tree(36)
    if (len(node), end, commands[35]['descriptor_name'], commands[35]['relative_handle'],
            commands[82]['descriptor_name'], commands[82]['relative_handle'],
            commands[83]['descriptor_name'], commands[83]['relative_handle']) != (
            35, 82, 'WeaponPartNodes', 36, 'PoorItemId', 37, 'SkinInfo', 38):
        raise ValueError('The actual full recipe command tree changed')
    enums = documents[BASE+'native-owned-weapon-node-type-wire-enums-v1.json']['enums']
    if (enums['NodeType']['wire_bits'], enums['PartType']['wire_bits']) != (3, 7):
        raise ValueError('The recipe enum widths changed')
    tables = documents[BASE+'native-owned-weapon-parts-config-cooked-sources-v1.json']
    parts = _table(tables, 'PartsDataTable', pins)
    keys = ('ItemId', 'FunctionId', 'FunctionId_SOL', 'AnimFunctionId', 'AudioFunctionId',
            'FxFuntionId', 'PartsTypeId', 'PartsTypePriority', 'TuneIds')
    part_rows = {}
    for key, record in parts['rows'].items():
        fields = record['fields']
        if key != str(fields['ItemId']):
            raise ValueError('Parts row key differs from original item ID')
        part_rows[key] = {k: fields[k] for k in keys}
    dependencies = documents[BASE+'native-owned-weapon-recipe-socket-skin-cooked-sources-v1.json']
    sockets = _table(dependencies, 'PartSocketsTable', pins)
    socket_asset = Path(sockets['source_uasset']).read_bytes()
    socket_data = Path(sockets['source_uexp']).read_bytes()
    names = installed_name_map(socket_asset)
    socket_rows = {}
    socket_numbers = {}
    for key, row in sockets['rows'].items():
        fields = row['fields']
        socket_id = str(fields['SocketId'])
        if socket_id in socket_rows or type(fields['SocketName']) is not str:
            raise ValueError('Socket IDs must be unique with actual names')
        declarations, _ = tags(socket_data, row['serialized_uexp_offset']+8, names, len(socket_data))
        tag = next(t for t in declarations if t['name'] == 'SocketName')
        index, number = struct.unpack_from('<II', socket_data, tag['value_start'])
        socket_rows[socket_id] = names[index]
        socket_numbers[socket_id] = number
    armed = _table(dependencies, 'ArmedPropSkinDataTable', pins)
    appearances = {key: r['fields']['DefaultSkinApperaranceID'] for key, r in armed['rows'].items()}
    exe = Path('F:/deltaforce-local-shadow/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
    with exe.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != CLIENT_SHA:
            raise ValueError('The immutable native recipe source binary changed')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            defaults = bytearray()
            for rva, count in ((0x1e2f8090, 8), (0x1e2f8098, 4),
                    (0x1e2f80a0, 8), (0x1e2f80a8, 4)):
                section = [s for s in image.sections if s[0]+s[1] <= rva < rva+count <= s[0]+s[3]]
                if len(section) != 1:
                    raise ValueError('Node zero-offset globals left the PE zero-filled virtual range')
                defaults.extend(bytes(count))
    if defaults != bytes(24):
        raise ValueError('The native node vector/rotation constructor defaults changed')
    return dict(kind='source_qualified_modular_actor_recipe_subset_v1', client_sha256=CLIENT_SHA,
        actor_class_path=klass['class_path'], parent_index=26, property_offset=0x8f0,
        native_node_bytes=296, outer_handles=dict(nodes=36, poor_item_id=37, skin=38),
        node_commands=node, node_enums=enums, parts_rows=part_rows,
        socket_names=socket_rows, socket_numbers=socket_numbers, armed_skin_appearances=appearances,
        native_default_vector_rotation_sha256=hashlib.sha256(defaults).hexdigest(),
        vector_rotation_default_source='native constructor references PE virtual zero-initialized globals; current value not observed',
        array_length_bits=16, array_handle_rule='element_index*35+local_handle; nested arrays independent',
        skin_serializer_rva='0x509d220', skin_default_selector_bits=32,
        fname_grammar='canonical PackageMap v278; hardcoded bit or FString plus raw uint32 number',
        package_map_v278_current_value_observed=False,
        projection_mode=1, projection_mode_name='SOL', physical_node_type=1,
        durability_policy='copy exact inventory row encoded DWORD bits into reflected IntProperty32',
        nonzero_durability_business_semantics_verified=False,
        tune_policy='empty account tune IDs; zero TuneValues grown to PartsDataTable TuneIds count',
        socket_guid_policy='native constructor MAX_int64, normal receiver relinks unconditionally',
        recipe_receiver='OnRepBuildModularDesc exec6100880 ->58d9700 ->5066570 ->58c7820',
        extra_model_call_unconditional=False, internal_ready_flags_emitted=False,
        native_held_weapon_verified=False, process_access=False, sources=pins)


if __name__ == '__main__':
    result = derive()
    raw = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)+'\n').encode('utf8')
    with OUTPUT.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(OUTPUT), sha256=hashlib.sha256(raw).hexdigest(),
        parts=len(result['parts_rows']), sockets=len(result['socket_names']))))
