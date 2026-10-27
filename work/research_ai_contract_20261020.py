"""Read-only AI source qualification from the immutable PE and saved code cache.

Prints JSON only. Selected PAK payloads stay in memory; the optional installed
Oodle codec only decompresses bounded asset data. No native gameplay code runs.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
PEER = ROOT.parent / 'deltaforce-map-appearance'
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
CACHE_SHA = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
sys.path.insert(0, str(PEER / 'work'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


def qualify(assets=False):
    cache = CodeCache(PEER / 'work/native-code-cache/1792259162856698600', CACHE_SHA, GAME)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code_rows, instructions, data_rows = [], {}, []
    ranges = [
        ('AAIController UHT getter', 0x13639ed0, 47),
        ('AAIController StaticClass', 0x1363b9b0, 178),
        ('AAIController native registration', 0x1363bd20, 34),
        ('RunBehaviorTree exec', 0x1363e210, 150),
        ('UseBlackboard exec branch span', 0x1363eb70, 224),
        ('AAIController constructor', 0x135718a0, 402),
        ('AAIController RunBehaviorTree', 0x135945e0, 749),
        ('DFMAIController StaticClass', 0xcdf8510, 178),
        ('DFMAIController constructor thunk', 0xcdf8080, 20),
        ('DFMAIController constructor prefix', 0x9c769a0, 384),
        ('DFMAIController RunBehaviorTree branch span', 0x9cf9ff0, 374),
        ('GPAIBehaviorTree component getter branch span', 0x9c9c760, 787),
        ('GPAIBehaviorTreeComponent StaticClass', 0xebd5c0, 178),
        ('BlackboardComponent StaticClass', 0x13645b90, 178),
        ('BehaviorTreeComponent StaticClass', 0x13641840, 178),
        ('UseBlackboard branch span', 0x1359b690, 341),
        ('Blackboard compatibility', 0x13589650, 226),
        ('StartTree branch span', 0x13596a50, 162),
        ('ProcessPendingInitialize branch span', 0x1358ff30, 318),
        ('PushInstance', 0x135902f0, 1782),
        ('LoadTree', 0x1358ae50, 638),
        ('StopTree prefix', 0x13597280, 138),
    ]
    for label, rva, size in ranges:
        raw = cache.read(rva, size)
        code_rows.append(dict(label=label, rva=hex(rva), bytes=size,
                              sha256=hashlib.sha256(raw).hexdigest()))
        for ins in md.disasm(raw, rva):
            instructions[ins.address] = (ins.mnemonic, ins.op_str)
    anchors = {
        0x13639ee0: ('lea', 'rdx, [rip + 0x80bc909]'),
        0x1363bd29: ('mov', 'r8d, 0x14'),
        0x1363e287: ('call', 'qword ptr [rax + 0x830]'),
        0x1363e29c: ('mov', 'byte ptr [r14], al'),
        0x1363ec29: ('call', '0x1359b690'),
        0x135718c0: ('lea', 'rax, [rip + 0x8134bb9]'),
        0x135718ce: ('mov', 'qword ptr [rdi], rax'),
        0xcdf808e: ('jmp', '0x9c769a0'),
        0x9c769ca: ('lea', 'rax, [rip + 0xdd01177]'),
        0x9c769d8: ('mov', 'qword ptr [r14], rax'),
        0x9cfa066: ('test', 'rdx, rdx'),
        0x9cfa082: ('mov', 'rax, qword ptr [rdx + 0x30]'),
        0x9cfa09b: ('call', '0x13589650'),
        0x9cfa0b3: ('call', '0x1359b690'),
        0x9cfa0c5: ('call', 'qword ptr [rdx + 0x950]'),
        0x9cfa0d4: ('mov', 'r8d, 1'),
        0x9cfa0dd: ('call', '0x13596a50'),
        0x9cfa0e6: ('mov', 'qword ptr [rbx + 0x5c0], rax'),
        0x9c9c7c4: ('mov', 'rax, qword ptr [rsi + 0x588]'),
        0x9c9c7f0: ('call', '0xebd5c0'),
        0x9c9c94a: ('call', '0x10ebd0a0'),
        0x9c9c9a4: ('call', '0xebd5c0'),
        0x9c9c9d3: ('call', '0x10ebd0a0'),
        0x9c9c9e7: ('call', '0x1270c980'),
        0x9c9c9f8: ('mov', 'qword ptr [rsi + 0x430], rax'),
        0x13596ac1: ('call', '0x13597280'),
        0x13596ad0: ('mov', 'qword ptr [rdi + 0x1f0], rsi'),
        0x13596ad7: ('mov', 'dword ptr [rdi + 0x1f8], ebp'),
        0x13596add: ('call', '0x1358ff30'),
        0x1358ff5c: ('cmp', 'dword ptr [rbx + 0x1f8], 1'),
        0x1358ff78: ('or', 'dl, 0x20'),
        0x1359005c: ('call', '0x135902f0'),
        0x1359043a: ('call', '0x1358ae50'),
        0x135908b6: ('call', 'qword ptr [rax + 0x2a8]'),
        0x1359099c: ('call', '0x13592230'),
        0x1358aeb1: ('mov', 'rcx, qword ptr [rsi + 0x28]'),
        0x1358aeb8: ('je', '0x1358b0b1'),
        0x1358aee6: ('call', '0x10ebd390'),
        0x1358af4c: ('call', '0x13587fc0'),
    }
    for rva, expected in anchors.items():
        if instructions.get(rva) != expected:
            raise ValueError('AI source anchor changed at ' + hex(rva))
    exe = GAME / cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)

        def data(rva, size):
            raw = image.read(rva, size)
            data_rows.append(dict(rva=hex(rva), bytes=size, sha256=hashlib.sha256(raw).hexdigest()))
            return raw

        def literal(pointer, wide=False):
            rva = pointer - image.image_base
            raw = image.read(rva, 256)
            if wide:
                end = next(i for i in range(0, len(raw), 2) if raw[i:i+2] == b'\0\0')
                value = data(rva, end+2)[:-2].decode('utf-16le')
            else:
                value = data(rva, raw.index(0)+1)[:-1].decode('ascii')
            return value

        def pointer_slot(vtable, slot, expected):
            actual = struct.unpack('<Q', data(vtable+slot, 8))[0]-image.image_base
            if actual != expected:
                raise ValueError('AI virtual dispatch changed')
            return dict(vtable_rva=hex(vtable), slot=hex(slot), target_rva=hex(actual))

        params = struct.unpack('<10Q', data(0x1d836ae0, 80))
        if params[0]-image.image_base != 0x13639ed0 or literal(params[2]) != 'RunBehaviorTree':
            raise ValueError('RunBehaviorTree UHT identity changed')
        if (params[5], params[7] & 0xffffffff, params[8] & 0xffffffff) != (16, 2, 0x04020400):
            raise ValueError('RunBehaviorTree UHT signature changed')
        properties = []
        for pointer in struct.unpack('<2Q', data(params[6]-image.image_base, 16)):
            row = struct.unpack('<7Q', data(pointer-image.image_base, 56))
            offset = row[4] >> 32
            if row[3] & 0x3f == 12:
                setter = row[6]-image.image_base
                raw = cache.read(setter, 16)
                code_rows.append(dict(label='ReturnValue native bool setter', rva=hex(setter),
                                      bytes=16, sha256=hashlib.sha256(raw).hexdigest()))
                bool_md = Cs(CS_ARCH_X86, CS_MODE_64)
                bool_md.detail = True
                ins = next(bool_md.disasm(raw, setter, count=1))
                offset = ins.operands[0].mem.disp
            properties.append(dict(name=literal(row[0]), record_rva=hex(pointer-image.image_base),
                                   flags=hex(row[2]), generation=row[3] & 0x3f,
                                   native_offset=offset))
        if [(p['name'], p['native_offset']) for p in properties] != [('ReturnValue', 8), ('BTAsset', 0)]:
            raise ValueError('RunBehaviorTree native parameter declaration changed')
        native = []
        for pointer, target in struct.iter_unpack('<QQ', data(0x1b6f84b0, 20*16)):
            name = literal(pointer)
            if name in ('RunBehaviorTree', 'UseBlackboard'):
                native.append(dict(name=name, exec_rva=hex(target-image.image_base)))
        if {x['name']: x['exec_rva'] for x in native} != {
                'RunBehaviorTree': '0x1363e210', 'UseBlackboard': '0x1363eb70'}:
            raise ValueError('AI native registration changed')
        dispatch = [pointer_slot(0x1b6a6480, 0x830, 0x135945e0),
                    pointer_slot(0x17977b48, 0x830, 0x9cf9ff0),
                    pointer_slot(0x17977b48, 0x950, 0x9c9c760)]
        component_names = [literal(image.image_base+rva, True) for rva in
                           (0x14f42f62, 0x1b6fa2aa, 0x1b70117a)]
        controller_names = [literal(image.image_base+rva, True) for rva in (0x1b6f6b92, 0x185dbb52)]
        if controller_names != ['AIController', 'DFMAIController']:
            raise ValueError('Controller StaticClass identity changed')
        result = dict(kind='offline_ai_behavior_source_contract', client_sha256=cache.manifest['client_sha256'],
                      cache_manifest_sha256=CACHE_SHA, process_access=False, game_launched=False,
                      native_gameplay_code_invoked=False, source_written=False, database_access=False,
                      network_access=False, instruction_anchor_count=len(anchors), code_pins=code_rows,
                      data_pins=data_rows, uht=dict(record_rva='0x1d836ae0', native_size=16,
                      function_flags='0x04020400', server_rpc=False, properties=properties,
                      native_registration=native), virtual_dispatch=dispatch,
                      component_class_names=component_names,
                      controller_class_names=controller_names,
                      source_helper_pins=[dict(path=str(PEER/'work'/name),
                          sha256=hashlib.sha256((PEER/'work'/name).read_bytes()).hexdigest())
                          for name in ('portable_native_code_cache.py', 'offline_received_packet_xrefs.py')],
                      native_execution_observed=False, local_authoritative_ai_implemented=False,
                      recovered_selected_tree_start_path=True, recovered_perception_to_fire=False)
        result['unexported_function_labels_are_body_based_inferences'] = True
        if assets:
            result['patrol_asset'] = patrol_asset(cache, image)
    result['helper_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def patrol_asset(cache, image):
    import recover_economy_pak_access as access
    from scan_weapon_tables import parse_entry
    from extract_operator_avatar_catalog import fname, tags
    from recover_dam_gameplay_catalog import Package
    import oodle_payload_reader
    oodle_payload_reader.PATH = GAME/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    codec_sha = hashlib.sha256(oodle_payload_reader.PATH.read_bytes()).hexdigest()
    if codec_sha != 'fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6':
        raise ValueError('Installed decompression codec identity changed')
    keys, key_provenance = access.native_keys(cache, image)
    path = GAME/'DeltaForce/Content/Paks/pak-0-1-pakchunk73-WindowsClient.pak'
    footer = access.pak_footer(path)
    public, clear, key = access.validate_index(path, footer, keys)
    if clear is None:
        raise ValueError('Selected patrol PAK index did not validate')
    details, files, encoded = access.directory_index(path, footer, clear, key)
    selected = [(name, location) for name, location in files
                if name.endswith('/BT_Group_Patrol.uasset') or name.endswith('/BT_Group_Patrol.uexp')]
    if len(selected) != 2:
        raise ValueError('Selected exact patrol package pair is missing or ambiguous')
    parts, asset_pins = {}, []
    with path.open('rb') as stream:
        for name, location in selected:
            pos = access.entry_offset(encoded, location)
            entry = parse_entry(stream, pos, footer['offset'], variant='observed_permutation')
            if entry['uncompressed'] > 1024*1024:
                raise ValueError('Selected patrol asset exceeded 1 MiB bound')
            content, valid = access.decode_entry(stream, pos, entry, footer['methods'], key)
            if not valid:
                raise ValueError('Patrol payload compressed SHA1 did not validate')
            expected = {'.uasset': 'd60ff7f5f8d1fce4d58fefa20c9e9dab0d6454da3e1e67c36e7538dd23954f62',
                        '.uexp': '3af128804f38b30015802350a86f68b85f7820b3d3189a17db0d87f170ec749f'}
            if hashlib.sha256(content).hexdigest() != expected[Path(name).suffix]:
                raise ValueError('Selected patrol package payload identity changed')
            asset_pins.append(dict(path=name, encoded_offset=location, physical_offset=pos,
                                   bytes=len(content), compressed_sha1_valid=True,
                                   sha256=hashlib.sha256(content).hexdigest()))
            parts[Path(name).suffix] = content
    header, payload = parts['.uasset'], parts['.uexp']
    names = access.installed_name_map(header)
    versions = struct.unpack_from('<i', header, 20)[0]
    ec, eo, ic, io = struct.unpack_from('<4i', header, 57+versions*20)
    depends = struct.unpack_from('<i', header, 73+versions*20)[0]
    if not 0 < ec <= 512 or eo-io != ic*28 or depends-eo != ec*104:
        raise ValueError('Patrol package table boundaries changed')
    imports = []
    for i in range(ic):
        at = io+i*28
        imports.append(dict(index=-i-1, name=fname(header, at+20, names),
                            outer=struct.unpack_from('<i', header, at+16)[0],
                            class_name=fname(header, at+8, names)))
    exports, previous_end = [], len(header)
    for i in range(ec):
        at = eo+i*104
        cls, _, _, outer = struct.unpack_from('<4i', header, at)
        size, offset = struct.unpack_from('<qq', header, at+28)
        if offset != previous_end or size < 0:
            raise ValueError('Patrol export extent changed')
        previous_end = offset+size
        exports.append(dict(index=i+1, name=fname(header, at+16, names), class_index=cls,
                            outer_index=outer, size=size, offset=offset-len(header)))
    if previous_end-len(header)+4 != len(payload) or payload[-4:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Patrol companion extent/terminator changed')
    package = Package.__new__(Package)
    package.header, package.payload, package.names = header, payload, names
    package.exports, package.imports = exports, [row['name'] for row in imports]
    package.property_cache = {}

    def value(tag):
        if tag['name'] == 'Children' and tag['kind'] == 'ArrayProperty' and tag['meta'] == ['StructProperty']:
            at = tag['value_start']
            count = struct.unpack_from('<i', payload, at)[0]
            inner = at+4
            byte_count, array_index = struct.unpack_from('<ii', payload, inner+16)
            if not 0 <= count <= 128 or fname(payload, inner, names) != 'Children' or \
                    fname(payload, inner+8, names) != 'StructProperty' or \
                    fname(payload, inner+24, names) != 'BTCompositeChild' or array_index != 0 or \
                    payload[inner+32:inner+49] != bytes(17):
                raise ValueError('Selected BTCompositeChild array declaration changed')
            cursor = inner+49
            if byte_count != tag['end']-cursor:
                raise ValueError('BTCompositeChild serialized extent changed')
            children = []
            for _ in range(count):
                start = cursor
                nested, cursor = tags(payload, cursor, names, tag['end'])
                children.append(dict(start=start, end=cursor,
                    fields={item['name']: value(item) for item in nested}))
            if cursor != tag['end']:
                raise ValueError('BTCompositeChild array has unconsumed bytes')
            return dict(count=count, children=children)
        if tag['kind'] == 'StructProperty' and tag['meta'] == ['BlackboardKeySelector']:
            nested, end = tags(payload, tag['value_start'], names, tag['end'])
            if end != tag['end']:
                raise ValueError('Blackboard key selector has unconsumed bytes')
            return dict(serialized_fields={item['name']: package.value(item) for item in nested},
                        omitted_fields_resolved=False)
        decoded = package.value(tag)
        if isinstance(decoded, dict) and 'unparsed_type' in decoded:
            raw = payload[tag['value_start']:tag['end']]
            decoded['value_sha256'] = hashlib.sha256(raw).hexdigest()
        return decoded

    parsed = []
    for export in exports:
        props = package.properties(export['index'])
        parsed.append(dict(export, class_name=package.object(export['class_index']),
                           properties=[dict(tag, value=value(tag)) for tag in props.values()]))
    child_count = 0
    for export in parsed:
        for tag in export['properties']:
            if tag['name'] != 'Children':
                continue
            for child in tag['value']['children']:
                fields = child['fields']
                targets = [fields.get(name, 0) for name in ('ChildComposite', 'ChildTask')]
                targets = [target for target in targets if target != 0]
                if len(targets) != 1 or not 1 <= targets[0] <= ec:
                    raise ValueError('Patrol child target is missing or ambiguous')
                target = parsed[targets[0]-1]
                parents = [p['value'] for p in target['properties'] if p['name'] == 'ParentNode']
                if parents != [export['index']]:
                    raise ValueError('Patrol ordered child/ParentNode references disagree')
                child_count += 1
    helpers = ['recover_economy_pak_access.py', 'scan_weapon_tables.py',
               'probe_pak_payload_lua.py', 'extract_operator_avatar_catalog.py',
               'recover_dam_gameplay_catalog.py', 'oodle_payload_reader.py']
    return dict(pak=str(path), index=public, directory=details, asset_pins=asset_pins,
                codec_sha256=codec_sha, key_provenance=key_provenance, key_material_disclosed=False,
                source_helper_pins=[dict(path=str(PEER/'work'/name),
                    sha256=hashlib.sha256((PEER/'work'/name).read_bytes()).hexdigest()) for name in helpers],
                export_count=ec, import_count=ic, imports=imports, exports=parsed,
                parsed_property_count=sum(len(row['properties']) for row in parsed),
                ordered_child_count=child_count, child_parent_references_valid=True,
                authored_task_implementation_recovered=False, tree_executed=False)


def compact(result):
    """Retain the selected authored walk and reproducible full-parse identity."""
    result = dict(result)
    asset = dict(result['patrol_asset'])
    imports = {row['index']: row for row in asset.pop('imports')}
    exports = asset.pop('exports')

    def reference(index):
        if index == 0:
            return ''
        if index > 0:
            return exports[index-1]['name']
        item = imports[index]
        return reference(item['outer'])+('.' if item['outer'] else '')+item['name']

    ids = (1, 29, 12, 27, 23, 21, 75, 76, 56, 58, 143, 126, 82, 83)
    asset['all_parsed_exports_sha256'] = hashlib.sha256(json.dumps(
        exports, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    asset['selected_exports'] = [dict(index=e['index'], name=e['name'], class_name=e['class_name'],
        class_path=reference(e['class_index']), uexp_offset=e['offset'], serialized_size=e['size'],
        properties=[dict(name=p['name'], kind=p['kind'], start=p['start'],
                         value_start=p['value_start'], bytes=p['size'], value=p['value'])
                    for p in e['properties']]) for e in exports if e['index'] in ids]
    asset['blackboard_path'] = reference(-3)
    asset['selected_walk'] = [dict(parent=p, child_array_index=i, target=t)
        for p, i, t in ((29, 5, 12), (12, 1, 27), (27, 1, 23), (23, 0, 21),
                        (21, 0, 143), (21, 4, 126))]
    for edge in asset['selected_walk']:
        row = exports[edge['parent']-1]
        children = next(p['value']['children'] for p in row['properties'] if p['name'] == 'Children')
        fields = children[edge['child_array_index']]['fields']
        if edge['target'] not in (fields.get('ChildComposite'), fields.get('ChildTask')):
            raise ValueError('Selected authored patrol walk changed')
    asset['selected_walk_is_unconditional_execution'] = False
    result['patrol_asset'] = asset
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', action='store_true')
    parser.add_argument('--compact', action='store_true')
    args = parser.parse_args()
    if args.compact and not args.assets:
        parser.error('--compact requires --assets')
    result = qualify(args.assets)
    print(json.dumps(compact(result) if args.compact else result, ensure_ascii=False, indent=2))
