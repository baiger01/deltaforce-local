"""Bounded read-only recovery of the installed GetGroupPatrolPoint Blueprint.

Only selected asset payloads are decoded in memory. No client gameplay methods,
process access, database access, or game network traffic are used.
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
from portable_native_code_cache import CodeCache
from offline_received_packet_xrefs import ImmutableImage
import recover_economy_pak_access as access
from scan_weapon_tables import parse_entry
from extract_operator_avatar_catalog import fname, tags
from recover_dam_gameplay_catalog import Package
import oodle_payload_reader


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load():
    cache = CodeCache(PEER/'work/native-code-cache/1792259162856698600', CACHE_SHA, GAME)
    exe = GAME/cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        keys, key_provenance = access.native_keys(cache, ImmutableImage(mapped))
    codec = GAME/'DeltaForce/Binaries/Win64/oo2core_8_win64.dll'
    codec_sha = digest(codec.read_bytes())
    if codec_sha != 'fc923f9bbbf185ca6e853de0e3ebbc81c839323e6e161cd0f75058c60a2b05a6':
        raise ValueError('Installed pure decompression codec changed')
    oodle_payload_reader.PATH = codec
    path = GAME/'DeltaForce/Content/Paks/pak-0-1-pakchunk73-WindowsClient.pak'
    footer = access.pak_footer(path)
    public, clear, key = access.validate_index(path, footer, keys)
    if clear is None:
        raise ValueError('Selected PAK index failed validation')
    directory, files, encoded = access.directory_index(path, footer, clear, key)
    selected = [(name, location) for name, location in files if '/GetGroupPatrolPoint.' in name]
    if len(selected) != 2:
        raise ValueError('Exact selected package pair is missing or ambiguous')
    expected = {'.uasset': '77506f4b901a3fda3c4ab97d37aaa14e9cbb435a69892423324202c33ed9aa69',
                '.uexp': '6bc324b4c54af74576be30b2d0495a7913b7e982544b7387f6bcd706e8889180'}
    parts, pins = {}, []
    with path.open('rb') as stream:
        for name, location in selected:
            pos = access.entry_offset(encoded, location)
            entry = parse_entry(stream, pos, footer['offset'], variant='observed_permutation')
            if entry['uncompressed'] > 64*1024:
                raise ValueError('Selected asset exceeded its 64 KiB bound')
            raw, valid = access.decode_entry(stream, pos, entry, footer['methods'], key)
            suffix = Path(name).suffix
            if not valid or digest(raw) != expected[suffix]:
                raise ValueError('Selected payload compressed SHA1 or clear SHA256 changed')
            parts[suffix] = raw
            pins.append(dict(path=name, encoded_offset=location, physical_offset=pos,
                             bytes=len(raw), sha256=digest(raw), compressed_sha1_valid=valid))
    h, b = parts['.uasset'], parts['.uexp']
    names = access.installed_name_map(h)
    cv = struct.unpack_from('<i', h, 20)[0]
    ec, eo, ic, io = struct.unpack_from('<4i', h, 57+cv*20)
    depends = struct.unpack_from('<i', h, 73+cv*20)[0]
    if (ec, ic) != (4, 32) or eo-io != ic*28 or depends-eo != ec*104:
        raise ValueError('Selected package import/export extents changed')
    imports = []
    for i in range(ic):
        at = io+i*28
        imports.append(dict(index=-i-1, name=fname(h, at+20, names),
                            outer=struct.unpack_from('<i', h, at+16)[0],
                            class_name=fname(h, at+8, names)))
    exports, previous = [], len(h)
    for i in range(ec):
        at = eo+i*104
        cls, sup, template, outer = struct.unpack_from('<4i', h, at)
        size, offset = struct.unpack_from('<qq', h, at+28)
        if offset != previous or size < 0:
            raise ValueError('Nonsequential selected export extent')
        previous = offset+size
        exports.append(dict(index=i+1, name=fname(h, at+16, names), class_index=cls,
                            super_index=sup, template_index=template, outer_index=outer,
                            size=size, offset=offset-len(h)))
    if previous-len(h)+4 != len(b) or b[-4:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Selected companion extent or terminal magic changed')
    pkg = Package.__new__(Package)
    pkg.header, pkg.payload, pkg.names = h, b, names
    pkg.exports, pkg.imports = exports, [item['name'] for item in imports]
    pkg.property_cache = {}
    info = dict(kind='offline_ai_leaf_source_contract', pak=str(path), index=public,
                directory=directory, asset_pins=pins, key_provenance=key_provenance,
                key_material_disclosed=False, codec_sha256=codec_sha,
                client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=CACHE_SHA,
                process_access=False, game_launched=False, game_network_traffic=False,
                database_access=False, native_gameplay_code_invoked=False,
                source_written=False, peer_written=False,
                import_count=ic, export_count=ec, imports=imports, exports=exports)
    return pkg, info


def field(pkg, at):
    b, ns = pkg.payload, pkg.names
    start = at
    kind, name = fname(b, at, ns), fname(b, at+8, ns)
    flags, count, width, propflags = struct.unpack_from('<iiiQ', b, at+16)
    notify = fname(b, at+38, ns)
    if count != 1 or notify != 'None':
        raise ValueError('Selected field common layout changed')
    at += 47
    row = dict(start=start, kind=kind, name=name, object_flags=hex(flags), array_dim=count,
               element_size=width, property_flags=hex(propflags))
    if kind in ('StructProperty', 'ObjectProperty', 'ByteProperty'):
        row['type_reference'] = struct.unpack_from('<i', b, at)[0]
        pkg.object(row['type_reference'])
        at += 4
    elif kind == 'BoolProperty':
        row['bool_layout_hex'] = b[at:at+6].hex()
        at += 6
    elif kind == 'EnumProperty':
        row['enum_reference'] = struct.unpack_from('<i', b, at)[0]
        row['underlying'], at = field(pkg, at+4)
    elif kind not in ('IntProperty', 'FloatProperty'):
        raise ValueError('Unqualified selected field type: '+kind)
    row['end'] = at
    row['sha256'] = digest(b[start:at])
    return row, at


TOKENS = {0: 'LocalVariable', 1: 'InstanceVariable', 4: 'Return', 6: 'Jump',
          7: 'JumpIfNot', 11: 'Nothing', 15: 'Let', 20: 'LetBool',
          22: 'EndFunctionParms', 23: 'Self', 25: 'Context', 26: 'ContextFailSilent',
          27: 'VirtualFunction', 28: 'FinalFunction', 29: 'IntConst', 30: 'FloatConst',
          32: 'ObjectConst', 36: 'ByteConst', 37: 'IntZero', 38: 'IntOne',
          39: 'True', 40: 'False', 46: 'DynamicCast', 56: 'PrimitiveCast', 69: 'LocalVirtualFunction',
          70: 'LocalFinalFunction', 72: 'LocalOutVariable', 78: 'ComputedJump',
          83: 'EndOfScript', 95: 'LetObj', 100: 'LetValueOnPersistentFrame', 104: 'CallMath'}


class Script:
    def __init__(self, pkg, start, length):
        self.pkg, self.data, self.base = pkg, pkg.payload[start:start+length], start
        self.at = self.index = 0

    def read(self, fmt, virtual=None):
        size = struct.calcsize('<'+fmt)
        if self.at+size > len(self.data):
            raise ValueError('Script read outside selected function')
        value = struct.unpack_from('<'+fmt, self.data, self.at)[0]
        self.at += size
        self.index += size if virtual is None else virtual
        return value

    def name(self):
        value = fname(self.data, self.at, self.pkg.names)
        self.at += 8
        self.index += 12
        return value

    def obj(self):
        index = self.read('i', 8)
        return dict(index=index, name=self.pkg.object(index))

    def pointer(self):
        start, index = self.at, self.index
        count = self.read('i')
        if not 0 <= count <= 4:
            raise ValueError('Selected script field path is outside bound')
        path = [self.name() for _ in range(count)]
        owner = self.read('i')
        self.pkg.object(owner)
        self.index = index+8
        return dict(path=path, owner=owner, uexp_offset=self.base+start)

    def expr(self, depth=0):
        if depth > 32:
            raise ValueError('Selected script nesting exceeded bound')
        at, index = self.at, self.index
        token = self.read('B')
        if token not in TOKENS:
            raise ValueError(f'Unqualified script opcode {token:#x} at {at}')
        row = dict(op=TOKENS[token], code_offset=index, uexp_offset=self.base+at)
        if token in (0, 1, 72):
            row['field'] = self.pointer()
        elif token in (28, 70, 104, 27, 69):
            row['function'] = self.name() if token in (27, 69) else self.obj()
            row['args'] = []
            while True:
                arg = self.expr(depth+1)
                if arg['op'] == 'EndFunctionParms':
                    break
                row['args'].append(arg)
        elif token in (25, 26):
            row['context'] = self.expr(depth+1)
            row['skip'] = self.read('I')
            row['rvalue'] = self.pointer()
            row['call'] = self.expr(depth+1)
        elif token in (95, 20, 15):
            if token == 15:
                row['property'] = self.pointer()
            row['destination'] = self.expr(depth+1)
            row['value'] = self.expr(depth+1)
        elif token == 100:
            row['destination'] = self.pointer()
            row['value'] = self.expr(depth+1)
        elif token == 46:
            row['class'] = self.obj()
            row['value'] = self.expr(depth+1)
        elif token == 56:
            row['conversion'] = self.read('B')
            row['value'] = self.expr(depth+1)
        elif token in (6, 7):
            row['target'] = self.read('I')
            if token == 7:
                row['condition'] = self.expr(depth+1)
        elif token in (4, 78):
            row['value'] = self.expr(depth+1)
        elif token in (29, 30, 36):
            row['value'] = self.read({29: 'i', 30: 'f', 36: 'B'}[token])
        elif token == 32:
            row['value'] = self.obj()
        row['code_end'], row['uexp_end'] = self.index, self.base+self.at
        return row


def parse_struct(pkg, export):
    b = pkg.payload
    props, at = tags(b, export['offset'], pkg.names, export['offset']+export['size'])
    zero, sup, count = struct.unpack_from('<3i', b, at)
    if zero != 0 or not 0 <= count <= 4:
        raise ValueError('Selected UObject/UStruct prefix changed')
    at += 12
    children = list(struct.unpack_from('<'+str(count)+'i', b, at))
    at += count*4
    field_count = struct.unpack_from('<i', b, at)[0]
    at += 4
    fields = []
    if not 0 <= field_count <= 32:
        raise ValueError('Selected FField count exceeded bound')
    for _ in range(field_count):
        row, at = field(pkg, at)
        fields.append(row)
    memory_size, disk_size = struct.unpack_from('<2i', b, at)
    script_start = at+8
    reader = Script(pkg, script_start, disk_size)
    statements = []
    while reader.at < disk_size:
        statements.append(reader.expr())
    if reader.index != memory_size or reader.at != disk_size:
        raise ValueError('Script runtime/disk extent accounting failed')
    tail = script_start+disk_size
    result = dict(index=export['index'], name=export['name'], super_struct=sup,
                  children=children, field_count=field_count, fields=fields,
                  properties=props, script_uexp_offset=script_start,
                  script_disk_bytes=disk_size, script_memory_bytes=memory_size,
                  script_sha256=digest(b[script_start:tail]), statements=statements)
    if export['index'] < 3:
        flags, graph, graph_offset = struct.unpack_from('<Iii', b, tail)
        if tail+12 != export['offset']+export['size']:
            raise ValueError('Selected UFunction extent not fully consumed')
        result.update(function_flags=hex(flags), network_function=bool(flags & 0x40),
                      server_rpc=bool(flags & 0x40 and flags & 0x200000),
                      event_graph_function=graph, event_graph_offset=graph_offset)
        boundaries = {s['code_offset'] for s in statements}
        for statement in statements:
            if statement['op'] in ('Jump', 'JumpIfNot') and statement['target'] not in boundaries:
                raise ValueError('Selected branch does not target a statement boundary')
        if statements[-1]['op'] != 'EndOfScript':
            raise ValueError('Selected function is missing terminal script opcode')
        result['jump_targets_valid'] = True
    else:
        result['class_tail_uexp_offset'] = tail
        result['class_tail_sha256'] = digest(b[tail:export['offset']+export['size']])
    return result


def native_boundary():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    cache = CodeCache(PEER/'work/native-code-cache/1792259162856698600', CACHE_SHA, GAME)
    exe = GAME/cache.manifest['plan']['client_relative_to_game_root']
    pins, data_pins = [], []
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)

        def data(at, size):
            raw = image.read(at, size)
            data_pins.append(dict(rva=hex(at), bytes=size, sha256=digest(raw)))
            return raw

        def literal(pointer):
            at = pointer-image.image_base
            raw = image.read(at, 128).split(b'\0')[0]
            data(at, len(raw)+1)
            return raw.decode('ascii')

        record = struct.unpack('<10Q', data(0x1d17c730, 80))
        if (record[0]-image.image_base, literal(record[2]), record[5], record[7] & 0xffffffff,
                record[8] & 0xffffffff) != (0xcd4afc0, 'GetNextPointConfig', 72, 9, 0x04c20401):
            raise ValueError('Native GetNextPointConfig UHT identity changed')
        properties = []
        for pointer in struct.unpack('<9Q', data(0x184f04b0, 72)):
            at = pointer-image.image_base
            row = struct.unpack('<7Q', data(at, 56))
            offset = row[4] >> 32
            if row[3] & 0x3f == 12:
                setter = row[6]-image.image_base
                raw = cache.read(setter, 16)
                pins.append(dict(label='ReturnValue native bool setter', rva=hex(setter),
                                 bytes=16, sha256=digest(raw)))
                if setter != 0xe34e90 or raw[:5] != b'\xc6\x41\x40\x01\xc3':
                    raise ValueError('Native return bool setter changed')
                offset = 0x40
            properties.append(dict(name=literal(row[0]), rva=hex(at),
                generation=row[3] & 0x3f, flags=hex(row[2]),
                native_offset=offset))
        if [p['name'] for p in properties] != [
                'ReturnValue', 'Dir', 'Pose', 'UnderlyingType', 'Staytime',
                'KP', 'Adjusted', 'Destination', 'AIController']:
            raise ValueError('Native GetNextPointConfig property order changed')
        registration = struct.unpack('<2Q', data(0x184f65e0, 16))
        if literal(registration[0]) != 'GetNextPointConfig' or registration[1]-image.image_base != 0xcd51f80:
            raise ValueError('Native GetNextPointConfig exec registration changed')
        getter = struct.unpack('<2Q', data(0x184f0a58, 16))
        if literal(getter[0]) != 'GetNextPointConfig' or getter[1]-image.image_base != 0xcd4c000:
            raise ValueError('UFunction construction registration changed')
        class_record = struct.unpack('<12Q', data(0x184f0ed0, 96))
        if class_record[0]-image.image_base != 0xcd4bf40:
            raise ValueError('UHT outer class StaticClass pointer changed')
        class_raw = image.read(0x184f0f3a, 64)
        class_end = next(i for i in range(0, len(class_raw), 2) if class_raw[i:i+2] == b'\0\0')
        class_name = data(0x184f0f3a, class_end+2)[:-2].decode('utf-16le')
        if class_name != 'AIGroupPatrolJob':
            raise ValueError('UHT outer class name changed')
        extent = image.containing(0x9eb13d0)
        if extent[:2] != (0x9eb13d0, 0x9eb3612):
            raise ValueError('Native selected method unwind extent changed')
        expected = {0xcd521bd: ('call', '0x9eb13d0'),
                    0xcd521c6: ('mov', 'byte ptr [rcx], al'),
                    0x9eb15a2: ('cmp', 'qword ptr [rsp + 0xa38], 0'),
                    0x9eb15b5: ('mov', 'eax, dword ptr [rax + 0x58]'),
                    0x9eb167c: ('imul', 'rax, rax, 0x78'),
                    0x9eb16ee: ('cmp', 'qword ptr [rax + 8], rcx'),
                    0x9eb1753: ('inc', 'eax'),
                    0x9eb175d: ('mov', 'dword ptr [rcx + 0x20], eax'),
                    0x9eb1773: ('call', '0x9eb4190'),
                    0x9eb17d8: ('imul', 'rax, rax, 0x50'),
                    0x9eb1812: ('movss', 'xmm0, dword ptr [rcx + 0x44]'),
                    0x9eb1817: ('movss', 'dword ptr [rax], xmm0'),
                    0x9eb188b: ('movzx', 'ecx, byte ptr [rcx + 0x48]'),
                    0x9eb188f: ('mov', 'byte ptr [rax], cl')}
        actual = {}
        for label, at, size in [('GetNextPointConfig outer getter', 0xcd4afc0, 47),
                                ('AIGroupPatrolJob StaticClass', 0xcd4bf40, 178),
                                ('GetNextPointConfig UFunction constructor getter', 0xcd4c000, 47),
                                ('GetNextPointConfig exec', 0xcd51f80, 604),
                                ('GetNextPointConfig native body', 0x9eb13d0, 8770)]:
            raw = b''.join(cache.read(pos, min(8192, at+size-pos))
                           for pos in range(at, at+size, 8192))
            pins.append(dict(label=label, rva=hex(at), bytes=size, sha256=digest(raw)))
            if label in ('GetNextPointConfig exec', 'GetNextPointConfig native body'):
                for ins in Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, at):
                    if ins.address in expected:
                        actual[ins.address] = (ins.mnemonic, ins.op_str)
        if actual != expected:
            raise ValueError('Native method/exec instruction anchors changed')
    return dict(uht_rva='0x1d17c730', name='GetNextPointConfig', outer_class=class_name,
                native_parameter_frame_bytes=72,
                function_flags='0x04c20401', network_function=False, server_rpc=False,
                property_records=properties, underlying_type_is_not_a_parameter=True,
                native_exec_rva='0xcd51f80', native_method_rva='0x9eb13d0',
                native_method_bytes_available=True, native_method_fully_decompiled=False,
                code_pins=pins, data_pins=data_pins, instruction_anchor_count=len(expected),
                instruction_anchors=[dict(rva=hex(at), mnemonic=mnemonic, operands=operands)
                                     for at, (mnemonic, operands) in expected.items()],
                body_prefix_recovered=['Null AIController or zero array count returns false.',
                    'Member records have stride 0x78 and are matched to the AIController at record+8.',
                    'Missing controller member returns false; record+0x20 is incremented or replaced from self+0xc8 according to self+0xcc.',
                    'Index helper 0x9eb4190 receives the selected and following record index; patrol point entries have stride 0x50.',
                    'Staytime output is copied from selected point+0x44; Pose output from selected point+0x48.'],
                remaining='Index helper, current point/config data, coordinate/nav adjustment and all later native paths remain unqualified.')


def qualify(pkg, result):
    structures = [parse_struct(pkg, e) for e in pkg.exports[:3]]
    result['structs'] = structures
    declarations = {s['index']: {f['name'] for f in s['fields']} for s in structures}
    references, primitive_casts = [], []

    def walk(value):
        if isinstance(value, list):
            for child in value:
                walk(child)
        elif isinstance(value, dict):
            if 'path' in value and 'owner' in value:
                owner, path = value['owner'], value['path']
                if owner and (owner not in declarations or len(path) != 1 or path[0] not in declarations[owner]):
                    raise ValueError('Script field path does not resolve to its serialized declaration')
                references.append(value)
            if value.get('op') == 'PrimitiveCast':
                primitive_casts.append(value['conversion'])
            for child in value.values():
                walk(child)
    for s in structures:
        walk(s['statements'])
    if primitive_casts != [0x47]:
        raise ValueError('Selected UObject-to-bool conversion changed')
    result['field_path_reference_count'] = len(references)
    result['all_script_field_paths_resolve'] = True
    cdo = pkg.exports[3]
    props, end = tags(pkg.payload, cdo['offset'], pkg.names, cdo['offset']+cdo['size'])
    if end != cdo['offset']+cdo['size']:
        raise ValueError('CDO typed tags did not consume full export')
    defaults = []
    for tag in props:
        row = dict(tag)
        if tag['meta'] == ['BlackboardKeySelector']:
            nested, nested_end = tags(pkg.payload, tag['value_start'], pkg.names, tag['end'])
            if nested_end != tag['end']:
                raise ValueError('CDO key selector extent was not consumed')
            values = {}
            for item in nested:
                values[item['name']] = (pkg.payload[item['value_start']] if item['name'] == 'SelectedKeyID'
                                       else pkg.value(item))
            row['value'] = values
        else:
            row['value_sha256'] = digest(pkg.payload[tag['value_start']:tag['end']])
        defaults.append(row)
    result['cdo'] = dict(index=4, start=cdo['offset'], end=end, properties=defaults,
                         assmble_pos_explicitly_serialized=any(t['name'] == 'AssmblePos' for t in props),
                         omitted_assmble_pos_effective_value_resolved=False)
    prior_path = ROOT/'work/evidence/gameplay-ai-authority-research-20261020.json'
    prior_raw = prior_path.read_bytes()
    prior = json.loads(prior_raw)
    node = next(e for e in prior['patrol_asset']['selected_exports'] if e['index'] == 143)
    if node['class_path'] != '/Game/BluePrints/Characters/AI_SOL_V2/Drama_SOL/Patrol/Common/GetGroupPatrolPoint.GetGroupPatrolPoint_C':
        raise ValueError('Previously qualified selected node class changed')
    bindings = {tag['name']: tag['value']['serialized_fields']['SelectedKeyName']
                for tag in node['properties'] if isinstance(tag.get('value'), dict)
                and 'serialized_fields' in tag['value'] and 'SelectedKeyName' in tag['value']['serialized_fields']}
    result['previous_tree_evidence'] = dict(path=str(prior_path), sha256=digest(prior_raw),
        asset_pins=prior['patrol_asset']['asset_pins'], selected_export=node['index'],
        node_name=node['name'], class_path=node['class_path'], bindings=bindings,
        assmble_pos_explicitly_serialized=any(t['name'] == 'AssmblePos' for t in node['properties']))
    main, event = structures[:2]
    if ([s['code_offset'] for s in main['statements']] !=
            [0, 10, 40, 69, 83, 113, 149, 178, 192, 206, 269, 298, 327, 356,
             415, 457, 486, 523, 552, 563, 568, 579, 584, 689, 718, 747, 776, 781, 783]):
        raise ValueError('Qualified ubergraph statement boundaries changed')
    if event['statements'][2]['args'][0]['value'] != 10:
        raise ValueError('ReceiveExecuteAI did not enter the qualified graph entry')
    result['flow_contract'] = dict(
        event_entry_code_offset=10,
        invalid_object_or_failed_cast_finish=False,
        patrol_job_read_key=bindings['PatrolJob'],
        normal_branch_native_call='AIGroupPatrolJob.GetNextPointConfig',
        normal_branch_write_keys={name: bindings[field] for name, field in
            [('Destination', 'TempTargetLocation'), ('Adjusted', 'AdjustedLocation'), ('KP', 'KPCenter')]},
        common_branch_writes={name: bindings[field] for name, field in
            [('Dir', 'FucosPoint'), ('Staytime', 'Staytime'), ('Pose byte converted to int', 'Pose'),
             ('GetMemberOrder(OwnerController) multiplied by float32 0.6', 'RandomStartTime')]},
        native_getnext_bool_is_used_as_condition=False,
        successful_cast_both_branches_finish=True,
        assemble_branch='GetAssemblePosition(OwnerController) writes TempTargetLocation, then jumps to common writes; no GetNextPointConfig call in that branch.',
        assemble_common_outputs_reset_in_this_script=False,
        current_instance_assmble_pos_and_temporary_values_observed=False,
        script_executed=False, local_authoritative_ai_implemented=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect', action='store_true')
    args = parser.parse_args()
    pkg, result = load()
    result = qualify(pkg, result)
    result['native_boundary'] = native_boundary()
    helpers = ['recover_economy_pak_access.py', 'scan_weapon_tables.py',
               'probe_pak_payload_lua.py', 'extract_operator_avatar_catalog.py',
               'recover_dam_gameplay_catalog.py', 'oodle_payload_reader.py',
               'portable_native_code_cache.py', 'offline_received_packet_xrefs.py',
               'snapshot_native_image_code.py']
    result['source_helper_pins'] = [dict(path=str(PEER/'work'/name),
                                         sha256=digest((PEER/'work'/name).read_bytes())) for name in helpers]
    result['parser_references'] = [
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Objects/UObject/UStruct.cs',
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Objects/UObject/UFunction.cs',
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Objects/UObject/FFieldPath.cs',
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Assets/Readers/FKismetArchive.cs',
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Kismet/KismetExpression.cs',
        'https://github.com/FabianFG/CUE4Parse/blob/master/CUE4Parse/UE4/Kismet/EExprToken.cs']
    result['external_parser_documentation_consulted'] = True
    result['helper_sha256'] = digest(Path(__file__).read_bytes())
    if args.inspect:
        result['names'] = list(enumerate(pkg.names))
        for item in result['exports']:
            props, end = tags(pkg.payload, item['offset'], pkg.names, item['offset']+item['size'])
            item['properties'] = props
            item['after_tags'] = end
            item['tail_hex'] = pkg.payload[end:item['offset']+item['size']].hex()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
