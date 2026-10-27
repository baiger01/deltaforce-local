"""Bounded, offline medical declaration/code inspection; prints JSON only.

Uses the already saved code cache and immutable installed PE data. It never
opens a process, invokes game code, launches a client, sends packets, or writes
research inputs. Run with PYTHONDONTWRITEBYTECODE=1.
"""
import argparse
import ast
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

PEER = Path('E:/新建文件夹/DSH/deltaforce-map-appearance')
GAME = Path('F:/WeGameApps/rail_apps/DeltaForce(2001918)')
CACHE_SHA = 'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754'
sys.path.insert(0, str(PEER/'work'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


def reflection_contract():
    """Qualify source-equivalent leaf grammar without constructing native objects."""
    cache = CodeCache(PEER/'work/native-code-cache/1792259162856698600', CACHE_SHA, GAME)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ranges = [
        (0x10ea37f0, 1536), (0x10ea561c, 384), (0x10ea4e4a, 384),
        (0x10ea4401, 384), (0x10ea41aa, 384), (0x10ea58b5, 240),
        (0x10e3e530, 240), (0x10cf7980, 256), (0x10e38cb0, 256),
        (0x10e272c0, 256), (0x10d02978, 768), (0x12db93c0, 256),
        (0x12db9640, 384), (0x10e29fa0, 256), (0x12db2cb0, 838),
        (0x12d9b1e0, 1024), (0x4a24e50, 1024), (0x12dc20b0, 1024),
        (0x12dc23f0, 512), (0x10e8ed20, 256), (0x10e8ebe0, 160),
        (0x10d03cb0, 2849), (0x10e8ed20, 193), (0x10e1e2d0, 256),
        (0x128932e9, 256),
        (0x10ea6010, 800), (0x10e37fb0, 1024),
        (0xcfc6100, 64), (0xcfc5000, 64), (0xcfc66f0, 128),
    ]
    pins, instructions = [], {}
    for rva, size in ranges:
        raw = cache.read(rva, size)
        pins.append(dict(rva=hex(rva), bytes=size, sha256=hashlib.sha256(raw).hexdigest()))
        for ins in md.disasm(raw, rva):
            instructions[ins.address] = (ins.mnemonic, ins.op_str)
    anchors = {
        0x10ea3855: ('add', 'rax, 8'),
        0x10ea386c: ('and', 'eax, 0x3f'),
        0x10ea56ba: ('call', '0x10e096d0'),
        0x10ea593e: ('dec', 'dword ptr [rax]'),
        0x10ea5974: ('call', '0x10ea37f0'),
        0x10cf7980: ('mov', 'rax, qword ptr [rcx + 0x70]'),
        0x10cf7984: ('mov', 'qword ptr [rdx + 0x18], rax'),
        0x10cf7988: ('mov', 'qword ptr [rcx + 0x70], rdx'),
        0x10e38d07: ('movabs', 'r9, 0x1000000008001'),
        0x10e27301: ('movabs', 'rax, 0x1040000200'),
        0x10e2730b: ('or', 'qword ptr [rdi + 0x48], rax'),
        0x10d029c1: ('call', 'qword ptr [rax + 0x70]'),
        0x12db9466: ('bt', 'rax, 9'),
        0x12db947c: ('call', '0x1497fcc2'),
        0x12db9679: ('shr', 'rcx, 0x11'),
        0x12db96cf: ('inc', 'qword ptr [r13 + 0xa8]'),
        0x12db96e1: ('je', '0x12db98ad'),
        0x12db9742: ('call', '0x12dc23f0'),
        0x12db2d34: ('and', 'eax, 0x480'),
        0x12db2d39: ('cmp', 'rax, 0x80'),
        0x12db2e16: ('call', '0x12d9b1e0'),
        0x12db2eb3: ('or', 'dword ptr [r8 + 0x38], 0x40'),
        0x12db943d: ('shr', 'ecx, 6'),
        0x12db9443: ('jne', '0x12db948f'),
        0x128932e9: ('movzx', 'r8d, word ptr [rsi + 0xba]'),
        0x1289336a: ('xor', 'edx, edx'),
        0x1289336c: ('mov', 'r8, rax'),
        0x1289336f: ('mov', 'rcx, r14'),
        0x12893372: ('call', '0x1497fcc2'),
        0x1289332f: ('mov', 'rax, r9'),
        0x128933ad: ('mov', 'qword ptr [rsp + 0x28], r14'),
        0x128933b7: ('call', '0x12db93c0'),
        0x12d9b367: ('je', '0x12d9b3d9'),
        0x12d9b416: ('bt', 'rax, 0x1f'),
        0x12d9b47c: ('call', '0x4a24e50'),
        0x12d9b54c: ('call', '0x12d9b1e0'),
        0x4a24f74: ('mov', 'eax, dword ptr [rsi + 0x54]'),
        0x4a24f77: ('cmp', 'eax, dword ptr [rdx + 0x54]'),
        0x4a25000: ('setl', 'sil'),
        0x10e29faa: ('cmp', 'dword ptr [rdx + 0x54], 0xc'),
        0x10e29fe2: ('inc', 'rax'),
        0x10e2a031: ('call', 'qword ptr [rax + 0x68]'),
        0x12dc2125: ('mov', 'r8d, 2'),
        0x12dc212b: ('call', 'qword ptr [rax + 0x60]'),
        0x12dc23c5: ('call', '0x12dc23f0'),
        0x12dc2554: ('call', 'qword ptr [rax + 0x90]'),
        0x10e8ed44: ('call', 'qword ptr [rax + 0x140]'),
        0x10e8ed76: ('call', 'qword ptr [rax + 0x260]'),
        0x10e8edc4: ('call', 'qword ptr [rax + 0x148]'),
        0x10d03fc5: ('call', 'qword ptr [rax + 0x60]'),
        0x10d0405a: ('or', 'dword ptr [rbx], 0x400'),
        0x10ea6203: ('cmp', 'dword ptr [r14 + 0x30], r12d'),
        0x10ea6217: ('sete', 'r9b'),
        0x10ea621b: ('call', 'qword ptr [rax + 0x288]'),
        0x10e38300: ('call', '0x10e1e2d0'),
        0x10e38309: ('lea', 'r14, [rax + 1]'),
        0x10e3833c: ('mov', 'qword ptr [rdx + 8], r14'),
        0x10e8ebfa: ('mov', 'r8d, 1'),
        0x10e8ec19: ('call', 'qword ptr [rax + 0x68]'),
        0xcfc66f2: ('mov', 'dword ptr [rdx], 0xffffffff'),
        0xcfc66fb: ('mov', 'byte ptr [rdx + 8], al'),
        0xcfc66fe: ('mov', 'byte ptr [rdx + 0x20], al'),
    }
    for rva, expected in anchors.items():
        if instructions.get(rva) != expected:
            raise ValueError('Medical reflection source anchor changed: '+hex(rva))
    exe = GAME/cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        data_pins = []

        def data(rva, size):
            raw = image.read(rva, size)
            data_pins.append(dict(rva=hex(rva), bytes=size, sha256=hashlib.sha256(raw).hexdigest()))
            return raw

        def pointer_slot(vtable, slot, target):
            if struct.unpack('<Q', data(vtable+slot, 8))[0]-image.image_base != target:
                raise ValueError('Medical reflection vtable target changed')

        def name(pointer):
            return image.read(pointer-image.image_base, 256).split(b'\0', 1)[0].decode('ascii')

        def properties(params_rva, is_struct=False):
            raw = data(params_rva, 72 if is_struct else 80)
            values = struct.unpack('<'+'Q'*(len(raw)//8), raw)
            count = values[7] & 0xffffffff
            if not 1 <= count <= 32:
                raise ValueError('Medical property-list bound changed')
            pointers = list(struct.unpack('<'+'Q'*count, data(values[6]-image.image_base, count*8)))
            at = 0

            def take():
                nonlocal at
                if at >= len(pointers):
                    raise ValueError('Missing enum/array inner declaration')
                rva = pointers[at]-image.image_base
                at += 1
                raw = data(rva, 56)
                words = struct.unpack_from('<5Q', raw)
                gen = words[3] & 0xffffffff
                row = dict(name=name(words[0]), record_rva=hex(rva), gen=gen,
                           property_flags=hex(words[2]), native_offset=words[4] >> 32)
                if gen & 0x3f in (22, 30):
                    row['inner'] = take()
                if gen & 0x3f == 12:
                    row['native_bool'] = bool(gen & 0x40)
                    setter = struct.unpack_from('<Q', raw, 48)[0]-image.image_base
                    if 0 <= setter < 0x14e00000:
                        ins = next(md.disasm(cache.read(setter, 16), setter, count=1))
                        row['native_offset'] = ins.operands[0].mem.disp
                return row

            declared = []
            while at < count:
                declared.append(take())
            linked = list(reversed(declared))
            return dict(params_rva=hex(params_rva), uht_record_count=count,
                        uht_logical_order=[row['name'] for row in declared],
                        runtime_child_property_order=[row['name'] for row in linked],
                        properties=linked)

        cancel = properties(0x1d23d970)
        use = properties(0x1d23d9c0)
        args = properties(0x1d23c610, True)
        if cancel['runtime_child_property_order'] != ['Reason'] or use['runtime_child_property_order'] != ['ItemGid', 'UseItemArgs', 'ClientAnimTime']:
            raise ValueError('Medical RPC parent declaration order changed')
        ordered = sorted(args['properties'], key=lambda row: row['native_offset'])
        if [row['name'] for row in ordered] != ['Target', 'Part', 'bUseOnHelmet', 'bUseOnArmor', 'TargetItemGID', 'TargetItemID', 'UseItemSource', 'PutInSafeBoxFirst']:
            raise ValueError('Medical struct leaf order changed')
        if (cancel['properties'][0]['gen'], cancel['properties'][0]['inner']['gen']) != (30, 0):
            raise ValueError('Cancel enum or byte underlying property changed')
        enum_raw = data(0x18859e50, 22*16)
        reasons = [(name(pointer), value) for pointer, value in struct.iter_unpack('<Qq', enum_raw)]
        if [value for _, value in reasons] != list(range(22)):
            raise ValueError('Installed cancel reason extent changed')
        enum_values = {}
        for enum_name, params_rva in (('CancelReason', 0x1d23c748),
                                      ('CharacterPart', 0x1ccf3c28), ('InputSource', 0x1d23c5d0)):
            raw = data(params_rva, 56)
            if struct.unpack_from('<I', raw, 0x30)[0] != 0:
                raise ValueError('Native enum disabled automatic MAX generation')
            table = struct.unpack_from('<Q', raw, 0x20)[0]-image.image_base
            count = struct.unpack_from('<I', raw, 0x28)[0]
            if not 1 <= count <= 32:
                raise ValueError('Bounded native enum table required')
            entries = [(name(pointer), value) for pointer, value in struct.iter_unpack('<Qq', data(table, count*16))]
            maximum = max(value for _, value in entries)+1
            enum_values[enum_name] = dict(entries=entries, generated_maximum=maximum,
                                         archive_version_at_least_12_wire_bits=maximum.bit_length())
        for vtable, slot, target in ((0x15a87070, 0x70, 0x10e272c0),
                                     (0x15a87070, 0x90, 0x10e29fa0),
                                     (0x1ab610f0, 0x90, 0x10e8ed20),
                                     (0x15a868a0, 0x90, 0x10e8ebe0),
                                     (0x15aba860, 0x258, 0x10cf7980),
                                     (0x1ab39f20, 0x258, 0x10cf7980)):
            pointer_slot(vtable, slot, target)
        pointer_slot(0x1ab53b50, 0x288, 0x10e37fb0)
        for vtable in (0x18859d20, 0x1885a7c0):
            pointer_slot(vtable, 0x60, 0xd5f3a0)
            pointer_slot(vtable, 0x70, 0xd5f3a0)
    return dict(kind='source_equivalent_medical_reflection_grammar_20261020',
                client_sha256=cache.manifest['client_sha256'], cache_manifest_sha256=CACHE_SHA,
                code_ranges=pins, data_ranges=data_pins,
                anchors=[dict(rva=hex(rva), mnemonic=value[0], operands=value[1]) for rva, value in anchors.items()],
                cancel=cancel, use=use, use_item_args=dict(args, sorted_leaves=ordered),
                cancel_reason_explicit_values=reasons, reason_width_bits=5,
                enums=enum_values,
                reason_default_when_absent=0, parameter_presence_bits=1,
                enum_link_adds_zero_constructor=True, enum_class_flags='0x1000000008001',
                source_equivalent_parameter_grammar_closed=True,
                use_item_args_custom_netserialize_flag=False,
                use_item_source_equivalent_leaf_order_closed=True,
                bool_array_count_bits=16, bool_array_inner_bits=1,
                weak_object_serializer_rva='0x10e8ed20',
                captured_medical_request_replayed=False,
                native_handler_or_medical_success_verified=False,
                process_access=False, game_methods_invoked=False, packets_sent=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rva', type=lambda value: int(value, 0), action='append', default=[])
    parser.add_argument('--bytes', type=int, default=256)
    parser.add_argument('--target', type=lambda value: int(value, 0), action='append', default=[])
    parser.add_argument('--call-target', type=lambda value: int(value, 0), action='append', default=[])
    parser.add_argument('--reflection', action='store_true')
    args = parser.parse_args()
    if args.reflection:
        print(json.dumps(reflection_contract(), indent=2))
        return
    if not 1 <= args.bytes <= 8192 or len(args.rva) > 32 or len(args.target)+len(args.call_target) > 16:
        parser.error('Bounded code queries only')
    cache = CodeCache(PEER/'work/native-code-cache/1792259162856698600', CACHE_SHA, GAME)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    exe = GAME/cache.manifest['plan']['client_relative_to_game_root']
    result = dict(process_access=False, client_launched=False, game_methods_invoked=False,
                  packets_sent=False, files_written=False, cache_manifest_sha256=CACHE_SHA)
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        env = dict(image=image, cache=cache, md=md, struct=struct, hashlib=hashlib)
        import capstone.x86_const as constants
        env.update(vars(constants))
        helper = PEER/'work/inspect_economy_uht_class_metadata.py'
        tree = ast.parse(helper.read_text(encoding='utf8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in ('text', 'prop', 'function'):
                exec(compile(ast.Module(body=[node], type_ignores=[]), str(helper), 'exec'), env)
        text, prop, function = (env[name] for name in ('text', 'prop', 'function'))

        def code(rva, size):
            raw = cache.read(rva, size)
            return dict(rva=hex(rva), bytes=size, sha256=hashlib.sha256(raw).hexdigest(),
                        instructions=[dict(rva=hex(ins.address), bytes=ins.bytes.hex(),
                                           mnemonic=ins.mnemonic, operands=ins.op_str)
                                      for ins in md.disasm(raw, rva)])

        def declaration_from_getter(getter):
            for ins in md.disasm(cache.read(getter, 128), getter):
                if ins.mnemonic == 'lea' and len(ins.operands) == 2:
                    operand = ins.operands[1]
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        target = ins.address+ins.size+operand.mem.disp
                        if 0x1c000000 <= target < 0x1d400000:
                            return target
            raise ValueError('No bounded declaration address in getter')

        def struct_record(getter):
            rva = declaration_from_getter(getter)
            raw = image.read(rva, 72)
            values = struct.unpack('<9Q', raw)
            count = values[7] & 0xffffffff
            if values[7] >> 32 != 0x45 or not 0 < count <= 128:
                raise ValueError('Struct declaration shape changed')
            array = image.read(values[6]-image.image_base, count*8)
            return dict(name=text(values[3]), getter_rva=hex(getter), record_rva=hex(rva),
                        record_sha256=hashlib.sha256(raw).hexdigest(), native_size=values[4],
                        alignment=values[5], fields=[prop(pointer) for pointer in struct.unpack('<'+'Q'*count, array)])

        def literal(pointer):
            raw = image.read(pointer-image.image_base, 256)
            return (raw.decode('utf-16le').split('\0', 1)[0] if raw[1] == 0
                    else raw.split(b'\0', 1)[0].decode('ascii'))

        if args.rva:
            result['code'] = [code(rva, args.bytes) for rva in args.rva]
        elif args.target or args.call_target:
            targets = set(args.target)
            found = []
            for first, length, block in cache.blocks:
                if not block['available']:
                    continue
                raw = (cache.folder/block['file']).read_bytes()
                if len(raw) != length or hashlib.sha256(raw).hexdigest() != block['code_sha256']:
                    raise ValueError('Cached code block identity changed')
                cursor = 0
                while True:
                    choices = [at for opcode in (b'\x8d', b'\x8b')
                               if (at := raw.find(opcode, cursor)) >= 0]
                    cursor = min(choices) if choices else -1
                    if cursor < 0:
                        break
                    if cursor >= 1 and 0x48 <= raw[cursor-1] <= 0x4f and cursor+6 <= len(raw):
                        modrm = raw[cursor+1]
                        if modrm & 0xc7 == 0x05:
                            target = first+cursor+6+struct.unpack_from('<i', raw, cursor+2)[0]
                            if target in targets:
                                found.append(dict(instruction_rva=hex(first+cursor-1), target_rva=hex(target),
                                                  opcode='lea' if raw[cursor] == 0x8d else 'mov',
                                                  block_sha256=block['code_sha256']))
                    cursor += 1
                cursor = 0
                while args.call_target:
                    cursor = raw.find(b'\xe8', cursor)
                    if cursor < 0:
                        break
                    if cursor+5 <= len(raw):
                        target = first+cursor+5+struct.unpack_from('<i', raw, cursor+1)[0]
                        if target in args.call_target:
                            found.append(dict(instruction_rva=hex(first+cursor), target_rva=hex(target),
                                              opcode='call_candidate', block_sha256=block['code_sha256']))
                    cursor += 1
                if len(found) > 128:
                    raise ValueError('Reference result bound exceeded')
            result['rip_lea_or_mov_xrefs'] = found
            result['scan_is_complete_xref_analysis'] = False
        else:
            rva = 0x18859790
            raw = image.read(rva, 80)
            values = struct.unpack('<10Q', raw)
            dep, function_count, property_count, interfaces = struct.unpack_from('<4I', raw, 56)
            if (dep, function_count, property_count, interfaces) != (2, 68, 36, 0):
                raise ValueError('Use item class declaration counts changed')
            selected = {'AttemptUseItem', 'AttemptUseItemWithArgs', 'AttemptCancelUseItem',
                        'ServerAttemptUseItem', 'ServerAttemptCancelUseItem', 'ServerTryUseItem',
                        'ServerUseItemImpl_ItemHealth', 'ClientPreUseItem', 'ClientCancelUseItem',
                        'ClientFinshUseItem', 'ClientStopUseItem', 'ClientNotifyUseItemFaild',
                        'RouleteeSelectItem', 'ServerRouleteeSelectItem', 'OnRep_PreUseItemInfo'}
            functions = []
            for getter, pointer in struct.iter_unpack('<QQ', image.read(values[4]-image.image_base, function_count*16)):
                name = text(pointer)
                if name in selected:
                    functions.append(function(getter-image.image_base, name))
            pointers = struct.unpack('<'+'Q'*property_count,
                                     image.read(values[5]-image.image_base, property_count*8))
            properties = [prop(pointer) for pointer in pointers]
            result['class'] = dict(record_rva=hex(rva), record_sha256=hashlib.sha256(raw).hexdigest(),
                                   static_class_getter_rva=hex(values[0]-image.image_base),
                                   function_count=function_count, property_count=property_count,
                                   selected_functions=functions,
                                   net_properties=[item for item in properties if int(item['property_flags'], 16) & 0x20])
            result['structs'] = [struct_record(getter) for getter in (0xcfc5fe0, 0xcfc4f50)]
            result['enum_getter_code'] = code(0xcfc4e90, 64)
            result['native_lookup'] = dict(rva='0x1885a8f0', sha256=hashlib.sha256(
                image.read(0x1885a8f0, 68*16)).hexdigest(), entries=[dict(name=literal(pointer),
                exec_rva=hex(function_pointer-image.image_base)) for pointer, function_pointer
                in struct.iter_unpack('<QQ', image.read(0x1885a8f0, 68*16)) if literal(pointer) in selected])
            result['enums'] = []
            for rva, count in ((0x18859c30, 5), (0x18859e50, 22),
                               (0x16618900, 9), (0x1885a310, 6)):
                raw = image.read(rva, count*16)
                result['enums'].append(dict(rva=hex(rva), sha256=hashlib.sha256(raw).hexdigest(),
                    entries=[dict(name=literal(pointer), value=value)
                             for pointer, value in struct.iter_unpack('<Qq', raw)]))
            result['cppops'] = []
            for rva in (0x18859d20, 0x1885a7c0):
                raw = image.read(rva, 25*8)
                if struct.unpack_from('<Q', raw, 0x70)[0]-image.image_base != 0xd5f3a0:
                    raise ValueError('Medical struct acquired a custom NetSerialize operation')
                result['cppops'].append(dict(vtable_rva=hex(rva), bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                    slots={hex(index*8): hex(value-image.image_base)
                           for index, value in enumerate(struct.unpack('<25Q', raw))},
                    netserialize_slot='0x70', custom_netserialize_present=False))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
