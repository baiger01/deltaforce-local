"""Offline evidence for new-build replication cache initialization.

Only reads pinned saved observations and immutable PE bytes. Does not emulate
native callees, inspect a process, initialize reflection, or change runtime code.
"""
import argparse
import bisect
import json
import mmap
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import (
    ROOT, CLIENT, PINS, ForensicObservation, NewImage, disasm, instruction_row, sha,
)
from research_updated_replication_core import compare_full, PAIRS as CORE_PAIRS


INPUT_PINS = {
    'work/research_updated_metadata_roots.py':
        'ea107a5bc475bea3ec262dd26ea91283b6fdfa5ad564e29fec3763b737c32cf6',
    'work/research_updated_replication_core.py':
        '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
    'work/evidence/updated-replication-core-79fb7b10.json':
        '762e8111b52e4bd4273489b0a9444adb2340c8a21fd6808cb23c1e1d6bb7cd58',
    'work/research_updated_schema_comparison_79fb7b10.json':
        '1b838ccdf0bc587418b2e6c8a22a29d275f64094996cb8d220b0982a7a50b6cf',
    'work/native-client-tests/1792800038357938800/updated-class-metadata.json':
        '4dc2803f2c41d4efdc2d93dc27487eb9a17880eb3796a87de6dd4f9586aa4168',
}
CORE_NAMES = {
    'weak_key_lookup_cache24', 'weak_key_equality', 'class_cache_get_or_build',
    'class_replication_descriptor_setup', 'property_checksum',
    'property_iterator', 'ufield_iterator', 'field_owner_variant_isa',
    'driver_cache_binding_consumer', 'class_layout_initialize',
    'leaf_command_builder',
}
PAIRS = [row for row in CORE_PAIRS if row[0] in CORE_NAMES] + [
    ('weak_key_constructor', 0x109929f0, 0x10992480),
    ('property_sort', 0x4a24e50, 0x4a24a60),
    ('property_sort_heap_fallback', 0x4a24410, 0x4a24020),
    ('function_sort', 0x10cf4ac0, 0x10cf4460),
    ('function_sort_heap_fallback', 0x10cf3b10, 0x10cf34b0),
    ('ascii_case_insensitive_compare', 0x10a137d0, 0x10a13230),
    ('fstring_ascii_lower_wrapper', 0x109fc3c0, 0x109fbe20),
    ('fstring_ascii_lower_inplace', 0x109fc3f0, 0x109fbe50),
    ('fstring_copy_move', 0xd61e40, 0xd61ec0),
    ('crc_utf16_zero_extended_words', 0xe56940, 0xe56960, 0x6e),
    ('nested_property_iterator', 0xdd97b0, 0xdd97d0),
    ('owner_uobject_class_getter', 0x10ed41f0, 0x10ed3b90),
    ('ufunction_class_getter', 0x10cff710, 0x10cff0b0),
    ('unsigned_format_wrapper', 0x109f45f0, 0x109f4050),
    ('conditional_post_setup', 0x10e062a0, 0x10e05c40),
    ('weapon_hide', 0x21e3440, 0x21e3130),
    ('byte_net_serializer', 0x10e8ec50, 0x10e8e5f0),
    ('enum_max_value', 0x10e1e2d0, 0x10e1dc70),
]


def pinned_inputs():
    rows = []
    for path, expected in INPUT_PINS.items():
        actual = sha((ROOT/path).read_bytes())
        if actual != expected:
            raise ValueError('Pinned research input changed: '+path)
        rows.append(dict(path=path, sha256=actual))
    return rows


def unwind_inventory(image, functions, extra_fragments):
    known = {tuple(int(f[k], 16) for k in ('begin', 'end_exclusive', 'unwind_rva'))
             for row in functions for f in row['new_fragments']}
    known.update(extra_fragments)
    sections = sorted(image.sections)
    starts = [row[0] for row in sections]
    chains = []
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        for row in image.entries:
            first, size, offset = sections[bisect.bisect_right(starts, row[2])-1]
            at = offset+row[2]-first
            if not first <= row[2] < first+size or at+4 > offset+size:
                raise ValueError('Unwind header outside raw-backed PE')
            if raw[at] >> 3 == 4:
                tail = at+4+((raw[at+2]+1)&~1)*2
                if tail+12 > offset+size:
                    raise ValueError('Unwind chain outside raw-backed PE')
                chains.append((row, struct.unpack_from('<III', raw, tail)))
    missing = []
    for _ in range(64):
        changed = False
        for row, parent in chains:
            if parent in known and row not in known:
                known.add(row)
                missing.append(row)
                changed = True
        if not changed:
            break
    else:
        raise ValueError('Unwind closure exceeded')
    if missing:
        raise ValueError('Detached function fragments missing from proof')
    return dict(exception_entries_scanned=len(image.entries),
                chained_entries_scanned=len(chains), detached_uncompared_fragments=0,
                complete_current_unwind_extent_verified=True,
                leaf_crc_boundary='closed branches, no calls, explicit final ret')


def unqualified_name_wrapper(old, new, image):
    old_rva, new_rva = 0x10b78000, 0x10b779d0
    fragments = image.fragments(new_rva)
    length = fragments[-1][1]-new_rva
    oi, ni = disasm(old, old_rva, length), disasm(new, new_rva, length)
    differences = []
    if len(oi) != len(ni) or sum(i.size for i in ni) != length:
        raise ValueError('FName wrapper shape changed beyond recorded scope')
    for a, b in zip(oi, ni):
        if (a.address-old_rva, a.size, a.id) != (b.address-new_rva, b.size, b.id):
            raise ValueError('FName instruction shape changed')
        aa, bb = bytearray(a.bytes), bytearray(b.bytes)
        for x, y in zip(a.operands, b.operands):
            if x.type != y.type:
                raise ValueError('FName operand type changed')
            if x.type == X86_OP_MEM and x.mem.base == X86_REG_RIP:
                aa[a.disp_offset:a.disp_offset+4] = bb[b.disp_offset:b.disp_offset+4] = bytes(4)
            elif x.type == X86_OP_IMM and a.mnemonic.startswith(('j', 'call')):
                aa[a.imm_offset:a.imm_offset+a.imm_size] = bytes(a.imm_size)
                bb[b.imm_offset:b.imm_offset+b.imm_size] = bytes(b.imm_size)
        if aa != bb:
            differences.append(dict(old=instruction_row(a), new=instruction_row(b)))
    if [(r['old']['instruction'], r['new']['instruction']) for r in differences] != [
        ('mov rax, qword ptr [rcx + rdx + 0x1e2cfe40]',
         'mov rax, qword ptr [rcx + rdx + 0x1e2cfe80]'),
        ('mov rax, qword ptr [rcx + rdx + 0x1e2afe40]',
         'mov rax, qword ptr [rcx + rdx + 0x1e2afe80]'),
    ]:
        raise ValueError('FName non-reference differences changed')
    return dict(name='fname_to_string_wrapper', old_rva=hex(old_rva), new_rva=hex(new_rva),
        bytes=length, old_code_sha256=sha(old.read(old_rva, length)),
        new_code_sha256=sha(new.read(new_rva, length)), qualified=False,
        reason='Two image-base-relative table displacements changed; not silently masked or relocated.',
        non_reference_differences=differences,
        decoded_new_instructions=[instruction_row(i) for i in ni]), fragments


def qualify():
    inputs = pinned_inputs()
    old, new, image = ForensicObservation('old'), ForensicObservation('new'), NewImage()
    functions = [compare_full(old, new, image, *row) for row in PAIRS]
    by_name = {row['name']:row for row in functions}
    rows = {int(i['rva'], 16):i for f in functions for i in f['decoded_new_instructions']}
    witnesses = []

    def exact(rule, address, expected):
        actual = rows.get(address)
        if actual is None or actual['instruction'].strip() != expected:
            raise ValueError(f'Cache initialization witness changed: {rule}: {actual}')
        witnesses.append(dict(rule=rule, **actual))

    checks = [
        ('Class weak key starts with object index +0x24', 0x1099248e, 'mov edx, dword ptr [rdx + 0x24]'),
        ('Weak serial constructor delegate; never executed by research', 0x1099249a, 'call 0x10ea1020'),
        ('Current NetDriver manager pointer +0x170', 0x1289bee2, 'mov rcx, qword ptr [rcx + 0x170]'),
        ('Class cache map +8', 0x10cfd49f, 'lea rcx, [r15 + 8]'),
        ('Look up runtime class weak key', 0x10cfd4a3, 'call 0xd8cbe0'),
        ('Cache hit reads entry value +8', 0x10cfd4c8, 'mov rax, qword ptr [rax + 8]'),
        ('Non-null cache hit skips initialization', 0x10cfd4cf, 'jne 0x10cfdb8e'),
        ('Cache miss calls class replication setup first', 0x10cfd4f0, 'call 0x10e04f40'),
        ('Allocate cache record size 0xd0', 0x10cfd4f5, 'mov ecx, 0xd0'),
        ('Cache owns class weak key +0x10', 0x10cfd507, 'lea rcx, [rax + 0x10]'),
        ('Manager entry value written before parent recursion', 0x10cfd5a6, 'mov qword ptr [r9 + 8], rdi'),
        ('Manager entry hash low XOR high', 0x10cfd5ce, 'xor r8d, eax'),
        ('Then recursively acquire parent cache', 0x10cfd60e, 'call 0x10cfd470'),
        ('Parent pointer cache+8', 0x10cfd613, 'mov qword ptr [r12 + 8], rax'),
        ('Inherited total from parent own count', 0x10cfd618, 'mov ecx, dword ptr [rax + 0x28]'),
        ('Inherited total includes parent own start', 0x10cfd61b, 'add ecx, dword ptr [rax]'),
        ('Own field index start cache+0', 0x10cfd61d, 'mov dword ptr [r12], ecx'),
        ('Class checksum seeded from parent', 0x10cfd624, 'mov dword ptr [r12 + 0x18], eax'),
        ('Own NetProperties count class+0x138', 0x10cfd63c, 'mov edx, dword ptr [r14 + 0x138]'),
        ('Property field checksum recursion false, seed0', 0x10cfd6cd, 'call 0x10cffc80'),
        ('Property field representation tag0', 0x10cfd6e7, 'mov byte ptr [rbp - 0x61], 0'),
        ('Cache field record32 stride', 0x10cfd722, 'shl rcx, 5'),
        ('Function name token +0x1c', 0x10cfd7d1, 'mov rax, qword ptr [rdi + 0x1c]'),
        ('Function name checksum seed0', 0x10cfd810, 'call 0xe56960'),
        ('Function flags uint32 +0xc0 enter checksum', 0x10cfd829, 'mov r8d, dword ptr [rdi + 0xc0]'),
        ('Function checksum second fold', 0x10cfd85e, 'call 0xe56960'),
        ('Function field representation tag1', 0x10cfd8ef, 'mov byte ptr [rbp - 0x39], 1'),
        ('Build descriptor-to-field lookup cache+0x30', 0x10cfd9b7, 'lea rcx, [r12 + 0x30]'),
        ('Build field-checksum lookup cache+0x80', 0x10cfd9d0, 'lea rcx, [r12 + 0x80]'),
        ('Field checksum in record+0x14', 0x10cfd9d8, 'mov r8d, dword ptr [r14 + rax + 0x14]'),
        ('Duplicate checksum check', 0x10cfd9dd, 'call 0xe48a00'),
        ('Duplicate checksum path rejoins insertion', 0x10cfda9c, 'call 0xd64a70'),
        ('Sort property list before class checksum fold', 0x10cfdb14, 'call 0x4a24a60'),
        ('Class checksum uses current cumulative seed', 0x10cfdb50, 'mov r8d, dword ptr [r12 + 0x18]'),
        ('Class checksum recursive mode true', 0x10cfdb55, 'mov r9b, 1'),
        ('Class checksum only folds collected property list', 0x10cfdb5f, 'call 0x10cffc80'),
        ('Update class checksum cache+0x18', 0x10cfdb68, 'mov dword ptr [r12 + 0x18], eax'),
        ('Setup guard UClass flags +0xd4', 0x10e04f4d, 'mov eax, dword ptr [rcx + 0xd4]'),
        ('Setup needs non-null class+0x78', 0x10e04f61, 'cmp qword ptr [rcx + 0x78], 0'),
        ('Setup recursively initializes superclass', 0x10e04fbd, 'call 0x10e04f40'),
        ('Own FProperty chain class+0x70', 0x10e050ce, 'mov rax, qword ptr [r13 + 0x70]'),
        ('Own property Net flag bit5', 0x10e05116, 'test byte ptr [rbx + 0x48], 0x20'),
        ('Owner validation uses Object class getter', 0x10e0511c, 'call 0x10ed3b90'),
        ('Owner variant is field+8', 0x10e05124, 'lea rcx, [rbx + 8]'),
        ('Require property owner is this class', 0x10e05139, 'cmp rax, r13'),
        ('FProperty Next is +0x18', 0x10e05166, 'mov rax, qword ptr [rbx + 0x18]'),
        ('Own UObject UField children class+0x58', 0x10e05187, 'mov rax, qword ptr [r13 + 0x58]'),
        ('UFunction membership getter thunk', 0x10e051ba, 'call 0x28f81b0'),
        ('UObject class pointer is +8', 0x10e051bf, 'mov rdx, qword ptr [rbx + 8]'),
        ('Function class inheritance identity +0x30', 0x10e051c3, 'lea r8, [rax + 0x30]'),
        ('Function class inheritance depth +0x38', 0x10e051c7, 'movsxd rax, dword ptr [rax + 0x38]'),
        ('UFunction Net flag bit6', 0x10e051e2, 'test byte ptr [rbx + 0xc0], 0x40'),
        ('Exclude functions with super function +0x48', 0x10e051eb, 'cmp qword ptr [rbx + 0x48], 0'),
        ('UField Next is +0x28', 0x10e0521d, 'mov rax, qword ptr [rbx + 0x28]'),
        ('Sort NetProperties before assigning RepIndex', 0x10e05261, 'call 0x4a24a60'),
        ('Read low16 of inherited/current ClassReps count', 0x10e0528f, 'movzx eax, word ptr [r13 + 0x118]'),
        ('Setup assigns RepIndex', 0x10e05297, 'mov word ptr [rcx + 0x50], ax'),
        ('Static array dimension controls ClassReps expansion', 0x10e052a8, 'cmp dword ptr [rcx + 0x3c], esi'),
        ('ClassReps count is i32 +0x118', 0x10e052b0, 'movsxd rdi, dword ptr [r13 + 0x118]'),
        ('ClassReps descriptor at record+0', 0x10e052fb, 'mov qword ptr [rdi], rcx'),
        ('ClassReps static array index at record+8', 0x10e052fe, 'mov dword ptr [rdi + 8], esi'),
        ('Sort NetFunctions after property indices assigned', 0x10e05392, 'call 0x10cf4460'),
        ('Mark setup initialized after both sorts', 0x10e05397, 'or dword ptr [r13 + 0xd4], 0x800'),
        ('Conditional post-setup delegate', 0x10e053b3, 'call 0x10e05c40'),
        ('Conditional post-setup skip class flag bit18', 0x10e05c5b, 'shr eax, 0x12'),
        ('Post-setup may create class default object', 0x10e05d39, 'call qword ptr [rax + 0x388]'),
        ('Post-setup calls default object lifetime list', 0x10e05d4e, 'call qword ptr [rax + 0x1b8]'),
        ('Signed property storage offset primary sort key', 0x4a24b84, 'mov eax, dword ptr [rsi + 0x54]'),
        ('Property sort compares primary offset', 0x4a24b87, 'cmp eax, dword ptr [rdx + 0x54]'),
        ('Property tie break uses name compare', 0x4a24beb, 'call 0x10a13230'),
        ('Function sort uses name compare', 0x10cf45f3, 'call 0x10a13230'),
        ('Checksum property GetCPPType virtual slot0x60', 0x10cffeb9, 'call qword ptr [r10 + 0x60]'),
        ('Checksum ArrayDim uint32 +0x3c', 0x10cffefb, 'mov r8d, dword ptr [rbx + 0x3c]'),
        ('Recursive array type flag bit21', 0x10cfff4e, 'shr rax, 0x15'),
        ('Recursive array inner descriptor +0x90', 0x10cfff5b, 'mov rbx, qword ptr [rbx + 0x90]'),
        ('Recursive struct type flag bit20', 0x10cfff67, 'shr rcx, 0x14'),
        ('Struct name checksum folded before fields', 0x10d0006f, 'call 0xe56960'),
        ('Nested iterator includes super and deprecated', 0x10d000c2, 'mov word ptr [rbp - 0x45], 0x101'),
        ('Nested struct excludes property flags bit31', 0x10d000d9, 'bt rax, 0x1f'),
        ('Nested struct children sorted before fold', 0x10d0013c, 'call 0x4a24a60'),
        ('Nested struct recursive checksum fold', 0x10d0017c, 'call 0x10cffc80'),
        ('RepLayout separately calls setup', 0x12db2304, 'call 0x10e04f40'),
        ('RepLayout consumes expanded ClassReps count', 0x12db2309, 'mov edx, dword ptr [r15 + 0x118]'),
        ('RepLayout handle belongs to command record+0x14', 0x12da2839, 'mov word ptr [rdi + 0x14], bp'),
        ('Byte serializer enum pointer property+0x90', 0x10e8e5fa, 'mov rcx, qword ptr [rcx + 0x90]'),
        ('Byte enum maximum helper', 0x10e8e60c, 'call 0x10e1dc70'),
        ('Byte without enum serializes8 bits', 0x10e8e651, 'mov ecx, 8'),
        ('Byte bit serializer archive slot0x68', 0x10e8e662, 'call qword ptr [rax + 0x68]'),
        ('Enum entries TArray count +0x48', 0x10e1dc76, 'movsxd rdi, dword ptr [rcx + 0x48]'),
        ('Enum entry signed value at stride16 plus8', 0x10e1dcbd, 'mov rcx, qword ptr [rdi + rax - 8]'),
    ]
    for row in checks:
        exact(*row)

    data = []

    def datum(label, address, expected):
        raw = image.read(address, len(expected))
        if raw != expected:
            raise ValueError('Immutable data witness changed: '+label)
        section = next((r,s,o) for r,s,o in image.sections if r <= address < address+len(raw) <= r+s)
        data.append(dict(label=label, rva=hex(address), bytes=len(raw),
            file_offset=hex(section[2]+address-section[0]), bytes_hex=raw.hex(), sha256=sha(raw),
            source='exact updated PE; old data table is unavailable'))

    datum('ASCII compare map lowercases A-Z only', 0x1aae6f90,
          bytes(c+32 if 65 <= c <= 90 else c for c in range(128)))
    datum('SIMD lowercase starting character', 0x1aad7bf0, struct.pack('<4I', *([65]*4)))
    datum('SIMD lowercase unsigned range size', 0x1aad7be0, struct.pack('<4I', *([26]*4)))
    datum('SIMD lowercase mask seed', 0x14ec2540, struct.pack('<4I', *([1]*4)))
    datum('ArrayDim and UFunction flags unsigned decimal format', 0x15026b74, '%u\0'.encode('utf-16-le'))
    datum('Empty FString fallback', 0x14ec36a8, b'\0\0')
    datum('Null property name fallback', 0x14ec37c8, 'None\0'.encode('utf-16-le'))
    datum('Owner getter literal Object', 0x1ab6ff4a, 'Object\0'.encode('utf-16-le'))
    datum('Function getter literal Function', 0x1ab39ab2, 'Function\0'.encode('utf-16-le'))
    datum('Getter package /Script/CoreUObject', 0x15a84fb8, '/Script/CoreUObject\0'.encode('utf-16-le'))
    datum('TArray accessor import', 0x1d59de88, struct.pack('<Q', image.image_base+0xd968f0))
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = value >> 1 ^ (0xedb88320 if value & 1 else 0)
        table.append(value)
    datum('CRC table equals reflected polynomial0xedb88320', 0x1d599a70, struct.pack('<256I', *table))
    thunk_instructions = []
    for observation, rva, target in ((old, 0x28f84f0, 0x10cff710), (new, 0x28f81b0, 0x10cff0b0)):
        decoded = disasm(observation, rva, 5)
        if len(decoded) != 1 or decoded[0].mnemonic != 'jmp' or decoded[0].operands[0].imm != target:
            raise ValueError('Function class getter tail thunk changed')
        if observation.read(rva+5, 11) != b'\xcc'*11:
            raise ValueError('Function class getter tail thunk boundary changed')
        thunk_instructions.append(instruction_row(decoded[0]))
    name_gap, extra_fragments = unqualified_name_wrapper(old, new, image)
    inventory = unwind_inventory(image, functions, extra_fragments)
    capture_path = 'work/native-client-tests/1792800038357938800/updated-class-metadata.json'
    capture = json.loads((ROOT/capture_path).read_bytes())
    classes = capture['selected_classes']
    properties = [p for c in classes for p in c['own_properties']]
    if len(classes) != 44 or len(properties) != 1705 or any(p['rep_index'] != 0 for p in properties):
        raise ValueError('Expected current bounded property snapshot changed')

    setup_order = [
        dict(step=1, action='Return if UClass+d4 bit11 is set; also return if UClass+78 is null.',
             witnesses=['0x10e04f4d', '0x10e04f61']),
        dict(step=2, action='Clear own NetFunctions+120 and NetProperties+130; recurse into SuperStruct+48.',
             witnesses=['0x10e04f90', '0x10e04fa1', '0x10e04fbd']),
        dict(step=3, action='Inherit parent ClassReps+110 (stride16), and auxiliary array+100 (stride16). Root clears ClassReps.',
             witnesses=['0x10e04fc2', '0x10e05021', '0x10e050c6'],
             auxiliary_array_semantic_name_qualified=False),
        dict(step=4, action='Walk own FProperty chain+70 with excludeSuper/includeDeprecated/noInterfaces. Require FFieldClass bit15, flags+48 bit5, Object owner variant, owner exactly this class. Append NetProperties.',
             witnesses=['0x10e050ce', '0x10e050e5', '0x10e05101', '0x10e05116', '0x10e05124', '0x10e05139', '0x10e05162']),
        dict(step=5, action='Walk own UObject Children+58 with same iterator flags; require Function class, FUNC_Net bit6, no SuperFunction+48. Append NetFunctions.',
             witnesses=['0x10e05187', '0x10e051ba', '0x10e051e2', '0x10e051eb', '0x10e05219']),
        dict(step=6, action='Sort own NetProperties by signed offset+54 then case-insensitive ASCII name. For each property write RepIndex=low16(ClassReps count); append ArrayDim stride16 {property, static_array_index} records.',
             witnesses=['0x10e05261', '0x10e0528f', '0x10e05297', '0x10e052a8', '0x10e052fb', '0x10e052fe']),
        dict(step=7, action='Shrink arrays, sort NetFunctions by case-insensitive ASCII name, set class bit0x800.',
             witnesses=['0x10e05335', '0x10e05392', '0x10e05397']),
        dict(step=8, action='If current global1e340a04 nonzero call conditional post-setup validation. It may create CDO (class vslot388) and calls CDO vslot1b8 to collect lifetime entries. Virtual callback bodies/current global value are not qualified.',
             witnesses=['0x10e053a2', '0x10e053b3', '0x10e05d39', '0x10e05d4e']),
    ]
    cache_order = [
        dict(step=1, action='Construct class weak key from object index+24 and native registry serial delegate. Lookup manager+8 weak-key map (hash low XOR high, equality qualified). Non-null value returns immediately without setup or checksum revalidation.',
             witnesses=['0x1099248e', '0x1099249a', '0x10cfd4a3', '0x10cfd4cf']),
        dict(step=2, action='On miss, call descriptor setup; allocate0xd0 cache, construct weak key+10 and empty field/maps, then publish manager entry before parent recursion.',
             witnesses=['0x10cfd4f0', '0x10cfd4f5', '0x10cfd507', '0x10cfd5a6']),
        dict(step=3, action='Reset parent/start/checksum; recursively acquire superclass cache; parent+8 points to it, own_start=parent.own_start+parent.own_count, checksum=parent checksum.',
             witnesses=['0x10cfd5f4', '0x10cfd60e', '0x10cfd613', '0x10cfd61b', '0x10cfd624']),
        dict(step=4, action='Append one stride32 cache field per NetProperty in setup-sorted order. Property tag0, index=own_start+own_count, field checksum=property_checksum(seed0, recurse=false), reserved/incompatible byte0. Does not read or copy FProperty.RepIndex.',
             witnesses=['0x10cfd6cd', '0x10cfd6d2', '0x10cfd6e7', '0x10cfd6eb', '0x10cfd6f1', '0x10cfd722']),
        dict(step=5, action='Append one stride32 field per sorted NetFunction. Function tag1; index increments same cache field sequence. Checksum folds lowercased name then flags+c0 formatted %u; invalid Function-class cast yields checksum0.',
             witnesses=['0x10cfd7a6', '0x10cfd810', '0x10cfd829', '0x10cfd85e', '0x10cfd8d8', '0x10cfd8ef']),
        dict(step=6, action='Finalize/shrink fields. Build descriptor-to-field map+30 and checksum-to-field map+80. Duplicate checksum causes optional log, then insertion continues; not an identity/compatibility rejection.',
             witnesses=['0x10cfd966', '0x10cfd9b7', '0x10cfd9dd', '0x10cfda65', '0x10cfda9c', '0x10cfdae0']),
        dict(step=7, action='Sort property-only temporary list using same comparator, fold recursive property checksums with inherited class seed into cache+18, then return. Function checksums are separate field entries and not part of this aggregate class checksum loop.',
             witnesses=['0x10cfdb14', '0x10cfdb50', '0x10cfdb55', '0x10cfdb5f', '0x10cfdb68', '0x10cfdb83']),
    ]
    # Every semantic address must be an instruction boundary in a full compared body.
    for step in setup_order+cache_order:
        for address in step['witnesses']:
            if int(address, 16) not in rows:
                raise ValueError('Semantic step witness is not an instruction boundary: '+address)

    return dict(kind='updated_replication_cache_initialization_offline_qualification',
        client_sha256=PINS['new'][2], process_access=False, native_called=False,
        native_emulated=False, client_launched=False, production_sources_changed=False,
        protocol_acceptance=False, source_inputs=inputs,
        immutable_new_pe=dict(path=str(CLIENT), sha256=PINS['new'][2],
            bytes=CLIENT.stat().st_size, exception_table_sha256=sha(image.exc_data)),
        functions=functions, exact_instruction_witnesses=witnesses,
        function_class_getter_thunk=dict(bytes=5, complete_direct_tail_jump=True,
            boundary='Single jump followed by11 int3 bytes; target whole getter qualified separately.',
            old_and_new_instructions=thunk_instructions),
        immutable_data_witnesses=data, unwind_inventory=inventory,
        setup_initialization_order=setup_order, class_net_cache_initialization_order=cache_order,
        index_domains=dict(
            property_rep_index='u16 property+50: inherited ClassReps record count before this property; static ArrayDim expands records; native writes low16, no overflow guard proved here.',
            class_net_cache_index='u32 field record+10: inherited cache total + one per property or function; ArrayDim does not expand this cache vector.',
            rep_layout_handle='u16 RepLayout command record+14 generated separately by recursive/leaf command builder; ClassReps index and ClassNetCache index cannot be substituted.'),
        checksum_rules=dict(
            property_field='CRC of ASCII-lowercased FName::ToString property name (None for null), then ASCII-lowercased GetCPPType virtual slot60 string, then ArrayDim formatted unsigned decimal %u; seed0, recurse=false.',
            function_field='CRC of ASCII-lowercased Function FName::ToString, then full u32 FunctionFlags+c0 formatted %u; seed0.',
            aggregate_class='Seed parent aggregate checksum or0, fold recursive property checksums in sorted own property order; excludes function field checksums.',
            recursive_array='FFieldClass flags+10 bit21 follows inner property+90 and repeats base checksum fold with current seed.',
            recursive_struct='FFieldClass flags+10 bit20 folds lowercased UScriptStruct name+1c, enumerates property fields+70 including super/deprecated, excluding flags+48 bit31, sorts then recursively folds.',
            crc='Reflected CRC32 polynomial0xedb88320; complement seed, process each nonzero UTF16 code unit as four bytes low8/high8/0/0, complement result. Terminator excluded.',
            ascii_lower='A-Z become a-z in scalar and SIMD paths; other UTF16 words retained. This is not Unicode case folding.',
            ordering='Signed OffsetInternal+54 ascending, tie by UTF16 lexicographic name comparison with ASCII-only lowercase table when both differing code units<128. Non-ASCII compares raw words. Function comparator uses name alone.',
            closure_status='Native main bodies, sorting/CRC/lowercase helpers and updated immutable tables qualified. Complete checksum output equivalence is NOT qualified: current FName wrapper tables and dynamic GetCPPType outputs/vtable bindings remain missing.'),
        deterministic_reuse_requirements=[
            'For current native-cache reuse: same current process/driver/cache manager; decoded class object identity, object index+24 and current registry serial; allocated/live weak-key map entry with exact weak-key equality and non-null cache pointer.',
            'Capture current cache weak key+10, parent+8, own_start+0, own_count+28, checksum+18, fields+20 (stride32), descriptor-map+30 and checksum-map+80, including sparse occupancy/hash/next-index evidence. Revalidate class identities and parent chain in a bounded consistent snapshot.',
            'Map field records to current property/function descriptors and names, not old pointer values. CRC equality alone cannot prove identity; duplicate-checksum path logs then continues.',
            'Require completed/stable cache observation: insertion occurs before parent recursion and population, so non-null cache pointer alone can expose an in-progress build to a racing reader.',
            'A native cache hit does not re-check class flags, RepIndex, class checksum, or metadata mutations. Historical cache records/weak serials from another process/build do not prove a current hit or compatible schema.',
        ],
        independent_reconstruction_requirements=[
            'Capture current complete superclass chain, class identity/path, flags+d4 (bit11 setup state), class+78 guard, original own field chains+70/+58 and their ordering, property/function ownership and type-test identities/flags.',
            'For properties: actual FName token and qualified exact display string, descriptor type/FFieldClass flags, Net/deprecated/skip flags used by each iterator, ArrayDim, signed OffsetInternal, Object owner variant, existing RepIndex and current ClassReps/NetProperties arrays for verification.',
            'For functions: current Function class membership, FName/display string, full uint32 FunctionFlags+c0, SuperFunction+48; sorted NetFunctions array and parent functions. The own-property snapshot has no UFunctions.',
            'For checksums: actual current GetCPPType slot60 target/output for every property; exact FName::ToString numeric suffix/name formatting; recursive array Inner+90, struct+90/name/field chain/super chain and all nested type/skip flags. Qualify callees before independent emulation.',
            'Preserve original chain order or prove comparator keys unique. These native sorts are not certified stable; equal offset and case-insensitive name keys need original input order and the exact algorithm to prove resulting order.',
            'To reproduce RepLayout handles or lifetime conditions, additionally capture current layout/parent/command arrays, CDO class/instance and lifetime-property callback output/flags/conditions, dynamic type-specific serializers and native build context. Those inputs exceed ClassNetCache/RepIndex construction.',
            'This research does not emulate setup/cache/checksum or invoke virtual methods. Reconstruction remains blocked on missing current metadata and unqualified dynamic dependencies, not on the unchanged storage offsets alone.',
        ],
        fresh_snapshot=dict(path=capture_path, sha256=INPUT_PINS[capture_path], classes=len(classes),
            own_properties=len(properties), all_rep_index_zero=True, snapshot_atomic=False,
            proves_setup_or_cache_initialized=False,
            interpretation='RepIndex0 is valid for the first inherited-expanded slot. All zero is insufficient to infer setup state because class flags/guard/ClassReps/cache entries were not captured. It cannot certify old handle reuse.'),
        additional_full_qualifications={name:{k:v for k,v in by_name[name].items()
            if k not in ('decoded_new_instructions', 'references')} for name in ('weapon_hide', 'byte_net_serializer', 'enum_max_value')},
        byte_serializer_limits=[
            'Whole function and enum max helper match outside qualified references. Enum pointer property+90 null selects8bits; non-null enumerates UEnum entries+40/count+48 stride16 signed64 values+8 and computes width using low32 max and BSR sequence.',
            'Current property vtable+90 binding, enum pointer and enum values were not observed. This does not certify WeaponSlot is2bits or any particular updated property serializer binding.',
            'Weapon hide body is fully compared; its external direct/virtual callee bodies and current object field values are not certified by this optional qualification.',
        ], unqualified_dependency=name_gap,
        limits=[
            'Old immutable data tables are unavailable; updated table values are validated against explicit data rules rather than claiming old/new table byte equality.',
            'Caller instruction equality permits only direct control-flow/RIP references to relocate. Structure offsets and non-address constants are never masked in qualified comparisons.',
            'Static whole-function equality is not native protocol acceptance, a current metadata observation, a proof of runtime callback identity, or permission to transplant old handles.',
            'No existing helper, reader, gate or runtime dependency was edited.',
        ], source_observations=[old.source_evidence(), new.source_evidence()],
        research_script=dict(path='work/research_updated_cache_initialization.py',
            sha256=sha((ROOT/'work/research_updated_cache_initialization.py').read_bytes())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualify', action='store_true', required=True)
    args = parser.parse_args()
    result = qualify()
    output = ROOT/'work/research_updated_cache_initialization_79fb7b10.json'
    raw = (json.dumps(result, indent=2)+'\n').encode('utf-8')
    output.write_bytes(raw)
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), sha256=sha(raw),
        functions=len(result['functions']), witnesses=len(result['exact_instruction_witnesses']),
        native_called=False, native_emulated=False, independent_reconstruction_qualified=False)))


if __name__ == '__main__':
    main()
