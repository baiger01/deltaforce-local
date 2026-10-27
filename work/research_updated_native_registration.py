"""Bounded extraction of current UECodeGen registrations; no engine execution.

The current constructor's switch and recursive parameter consumption determine
the declaration tree. Pointer-array entries are not aliased to UObject fields.
"""
import argparse
import json
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from research_updated_metadata_roots import ROOT, NewImage, ForensicObservation, disasm, instruction_row, sha

CLIENT_SHA = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
CLASS_CTOR, FUNCTION_CTOR, STRUCT_CTOR, ENUM_CTOR = 0x10ea53d0, 0x10ea5cd0, 0x10ea61c0, 0x10ea59b0
PROPERTY_CTOR = 0x10ea3190
REGISTRATIONS = (
    ('BaseGameState', 0x3e9aa0), ('GPGameState', 0x418e10),
    ('DFMGameState', 0x7a9020), ('DFMPlayerController', 0x7b2200),
    ('DFMPlayerState', 0x7b40b0), ('GameState_PVPVE', 0x7d0500),
    ('GameState_SOL', 0xacf6c0), ('SOLPlayerState', 0xae35c0), ('GameState', 0xcf4d00))


def text(read, rva, *, wide=False):
    if type(rva) is not int or rva < 0:
        raise ValueError('Nonnegative immutable string RVA required')
    data, width = bytearray(), 2 if wide else 1
    for index in range(512):
        item = read(rva+index*width, width)
        if item == bytes(width):
            return bytes(data).decode('utf-16le' if wide else 'ascii')
        data.extend(item)
    raise ValueError('Bounded registration string terminator absent')


def derive_bool_storage(instructions, owner_size):
    if type(owner_size) is not int or not 1 <= owner_size <= 1048576:
        raise ValueError('Bounded Boolean owner size required')
    if len(instructions) != 2 or instructions[-1].mnemonic != 'ret':
        raise ValueError('Only one explicit Boolean write followed by return is qualified')
    write = instructions[0]
    if (write.mnemonic not in ('or', 'mov') or len(write.operands) != 2 or
            write.operands[0].type != X86_OP_MEM or write.operands[1].type != X86_OP_IMM):
        raise ValueError('Boolean setter is not an immutable immediate write')
    target, value = write.operands
    if (write.reg_name(target.mem.base) != 'rcx' or target.mem.index or
            target.size not in (1, 2, 4, 8) or target.mem.disp < 0 or
            target.mem.disp+target.size > owner_size):
        raise ValueError('Boolean setter write escapes its zeroed owner buffer')
    raw = (value.imm & ((1 << (target.size*8))-1)).to_bytes(target.size, 'little')
    nonzero = [(index, byte) for index, byte in enumerate(raw) if byte]
    if len(nonzero) != 1:
        raise ValueError('Boolean setter must produce exactly one nonzero byte')
    index, mask = nonzero[0]
    if mask & (mask-1):
        raise ValueError('Boolean setter must set exactly one bit')
    return dict(storage_offset=target.mem.disp+index, byte_mask=mask)


def literal_bool(instructions):
    if len(instructions) != 2 or instructions[-1].mnemonic != 'ret':
        raise ValueError('Boolean trait needs a complete constant leaf')
    first = instructions[0]
    if first.mnemonic == 'mov' and first.op_str in ('al, 0', 'al, 1'):
        return bool(first.operands[1].imm)
    if first.mnemonic == 'xor' and first.op_str in ('al, al', 'eax, eax'):
        return False
    raise ValueError('Boolean trait return is not an explicit constant')


def decode_property_tree(read, pointer_array_rva, count, grammar, *, image_base):
    if type(count) is not int or not 0 <= count <= 2048:
        raise ValueError('Bounded property-parameter count required')
    pointers = list(struct.unpack('<'+'Q'*count, read(pointer_array_rva, count*8))) if count else []
    if len(set(pointers)) != count or any(p < image_base for p in pointers):
        raise ValueError('Distinct immutable parameter record identities required')
    at, nodes = 0, 0

    def consume(depth):
        nonlocal at, nodes
        if at >= count or depth > 32 or nodes >= 2048:
            raise ValueError('Truncated or excessive nested property parameters')
        ordinal, rva = at, pointers[at]-image_base
        at += 1; nodes += 1
        raw = read(rva, 40)
        name, notify, flags, gen, object_flags, dimension, offset = struct.unpack('<3Q4i', raw)
        tag = gen&0x3f
        case = grammar.get(tag)
        if (case is None or case.get('qualified') is False or
                not 0 <= case['nested_count'] <= 2 or not 40 <= case['record_bytes'] <= 128):
            raise ValueError('Property parameter kind lacks complete current factory grammar: tag='+str(tag)+' record='+hex(rva))
        if not 1 <= dimension <= 4096 or offset < 0:
            raise ValueError('Unbounded native declaration dimensions/offset')
        whole = read(rva, case['record_bytes'])
        name = text(read, name-image_base)
        if not name or len(name) > 511:
            raise ValueError('Exact native property name required')
        callback_rows = []
        for slot in case['callback_offsets']:
            pointer, = struct.unpack_from('<Q', whole, slot)
            callback_rows.append(dict(parameter_offset=hex(slot), function_rva=hex(pointer-image_base) if pointer else None))
        row = dict(name=name, kind=case['kind'], parameter_record_rva=hex(rva), parameter_ordinal=ordinal,
            parameter_record_bytes=len(whole), parameter_sha256=sha(whole),
            property_flags64_before_factory=hex(flags), net_flag=bool(flags&0x20),
            generation_flags=hex(gen), object_flags=hex(object_flags), array_dim=dimension,
            constructor_offset_argument=offset, runtime_offset_observed=False,
            rep_notify_name=text(read, notify-image_base) if notify else None,
            callbacks=callback_rows, children=[])
        if 'field_class_name' in case:
            row['field_class_name'] = case['field_class_name']
        if case['kind'] == 'FBoolProperty':
            row['bool_field_size_argument'] = row.pop('constructor_offset_argument')
            row['bool_owner_size_argument'], = struct.unpack_from('<Q', whole, 40)
        for _ in range(case['nested_count']):
            row['children'].append(consume(depth+1))
        return row

    outer = []
    while at < count:
        outer.append(consume(0))
    if len({r['name'] for r in outer}) != len(outer):
        raise ValueError('Duplicate top-level native property name')
    # FProperty construction prepends each outer property to UStruct.ChildProperties.
    return dict(fields=list(reversed(outer)), construction_order=outer,
        top_level_count=len(outer), parameter_record_count=count,
        own_net_property_count=sum(r['net_flag'] for r in outer),
        runtime_metadata_observed=False, numeric_wire_handles_recovered=False)


class Archive:
    def __init__(self):
        self.image, self.code = NewImage(), ForensicObservation('new')
        self.base = self.image.image_base
        self.functions, self.data, self.case_grammar, self.factories = {}, {}, None, {}

    def read(self, rva, size):
        if not 0 <= size <= 65536:
            raise ValueError('Bounded immutable registration read required')
        if size == 0:
            return b''
        raw = self.image.read(rva, size)
        self.data[rva, size] = dict(rva=hex(rva), bytes=size, sha256=sha(raw))
        return raw

    def instructions(self, rva):
        if rva in self.functions:
            return self.functions[rva][0]
        if len(self.functions) >= 2048:
            raise ValueError('Native registration function budget exceeded')
        ranges = self.image.fragments(rva)
        if not ranges:
            raw = self.code.read(rva, 128)
            if raw[0] == 0xe9 and raw[5:16] == b'\xcc'*11:
                ins = list(disasm(self.code, rva, 5))
                extent, terminal = 5, 'padded_direct_tail_thunk'
            else:
                ins = []
                for item in disasm(self.code, rva, 128):
                    if item.mnemonic not in ('mov','movabs','lea','xor','or','and','ret','jmp'):
                        raise ValueError('Unqualified function without unwind data: '+hex(rva))
                    ins.append(item)
                    if item.mnemonic in ('ret','jmp'):
                        if item.mnemonic == 'jmp' and item.operands[0].type != X86_OP_IMM:
                            raise ValueError('Unqualified indirect leaf tail: '+hex(rva))
                        break
                if not ins or ins[-1].mnemonic not in ('ret','jmp'):
                    raise ValueError('Unterminated straight-line leaf')
                extent = ins[-1].address+ins[-1].size-rva
                if raw[extent:extent+1] != b'\xcc':
                    raise ValueError('Straight-line leaf does not end at explicit padding')
                terminal = 'padded_straight_line_leaf'
            self.functions[rva] = (ins, dict(entry_rva=hex(rva), bytes=extent, sha256=sha(raw[:extent]),
                complete_leaf=terminal, instructions=[instruction_row(i) for i in ins]))
            return ins
        if sum(b-a for a,b,_ in ranges) > 16384:
            raise ValueError('Native function exceeds complete-body local bound')
        all_ins, fragments, tables = [], [], []
        for first, end, unwind in ranges:
            raw = self.code.read(first, end-first)
            code_end = min(end, 0x10ea5340) if rva == PROPERTY_CTOR else end
            ins = list(disasm(self.code, first, max(0, code_end-first))) if first < code_end else []
            if sum(i.size for i in ins) != max(0, code_end-first):
                raise ValueError('Complete native instruction decode required: '+hex(first))
            if code_end < end:
                if code_end != 0x10ea5340 or end != 0x10ea53d0:
                    raise ValueError('Unknown embedded factory data extent')
                tables.append(dict(rva=hex(code_end), bytes=end-code_end,
                    sha256=sha(self.code.read(code_end, end-code_end)), interpretation='36 RVA32 switch entries'))
            all_ins.extend(ins)
            fragments.append(dict(first_rva=hex(first), end_rva=hex(end), unwind_rva=hex(unwind),
                bytes=len(raw), sha256=sha(raw), instructions=[instruction_row(i) for i in ins]))
        if not all_ins or all_ins[-1].mnemonic not in ('ret', 'jmp', 'nop'):
            raise ValueError('Native function boundary lacks a qualified terminal instruction: '+hex(rva))
        report = dict(entry_rva=hex(rva), complete_unwind_coverage=True,
            fragments=fragments, embedded_data=tables, function_called=False)
        self.functions[rva] = (all_ins, report)
        return all_ins

    @staticmethod
    def rip(ins):
        hits = [ins.address+ins.size+o.mem.disp for o in ins.operands if o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP]
        if len(hits) != 1:
            raise ValueError('One exact RIP-relative registration source required')
        return hits[0]

    def factory(self, rva):
        if rva in self.factories:
            return self.factories[rva]
        ins = self.instructions(rva)
        if len(ins) == 1 and ins[0].mnemonic == 'jmp':
            target = ins[0].operands[0].imm
            return dict(kind='native_class_getter_thunk', getter_rva=hex(target), factory_rva=hex(rva))
        if len(ins) != 10 or ins[0].mnemonic != 'sub' or ins[-1].mnemonic != 'ret':
            raise ValueError('Only the complete observed lazy registration-factory shape is accepted: '+hex(rva))
        # Native factories all have one guarded immutable Params address and one
        # constructor call; all three cache-cell references must be identical.
        calls = [i for i in ins if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM]
        params = [i for i in ins if i.mnemonic == 'lea' and i.op_str.startswith('rdx,')]
        cells = [self.rip(i) for i in ins if i.mnemonic == 'mov' and i.op_str.startswith('rax, qword ptr [rip')]
        cells += [self.rip(i) for i in ins if i.mnemonic == 'lea' and i.op_str.startswith('rcx,')]
        if len(calls) != 1 or len(params) != 1 or len(cells) != 3 or len(set(cells)) != 1:
            raise ValueError('Factory guarded cache/parameter binding differs')
        constructor = calls[0].operands[0].imm
        kind = {CLASS_CTOR:'class', FUNCTION_CTOR:'function', STRUCT_CTOR:'struct', ENUM_CTOR:'enum', 0x10ea6090:'package'}.get(constructor)
        if kind is None:
            raise ValueError('Unqualified native registration constructor: '+hex(constructor))
        self.instructions(constructor)
        row = dict(kind=kind, factory_rva=hex(rva), parameter_rva=hex(self.rip(params[0])),
            constructor_rva=hex(constructor), runtime_singleton_pointer_observed=False)
        self.factories[rva] = row
        return row

    def property_grammar(self):
        if self.case_grammar is not None:
            return self.case_grammar
        ins = self.instructions(PROPERTY_CTOR)
        for helper in (0x10e3ded0, 0x10e09110, 0x10e09140):
            self.instructions(helper)
        field_class_ctor = {i.address:i for i in self.instructions(0x10e09140)}
        if field_class_ctor[0x10e0915d].op_str != 'rdx, 2':
            raise ValueError('Current FieldClass constructor no longer strips the C++ prefix')
        by_address = {i.address:i for i in ins}
        if (by_address[0x10ea3208].op_str != 'eax, dword ptr [r13 + 0x18]' or
                by_address[0x10ea320c].op_str != 'eax, 0x3f' or
                by_address[0x10ea5314].op_str != '0x10ea3190'):
            raise ValueError('Current property switch/recursive consumption changed')
        table = list(struct.unpack('<36I', self.code.read(0x10ea5340, 144)))
        if table[0] != 0x10ea514f or table[34] != table[0]:
            raise ValueError('Current switch default target changed')
        starts = sorted(set(table))
        cases = {}
        for at in starts:
            pending, visited, reachable, child_counts = [(at,None)], set(), {}, set()
            while pending:
                address, edi = pending.pop()
                if (address,edi) in visited:
                    continue
                visited.add((address,edi))
                if len(visited) > 4096:
                    raise ValueError('Factory case control-flow budget exceeded')
                if address in (0x10ea5255,0x10ea5259):
                    count = 0 if address == 0x10ea5255 else edi
                    if count not in (0,1,2):
                        raise ValueError('Unqualified recursive child-count state: '+hex(at))
                    child_counts.add(count)
                    continue
                item = by_address.get(address)
                if item is None:
                    raise ValueError('Factory case escaped complete qualified body')
                reachable[address] = item
                if item.mnemonic == 'mov' and item.op_str.startswith('edi, ') and item.operands[1].type == X86_OP_IMM:
                    edi = item.operands[1].imm
                if item.mnemonic.startswith('j'):
                    if item.operands[0].type != X86_OP_IMM:
                        raise ValueError('Unexpected nested indirect factory dispatch')
                    pending.append((item.operands[0].imm,edi))
                    if item.mnemonic != 'jmp':
                        pending.append((item.address+item.size,edi))
                elif item.mnemonic == 'ret':
                    raise ValueError('Factory branch returns before common parameter consumption')
                else:
                    pending.append((item.address+item.size,edi))
            block = [reachable[x] for x in sorted(reachable)]
            entry_block = [i for i in block if at <= i.address < at+128]
            direct = [i.operands[0].imm for i in entry_block if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM]
            if not direct:
                raise ValueError('Property constructor branch has no qualified allocation')
            binding = [i for i in block if i.address >= at]
            base_calls = [j for j,i in enumerate(binding) if i.mnemonic == 'call' and i.op_str == '0x10e09110']
            if not base_calls:
                binding = self.instructions(direct[0])
                base_calls = [j for j,i in enumerate(binding) if i.mnemonic == 'call' and i.op_str == '0x10e09110']
            if len(base_calls) != 1:
                raise ValueError('Exact FField base construction binding absent: '+hex(at))
            if any(i.mnemonic == 'call' and i.op_str == '0x10e09140' for i in binding):
                getter, gi = direct[0], binding
            else:
                preceding_calls = [i for i in binding[:base_calls[0]]
                    if i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM]
                if not preceding_calls:
                    raise ValueError('FieldClass source before FField constructor absent')
                getter = preceding_calls[-1].operands[0].imm
                gi = self.instructions(getter)
            constructor_calls = [j for j,i in enumerate(gi) if i.mnemonic == 'call' and i.op_str == '0x10e09140']
            if len(constructor_calls) != 1:
                cases[at] = dict(qualified=False, case_rva=hex(at),
                    reason='Specialized constructor has no direct named FieldClass construction in the accepted grammar',
                    unresolved_constructor_rva=hex(direct[-1]))
                continue
            choices = [i for i in gi[:constructor_calls[0]] if i.mnemonic == 'lea' and i.op_str.startswith('rdx, [rip')]
            if not choices:
                raise ValueError('Named current FieldClass argument absent')
            kind = text(self.read, self.rip(choices[-1]), wide=True)
            if not kind.startswith('F') or not kind.endswith('Property'):
                raise ValueError('FieldClass literal is not a property family')
            if len(child_counts) != 1:
                raise ValueError('Factory case has ambiguous recursive consumption: '+hex(at))
            nested = next(iter(child_counts))
            reads, callbacks = [], []
            for j,i in enumerate(block):
                for op in i.operands:
                    if op.type == X86_OP_MEM and i.reg_name(op.mem.base) == 'r13' and op.mem.disp >= 0:
                        reads.append((op.mem.disp, op.size))
                if (i.mnemonic == 'mov' and i.op_str.startswith('rax, qword ptr [r13 +') and
                        any(n.mnemonic == 'call' and n.op_str == 'rax' for n in block[j+1:j+6])):
                    callbacks.append(i.operands[1].mem.disp)
            if kind == 'FBoolProperty':
                if (by_address[0x10ea3b4a].op_str != 'rsi, qword ptr [r13 + 0x30]' or
                        by_address[0x10ea3b59].op_str != 'rdi, qword ptr [r13 + 0x28]' or
                        by_address[0x10ea3b82].op_str != 'rsi'):
                    raise ValueError('Current Boolean setter/zero-buffer arguments changed')
                self.instructions(0x10e70240)
                callbacks.append(48)
            size = max([40]+[offset+width for offset,width in reads])
            cases[at] = dict(qualified=True, kind=kind, field_class_name=kind[1:],
                case_rva=hex(at), field_class_binding_rva=hex(getter),
                record_bytes=size, native_read_fields=[dict(offset=o,bytes=w) for o,w in sorted(set(reads))],
                nested_count=nested, callback_offsets=sorted(set(callbacks)))
        self.case_grammar = {tag:cases[target] for tag,target in enumerate(table)}
        return self.case_grammar

    def tree(self, pointer, count):
        if count and pointer < self.base:
            raise ValueError('Native property pointer array absent')
        result = decode_property_tree(self.read, pointer-self.base if pointer else 0, count,
            self.property_grammar(), image_base=self.base)
        def augment(row):
            if row['kind'] == 'FBoolProperty':
                setters = [c for c in row['callbacks'] if c['parameter_offset'] == '0x30']
                if len(setters) != 1:
                    raise ValueError('Current Boolean SetBit slot is ambiguous')
                if setters[0]['function_rva'] is None:
                    row['source_derived_bool_storage'] = dict(setter_called=False,
                        null_setter_branch=True, initial_offset_argument=0, initial_mask_argument=0,
                        final_linked_storage_recovered=False)
                else:
                    storage = derive_bool_storage(self.instructions(int(setters[0]['function_rva'],16)),
                        row['bool_owner_size_argument'])
                    row['source_derived_bool_storage'] = dict(**storage, setter_called=False,
                        native_bool=bool(int(row['generation_flags'],16)&0x40))
            for child in row['children']:
                augment(child)
        for field in result['fields']:
            augment(field)
        return result

    def registered_class(self, expected, rva):
        ins = self.instructions(rva)
        if len(ins) != 12 or ins[-3].op_str != '0x10ec0a90':
            raise ValueError('Complete class registration initializer shape changed')
        args = {i.reg_name(i.operands[0].reg):self.rip(i) for i in ins
            if i.mnemonic == 'lea' and i.operands[0].type == X86_OP_REG}
        if text(self.read, args['r8'], wide=True) != 'A'+expected:
            raise ValueError('Named native class registration identity mismatch')
        package = text(self.read, args['r9'], wide=True)
        factory = self.factory(args['rcx'])
        if factory['kind'] != 'class':
            raise ValueError('Named registration does not bind a class factory')
        row = self.class_record(factory)
        if (row['name'] != expected or row['package'] != package or
                row['native_no_register_getter_rva'] != hex(args['rdx'])):
            raise ValueError('Named compiled initializer and native class getter disagree')
        row['registration_initializer_rva'] = hex(rva)
        return row

    def class_identity(self, no_register):
        at, followed = no_register, []
        for _ in range(8):
            ins = self.instructions(at)
            if len(ins) != 1 or ins[0].mnemonic != 'jmp':
                break
            followed.append(at)
            at = ins[0].operands[0].imm
        else:
            raise ValueError('Class getter tail chain exceeds local bound')
        calls = [j for j,i in enumerate(ins) if i.mnemonic == 'call' and i.op_str == '0x10cff980']
        if len(calls) != 1:
            raise ValueError('Native class getter lacks a unique named GetPrivateStaticClassBody: '+hex(at))
        self.instructions(0x10cff980)
        before = ins[:calls[0]]
        names = [i for i in before if i.mnemonic == 'lea' and i.op_str.startswith('rdx, [rip')]
        packages = [i for i in before if i.mnemonic == 'lea' and i.op_str.startswith('rcx, [rip')]
        if not names or not packages:
            raise ValueError('Native class getter string arguments absent')
        name, package_name = text(self.read,self.rip(names[-1]),wide=True), text(self.read,self.rip(packages[-1]),wide=True)
        if not package_name.startswith('/Script/') or not name or '.' in name or '/' in name:
            raise ValueError('Native class identity is not a script-package class')
        return dict(name=name,package=package_name, private_class_getter_rva=hex(at),
            no_register_tail_chain=[hex(r) for r in followed])

    def class_record(self, factory, *, include_functions=True):
        if factory['kind'] != 'class':
            raise ValueError('Current class factory required')
        params = int(factory['parameter_rva'],16)
        raw = self.read(params,88)
        no_register, config, cpp_info, dependencies, functions, properties, interfaces = struct.unpack_from('<7Q',raw)
        nd,nf,np,ni,flags,cast = struct.unpack_from('<6I',raw,56)
        if not 0 <= nd <= 8 or not 0 <= nf <= 512 or not 0 <= ni <= 128:
            raise ValueError('Class parameters disagree with named registration/bounds')
        identity = self.class_identity(no_register-self.base)
        fields = self.tree(properties,np)
        function_rows = []
        for i in range(nf):
            target, name = struct.unpack('<QQ',self.read(functions-self.base+i*16,16))
            fn = self.function(target-self.base) if include_functions else dict(name=text(self.read,name-self.base), factory_rva=hex(target-self.base))
            if fn['name'] != text(self.read,name-self.base):
                raise ValueError('Function link-table name differs from its Params identity')
            function_rows.append(fn)
        interface_rows = []
        for i in range(ni):
            getter,adjustment,script = struct.unpack('<QiB',self.read(interfaces-self.base+i*16,13))
            if script not in (0,1):
                raise ValueError('Invalid native implemented-interface script flag')
            self.instructions(getter-self.base)
            interface_rows.append(dict(class_getter_rva=hex(getter-self.base), pointer_adjustment=adjustment,
                implemented_by_script=bool(script), runtime_interface_observed=False))
        deps = list(struct.unpack('<'+'Q'*nd,self.read(dependencies-self.base,nd*8))) if nd else []
        return dict(**identity, **factory, native_no_register_getter_rva=hex(no_register-self.base),
            parameter_sha256=sha(raw), native_class_flags_input=hex(flags),
            dependency_factories=[self.factory(p-self.base) for p in deps],
            fields=fields, function_count=len(function_rows), functions=function_rows,
            own_interfaces=interface_rows, current_wire_handles_recovered=False)

    def structure(self, rva):
        factory = self.factory(rva)
        if factory['kind'] != 'struct':
            raise ValueError('Exact current UScriptStruct registration factory required')
        raw = self.read(int(factory['parameter_rva'],16),68)
        outer,super_fn,ops,name,size,alignment,props = struct.unpack_from('<7Q',raw)
        count,obj_flags,struct_flags = struct.unpack_from('<3I',raw,56)
        if not 1 <= size <= 1048576 or alignment not in (1,2,4,8,16,32,64,128):
            raise ValueError('Bounded current native struct size/alignment required')
        ops_binding = self.cpp_struct_ops(ops-self.base,size,alignment) if ops else None
        return dict(**factory,name=text(self.read,name-self.base), native_size=size, native_alignment=alignment,
            declared_struct_flags=hex(struct_flags), cpp_struct_ops_factory_rva=hex(ops-self.base) if ops else None,
            cpp_struct_ops_source_binding=ops_binding,
            effective_struct_flags_after_cpp_ops_recovered=False,
            super_struct_factory_rva=hex(super_fn-self.base) if super_fn else None,
            outer_package_factory_rva=hex(outer-self.base) if outer else None,
            fields=self.tree(props,count), native_engine_function_called=False)

    def cpp_struct_ops(self, rva, size, alignment):
        ins = self.instructions(rva)
        if (len(ins) != 13 or ins[2].op_str != '0x17179a0' or
                ins[7].op_str != 'qword ptr [rax], rcx' or
                ins[6].operands[1].imm != size or ins[8].operands[1].imm != alignment):
            raise ValueError('CppStructOps allocation/vtable/size binding differs from accepted source grammar')
        vtable = self.rip(ins[5])
        prepare = {i.address:i for i in self.instructions(0x10d03650)}
        for at, expected in ((0x10d03965,'qword ptr [rax + 0x60]'),
                (0x10d0396a,'0x10d03a95'),(0x10d039fa,'dword ptr [rbx], 0x400'),
                (0x10d03a06,'qword ptr [rax + 0x68]'),(0x10d03a0b,'0x10d03a95'),
                (0x10d03a82,'dword ptr [r12], 0x400000')):
            if prepare[at].op_str != expected:
                raise ValueError('Current struct trait-to-flag source witness changed')
        traits = []
        for slot in (0x30,0x38,0x60,0x68):
            target, = struct.unpack('<Q',self.read(vtable+slot,8))
            value = literal_bool(self.instructions(target-self.base))
            traits.append(dict(vtable_slot=hex(slot), target_rva=hex(target-self.base), value=value,
                native_function_called=False))
        net = next(r['value'] for r in traits if r['vtable_slot']=='0x60')
        target, = struct.unpack('<Q',self.read(vtable+0x70,8))
        if net:
            self.instructions(target-self.base)
        return dict(factory_rva=hex(rva), vtable_rva=hex(vtable), traits=traits,
            struct_flag_0x400_after_prepare=net, struct_flag_0x400000_after_prepare=net and traits[-1]['value'],
            net_serialize_slot='0x70', net_serialize_target_rva=hex(target-self.base) if net else None,
            runtime_ops_pointer_observed=False, all_effective_struct_flags_recovered=False)

    def function(self, rva):
        factory = self.factory(rva)
        if factory['kind'] != 'function':
            raise ValueError('Exact current UFunction registration factory required')
        raw = self.read(int(factory['parameter_rva'],16),72)
        outer,super_fn,name,implementation,validation,structure_size,props = struct.unpack_from('<7Q',raw)
        count,obj_flags,flags,rpc,response = struct.unpack_from('<3I2H',raw,56)
        if structure_size > 65536:
            raise ValueError('Bounded function parameter structure required')
        return dict(**factory, name=text(self.read,name-self.base), function_flags=hex(flags), net_flag=bool(flags&0x40),
            super_function_factory_rva=hex(super_fn-self.base) if super_fn else None,
            outer_class_getter_rva=hex(outer-self.base) if outer else None,
            parameter_structure_bytes=structure_size, rpc_id=rpc, rpc_response_id=response,
            parameters=self.tree(props,count), native_engine_function_called=False)


def derive():
    archive = Archive()
    for rva in (CLASS_CTOR, FUNCTION_CTOR, STRUCT_CTOR, ENUM_CTOR, 0x10ec0a90):
        archive.instructions(rva)
    classes = [archive.registered_class(name,rva) for name,rva in REGISTRATIONS]
    queue, known, supporting = list(classes), {c['factory_rva'] for c in classes}, []
    while queue:
        owner = queue.pop(0)
        for dependency in owner['dependency_factories']:
            key = dependency['factory_rva']
            if dependency['kind'] != 'class' or key in known:
                continue
            if len(known) >= 64:
                raise ValueError('Class ancestry registration budget exceeded')
            known.add(key)
            node = archive.class_record(dependency)
            supporting.append(node); queue.append(node)
    by_name = {c['name']:c for c in classes+supporting}
    structures = []
    for owner, field_name, expected in (('Actor','ReplicatedMovement','RepMovement'),
            ('Actor','AttachmentReplication','RepAttachment'),('DFMGameState','MatchInfo','MatchInfo')):
        fields = [p for p in by_name[owner]['fields']['fields'] if p['name']==field_name and p['kind']=='FStructProperty']
        if len(fields) != 1 or len(fields[0]['callbacks']) != 1:
            raise ValueError('Unique selected struct property-to-factory source binding absent')
        field = fields[0]
        node = archive.structure(int(field['callbacks'][0]['function_rva'],16))
        if node['name'] != expected:
            raise ValueError('Selected nested struct identity differs from its exact field callback')
        structures.append(dict(owner_class=owner, owner_property=field_name,
            property_parameter_rva=field['parameter_record_rva'], **node))
    helpers = [Path(__file__), ROOT/'work/research_updated_native_registration_test.py',
        ROOT/'work/research_updated_metadata_roots.py']
    return dict(kind='current_native_uecodegen_registration_extraction', client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        classes=classes, supporting_native_ancestors=supporting, selected_nested_structs=structures,
        property_factory_grammar=archive.property_grammar(),
        native_functions=[report for _,report in archive.functions.values()],
        immutable_reads=list(archive.data.values()), code_source=archive.code.source_evidence(),
        native_engine_function_called=False, process_opened=False, runtime_files_changed=False,
        current_wire_handles_recovered=False, native_acceptance_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    if target.exists() or target.parent != ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report = derive()
    raw = (json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),classes=len(report['classes']))))
