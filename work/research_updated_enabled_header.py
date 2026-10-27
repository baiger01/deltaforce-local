"""Actual enabled alternate Actor receiver: intact bunch paths and hook gates.

Research only. Uses saved, pinned observations and immutable/current cached code.
Does not open a process, call native code, edit old proofs, or activate a profile.
"""
import argparse
import json
from pathlib import Path
import struct

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from research_updated_metadata_roots import ROOT, ForensicObservation, disasm, instruction_row, sha
from research_updated_native_registration import Archive, CLIENT_SHA
from research_updated_replication_core import compare_full, locate

CAPTURE = 'work/native-client-tests/1793063482116451500/updated-class-metadata.json'
INPUTS = {
    CAPTURE:'0d67c2042ee16854754da498b0a675bbf45df8d27f97c7e5b45480bad6c96b65',
    'work/research_updated_header_context_79fb7b10_v1.json':'8cda6a07e1875045f380dbe86a3d854fd6ab4bd19af09f6f1d6f81d3051a2e53',
    'work/research_updated_header_cells_79fb7b10_v3.json':'b0c98f1a378bca8b1c98a38cdc9a973f4c8318bc5691171133a354890baac2d8',
    'work/research_updated_rpc_receive_79fb7b10_v2.json':'7463766d9602b3b96bbaa2451bcdc5c4580142f9de00463db502b5ee39c8022c',
}
TABLE, TABLE_BYTES = 0x1de36180, 0x8f56
PAIRS = (
    ('alternate_receive',0x4941e10,0x4941a20),
    ('seamless_direct_receive',0x4942120,0x4941d30),
    ('direct_base_receive',0x49422d0,0x4941ee0),
    ('direct_receive_predicate',0x4981440,0x4981050),
    ('queue_receive_predicate',0x4980dc0,0x49809d0),
    ('queue_timestamp',0x4956dc0,0x49569d0),
    ('saved_bunch_constructor',0x1283e720,0x1283ea70),
    ('in_bunch_copy_constructor',0x1283e770,0x1283eac0),
    ('archive_deep_copy',0x10b3d120,0x10b3caf0),
    ('byte_array_deep_copy',0xe52fa0,0xe52fc0),
    ('timed_queue_replay',0x4949c60,0x4949870),
    ('flush_queue',0x4952d80,0x4952990),
    ('release_queue_entry',0x4949220,0x4948e30),
    ('current_queue_entry',0x4954810,0x4954420),
    ('seamless_actor_reset',0x4941bd0,0x49417e0),
    ('seamless_completion',0x4951fc0,0x4951bd0),
    ('seamless_native_notifications',0x49520d0,0x4951ce0),
    ('generic_hook_dispatcher',0x10c8e260,0x10c8dc00),
    ('mode_enabled_object_property',0x10e8ed20,0x10e8e6c0),
    ('mode_enabled_guid_fallback',0x49b05c0,0x49b01d0),
)
HOOK_ROOTS = (
    0x4977dc0,0x4941a20,0x4941d30,0x4941ee0,0x4981050,0x49809d0,0x49569d0,
    0x4949870,0x4952990,0x4948e30,0x4954420,0x49417e0,0x4951bd0,0x4951ce0,
    0x497d540,0x4969640,0x4e24db0,0x49ccfc0,0x49b01d0,
)


def register_family(name):
    for family, aliases in (('rax',('rax','eax','ax','al','ah')),('rcx',('rcx','ecx','cx','cl','ch')),
            ('rdx',('rdx','edx','dx','dl','dh')),('rbx',('rbx','ebx','bx','bl','bh')),
            ('rsi',('rsi','esi','si','sil')),('rdi',('rdi','edi','di','dil')),
            ('rbp',('rbp','ebp','bp','bpl')),('rsp',('rsp','esp','sp','spl'))):
        if name in aliases:
            return family
    for number in range(8,16):
        if name in ('r'+str(number),'r'+str(number)+'d','r'+str(number)+'w','r'+str(number)+'b'):
            return 'r'+str(number)
    return name


def definition_dominates(instructions, definition, target):
    by_address = {i.address:i for i in instructions}
    def reachable(skip):
        pending, seen = [instructions[0].address], set()
        while pending:
            at = pending.pop()
            if at in seen or at==skip or at not in by_address:
                continue
            if at==target:
                return True
            seen.add(at); ins=by_address[at]
            if ins.mnemonic=='ret':
                continue
            if ins.mnemonic.startswith('j'):
                if ins.operands[0].type!=X86_OP_IMM:
                    raise ValueError('Register-zero hook guard has an unqualified indirect branch')
                pending.append(ins.operands[0].imm)
                if ins.mnemonic=='jmp':
                    continue
            pending.append(ins.address+ins.size)
        return False
    return reachable(None) and not reachable(definition)


def hook_states(instructions, table=TABLE, table_bytes=TABLE_BYTES):
    keys = {i.operands[1].imm for i in instructions if i.mnemonic=='mov'
        and i.op_str.startswith('ecx, ') and len(i.operands)==2 and i.operands[1].type==X86_OP_IMM}
    by_cell, zeros = {}, {}
    for ins in instructions:
        proof = None
        if (ins.mnemonic=='cmp' and len(ins.operands)==2 and ins.operands[1].type==X86_OP_REG):
            family=register_family(ins.reg_name(ins.operands[1].reg))
            definition=zeros.get(family)
            if definition and definition_dominates(instructions,definition.address,ins.address):
                proof=instruction_row(definition)
        if ins.mnemonic=='call':
            for family in ('rax','rcx','rdx','r8','r9','r10','r11'):
                zeros.pop(family,None)
        else:
            for register in ins.regs_access()[1]:
                zeros.pop(register_family(ins.reg_name(register)),None)
        if (ins.mnemonic=='xor' and len(ins.operands)==2 and ins.operands[0].type==X86_OP_REG
                and ins.operands[1].type==X86_OP_REG and ins.operands[0].reg==ins.operands[1].reg
                and ins.operands[0].size>=4):
            zeros[register_family(ins.reg_name(ins.operands[0].reg))]=ins
        if ins.mnemonic != 'cmp' or len(ins.operands)!=2:
            continue
        mem, value = ins.operands
        if mem.type!=X86_OP_MEM or mem.size!=1 or mem.mem.base!=X86_REG_RIP:
            continue
        target = ins.address+ins.size+mem.mem.disp
        if not table < target < table+table_bytes:
            continue
        key = target-table
        if key not in keys:
            raise ValueError('Hook state lacks matching exact current dispatcher key: '+hex(target))
        if value.type==X86_OP_IMM:
            compared=value.imm
        elif proof is not None:
            compared=0
        else:
            raise ValueError('Hook byte comparison value is not source-qualified: '+hex(ins.address))
        row = by_cell.setdefault(target,dict(rva=hex(target),bytes=1,dispatch_key=key,guards=[]))
        row['guards'].append(dict(compared_value=compared,zero_register_source=proof,**instruction_row(ins)))
    for row in by_cell.values():
        if not any(g['compared_value']==0 for g in row['guards']):
            raise ValueError('Post-dispatch state comparison alone cannot qualify disabled hook')
    return [by_cell[rva] for rva in sorted(by_cell)]


def coalesce_cells(addresses):
    if len(addresses)>128 or len(set(addresses))!=len(addresses):
        raise ValueError('At most128 distinct proved hook bytes required')
    result = []
    for address in sorted(addresses):
        if result and int(result[-1]['rva'],16)+result[-1]['bytes']==address:
            result[-1]['bytes'] += 1
        else:
            result.append(dict(rva=hex(address),bytes=1))
    return result


def hook_dispatch_calls(instructions, keys):
    current, result = None, []
    for ins in instructions:
        if ins.mnemonic=='call':
            if current in keys:
                if ins.operands[0].type!=X86_OP_IMM:
                    raise ValueError('Hook-key argument reached an unqualified indirect dispatch')
                result.append(dict(call_rva=hex(ins.address),target_rva=hex(ins.operands[0].imm),dispatch_key=current))
            current = None
        elif any(ins.reg_name(r) in ('rcx','ecx','cx','cl','ch') for r in ins.regs_access()[1]):
            current = (ins.operands[1].imm if ins.mnemonic=='mov' and ins.op_str.startswith('ecx, ')
                and ins.operands[1].type==X86_OP_IMM else None)
    return result


def derive():
    docs = {}
    for path, expected in INPUTS.items():
        raw = (ROOT/path).read_bytes()
        if sha(raw)!=expected:
            raise ValueError('Enabled receiver input changed: '+path)
        docs[path] = json.loads(raw)
    capture = docs[CAPTURE]
    if capture['client_sha256']!=CLIENT_SHA or capture['complete'] is not True or len(capture['selected_classes'])!=49:
        raise ValueError('Exact complete49-class actual observation required')
    before, after = (capture[k] for k in ('header_context_before_class_scan','header_context'))
    for context in (before,after):
        if (context['values']!={'global_hook_enable':1,'alternate_actor_channel':1}
                or context['source_instructions_rechecked'] is not True or context['backend_identity_rechecked'] is not True):
            raise ValueError('Actual enabled header context facts changed')
    a, old = Archive(), ForensicObservation('old')
    functions = [compare_full(old,a.code,a.image,name,previous,current) for name,previous,current in PAIRS]
    copied = list(disasm(a.code,0x10b3f700,600))
    if (sum(i.size for i in copied)!=600 or copied[-1].mnemonic!='ret'
            or any(i.mnemonic not in ('mov','movzx','movsd','xor','and','ret') for i in copied)
            or a.code.read(0x10b3f700+600,1)!=b'\xcc'):
        raise ValueError('Complete straight-line Archive flag-copy leaf changed')
    functions.append(compare_full(old,a.code,a.image,'archive_flags_copy',0x10b3fd30,0x10b3f700,600))
    native_bodies = {root:a.instructions(root) for root in sorted(set(HOOK_ROOTS)|{0x4999080,0x4999600,0x49b10e0})}
    hooks = {}
    for root in HOOK_ROOTS:
        for row in hook_states(native_bodies[root]):
            address = int(row['rva'],16)
            item = hooks.setdefault(address,dict(rva=row['rva'],bytes=1,dispatch_key=row['dispatch_key'],
                functions=[],guards=[],required_quiet_value=0))
            item['functions'].append(hex(root))
            item['guards'].extend(g for g in row['guards'] if g not in item['guards'])
    dispatch_calls = []
    for root in HOOK_ROOTS:
        keys = {r['dispatch_key'] for r in hook_states(native_bodies[root])}
        dispatch_calls.extend(dict(function_rva=hex(root),**r) for r in hook_dispatch_calls(native_bodies[root],keys))
    dispatcher_targets = {int(r['target_rva'],16) for r in dispatch_calls}
    dispatchers = []
    for target in sorted(dispatcher_targets):
        ins = a.instructions(target)
        if not any(i.mnemonic=='call' and i.op_str=='0x10c8dc00' for i in ins):
            raise ValueError('Current typed hook dispatcher does not reach proved generic dispatcher: '+hex(target))
        if not any(i.mnemonic=='mov' and i.op_str=='ecx, 0xb' for i in ins):
            raise ValueError('Current typed hook dispatcher group11 binding changed')
        dispatchers.append(dict(target_rva=hex(target),full_current_native_body_qualified=True,
            generic_dispatcher_rva='0x10c8dc00',group_id=11,
            historical_binding_claimed=False, reason='Current selected direct call binding and complete body; clone prefix matches are not historical method identities.'))
    witnesses = []
    checks = (
        (0x4941a20,0x4941a98,'call 0x606aaa0','Alternate receiver requests exact GPSeamlessConnectionInterface'),
        (0x4941a20,0x4941abd,'call qword ptr [r8 + 0x368]','Direct-mode predicate controls immediate path'),
        (0x4941a20,0x4941ad4,'call qword ptr [r9 + 0x358]','Direct branch invokes seamless direct wrapper'),
        (0x4941a20,0x4941ae0,'call qword ptr [r9 + 0x388]','Other branch tests queue policy'),
        (0x4941a20,0x4941b05,'call qword ptr [rax + 0x360]','No-queue branch invokes direct base wrapper'),
        (0x4941a20,0x4941c6c,'call 0x1283ea70','Queue branch copies a complete FInBunch'),
        (0x4941a20,0x4941cd9,'call 0x12861530','Missing interface falls back to qualified Engine receiver'),
        (0x4941ee0,0x4941fe1,'call 0x12861530','Direct base wrapper consumes the original bunch once'),
        (0x4949870,0x4949935,'mov rdx, qword ptr [rax + 8]','Timed replay obtains saved FInBunch pointer'),
        (0x4949870,0x4949944,'call qword ptr [rax + 0x360]','Timed replay invokes direct base wrapper'),
        (0x4952990,0x4952a7e,'mov rdx, qword ptr [rax + 8]','Flush obtains saved FInBunch pointer'),
        (0x4952990,0x4952a8d,'call qword ptr [rax + 0x360]','Flush invokes same direct base wrapper'),
        (0x1283ea70,0x1283ea89,'call 0x1283eac0','Saved bunch uses full current copy constructor'),
        (0x1283ea70,0x1283ea9c,'mov rax, qword ptr [rsi + 0xa8]','Preserve-position branch reads original bit position'),
        (0x1283ea70,0x1283eaa3,'mov qword ptr [rdi + 0xa8], rax','Saved bunch preserves original bit position'),
        (0x1283eac0,0x1283ec74,'mov rax, qword ptr [rsi + 0xb0]','Bunch copy preserves PackageMap context'),
        (0x1283eac0,0x1283ec9f,'call 0xe52fc0','Bunch copy deep-copies byte array'),
        (0x1283eac0,0x1283eca4,'mov rax, qword ptr [rsi + 0xa0]','Bunch copy preserves bit limit'),
        (0x10b3caf0,0x10b3cb25,'call 0x10b3f700','Deep Archive copy preserves flags and versions'),
        (0x10c8dc00,0x10c8dd68,'call qword ptr [rbx + 0x128]','Nonzero hook reaches mutable registered external callback'),
        (0x4e24db0,0x4e24ddf,'je 0x4e24e80','Pawn hook state2 can skip its native byte'),
        (0x10e8e6c0,0x10e8e74d,'call qword ptr [rax + 0x268]','Enabled global permits PackageMap unresolved-reference fallback'),
    )
    for root,at,text,meaning in checks:
        ins = next((i for i in a.instructions(root) if i.address==at),None)
        if ins is None or ins.mnemonic+' '+ins.op_str!=text:
            raise ValueError('Actual enabled receiver witness changed: '+meaning)
        witnesses.append(dict(meaning=meaning,**instruction_row(ins)))
    table = 0x15e64ed8
    slots = {0x350:0x4941a20,0x358:0x4941d30,0x360:0x4941ee0,
        0x368:0x4981050,0x370:0x4949870,0x378:0x4951bd0,0x380:0x4951ce0,
        0x388:0x49809d0,0x390:0x49569d0}
    for slot,target in slots.items():
        if struct.unpack('<Q',a.read(table+slot,8))[0]-a.base!=target:
            raise ValueError('Current configured GP channel virtual target changed')
    conn = a.class_record(a.factory(0x603f8a0),include_functions=False)
    interface = a.class_identity(0x606aaa0)
    own = [r for r in conn['own_interfaces'] if a.class_identity(int(r['class_getter_rva'],16))==dict(interface,no_register_tail_chain=['0x606ac60'])]
    if len(own)!=1 or own[0]['pointer_adjustment']!=0x20b0 or own[0]['implemented_by_script']:
        raise ValueError('Current GP connection native seamless interface binding changed')
    pawn = next(c for c in capture['selected_classes'] if c['name']=='BP_DFMCharacter_C')
    template = pawn['template_metadata']
    if (template['identities_and_fields_rechecked'] is not True
            or template['cdo']['status']!='observed'
            or template['net_rep_actor_interface']['pointer_adjustment']!=0xa60
            or template['net_rep_actor_interface']['method']['target_rva']!=0x4e19500):
        raise ValueError('Actual current Pawn template/interface facts changed')
    proof_paths = [Path(__file__),ROOT/'work/research_updated_enabled_header_test.py',
        ROOT/'work/research_updated_native_registration.py',ROOT/'work/research_updated_replication_core.py']
    return dict(kind='current_actual_enabled_actor_receiver_source_contract',client_sha256=CLIENT_SHA,
        source_inputs=INPUTS,source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in proof_paths},
        actual_capture=dict(path=CAPTURE,sha256=INPUTS[CAPTURE],complete=True,selected_class_count=49,
            before_values=before['values'],after_values=after['values'],
            observed_zero_gate=False,native_actor_or_map_acceptance=False),
        selected_current_vtable=dict(rva=hex(table),slots={hex(k):hex(v) for k,v in slots.items()}),
        functions=functions,exact_instruction_witnesses=witnesses,
        native_receive_routes=[
            dict(condition='No native GPSeamlessConnectionInterface',route=['4941a20','12861530']),
            dict(condition='Direct predicate slot368 true',route=['4941a20','4941d30','4941ee0','12861530']),
            dict(condition='Direct predicate false and queue predicate false',route=['4941a20','4941ee0','12861530']),
            dict(condition='Queue predicate true and FInBunch+e4 bit1 set',route=['flush4952990','4941ee0','12861530']),
            dict(condition='Queue predicate true and FInBunch+e4 bit1 clear',route=['copy1283ea70','queue entry+8',
                'timed replay4949870 or flush4952990','4941ee0','12861530'])],
        wire_shape=dict(extra_payload_header_fields_in_native_alternate_wrappers=False,
            original_bunch_preserved=True,queued_bytes_deep_copied=True,bit_position_preserved=True,
            package_map_versions_and_archive_flags_preserved=True,
            base_parser='Qualified current Engine ActorChannel.ProcessBunch12861530',
            condition='Current configured GPActorChannel methods and all listed per-hook bytes0; does not require either observed top-level flag to be zero.',
            native_delivery_timing_equivalent=False,gameplay_side_effects_equivalent=False,
            note='Native reset/completion/notification calls can alter Actor/application state. Queue clock/state determines when the base parser runs; source proof does not establish eventual replay.'),
        hook_gate_scope=dict(table_rva=hex(TABLE),registered_group_id=11,registered_bytes=TABLE_BYTES,
            global_enable_actual_value=1,all_selected_method_states_observed=False,
            required_quiet_cells=[hooks[k] for k in sorted(hooks)],
            exact_read_ranges=coalesce_cells(list(hooks)),bytes_to_read=len(hooks),
            guard_policy='Read only these proved byte cells and their exact source instruction guards; accept source-native route only when each is0 and identities/bytes recheck after callback. Other values remain explicit unsupported callback paths.',
            dispatcher_effects='State nonzero invokes typed boxing then generic dispatcher group11/function key. Its mutable callback pointer+128 may override output/arguments; state2 can bypass native bodies. Source initial data or global1 alone does not resolve those effects.',
            current_complete_typed_dispatchers=dispatchers,current_typed_dispatch_calls=dispatch_calls),
        optional_delivery_diagnostics=dict(required_for_payload_wire_shape=False,
            global_direct_predicate=dict(rva='0x1de76610',bytes=1,source_function='0x4981050'),
            native_seamless_interface=dict(class_path=interface['package']+'.'+interface['name'],
                declaring_connection='/Script/GPGameplay.GPNetConnection',adjustment='0x20b0',
                pending_flag_offset='0x121',queue_flag_offset='0x122',
                requirement='Resolve actual connection type/native interface before any read; these are interface-relative control state, not a reason to read arbitrary object payload.'),
            queue_state='After a concrete channel exists, proved read/write counters channel+2cc/+2c8 and timestamped entries explain delayed application; not needed to determine an extra wire field.'),
        actual_pawn_template=dict(class_path=pawn['path'],cdo=template['cdo'],
            net_rep_actor_interface=template['net_rep_actor_interface'],source_json_pointer='/selected_classes/'+str(capture['selected_classes'].index(pawn))+'/template_metadata',
            reader_source_provenance_preserved_without_replaying_historical_collector_code=True),
        minimum_next_step='Extend the bounded current metadata read with the sparse proved per-hook byte set. If all are0, compile a distinct enabled-context source contract accepting actual1/1 and intact-bunch routes; preserve native acceptance=false. No Dorian object-state sampling is necessary for payload shape.',
        explicit_limits=['Actual1/1 disproves the earlier conservative zero-flag model for this capture; the old report is retained as conditional evidence.',
            'No claim that the only source setter of the alternate flag is the commandlet. Direct-RIP writer inventory did not prove absence of indirect writes; actual normal-startup observation controls this task.',
            'All selected receiver/queue/copy/dispatcher bodies are complete. Arbitrary callback targets, gameplay notifications, logging, allocators and unselected virtual overrides are not certified as a closed application call graph.',
            'Nonzero individual hook states require the actual registered callback and applicable script/parameter effect proof, not blanket acceptance of the native branch.',
            'No native process, packet transmission, map, spawn, possession, inventory or loot acceptance is asserted.'],
        native_current_bodies=[a.functions[r][1] for r in sorted(a.functions)],
        immutable_reads=[a.data[r] for r in sorted(a.data)],
        code_sources=[old.source_evidence(),a.code.source_evidence()],
        process_opened=False,native_engine_function_called=False,process_memory_written=False,
        runtime_files_changed=False,old_proofs_changed=False,profile_activated=False,native_acceptance_verified=False)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if (target.exists() or target.parent not in (ROOT/'work',ROOT/'work/evidence')
            or not target.name.startswith(('research_','updated-enabled-actor-receiver-'))):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),functions=len(report['functions']),
        hook_bytes=report['hook_gate_scope']['bytes_to_read'],ranges=len(report['hook_gate_scope']['exact_read_ranges']))))
