"""Current hardcoded EName identities from the complete pool constructor."""
import argparse
import json
from pathlib import Path

from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
from research_updated_metadata_roots import ROOT,disasm,instruction_row,sha
from research_updated_native_registration import Archive,CLIENT_SHA,text


def extract_ename_bindings(instructions,read,required):
    regs={}; view=dict(pointer=None,length=None,wide=None); returned=None; rows={}
    def key(ins,op):
        name=ins.reg_name(op.reg)
        return {'eax':'rax','ecx':'rcx','r12d':'r12'}.get(name,name)
    for ins in instructions:
        ops=ins.operands
        if ins.mnemonic=='call':
            result=dict(view,call_rva=hex(ins.address)) if ins.op_str=='0x10b77890' else None
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'):
                regs.pop(name,None)
            if result:
                regs['rax']=('returned_id_pointer',result)
            continue
        if len(ops)!=2:
            continue
        dst,src=ops; value=None
        if ins.mnemonic=='lea' and dst.type==X86_OP_REG and src.type==X86_OP_MEM and ins.reg_name(src.mem.base)=='rip':
            value=('literal_pointer',ins.address+ins.size+src.mem.disp)
        elif ins.mnemonic=='xor' and dst.type==X86_OP_REG and src.type==X86_OP_REG and dst.reg==src.reg:
            value=('constant',0)
        elif ins.mnemonic in ('mov','movabs'):
            if src.type==X86_OP_IMM:
                value=('constant',src.imm)
            elif src.type==X86_OP_REG:
                value=regs.get(key(ins,src))
            elif src.type==X86_OP_MEM and not src.mem.index and src.mem.disp==0 and ins.reg_name(src.mem.base)=='rax':
                prior=regs.get('rax')
                if prior and prior[0]=='returned_id_pointer':
                    value=('name_id',prior[1])
        if dst.type==X86_OP_REG and dst.reg in ins.regs_access()[1]:
            regs.pop(key(ins,dst),None)
            if value:
                regs[key(ins,dst)]=value
        elif ins.mnemonic=='mov' and dst.type==X86_OP_MEM and not dst.mem.index:
            base=ins.reg_name(dst.mem.base); offset=dst.mem.disp
            if base=='rsp' and offset in (0x30,0x38,0x3c):
                label={0x30:'pointer',0x38:'length',0x3c:'wide'}[offset]
                accepted='literal_pointer' if label=='pointer' else 'constant'
                view[label]=value[1] if value and value[0]==accepted else None
            if base=='rbx' and dst.size==4 and 0x14040<=offset<0x15040 and (offset-0x14040)%4==0:
                index=(offset-0x14040)//4
                if index not in required:
                    continue
                if not value or value[0]!='name_id':
                    rows.pop(index,None)
                    continue
                source=value[1]
                if source['wide']!=0 or type(source['length']) is not int or not 1<=source['length']<=511:
                    raise ValueError('Selected hardcoded EName has an unqualified input string view')
                literal=text(read,source['pointer'])
                if len(literal)!=source['length']:
                    raise ValueError('Selected hardcoded EName extent or assignment identity is ambiguous')
                rows[index]=dict(ename_index=index,literal_name=literal,literal_rva=hex(source['pointer']),
                    name_store_call_rva=source['call_rva'],table_assignment_rva=hex(ins.address),
                    pool_table_offset=hex(offset),runtime_name_id_observed=False)
    if set(rows)!=set(required):
        raise ValueError('A required current hardcoded EName assignment is absent: '+str(sorted(set(required)-set(rows))))
    by_address={i.address:i for i in instructions}
    for row in rows.values():
        forbidden=int(row['table_assignment_rva'],16); pending=[instructions[0].address]; seen=set()
        while pending:
            at=pending.pop()
            if at==forbidden or at in seen:
                continue
            seen.add(at); ins=by_address.get(at)
            if ins is None:
                raise ValueError('Pool constructor control flow leaves its complete source body')
            if ins.mnemonic=='ret':
                raise ValueError('Final selected EName assignment does not cover every returning constructor path')
            if ins.mnemonic.startswith('j'):
                if ins.operands[0].type!=X86_OP_IMM:
                    raise ValueError('Pool constructor contains unqualified indirect control flow')
                pending.append(ins.operands[0].imm)
                if ins.mnemonic=='jmp':
                    continue
            pending.append(ins.address+ins.size)
        row['last_direct_table_assignment_postdominates_constructor_entry']=True
    return [rows[index] for index in sorted(rows)]


def derive():
    a=Archive(); constructor=a.instructions(0x10b55ca0)
    a.instructions(0x10b77890); lookup=a.instructions(0x10b63280); a.instructions(0x10cfe940)
    required={0x3b:'Vector',0x3c:'Rotator',0x66:'Actor',0x25c:'EncVector'}
    rows=extract_ename_bindings(constructor,a.read,set(required))
    if any(row['literal_name']!=required[row['ename_index']] for row in rows):
        raise ValueError('Current EName identity differs from required typed classifier semantics')
    body=list(disasm(a.code,0x10b5a420,17))
    if (sum(i.size for i in body)!=17 or body[-1].mnemonic!='ret' or
            a.code.read(0x10b5a431,1)!=b'\xcc' or body[2].op_str!='ecx, dword ptr [rdx + rax*4]'):
        raise ValueError('Current exact EName equality leaf changed')
    table=a.rip(body[1]); pool=a.rip(next(i for i in lookup if i.address==0x10b632a3))
    if table-pool!=0x14040:
        raise ValueError('Current immutable EName-comparison and constructor pool-base relation changed')
    a.functions[0x10b5a420]=(body,dict(entry_rva='0x10b5a420',bytes=17,
        sha256=sha(a.code.read(0x10b5a420,17)),complete_padded_leaf=True,
        instructions=[instruction_row(i) for i in body]))
    helpers=[Path(__file__),ROOT/'work/research_updated_ename_bindings_test.py',ROOT/'work/research_updated_native_registration.py']
    return dict(kind='current_source_hardcoded_ename_identities',client_sha256=CLIENT_SHA,
        source_pins={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in helpers},
        hardcoded_names=rows,name_pool_rva=hex(pool),ename_id_table_rva=hex(table),table_offset='0x14040',
        other_hardcoded_names_not_exported=True,
        native_functions=[p for _,p in a.functions.values()],immutable_reads=list(a.data.values()),
        code_source=a.code.source_evidence(),abstract_name_identity_qualified=True,
        runtime_name_pool_or_numeric_internal_ids_observed=False,profile_activation_authorized=False,
        process_opened=False,native_engine_function_called=False,runtime_files_changed=False,native_acceptance_verified=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); target=args.output.resolve()
    if target.exists() or target.parent!=ROOT/'work' or not target.name.startswith('research_'):
        parser.error('Fresh work/research_ report required')
    report=derive(); raw=(json.dumps(report,ensure_ascii=True,indent=2)+'\n').encode('ascii')
    with target.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(target),sha256=sha(raw),names=len(report['hardcoded_names']))))
