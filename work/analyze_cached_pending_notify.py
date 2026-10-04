"""Disk-only PendingNetGame control-handler switch and static-string audit.

The unwind span ends in an actual, indexed 21 DWORD switch table. It is not
claimed as instruction bytes. No live objects, process reads or functions.
"""
import hashlib
import json
import mmap
from pathlib import Path
import struct
import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from offline_native_code_cache import read_cached_code
from read_native_control_code import Image

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT/'work/native-code-cache/1790902501634810000'
MANIFEST_SHA = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
EXE = Path('D:/个人工作区/DeltaForce-local-client/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
EXE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
START, TABLE, END = 0x12c93f40, 0x12c951c4, 0x12c95218
CODE_SHA = 'a8cc88c468c1344791be8134b188e73292f0f2d43dca0666a862ec4a103e1922'
OUT = ROOT/'work/evidence/cached-pending-notify-1790902501634810000'

def sha(v):
    return hashlib.sha256(v).hexdigest()

def text_at(image, rva):
    try:
        raw = image.data(rva, 512)
    except ValueError:
        return None
    chars = []
    for i in range(0, len(raw), 2):
        n = struct.unpack_from('<H', raw, i)[0]
        if n == 0:
            break
        if n < 32 and n not in (9, 10, 13) or n > 126:
            return None
        chars.append(chr(n))
    if not chars or len(chars) > 254:
        return None
    text = ''.join(chars)
    return {'rva':hex(rva),'utf16_text':text,'bytes_with_terminator':2*(len(chars)+1),
            'sha256':sha(raw[:2*(len(chars)+1)])}

def run():
    with EXE.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != EXE_SHA:
            raise ValueError('Immutable PE identity mismatch')
        image = Image(raw)
        root, length, fragments = image.function_span(START)
        if root != (START, END, 0x1c881294) or fragments != [(START,END)] or length != END-START:
            raise ValueError('Exact Pending handler span mismatch')
        sample = read_cached_code(CACHE, START, length, MANIFEST_SHA)
        if sha(sample) != CODE_SHA:
            raise ValueError('Cached handler SHA mismatch')
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        ins = list(decoder.disasm(sample[:TABLE-START], START))
        cursor = START
        for i in ins:
            if i.address != cursor:
                raise ValueError('Noncontiguous handler code')
            cursor += i.size
        if cursor != TABLE or ins[-1].mnemonic != 'ret':
            raise ValueError('Handler code/table partition incomplete')
        by = {i.address:i for i in ins}
        expected = {0x12c93f61:('movzx','eax, r8b'),0x12c93f65:('dec','eax'),
            0x12c93f7b:('cmp','eax, 0x14'),0x12c93f7e:('ja','0x12c95176'),
            0x12c93f8d:('mov','ecx, dword ptr [rdx + rax*4 + 0x12c951c4]'),
            0x12c93f94:('add','rcx, rdx'),0x12c93f97:('jmp','rcx')}
        for at, wanted in expected.items():
            if at not in by or (by[at].mnemonic,by[at].op_str) != wanted:
                raise ValueError('Indexed switch proof mismatch')
        origin = by[0x12c93f84]
        if origin.mnemonic != 'lea' or origin.operands[1].mem.base != X86_REG_RIP or origin.address+origin.size+origin.operands[1].mem.disp != 0:
            raise ValueError('Indexed switch RVA origin mismatch')
        table = sample[TABLE-START:]
        targets = struct.unpack('<21I',table)
        if any(t not in by for t in targets):
            raise ValueError('Switch target is not a verified instruction boundary')
        refs, calls = [], []
        for i in ins:
            if i.mnemonic in ('call','jmp') and len(i.operands)==1 and i.operands[0].type==X86_OP_IMM:
                calls.append({'site':hex(i.address),'kind':i.mnemonic,'instruction_bytes':bytes(i.bytes).hex(),'target':hex(i.operands[0].imm)})
            for op in i.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = i.address+i.size+op.mem.disp
                    value = text_at(image,t)
                    if value:
                        refs.append({'site':hex(i.address),'kind':i.mnemonic,'instruction_bytes':bytes(i.bytes).hex(),**value})
        proof = {'kind':'native_pending_netgame_control_switch_audit','client_sha256':EXE_SHA,
            'cache_manifest_sha256':MANIFEST_SHA,'exact_root':list(map(hex,root)),
            'fragments':[[hex(a),hex(b)] for a,b in fragments], 'span_bytes':length,'span_sha256':sha(sample),
            'code_range':[hex(START),hex(TABLE)],'code_bytes':TABLE-START,'code_sha256':sha(sample[:TABLE-START]),
            'code_partition_fully_decoded':True,'declared_span_is_all_instruction_bytes':False,
            'table_range':[hex(TABLE),hex(END)],'table_bytes':len(table),'table_sha256':sha(table),
            'table_entries':[{'control_id':n+1,'target':hex(t),'target_verified_instruction_boundary':True} for n,t in enumerate(targets)],
            'default':hex(0x12c95176),'switch_proof':[{'site':hex(at),'bytes':bytes(by[at].bytes).hex(),'instruction':by[at].mnemonic+' '+by[at].op_str} for at in expected],
            'static_string_refs':refs,'direct_edges':calls,'instructions':[{'rva':hex(i.address),'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins],
            'process_accessed':False,'game_launched':False,'native_function_invoked':False,
            'qualified_identity':'Concrete PendingNetGame constructor creates FNetworkNotify subobject at object+28; its immutable interface table slot+18 targets this root. Current runtime instance is not read.'}
        OUT.mkdir(exist_ok=True)
        (OUT/'notify.code.asm.txt').write_text('\n'.join(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in ins)+'\n',encoding='utf-8')
        out=OUT/'notify.switch-audit.json'
        out.write_text(json.dumps(proof,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
        print(json.dumps({'output':str(out),'sha256':sha(out.read_bytes()),'code_bytes':TABLE-START,'table_bytes':len(table),'table_entries':proof['table_entries'],'strings':refs},ensure_ascii=False))

if __name__ == '__main__':
    run()
