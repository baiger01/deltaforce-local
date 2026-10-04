"""Bounded disk metadata inspection; never loads code or opens a process."""
from pathlib import Path
import hashlib
import json
import mmap
import struct
import capstone
import pefile

ROOT = Path(__file__).resolve().parent.parent
source = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
out = ROOT/'work/evidence/native_zone_reader'
out.mkdir(exist_ok=True)
symbols = ('GetServerInfo','GetCurrentBranchName','WeGameConnectSvrInfo','ZoneID','ZoneName_en','ZoneName_zh')
with source.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as raw:
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
    pe = pefile.PE(data=raw,fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    def rva(offset):
        for section in pe.sections:
            if section.PointerToRawData <= offset < section.PointerToRawData+section.SizeOfRawData:
                return section.VirtualAddress+offset-section.PointerToRawData
        return None
    exception = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    table = pe.get_offset_from_rva(exception.VirtualAddress)
    count = exception.Size//12
    rows = []
    functions = set()
    for symbol in symbols:
        needle = symbol.encode()+b'\0'
        position = raw.find(needle)
        while position >= 0:
            if position == 0 or raw[position-1] == 0:
                name_rva = rva(position)
                references = []
                if name_rva is not None:
                    pointer = struct.pack('<Q',image_base+name_rva)
                    at = raw.find(pointer)
                    while at >= 0 and len(references) < 40:
                        ref_rva = rva(at)
                        value = struct.unpack_from('<Q',raw,at+8)[0]
                        target_rva = value-image_base
                        section = pe.get_section_by_rva(target_rva) if 0 <= target_rva < pe.OPTIONAL_HEADER.SizeOfImage else None
                        executable = bool(section and section.Characteristics & 0x20000000)
                        references.append({'reference_rva':hex(ref_rva) if ref_rva is not None else None,
                                           'next_pointer_rva':hex(target_rva) if section else None,
                                           'next_pointer_is_executable':executable})
                        if symbol in ('GetServerInfo','GetCurrentBranchName') and executable:
                            functions.add(target_rva)
                        at = raw.find(pointer,at+8)
                rows.append({'symbol':symbol,'name_rva':hex(name_rva) if name_rva is not None else None,'references':references})
            position = raw.find(needle,position+len(needle))
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    decoded = []
    for target in sorted(functions):
        lo,hi = 0,count
        while lo < hi:
            middle = (lo+hi)//2
            if struct.unpack_from('<I',raw,table+middle*12)[0] <= target:
                lo = middle+1
            else:
                hi = middle
        if lo == 0:
            continue
        begin,end,_ = struct.unpack_from('<III',raw,table+(lo-1)*12)
        if not begin <= target < end or end-begin > 8192:
            continue
        offset = pe.get_offset_from_rva(begin)
        code = raw[offset:offset+end-begin]
        instructions = list(decoder.disasm(code,begin))
        consumed = sum(i.size for i in instructions)
        name = f'{begin:x}.asm.txt'
        (out/name).write_text('\n'.join(f'{i.address:08x} {i.mnemonic:8} {i.op_str}' for i in instructions)+'\n',encoding='utf-8')
        decoded.append({'target_rva':hex(target),'begin_rva':hex(begin),'raw_bytes':len(code),
                        'bytes_linearly_decoded':consumed,'linear_decode_complete':len(code)==consumed,
                        'semantics_verified':False,'listing':name})
report = {'source_sha256':digest,'native_symbols':rows,'functions':decoded,
          'process_memory_accessed':False,'client_modified':False}
(out/'index.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'source_sha256':digest,'symbol_records':len(rows),'functions':decoded},indent=2))
