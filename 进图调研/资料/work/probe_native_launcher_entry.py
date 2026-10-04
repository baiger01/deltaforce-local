"""Read named launcher reflection strings and static references only."""
from pathlib import Path
import hashlib
import json
import mmap
import re
import struct
import pefile

ROOT = Path(__file__).resolve().parent.parent
path = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
symbols = ('GetLauncherParamsByKey', 'SetLauncherParams', 'LauncherArgs', 'SetLauncherServerInfo', 'ServerAddrRelease')
with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
    pe = pefile.PE(data=raw, fast_load=True)
    def rva(offset):
        for section in pe.sections:
            if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
                return section.VirtualAddress + offset - section.PointerToRawData
        return None
    found = []
    for symbol in symbols:
        for encoding in ('ascii', 'utf-16le'):
            needle = symbol.encode(encoding)
            at = 0
            while True:
                at = raw.find(needle, at)
                if at < 0:
                    break
                address = rva(at)
                item = {'symbol': symbol, 'encoding': encoding, 'offset': at, 'rva': hex(address) if address is not None else None}
                if address is not None:
                    ptr = struct.pack('<Q', pe.OPTIONAL_HEADER.ImageBase + address)
                    refs, pos = [], 0
                    while len(refs) < 40:
                        pos = raw.find(ptr, pos)
                        if pos < 0:
                            break
                        refs.append({'offset': pos, 'rva': hex(rva(pos)) if rva(pos) is not None else None})
                        pos += 8
                    item['pointer_refs'] = refs
                found.append(item)
                at += len(needle)
    result = {'image_base': hex(pe.OPTIONAL_HEADER.ImageBase), 'exception_directory': {'rva': hex(pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress), 'size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size}, 'symbols': found}
    (ROOT / 'work/evidence/native_launcher_entry.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
