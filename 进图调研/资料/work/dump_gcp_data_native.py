"""Read-only, bounded native GCP data-handler disassembly for local analysis."""
from pathlib import Path
import hashlib
import json

import capstone
import pefile

source = Path('D:/三角洲/WeGameApps/rail_apps/DeltaForce(2001918)/DeltaForce/Binaries/Win64/GCloud.dll')
raw = source.read_bytes()
pe = pefile.PE(data=raw, fast_load=True)
pe.parse_data_directories(directories=[3])
ranges = [(entry.struct.BeginAddress, entry.struct.EndAddress)
          for entry in pe.DIRECTORY_ENTRY_EXCEPTION]
targets = (0x188180, 0x1883e0, 0x194a15, 0x194be7, 0x194cf1, 0x195cb0,
           0x1a0d40, 0x1a0d6f, 0x1a14eb, 0x188470,
           0x1954a2, 0x196bed, 0x19736b)
out = Path(__file__).resolve().parent / 'evidence/gcp_data_native'
out.mkdir(parents=True, exist_ok=True)
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
records = []
seen = set()
for target in targets:
    bounds = next(((first, last) for first, last in ranges if first <= target < last), None)
    if bounds is None:
        records.append({'target_rva': hex(target), 'unwind_range': False})
        continue
    first, last = bounds
    record = {'target_rva': hex(target), 'function_start_rva': hex(first),
              'function_end_rva': hex(last), 'size': last - first}
    records.append(record)
    if (first, last) in seen:
        continue
    seen.add((first, last))
    if last - first > 16384:
        raise ValueError('Native function exceeds scoped disassembly bound')
    body = pe.get_data(first, last - first)
    assert len(body) == last - first
    lines = [f'{inst.address:08x}  {inst.mnemonic:8} {inst.op_str}'
             for inst in decoder.disasm(body, first)]
    (out / f'{first:x}.asm.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(out / 'index.json').write_text(json.dumps({'source_sha256': hashlib.sha256(raw).hexdigest(),
                                           'functions': records}, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'source_sha256': hashlib.sha256(raw).hexdigest(),
                  'functions': records}, indent=2))
