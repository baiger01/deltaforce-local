"""Read-only references to public launcher diagnostics; no process memory access."""
from pathlib import Path
import hashlib
import json
import struct
import re
import capstone
import pefile

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'work/evidence'
SOURCE = ROOT / 'work/official-standalone-launcher/service_core.dll'
raw = SOURCE.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
assert digest == 'a7c22fac8c044cc96df4b9e565d8189f9cbeda31712e9d5dcb299252fd48bcee'
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
targets = {
    'servers_info': b'servers_info\0',
    'launch_rail_game': b'[GameMgr][launch_game] step5 LaunchRailGameImpl launch_param:',
    'update_launch_param': b'[GameMgr]OnGameProcessInfoRsp, update launch param, old:',
    'game_launch_param': b'GameInfo.LaunchParam\0',
    'on_launch_game': b'[GameMgr][launch_game] step1 OnLaunchGame,select:',
    'query_zone': b'[VersionMgr]QueryGameZone, success, task_id:',
    'zone_response': b'[VersionMgr]OnQueryGameZone, success, rsp:',
    'zone_json_event': b'Srv_VersionMgr_GetGameZoneJsonInfo\0',
    'zone_server_addresses': b'zone_server_addresses\0',
}
seh_starts = []
for m in re.finditer(rb'(?:\x68.{4}|\x6a.)\xb8.{4}\xe8.{4}', raw, re.DOTALL):
    call_offset = m.end() - 5
    call_va = base + pe.get_rva_from_offset(call_offset)
    destination = call_va + 5 + struct.unpack('<i', raw[call_offset + 1:call_offset + 5])[0]
    if destination in (0x104a80d7, 0x104a810b, 0x104a8179):
        seh_starts.append(m.start())
rows = []
for label, target in targets.items():
    target_offset = raw.index(target)
    target_va = base + pe.get_rva_from_offset(target_offset)
    needle = struct.pack('<I', target_va)
    cursor = 0
    refs = []
    while True:
        cursor = raw.find(needle, cursor)
        if cursor < 0:
            break
        section = pe.get_section_by_rva(pe.get_rva_from_offset(cursor))
        if section and section.Characteristics & 0x20000000:
            minimum = max(section.PointerToRawData, cursor - 16384)
            starts = [raw.rfind(b'\x55\x8b\xec', minimum, cursor)]
            starts.extend([s for s in seh_starts if minimum <= s < cursor][-1:])
            padding = raw.rfind(b'\xcc\xcc\xcc\xcc', minimum, cursor)
            if padding >= 0:
                start = padding + 4
                while raw[start] == 0xcc:
                    start += 1
                starts.append(start)
            for start in sorted(set(starts), reverse=True):
                if start < minimum:
                    continue
                code = list(md.disasm(raw[start:min(len(raw), cursor + 512)], base + pe.get_rva_from_offset(start)))
                reference_va = base + pe.get_rva_from_offset(cursor)
                if not any(i.address <= reference_va < i.address + i.size for i in code):
                    continue
                filename = f'official_core_{label}_{reference_va:x}.asm.txt'
                (OUT / filename).write_text('\n'.join(f'{i.address:08x} {i.mnemonic:8} {i.op_str}' for i in code) + '\n', encoding='utf-8')
                refs.append({'reference_va': hex(reference_va), 'start_va': hex(base + pe.get_rva_from_offset(start)), 'instructions': len(code), 'listing': filename})
                break
        cursor += 4
    rows.append({'label': label, 'target_va': hex(target_va), 'references': refs})
report = {'source_sha256': digest, 'read_only_static_inspection': True, 'targets': rows}
(OUT / 'official_core_server_info_references.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
