"""Read selected field labels and one public invalid-zone sentinel."""
from pathlib import Path
import json
import re
import pefile
from recover_editor_wire_fields import exports

ROOT = Path(__file__).resolve().parent.parent
sources = {
    'service_core.dll':(0x105759d4,0x1055d6f8,0x1055d994,0x1055def4,0x105759b4),
    'rail_independent.dll':(0x1082e158,0x1082de08,0x1082e174),
}
report = []
for name,addresses in sources.items():
    raw = (ROOT/'work/official-standalone-launcher'/name).read_bytes()
    pe = pefile.PE(data=raw,fast_load=True)
    values = []
    for address in addresses:
        offset = pe.get_offset_from_rva(address-pe.OPTIONAL_HEADER.ImageBase)
        end = raw.find(b'\0',offset,offset+96)
        value = raw[offset:end].decode('ascii',errors='replace') if end > offset else ''
        if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,64}',value) or any(k in value.lower() for k in ('secret','token','password')):
            value = '<non-control-label redacted>'
        values.append({'va':hex(address),'label':value})
    report.append({'module':name,'control_labels':values})
rows = json.loads((ROOT/'outputs/df-local-server/protocol/pak_baseline_lua_probe.json').read_text(encoding='utf-8'))['recovered_lua_metadata']
row = next(row for row in rows if row.get('source_name') == '@LoginLogic.lua')
fn = json.loads((ROOT/'work/evidence/carved_lua'/(row['sha256']+'.json')).read_text(encoding='utf-8'))
child = exports(fn)['ConfigureWeGameServerInfo']
sentinel = child['constants'][9]
assert sentinel is None or isinstance(sentinel,(int,bool)) or sentinel == ''
report.append({'consumer':'ConfigureWeGameServerInfo','invalid_zone_sentinel':sentinel})
(ROOT/'work/evidence/bridge_control_keys.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
