"""Static, selected-literal lookup; never loads or modifies launcher code."""
from pathlib import Path
import hashlib
import json
import struct
import pefile

ROOT = Path(__file__).resolve().parent.parent
folder = ROOT / 'work/official-standalone-launcher'
needles = ['tpf_ui.vfs', 'PathCfg', 'URLFile', 'LocalizationFile', 'url.xml', 'usevfs', 'LoadStr']
records = []
for path in sorted(folder.rglob('*')):
    if path.suffix.lower() not in {'.dll', '.exe'}:
        continue
    raw = path.read_bytes()
    found = []
    for text in needles:
        for encoding in ('utf-8', 'utf-16le'):
            needle = text.encode(encoding) + (b'\0' if encoding == 'utf-8' else b'\0\0')
            position = raw.find(needle)
            while position >= 0:
                found.append((text, encoding, position))
                position = raw.find(needle, position + len(needle))
    if not found:
        continue
    pe = pefile.PE(data=raw)
    base = pe.OPTIONAL_HEADER.ImageBase
    matches = []
    for text, encoding, position in found:
        va = base + pe.get_rva_from_offset(position)
        references = []
        if va < 2**32:
            pointer = struct.pack('<I', va)
            for section in pe.sections:
                if not section.Characteristics & 0x20000000:
                    continue
                start, size = section.PointerToRawData, section.SizeOfRawData
                at = raw.find(pointer, start, start + size)
                while at >= 0:
                    references.append(hex(base + pe.get_rva_from_offset(at)))
                    at = raw.find(pointer, at + 4, start + size)
        matches.append({'literal': text, 'encoding': encoding, 'address': hex(va), 'code_pointer_references': references})
    records.append({'module': path.relative_to(folder).as_posix(), 'sha256': hashlib.sha256(raw).hexdigest(), 'matches': matches})
(ROOT / 'work/evidence/official_resource_loader_references.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
print(json.dumps(records, indent=2))
