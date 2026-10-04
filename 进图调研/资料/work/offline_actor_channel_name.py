"""Narrow, offline FName registration check beside the proven Control entry."""
import hashlib
import argparse
import json
import struct
from pathlib import Path

import capstone

from offline_native_code_cache import read_cached_code

ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MANIFEST_SHA = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, required=True)
    args = parser.parse_args()
    digest = hashlib.sha256()
    with args.client.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
        if digest.hexdigest() != CLIENT_SHA:
            raise ValueError('Original client identity changed')
        stream.seek(0x3c)
        pe_at = struct.unpack('<I', stream.read(4))[0]
        stream.seek(pe_at)
        header = stream.read(24)
        if header[:4] != b'PE\0\0':
            raise ValueError('Invalid PE header')
        count, optional_size = struct.unpack_from('<H', header, 6)[0], struct.unpack_from('<H', header, 20)[0]
        optional = stream.read(optional_size)
        if struct.unpack_from('<H', optional)[0] != 0x20b:
            raise ValueError('Only the pinned PE32+ client is supported')
        section_data = stream.read(count * 40)
        sections = [struct.unpack_from('<IIII', section_data, i*40+8) for i in range(count)]

        def literal(rva):
            for _, first, amount, raw_at in sections:
                if first <= rva and rva + 64 <= first + amount:
                    stream.seek(raw_at + rva - first)
                    raw = stream.read(64)
                    # These neighboring registration records explicitly set
                    # string flag0 (ANSI), not UTF16. Length is NUL bounded.
                    length = raw.index(0)
                    value = raw[:length].decode('ascii')
                    return value, hashlib.sha256(raw[:length+1]).hexdigest()
            raise ValueError('Literal is outside bounded file-backed section')

        first, length = 0x10b57000, 8192
        code = read_cached_code(ROOT/'work/native-code-cache/1790902501634810000',
                                first, length, MANIFEST_SHA)
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        disassembler.detail = True
        literals = []
        # Search only the neighboring registration range for exact RIP LEA
        # bytes, then decode from that instruction boundary. Do not label an
        # arbitrary slice start as a complete function or disassembly root.
        for at in range(len(code)-7):
            if code[at:at+3] != b'\x48\x8d\x05':
                continue
            target = first+at+7+struct.unpack_from('<i', code, at+3)[0]
            try:
                value, value_sha = literal(target)
            except (ValueError, UnicodeDecodeError):
                continue
            if value in ('Control', 'Actor', 'File', 'Voice'):
                snippet = code[at:at+192]
                literals.append({'lea_rva': hex(first+at), 'literal_rva': hex(target),
                    'text': value, 'literal_sha256': value_sha,
                    'following_code_sha256': hashlib.sha256(snippet).hexdigest(),
                    'following_code_bytes': len(snippet),
                    'asm': [f'0x{i.address:x}: {i.mnemonic} {i.op_str}'
                            for i in disassembler.disasm(snippet, first+at)]})
        record = {'kind': 'offline_adjacent_channel_name_registration',
                  'client_sha256': CLIENT_SHA, 'code_rva': hex(first), 'code_bytes': length,
                  'code_sha256': hashlib.sha256(code).hexdigest(), 'manifest_sha256': MANIFEST_SHA,
                  'literal_anchors': literals,
                  'qualification': 'Exact neighboring registration code only; channel indices require pool-store offset proof.',
                  'process_read': False, 'game_started': False, 'server_modified': False}
        actor = next((row for row in literals if row['text'] == 'Actor'), None)
        if actor is None or not all(line in actor['asm'] for line in (
                '0x10b57e29: call 0x10b77ec0',
                '0x10b57e45: mov ecx, dword ptr [rax]',
                '0x10b57e58: mov dword ptr [rbx + 0x141d8], ecx')):
            raise ValueError('Actor registration/pool-store chain changed')
        record['hardcoded_Actor_index'] = (0x141d8 - 0x14040) // 4
        record['index_proof'] = {
            'registration_call_rva': '0x10b57e29',
            'returned_comparison_id_load_rva': '0x10b57e45',
            'pool_store_rva': '0x10b57e58', 'pool_store_offset': '0x141d8',
            'from_index_lookup_rva': '0x10b630ef', 'pool_array_offset': '0x14040',
            'lookup_source': 'work/evidence/native-wire-writer-summary.json',
            'lookup_source_sha256': 'ae70c25b5826fb9f3d4c721a5ee0fb7e098ba70bc7e423612281a2d88d8ef445',
            'formula': '(0x141d8 - 0x14040)/4 = 102',
            'name_mapping_is_not_spawn_acceptance': True,
        }
        output = ROOT/'work/evidence/native-actor-channel-name-adjacent.json'
        output.write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({'record': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                          'hardcoded_Actor_index': record['hardcoded_Actor_index'],
                          'literal_anchors': [{k:v for k,v in row.items() if k != 'asm'}
                                              for row in literals]}, indent=2))


if __name__ == '__main__':
    main()
