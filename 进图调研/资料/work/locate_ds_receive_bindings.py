"""Read only native reflection records for the pinned DS transport classes.

This locates named implementations in the installed file without loading it,
reading process memory, or changing the game. Encoded code is not disassembled
or treated as a verified implementation here. No session values are inspected.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import pefile

ROOT = Path(__file__).resolve().parent.parent
PIN = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
TYPES = ('UGPNetConnection *', 'UGPNetDriver *', 'UIpNetConnection *', 'UIpNetDriver *',
         'UDualChannelIpNetConnection *', 'UDualNetConnection *', 'UGPFakeNetConnection *',
         'UNetConnection *')


def locate(path):
    with path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != PIN:
            raise ValueError('Client version hash mismatch')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            pe = pefile.PE(data=raw, fast_load=True)
            base, size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
            data_sections = [section for section in pe.sections
                             if not section.Characteristics & 0x20000000 and section.SizeOfRawData]
            executable_ranges = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize)
                                 for s in pe.sections if s.Characteristics & 0x20000000]

            def executable(va):
                return any(first <= va-base < last for first, last in executable_ranges)

            def label(va):
                if not base <= va < base + size:
                    return None
                value = pe.get_data(va-base, 140).split(b'\0', 1)[0].decode('ascii', 'replace')
                return value if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_ :*<>~,&]{0,138}', value) else None

            def references(va):
                needle = struct.pack('<Q', va)
                for section in data_sections:
                    at, end = section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData
                    while True:
                        hit = raw.find(needle, at, end)
                        if hit < 0:
                            break
                        at = hit + len(needle)
                        if hit % 8 == 0:
                            yield section.VirtualAddress + hit - section.PointerToRawData

            result = []
            for typename in TYPES:
                labels, at = [], 0
                needle = typename.encode() + b'\0'
                while True:
                    hit = raw.find(needle, at)
                    if hit < 0:
                        break
                    at = hit + len(needle)
                    if hit and raw[hit-1] != 0:
                        continue
                    labels.append(pe.get_rva_from_offset(hit))
                    if len(labels) > 32:
                        raise ValueError('Transport type label bound exceeded')
                methods, seen = [], set()
                for label_rva in labels:
                    for args_rva in references(base + label_rva):
                        # First argument of a reflected instance method is its
                        # class pointer. Follow only tables starting at that slot.
                        for args_reference in references(base + args_rva):
                            record_rva = args_reference - 32
                            if record_rva in seen or record_rva < 0:
                                continue
                            seen.add(record_rva)
                            row = pe.get_data(record_rva, 48)
                            if len(row) != 48:
                                continue
                            name, implementation, invoker, returns, arguments, count = struct.unpack('<6Q', row)
                            if arguments != base + args_rva or not 1 <= count <= 16:
                                continue
                            if not executable(implementation) or not executable(invoker):
                                continue
                            method = label(name)
                            raw_args = pe.get_data(args_rva, count * 8)
                            if method is None or len(raw_args) != count * 8:
                                continue
                            types = [label(va) for va in struct.unpack('<' + 'Q' * count, raw_args)]
                            if types[0] != typename or any(value is None for value in types):
                                continue
                            methods.append({'method': method, 'record_rva': hex(record_rva),
                                            'implementation_rva': hex(implementation-base),
                                            'invoker_rva': hex(invoker-base), 'return_type': label(returns),
                                            'argument_types': types, 'runtime_code_verified': False})
                            if len(methods) > 256:
                                raise ValueError('Transport method bound exceeded')
                result.append({'class_argument_type': typename, 'type_label_rvas': list(map(hex, labels)),
                               'named_methods': sorted(methods, key=lambda item: item['method'])})
    return {'kind': 'static_ds_transport_named_bindings',
            'client_relative_to_game_root': 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe',
            'client_sha256': PIN, 'client_modified': False, 'process_memory_read': False,
            'reflection_record_layout': 'six qwords: name, implementation, invoker, return type, arguments, count',
            'runtime_code_may_be_encoded': True, 'incoming_transform_identified': False, 'classes': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root', type=Path, required=True)
    args = parser.parse_args()
    report = locate(args.game_root / 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
    output = ROOT / 'work/evidence/ds_receive_named_bindings.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': output.relative_to(ROOT).as_posix(),
                      'classes': [{'type': item['class_argument_type'],
                                   'named_methods': len(item['named_methods'])} for item in report['classes']],
                      'incoming_transform_identified': False}, indent=2))
