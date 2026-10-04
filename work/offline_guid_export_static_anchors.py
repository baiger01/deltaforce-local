"""Bounded immutable GUID export registration and static slot anchors."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
from offline_post_join_typed_method_anchors import text_at, file_rva

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
CACHE = ROOT / 'work/native-code-cache/1790902501634810000'


def main():
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Immutable identity mismatch')
    result = {'client_sha256': SOURCE_SHA, 'cache_manifest_sha256': PIN,
              'process_accessed': False, 'game_launched': False, 'anchors': []}
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        leaf = validated_range(CACHE, 0x133901e0, 24, PIN)
        instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(leaf, 0x133901e0))
        result['constructor_callback_fixed_prefix'] = {
            'rva': '0x133901e0', 'prefix_bytes': len(leaf), 'prefix_sha256': sha(leaf),
            'instructions': [f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions]}
        leaf = validated_range(CACHE, 0x11d8730, 24, PIN)
        instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(leaf, 0x11d8730))
        result['append_export_typed_adapter_fixed_prefix'] = {
            'rva': '0x11d8730', 'prefix_bytes': len(leaf), 'prefix_sha256': sha(leaf),
            'instructions': [f'0x{i.address:x}: {i.mnemonic} {i.op_str}' for i in instructions]}
        for name in ['AppendExportBunches', 'NotifyBunchCommit', 'NotifyAck', 'NotifyNak',
                     'ReceiveNetGUIDBunch', 'PackageMapClient']:
            for encoding in ['ascii', 'utf-16le']:
                token = name.encode(encoding) + (b'\0' if encoding == 'ascii' else b'\0\0')
                start = 0
                matches = []
                while True:
                    pos = mapped.find(token, start)
                    if pos < 0:
                        break
                    start = pos + len(token)
                    for section in image.sections:
                        base, raw_size, raw, virtual_size = section
                        if raw <= pos < raw + raw_size:
                            matches.append(hex(base + pos - raw))
                            break
                result['anchors'].append({'literal': name, 'encoding': encoding, 'rvas': matches})
        result['candidate_package_map_static_slots'] = []
        for table in [0x15a68ec0, 0x15a691d8, 0x15a694f0]:
            for slot in range(0x240, 0x318, 8):
                ptr = struct.unpack('<Q', image.read(table + slot, 8))[0]
                result['candidate_package_map_static_slots'].append({
                    'table_rva': hex(table), 'slot': hex(slot), 'target_rva': hex(ptr - image.image_base)})
        result['append_export_typed_records'] = []
        pointer = struct.pack('<Q', image.image_base + 0x1b3e9548)
        offset = -1
        while True:
            offset = mapped.find(pointer, offset + 1)
            if offset < 0:
                break
            if offset % 8:
                continue
            words = struct.unpack_from('<6Q', mapped, offset)
            if not 0 < words[5] <= 8 or text_at(image, words[3]) is None:
                continue
            try:
                args = struct.unpack('<' + 'Q' * words[5], image.read(words[4] - image.image_base, words[5] * 8))
            except ValueError:
                continue
            arg_types = [text_at(image, value) for value in args]
            if any(value is None for value in arg_types):
                continue
            result['append_export_typed_records'].append({'record_rva': hex(file_rva(image, offset)),
                'words': [hex(value) for value in words], 'return_type': text_at(image, words[3]),
                'argument_types': arg_types})
    out = ROOT / 'work/evidence/native-guid-export-static-anchors.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))
    print(json.dumps({'path': str(out), 'sha256': sha(out.read_bytes())}))


if __name__ == '__main__':
    main()
