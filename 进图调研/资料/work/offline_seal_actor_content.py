"""Validate and seal the current build's Actor content-block envelope, disk only."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
CACHE = ROOT / 'work/native-code-cache/1790902501634810000'
SOURCE_FILES = ('native-actor-content-header-initial-roots.json',
                'native-actor-content-parse-initial-roots.json',
                'native-post-join-actor-prerequisites.json')


def main():
    folder, manifest, manifest_sha = cache.validate_manifest(CACHE, PIN)
    if not manifest['complete']:
        raise ValueError('Incomplete cache')
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    sources, records, logs, slots = [], [], [], []
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Shipping identity mismatch')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            for name in SOURCE_FILES:
                path = ROOT / 'work/evidence' / name
                raw = path.read_bytes()
                source = json.loads(raw)
                if source['client_sha256'] != SOURCE_SHA:
                    raise ValueError('Wrong source image')
                sources.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(raw)})
                rows = (source['complete_function_groups']['ActorChannel_ProcessBunch']['fragments']
                        if name.endswith('prerequisites.json') else source['roots'])
                for record in rows:
                    begin = int(record['begin'], 16)
                    if begin not in (0x12863600, 0x12864a10, 0x10b4cee0,
                                      0x128611e0, 0x12861215, 0x12861dda,
                                      0x12861e63, 0x128620bb, 0x1286241c, 0x12862434):
                        continue
                    raw_code = (ROOT / record['code_relative_path']).read_bytes()
                    magic, version, rva, size, base = struct.unpack('<4sIQQQ', raw_code[:32])
                    if (magic, version, rva, size, base) != (b'DCDE', 1, begin, record['bytes'], image.image_base):
                        raise ValueError('Saved code header mismatch')
                    code = raw_code[32:]
                    if (len(code) != size or sha(raw_code) != record['file_sha256'] or
                            sha(code) != record['code_sha256'] or
                            validated_range(folder, begin, size, PIN) != code):
                        raise ValueError('Saved code/cache SHA mismatch')
                    asm = (ROOT / record['asm_relative_path']).read_bytes()
                    if sha(asm) != record['asm_sha256']:
                        raise ValueError('Assembly identity mismatch')
                    row = image.containing(begin)
                    actual = image.unwind(row)
                    if any(actual[k] != record[k] for k in actual):
                        raise ValueError('Unwind bounds/metadata mismatch')
                    decoded = list(decoder.disasm(code, begin))
                    if not decoded or sum(i.size for i in decoded) != len(code):
                        raise ValueError('Incomplete linear decode')
                    record = dict(record)
                    record['validation'] = 'header/file/code/asm/immutable-pdata/cache/full-decode'
                    records.append(record)
                    for i in decoded:
                        if i.mnemonic != 'lea':
                            continue
                        for op in i.operands:
                            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                                continue
                            target = i.address + i.size + op.mem.disp
                            try:
                                raw_literal = image.read(target, 768)
                            except ValueError:
                                continue
                            finish = next((at for at in range(0, len(raw_literal), 2)
                                           if raw_literal[at:at+2] == b'\0\0'), None)
                            if finish is None or finish < 8:
                                continue
                            raw_literal = raw_literal[:finish+2]
                            try:
                                text = raw_literal[:-2].decode('utf-16-le')
                            except UnicodeDecodeError:
                                continue
                            if not any(word in text for word in ('ContentBlock', 'ProcessBunch', 'RepLayout')):
                                continue
                            logs.append({'instruction_rva': hex(i.address), 'bytes_hex': i.bytes.hex(),
                                         'literal_rva': hex(target), 'literal_bytes': len(raw_literal),
                                         'sha256': sha(raw_literal), 'utf16': text})
            for offset, expected in ((0x68, 0xe509a0), (0x78, 0x10b4c190)):
                raw_slot = image.read(0x1b148470 + offset, 8)
                if struct.unpack('<Q', raw_slot)[0] - image.image_base != expected:
                    raise ValueError('Concrete FInBunch reader virtual binding mismatch')
                slots.append({'table_rva': '0x1b148470', 'slot': hex(offset),
                              'target_rva': hex(expected), 'bytes_hex': raw_slot.hex(),
                              'sha256': sha(raw_slot)})
    result = {'kind': 'native_actor_content_block_envelope', 'client_sha256': SOURCE_SHA,
              'cache_manifest_sha256': manifest_sha, 'sources': sources, 'verified_fragments': records,
              'exact_immutable_log_refs': logs,
              'concrete_inbunch_reader_slots': slots,
              'actor_selector_true_order': [
                  {'field': 'rep_layout', 'wire': 'one LSB bit, no alignment',
                   'evidence': ['12863656..1286369e read', '128636a5 store r9 output',
                                '12861a38/12861a5f pass to replicator virtual+28']},
                  {'field': 'actor_selector', 'wire': 'one LSB bit, must be true in restricted codec',
                   'evidence': ['12863714..1286375f read',
                                '128637d1..128637da true returns channel+70 Actor; no object GUID here']},
                  {'field': 'payload_bit_count', 'wire': 'packed uint32 at current bit cursor',
                   'evidence': ['12864b00..12864b0f archive.v78']},
                  {'field': 'payload', 'wire': 'exact preceding bit_count bits, no padding alignment',
                   'evidence': ['12864bb9..12864bc4 ->10b4cee0',
                                '10b4cf03 resets output position,10b4cf63 bit_count,10b4cf7b source.v68']}
              ],
              'sequence_end': {'wire': 'parent bunch EOF, no dedicated end marker in this layer',
                               'anchors': ['12861961/69 initial EOF gate', '12861dc8..12861dd0 loop EOF gate'],
                               'zero_payload': '128619c5..128619cc skips body;12861daa cleanup then EOF loop'},
              'subobject_selector_false': {'supported': False,
                    'physical_order': ['packageMap.v260 object reference @12863812',
                                       'when client-receive path, one bit @12863d89..12863db2',
                                       'when that bit false, packageMap.v260 class reference @12863f4b'],
                    'qualifier': 'client/server driver role, deletion, class validation/creation branches differ; no generic false-selector codec yet'},
              'replication_boundary': {'body_is_opaque': True,
                    'call': '12861a5f virtual+28 on per-object replicator returned by12853830',
                    'unknown': ['replicator concrete game override', 'class-dependent RepLayout/property handles',
                                'RPC field exports/parameters', 'Pawn/PlayerController references/OnRep delivery'],
                    'no_empty_body_claim': 'an empty block is framing only; not possession or ready-stage notification'},
              'policy': {'process_accessed': False, 'game_launched': False, 'live_heap_read': False,
                         'server_modified': False, 'native_acceptance': False, 'playable_map': False}}
    out = ROOT / 'work/evidence/native-actor-content-block-envelope.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'path': out.relative_to(ROOT).as_posix(), 'sha256': sha(out.read_bytes()),
                      'verified_fragments': len(records), 'exact_log_ref_count': len(logs)}))


if __name__ == '__main__':
    main()
