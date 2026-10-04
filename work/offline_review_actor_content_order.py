"""Pinned disk-only Actor-open/content ordering and local codec audit proof."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha
import offline_native_code_cache as cache

PIN = '0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf'
CACHE = ROOT / 'work/native-code-cache/1790902501634810000'


def main():
    folder, manifest, pin = cache.validate_manifest(CACHE, PIN)
    if not manifest['complete']:
        raise ValueError('Incomplete native cache')
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    sources, records, decoded, slots = [], [], {}, []
    with CLIENT.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SOURCE_SHA:
            raise ValueError('Shipping SHA mismatch')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            for name in ('native-post-join-actor-prerequisites.json',
                         'native-post-join-init-new-actor-roots.json',
                         'native-post-join-pc-open-rotator-full-roots.json',
                         'native-package-map-client-constructor.json'):
                path = ROOT / 'work/evidence' / name
                raw = path.read_bytes()
                source = json.loads(raw)
                if source['client_sha256'] != SOURCE_SHA:
                    raise ValueError('Source image mismatch')
                sources.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(raw)})
                if name.endswith('prerequisites.json'):
                    rows = source['complete_function_groups']['ActorChannel_ProcessBunch']['fragments']
                else:
                    rows = source['roots']
                for row in rows:
                    begin = int(row['begin'], 16)
                    if name.endswith('pc-open-rotator-full-roots.json') and begin != 0x12d4ddb0:
                        continue
                    blob = (ROOT / row['code_relative_path']).read_bytes()
                    header = struct.unpack('<4sIQQQ', blob[:32])
                    if header != (b'DCDE', 1, begin, row['bytes'], image.image_base):
                        raise ValueError('Native code header mismatch')
                    code = blob[32:]
                    if (len(code) != row['bytes'] or sha(blob) != row['file_sha256'] or
                            sha(code) != row['code_sha256'] or
                            validated_range(folder, begin, len(code), PIN) != code):
                        raise ValueError('Native file/code/cache SHA mismatch')
                    if sha((ROOT / row['asm_relative_path']).read_bytes()) != row['asm_sha256']:
                        raise ValueError('Native asm SHA mismatch')
                    if any(row[k] != v for k, v in image.unwind(image.containing(begin)).items()):
                        raise ValueError('Native pdata/unwind mismatch')
                    instructions = list(decoder.disasm(code, begin))
                    if sum(i.size for i in instructions) != len(code):
                        raise ValueError('Native incomplete decode')
                    decoded.update((i.address, i) for i in instructions)
                    records.append(dict(row, validation='header/code/file/asm/cache/pdata/full-decode'))
            for table, slot, expected in ((0x1b148d18, 0x308, 0x1286ed70),
                                          (0x1b148d18, 0x310, 0x1285dd90),
                                          (0x15a68ec0, 0x288, 0x12bcb060),
                                          (0x1b221ff0, 0x3d8, 0x12d4ddb0)):
                raw = image.read(table + slot, 8)
                if struct.unpack('<Q', raw)[0] - image.image_base != expected:
                    raise ValueError('Static virtual slot mismatch')
                slots.append({'table_rva': hex(table), 'slot': hex(slot),
                              'target_rva': hex(expected), 'bytes_hex': raw.hex(), 'sha256': sha(raw)})
            # Exact initialization root assigning the ActorChannel static table.
            ctor = image.unwind(image.containing(0x1283fbc0))
            code = validated_range(folder, 0x1283fbc0, ctor['bytes'], PIN)
            instructions = list(decoder.disasm(code, 0x1283fbc0))
            if sum(i.size for i in instructions) != len(code):
                raise ValueError('Constructor incomplete decode')
            decoded.update((i.address, i) for i in instructions)
            ctor.update(code_sha256=sha(code), full_decode=True,
                        instructions=[{'rva': hex(i.address), 'bytes_hex': i.bytes.hex(),
                                       'asm': i.mnemonic+' '+i.op_str} for i in instructions])

    required = {
        0x1283fbca: ('mov', 'rbx, rcx'),
        0x1283fbdc: ('lea', 'rax, [rip + 0x8909135]'),
        0x1283fbe7: ('mov', 'qword ptr [rbx], rax'),
        0x128613c3: ('call', 'qword ptr [rax + 0x288]'),
        0x128614cf: ('call', 'qword ptr [rax + 0x308]'),
        0x128614e2: ('call', 'qword ptr [rax + 0x310]'),
        0x128614f9: ('jmp', '0x128618a5'),
        0x1285dda5: ('mov', 'r12, r8'),
        0x1285de74: ('mov', 'rdx, r12'),
        0x1285de7e: ('call', 'qword ptr [rax + 0x3d8]'),
        0x12d4dde3: ('mov', 'byte ptr [rdi + 0x524], al'),
        0x12d4de05: ('call', 'qword ptr [rax + 0x60]'),
        0x12861961: ('call', 'qword ptr [rax + 0xb0]'),
        0x128619b2: ('call', '0x12864a10'),
        0x12861a5f: ('call', 'qword ptr [r10 + 0x28]'),
        0x12861dc8: ('call', 'qword ptr [rax + 0xb0]'),
        0x12861dd0: ('je', '0x12861970'),
    }
    anchors = []
    for rva, expected in required.items():
        i = decoded[rva]
        if (i.mnemonic, i.op_str) != expected:
            raise ValueError('Ordering anchor differs at '+hex(rva))
        anchors.append({'rva': hex(rva), 'bytes_hex': i.bytes.hex(),
                        'asm': i.mnemonic+' '+i.op_str})
    code_path = ROOT / 'outputs/df-local-server/dfserver/legacy_ds_actor_content.py'
    test_path = ROOT / 'outputs/df-local-server/tests/test_legacy_ds_actor_content.py'
    result = {
        'kind': 'pinned_actor_open_before_content_order_and_codec_review',
        'client_sha256': SOURCE_SHA, 'cache_manifest_sha256': pin,
        'sources': sources, 'verified_fragments': records, 'static_slots': slots,
        'actor_channel_initialization_root': ctor, 'exact_anchors': anchors,
        'ordered_same_bunch_cursor': [
            '128613c3 PackageMap.v288 SerializeNewActor(FInBunch=r15)',
            '128614cf ActorChannel.v308 sets Actor;128614e2 v310 receives same r15',
            '1285dda5 retains FInBunch inr12;1285de74 passes it toActor.v3d8 at1285de7e',
            'Base PlayerController.v3d8 reads one rawu8 at12d4dde3 or12d4de05',
            'v310 return→128614f9 jump128618a5→EOF gate12861961',
            '128619b2 direct ReadContentBlockPayload receives original r15;no reset/alignment',
            '12861a5f sends isolated bodyreader toreplicator.v28',
            '12861dc8 EOF gate;12861dd0 loops while remaining bits'],
        'qualification': [
            'This is the proven native base ActorChannel/PackageMap/PlayerController path;static tables do not prove a runtime game override.',
            'The optional PC index0 tail requires the caller explicitly selecting the supported base-PC-open profile.',
            'Content sequence consumes exact parent EOF;zero payload is framing,not a terminal marker.',
            'Opaque property/RPC bodies do not prove possession,world synchronization,native acceptance,or playable map.'],
        'codec_review': {
            'source_sha256': sha(code_path.read_bytes()), 'tests_sha256': sha(test_path.read_bytes()),
            'findings': [],
            'verified_boundaries': [
                'Read length budget precedes payload allocation;operation total measured from caller cursor.',
                'Read failure restores original cursor,including malformed second block and false selector.',
                'Write stages every block then makes one bounded atomic write_payload commit.',
                'Fixed max256 blocks,8192byte archive,and exact payload high-bit/length guards.',
                'Single read preserves tail;sequence requires exact content EOF excluding padding.',
                'Zero-bit block is legal10bits and advances cursor;does not make loop stall.'],
            'native_acceptance': False},
        'policy': {'process_accessed': False, 'game_launched': False,
                   'live_heap_read': False, 'existing_files_modified': False}}
    out = ROOT / 'work/evidence/native-actor-content-open-order-review.json'
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'evidence': out.relative_to(ROOT).as_posix(), 'sha256': sha(out.read_bytes()),
                      'fragments': len(records), 'order_anchors': len(anchors), 'codec_findings':0}))


if __name__ == '__main__':
    main()
