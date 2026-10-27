"""Derive the ordinary GS mode field and enum from the pinned client."""
import hashlib
import json
import mmap
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT/'\u8fdb\u56fe\u8c03\u7814/\u5b57\u6bb5\u5143\u6570\u636e/\u8fdb\u573a\u540e\u5b57\u6bb5.json'


def derive(game_root):
    from portable_map_bootstrap import class_export, property_handle
    cache = CodeCache(ROOT/'work/native-code-cache/1792259162856698600',
        'dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754', game_root)
    archive_raw = ARCHIVE.read_bytes()
    assert hashlib.sha256(archive_raw).hexdigest() == '52ae92bc0ba8206043409c2035036e7163b1eaa6c80889dbab5333eab3ed6c27'
    record = class_export(json.loads(archive_raw), 'BP_GameState_PVPVE_C', layout=True)
    handle = property_handle(record, 'DFMGamePlayerMode', opcode=6, serializer=0x10e29fa0)
    field = record['layout']['commands'][101]
    assert (handle, field['data_offset'], field['parent_index']) == (84, 0x6e1, 33)
    facts = ((0xb742aae, 'movzx', 'eax, byte ptr [rdi + 0x6e1]'),
        (0xc2a0455, 'cmp', 'dil, 1'), (0xc2a04d5, 'call', '0xc2a09f0'),
        (0x61f2620, 'lea', 'rdx, [rip + 0x16b9fc09]'),
        (0x10ea6203, 'cmp', 'dword ptr [r14 + 0x30], r12d'),
        (0x10ea6217, 'sete', 'r9b'), (0x10ea621b, 'call', 'qword ptr [rax + 0x288]'),
        (0x10e087d9, 'lea', 'rax, [rip + 0x9d4b370]'),
        (0x10e087e0, 'mov', 'qword ptr [rbx], rax'),
        (0x10e380bc, 'cmp', 'ebx, -1'), (0x10e381d5, 'cmp', 'eax, -1'),
        (0x10e38300, 'call', '0x10e1e2d0'),
        (0x10e38309, 'lea', 'r14, [rax + 1]'),
        (0x10e3833c, 'mov', 'qword ptr [rdx + 8], r14'),
        (0x10e29faa, 'cmp', 'dword ptr [rdx + 0x54], 0xc'),
        (0x10e29fdd, 'call', '0x10e1e2d0'), (0x10e29fe2, 'inc', 'rax'),
        (0x10e2a031, 'call', 'qword ptr [rax + 0x68]'))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    verified = []
    for rva, mnemonic, operands in facts:
        ins = next(md.disasm(cache.read(rva, 16), rva, count=1))
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands)
        verified.append(dict(rva=hex(rva), mnemonic=mnemonic, operands=operands,
                             bytes=ins.bytes.hex()))
    exe = Path(game_root)/cache.manifest['plan']['client_relative_to_game_root']
    with exe.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image = ImmutableImage(mapped)
        prop = image.read(0x186f4238, 48)
        assert struct.unpack_from('<IIQ', prop, 24) == (0x1e, 0x45, 0x6e100000001)
        assert struct.unpack_from('<Q', prop, 40)[0] - image.image_base == 0x61f2610
        params = image.read(0x1cd92230, 56)
        assert struct.unpack_from('<Q', params, 32)[0] - image.image_base == 0x16928260
        assert struct.unpack_from('<4I', params, 40) == (10, 0x45, 0, 2)
        assert struct.unpack('<Q', image.read(0x1ab53dd8, 8))[0] - image.image_base == 0x10e37fb0
        entries = []
        for index in range(10):
            pointer, value = struct.unpack('<Qq', image.read(0x16928260 + index*16, 16))
            name = image.read(pointer-image.image_base, 128).split(b'\0', 1)[0].decode('ascii')
            assert name.startswith('EDFMGamePlayMode::') and 'MAX' not in name
            entries.append(dict(name=name, value=value))
        assert [r['value'] for r in entries] == list(range(10))
    return dict(kind='client_derived_gameplay_mode_schema', client_sha256=cache.manifest['client_sha256'],
        archive_metadata_sha256=hashlib.sha256(archive_raw).hexdigest(),
        field=dict(name='DFMGamePlayerMode', handle=handle, offset=field['data_offset'],
            parent_index=field['parent_index'], serializer_rva=0x10e29fa0,
            property_record_rva='0x186f4238', property_record_sha256=hashlib.sha256(prop).hexdigest()),
        enum=dict(name='EDFMGamePlayMode', entries=entries, generated_maximum=10,
            static_params_rva='0x1cd92230', static_params_sha256=hashlib.sha256(params).hexdigest(),
            maximum_source='normal_SetEnums_with_add_max_and_no_declared_MAX',
            archive_version=13, wire_bits=4),
        verified_instruction_facts=verified, native_cache_manifest_sha256=cache.manifest_sha256,
        process_pointers_reused=False, live_enum_observed=False, native_map_markers_verified=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--game-root', type=Path, required=True)
    options = parser.parse_args()
    raw = (json.dumps(derive(options.game_root), indent=2, sort_keys=True)+'\n').encode()
    output = ROOT/'outputs/df-local-server/protocol/portable-map-spawn/world-state-schema.json'
    with output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(output), sha256=hashlib.sha256(raw).hexdigest())))
