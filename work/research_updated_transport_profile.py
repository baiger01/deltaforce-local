"""Offline updated hardcoded names, archive defaults and packet configuration.

Reads saved SHA-pinned code and immutable shadow PE data only. It does not
access a process or change the active diagnostic's dependencies or gates.
"""
import argparse
import bisect
import json
import mmap
import re
import struct

import numpy as np
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from research_updated_metadata_roots import (
    ROOT, PINS, CLIENT, ForensicObservation, decoder, disasm, instruction_row, sha,
)
from research_updated_transport_roots import TransportImage, compare_full, containing_primary, locate


def rip_references(observation, image, targets):
    """Candidate displacement scan, then exact full-root instruction validation."""
    candidates = {}
    wanted = set(targets)
    for first, end, block in observation.blocks:
        observation.read(first, 1)
        raw = observation.loaded[first]
        for alignment in range(4):
            count = (len(raw)-alignment)//4
            values = np.frombuffer(raw, dtype='<i4', count=count, offset=alignment)
            after_disp = first+alignment+np.arange(count, dtype=np.int64)*4+4
            computed = values+after_disp
            for trailing in (0, 1, 2, 4, 8):
                mask = np.isin(computed+trailing, targets)
                for index in np.flatnonzero(mask):
                    pos = alignment+int(index)*4
                    for before in range(max(0, pos-12), pos):
                        ins = next(decoder().disasm(raw[before:before+15], first+before, count=1), None)
                        if ins is None:
                            continue
                        hits = [ins.address+ins.size+op.mem.disp for op in ins.operands
                                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP
                                and ins.address+ins.size+op.mem.disp in wanted]
                        if hits:
                            candidates[ins.address] = (ins, hits)
    roots, results = {}, []
    for address, (ins, hits) in sorted(candidates.items()):
        root = containing_primary(image, address)
        if root is None:
            # The two independently derived version getter leaves are exact
            # seven-byte MOV/RET bodies without exception directory entries.
            if address not in (0x10b03d50, 0x10b03e40):
                continue
            decoded = disasm(observation, address, 7)
            if len(decoded) != 2 or decoded[-1].mnemonic != 'ret':
                raise ValueError('Version getter leaf extent changed')
            root, length = address, 7
        else:
            fragments = image.fragments(root)
            length = fragments[-1][1]-root
            if length > 65536:
                continue
            if root not in roots:
                roots[root] = disasm(observation, root, length)
            decoded = roots[root]
        valid = [i for i in decoded if i.address == address and i.bytes == ins.bytes]
        if not valid:
            continue
        offset = next(i for i,x in enumerate(decoded) if x.address == address)
        results.append(dict(root_rva=hex(root), root_bytes=length, targets=list(map(hex, hits)),
            **instruction_row(ins), context=[instruction_row(i) for i in decoded[max(0,offset-5):offset+7]]))
    return results


PAIRS = [
    ('name_pool_constructor', 0x10b562d0, 0x10b55ca0),
    ('name_from_hardcoded_index', 0x10b630c0, 0x10b62a90),
    ('register_name_literal', 0x10b77ec0, 0x10b77890),
    ('engine_archive_version_default', 0x10b04350, 0x10b03d50, 7),
    ('game_archive_version_default', 0x10b04440, 0x10b03e40, 7),
    ('archive_engine_version_setter', 0x2c08e70, 0x2c08b00, 4),
    ('archive_game_version_setter', 0x147bcb0, 0x147bc40, 4),
    ('connection_constructor', 0x12b87c00, 0x12b87f50),
    ('in_bunch_constructor', 0x1283e990, 0x1283ece0),
    ('local_network_checksum', 0x10b044b0, 0x10b03eb0),
    ('project_version_string', 0x10b04e50, 0x10b04850),
    ('base_connection_initialization', 0x12b92090, 0x12b923e0),
    ('ordinary_socket_initialization_wrapper', 0x2b43bc0, 0x2b43850),
    ('alternate_base_initialization', 0x12b92900, 0x12b92c50),
    ('internal_ack_initialization_wrapper', 0x128b39f0, 0x128b3d40),
]


def unwind_inventory(image):
    known = {fragment: row[2] for row in PAIRS if len(row) == 3
             for fragment in image.fragments(row[2])}
    sections = sorted(image.sections)
    starts = [row[0] for row in sections]
    chains = []
    with CLIENT.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        for row in image.entries:
            first, size, offset = sections[bisect.bisect_right(starts, row[2])-1]
            at = offset+row[2]-first
            if not first <= row[2] < first+size or at+4 > len(raw):
                raise ValueError('Profile unwind header outside raw-backed PE')
            if raw[at] >> 3 == 4:
                tail = at+4+((raw[at+2]+1)&~1)*2
                if tail+12 > offset+size:
                    raise ValueError('Profile unwind chain outside raw-backed section')
                chains.append((row, struct.unpack_from('<III', raw, tail)))
    missing = []
    for phase in range(64):
        changed = False
        for row, parent in chains:
            if parent in known and row not in known:
                known[row] = known[parent]
                missing.append(row)
                changed = True
        if not changed:
            break
    else:
        raise ValueError('Profile unwind closure depth exceeded')
    if missing:
        raise ValueError('Detached profile function fragments were not compared')
    return dict(exception_entries_scanned=len(image.entries), chained_entries_scanned=len(chains),
        all_profile_chained_fragments_compared=True, detached_uncompared_fragments=0)


def qualify():
    old, new, image = ForensicObservation('old'), ForensicObservation('new'), TransportImage()
    functions = [compare_full(old, new, image, *row) for row in PAIRS]
    rows = {int(i['rva'], 16): i for f in functions for i in f['decoded_new_instructions']}
    witnesses = []

    def exact(label, address, expected):
        actual = rows.get(address)
        if actual is None or actual['instruction'].strip() != expected:
            raise ValueError(f'Profile witness changed: {label}: {actual}')
        result = dict(rule=label, **actual)
        witnesses.append(result)
        return result

    def datum(label, address, length):
        raw = image.read(address, length)
        section = next((r,z,o) for r,z,o in image.sections if r <= address < address+length <= r+z)
        return dict(label=label, binary=str(CLIENT), client_sha256=PINS['new'][2],
            rva=hex(address), file_offset=hex(section[2]+address-section[0]),
            bytes=length, bytes_hex=raw.hex(), sha256=sha(raw))

    registrations = []
    constructor = next(f for f in functions if f['name'] == 'name_pool_constructor')
    for name, literal, call, load, store, offset, expected in [
        ('Actor', 0x14f09aa8, 0x10b577f9, 0x10b57815, 0x10b57828, 0x141d8, 102),
        ('Control', 0x15bafc18, 0x10b58263, 0x10b5827f, 0x10b58292, 0x1443c, 255),
    ]:
        literal_source = datum(name+' literal', literal, len(name)+1)
        if bytes.fromhex(literal_source['bytes_hex']) != name.encode('ascii')+b'\0':
            raise ValueError('Updated name literal changed')
        refs = [r for r in constructor['references'] if r['kind'] == 'rip_reference'
                and r['new_target'] == hex(literal)]
        if len(refs) != 1:
            raise ValueError('Unique name literal reference required')
        index = (offset-0x14040)//4
        if index != expected or (offset-0x14040)%4:
            raise ValueError('Hardcoded name index arithmetic changed')
        exact(name+' native registration', call, 'call 0x10b77890')
        exact(name+' returned comparison ID', load, 'mov ecx, dword ptr [rax]')
        exact(name+' pool slot store', store, f'mov dword ptr [rbx + {hex(offset)}], ecx')
        at = int(refs[0]['new_instruction'], 16)
        snippet = [i for i in constructor['decoded_new_instructions']
                   if at-32 <= int(i['rva'],16) <= store]
        length_row = [i for i in snippet if i['instruction'] == f'mov dword ptr [rsp + 0x38], {len(name)}']
        ascii_flag = [i for i in snippet if i['instruction'] == 'mov byte ptr [rsp + 0x3c], 0']
        if not length_row or not ascii_flag:
            raise ValueError('Literal descriptor length/ANSI proof absent')
        registrations.append(dict(name=name, hardcoded_index=index, literal=literal_source,
            literal_reference=refs[0], pool_array_offset='0x14040', pool_store_offset=hex(offset),
            index_formula=f'({hex(offset)}-0x14040)/4={index}',
            descriptor_length_and_ansi_checked=True, full_registration_snippet=snippet))

    checks = [
        ('hardcoded index array stride4/base14040', 0x10b62abf, 'mov ecx, dword ptr [rcx + rdi*4 + 0x14040]'),
        ('connection engine getter', 0x12b88219, 'call 0x10b03d50'),
        ('connection engine archive version', 0x12b8821e, 'mov dword ptr [rdi + 0x1528], eax'),
        ('connection game getter', 0x12b88224, 'call 0x10b03e40'),
        ('connection game archive version', 0x12b88245, 'mov dword ptr [rdi + 0x152c], eax'),
        ('FIn engine version input', 0x1283ed5e, 'mov edx, dword ptr [rbx + 0x1528]'),
        ('FIn engine version setter', 0x1283ed64, 'call 0x2c08b00'),
        ('archive engine offset54', 0x2c08b00, 'mov dword ptr [rcx + 0x54], edx'),
        ('FIn game version input', 0x1283ed69, 'mov edx, dword ptr [rbx + 0x152c]'),
        ('FIn game version setter', 0x1283ed72, 'call 0x147bc40'),
        ('archive game offset58', 0x147bc40, 'mov dword ptr [rcx + 0x58], edx'),
        ('connection constructor packet max initially zero', 0x12b87fe6, 'mov dword ptr [rdi + 0xb0], esi'),
        ('socket requested packet argument', 0x2b4385a, 'mov r10d, dword ptr [rsp + 0x78]'),
        ('socket zero uses default', 0x2b43865, 'test r10d, r10d'),
        ('socket request upper check1024', 0x2b4386a, 'cmp r10d, 0x400'),
        ('socket signed request <=1024 retained', 0x2b43871, 'jle 0x2b43879'),
        ('socket default1024', 0x2b43873, 'mov r10d, 0x400'),
        ('socket default overhead28', 0x2b43880, 'mov ecx, 0x1c'),
        ('socket cap passed as base arg6', 0x2b43895, 'mov dword ptr [rsp + 0x28], r10d'),
        ('socket base initialization binding', 0x2b4389e, 'call 0x12b923e0'),
        ('base requested packet argument', 0x12b92706, 'mov eax, dword ptr [rsp + 0xe8]'),
        ('base packet max field write', 0x12b92715, 'mov dword ptr [rsi + 0xb0], eax'),
        ('alternate base upper1024', 0x12b92c71, 'cmp eax, 0x400'),
        ('alternate base default1024', 0x12b92c78, 'mov eax, 0x400'),
        ('alternate base packet max write', 0x12b92c7f, 'mov dword ptr [rcx + 0xb0], eax'),
        ('internalACK packet upper2048', 0x128b3d66, 'cmp eax, 0x800'),
        ('internalACK packet default2048', 0x128b3d6d, 'mov eax, 0x800'),
        ('internalACK mode bit', 0x128b3d72, 'or dword ptr [rbx + 0xb4], 1'),
        ('internalACK override packet max', 0x128b3d7c, 'mov dword ptr [rbx + 0xb0], eax'),
        ('checksum cached value branch', 0x10b03ebb, 'je 0x10b03ec8'),
        ('checksum optional delegate', 0x10b03f1c, 'call qword ptr [rax + 0x48]'),
        ('checksum engine version input', 0x10b04016, 'mov eax, dword ptr [rip + 0xca99e60]'),
        ('checksum game version input', 0x10b03ffe, 'mov eax, dword ptr [rip + 0xd8148d0]'),
        ('checksum project version getter', 0x10b03fdb, 'call 0x10b04850'),
    ]
    for row in checks:
        exact(*row)
    engine = datum('engine archive version file default', 0x1d59de7c, 4)
    if struct.unpack('<I', bytes.fromhex(engine['bytes_hex']))[0] != 13:
        raise ValueError('File engine archive default changed')
    engine['u32_file_default'] = 13
    constants = [engine]
    for label, address, text in [
        ('project version literal', 0x15a3bb48, '1.0.0'),
        ('project name literal', 0x1cb9bd90, 'DeltaForce'),
        ('checksum input format literal', 0x1ab0cef0, '%s %s, NetCL: %d, EngineNetVer: %d, GameNetVer: %d'),
        ('command-line override key', 0x1ab0ce88, 'networkversionoverride='),
        ('console override key', 0x1ab0ce58, 'networkversionoverride'),
    ]:
        expected = (text+'\0').encode('utf-16-le')
        record = datum(label, address, len(expected))
        if bytes.fromhex(record['bytes_hex']) != expected:
            raise ValueError('Updated network checksum/configuration literal changed')
        constants.append(dict(text=text, **record))
    constants.extend([datum('MaxPacket generated property descriptor', 0x1b5a19e0, 56),
                      datum('MaxPacket property literal', 0x1b5a1d88, 10)])
    descriptor = bytes.fromhex(constants[-2]['bytes_hex'])
    if (struct.unpack_from('<Q', descriptor)[0] != image.image_base+0x1b5a1d88
            or struct.unpack_from('<I', descriptor,32)[0] != 1
            or struct.unpack_from('<I', descriptor,36)[0] != 0xb0):
        raise ValueError('MaxPacket native property descriptor changed')

    scan_keys = re.compile(rb'MaxPacket|NetVersion|ProtocolVersion|IpNetDriver|NetConnection', re.I)
    loose_configs = []
    shadow = CLIENT.parents[2]
    for folder in (shadow/'Config', shadow/'Saved/Config'):
        for path in sorted(folder.rglob('*.ini')):
            raw = path.read_bytes()
            matches = [dict(line=i+1, text=line.decode('utf-8', errors='replace')[:240])
                       for i,line in enumerate(raw.splitlines()) if scan_keys.search(line)]
            loose_configs.append(dict(path=str(path), sha256=sha(raw), bytes=len(raw), matching_lines=matches))
    old_read = old.source_evidence()
    new_read = new.source_evidence()
    return dict(kind='updated_transport_profile_offline_qualification',
        client_sha256=PINS['new'][2], process_access=False, native_called=False,
        client_launched=False, production_sources_changed=False, protocol_acceptance=False,
        functions=functions, witnesses=witnesses, hardcoded_names=registrations,
        unwind_inventory=unwind_inventory(image),
        immutable_file_data=constants, loose_config_search=loose_configs,
        archive_version_proof=dict(engine_default_file_value=13,
            engine_default_cell_rva='0x1d59de7c', game_default_cell_rva='0x1e3188d4',
            game_cell_file_value=None, game_cell_file_value_reason='not raw-backed; live value not observed',
            connection_engine_offset='0x1528', connection_game_offset='0x152c',
            archive_engine_offset='0x54', archive_game_offset='0x58',
            engine_default_reaches_existing_current_wire_gates=True,
            runtime_connection_values_observed=False),
        cap_proof=dict(connection_max_packet_offset='0xb0',
            ordinary_wrapper_rva='0x2b43850', ordinary_zero_or_gt1024_request_becomes=1024,
            ordinary_signed_nonzero_le1024_request_retained=True,
            default_packet_overhead_bytes=28, internal_ack_default_cap=2048,
            native_universal_max_1492_proved=False, runtime_cap_observed=False),
        hello_network_checksum=dict(function_rva='0x10b03eb0',
            sources=['cached checksum', 'optional delegate override',
                'networkversionoverride command line / console variable',
                'project DeltaForce', 'project version1.0.0', 'network changelist',
                'engine archive version global', 'game archive version global'],
            hello_checksum_is_not_engine_archive_enum=True,
            updated_hello_checksum_value_qualified=False,
            old_profile_1077088301_not_requalified=True),
        limits=[
            'The old adjacent-name report is absent. Names are rederived from the updated literal/register/returned-ID/store/lookup chain and complete pinned code.',
            'Actor102 and Control255 are qualified hardcoded-name meanings, not actor/control native acceptance.',
            'File defaults and input-argument clamp rules do not observe a live connection or its concrete dynamic dispatch path.',
            'The socket wrapper clamps ordinary positive requests to at most1024; negative inputs have no positive guard in this body and are not promoted as valid configuration.',
            'Internal ACK uses a distinct2048 default and is excluded by the current wire profile.',
            'Loose INI search is bounded to shadow Config and Saved/Config. Absence of a key does not exclude cooked configuration or runtime overrides.',
            'Version getters and checksum code are unchanged outside references. A current Hello checksum still requires actual new-client evidence; archive enum13 cannot replace it.',
            'No process inspection, memory write, launch, runtime helper edit or production gate change was made.',
        ], source_observations=[old_read,new_read],
        prior_wire_core_qualification=dict(path='work/research_updated_transport_79fb7b10.json',
            sha256=sha((ROOT/'work/research_updated_transport_79fb7b10.json').read_bytes())),
        source_scripts=[dict(path=p, sha256=sha((ROOT/p).read_bytes())) for p in (
            'work/research_updated_transport_profile.py', 'work/research_updated_transport_roots.py',
            'work/research_updated_metadata_roots.py', 'work/research_updated_replication_core.py')])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refs', nargs='+', type=lambda x:int(x, 0))
    parser.add_argument('--qualify', action='store_true')
    args = parser.parse_args()
    if args.qualify:
        result = qualify()
        output = ROOT/'work/research_updated_transport_profile_79fb7b10.json'
        raw = (json.dumps(result, indent=2)+'\n').encode('utf-8')
        output.write_bytes(raw)
        print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), sha256=sha(raw),
            functions=len(result['functions']), witnesses=len(result['witnesses']),
            hardcoded_names={r['name']:r['hardcoded_index'] for r in result['hardcoded_names']},
            protocol_acceptance=False)))
        return
    new, image = ForensicObservation('new'), TransportImage()
    if args.refs:
        print(json.dumps(rip_references(new, image, args.refs), indent=2))


if __name__ == '__main__':
    main()
