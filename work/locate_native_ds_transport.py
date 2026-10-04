"""Read-only named DS transport references; never load or edit the client."""
from pathlib import Path
import bisect
import hashlib
import json
import mmap
import re
import struct
import pefile

ROOT = Path(__file__).resolve().parent.parent
CLIENT = Path('D:/个人工作区/DeltaForce-local-client/DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe')
PIN = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
MARKERS = ('StatelessConnectHandlerComponent', 'SendInitialPacket', 'SendChallengeResponse',
           'SendChallengeAck', 'SendConnectChallenge', 'PacketHandler component',
           'ReliabilityHandlerComponent', 'EncryptionHandlerComponent', 'DFNetDriver')

with CLIENT.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == PIN
    with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        pe = pefile.PE(data=raw, fast_load=True)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        table = pe.get_data(directory.VirtualAddress, directory.Size)
        ranges = [struct.unpack_from('<III', table, at) for at in range(0, len(table), 12)]
        starts = [row[0] for row in ranges]
        findings = []
        targets = {}
        for marker in MARKERS:
            for encoding in ('ascii', 'utf-16le'):
                needle = marker.encode(encoding)
                cursor = 0
                while True:
                    at = raw.find(needle, cursor)
                    if at < 0:
                        break
                    cursor = at + len(needle)
                    try:
                        rva = pe.get_rva_from_offset(at)
                    except pefile.PEFormatError:
                        continue
                    targets[rva] = marker
                    findings.append({'marker': marker, 'encoding': encoding, 'string_rva': hex(rva)})
        references = []
        for section in pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            data = section.get_data()
            # LEA reg,[RIP+disp32], restricted to a named string destination.
            for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]([\s\S]{4})', data):
                at = section.VirtualAddress + match.start()
                target = at + 7 + struct.unpack('<i', match[1])[0]
                if target not in targets:
                    continue
                index = bisect.bisect_right(starts, at) - 1
                if index < 0 or not ranges[index][0] <= at < ranges[index][1]:
                    continue
                begin, end, unwind = ranges[index]
                references.append({'marker': targets[target], 'reference_rva': hex(at),
                                   'function_rva': hex(begin), 'fragment_bytes': end - begin,
                                   'unwind_rva': hex(unwind), 'static_code_may_be_encoded': True})
        # Independently identified native binding records consist of six qwords:
        # method name, implementation, invoker, return type, argument types, count.
        # Read only the adjacent class table pinned by the Shipping hash.
        methods = []
        for at in range(0x1b2c8980, 0x1b2c8bc0, 48):
            name_va, implementation, _, _, arguments, count = struct.unpack(
                '<6Q', pe.get_data(at, 48))
            def label(va):
                rva = va - pe.OPTIONAL_HEADER.ImageBase
                if not 0 <= rva < pe.OPTIONAL_HEADER.SizeOfImage:
                    return None
                value = pe.get_data(rva, 140).split(b'\0', 1)[0].decode('ascii', 'replace')
                return value if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_ :*<>~]{0,138}', value) else None
            name = label(name_va)
            if name is None or not 1 <= count <= 8:
                continue
            arguments_rva = arguments - pe.OPTIONAL_HEADER.ImageBase
            if not 0 <= arguments_rva < pe.OPTIONAL_HEADER.SizeOfImage:
                continue
            types = [label(va) for va in struct.unpack(
                '<' + 'Q' * count, pe.get_data(arguments_rva, count * 8))]
            if types[0] != 'StatelessConnectHandlerComponent *':
                continue
            methods.append({'method': name, 'record_rva': hex(at),
                            'implementation_rva': hex(implementation - pe.OPTIONAL_HEADER.ImageBase),
                            'argument_types': types})
        expected = {'NotifyHandshakeBegin': '0x13ab170', 'GetCookie': '0x1313f670',
                    'GetChallengeSequence': '0x1313f030', 'ResetChallengeData': '0x1313f360'}
        assert all(any(m['method'] == name and m['implementation_rva'] == rva
                       for m in methods) for name, rva in expected.items())
        report = {'client_relative_to_game_root': 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe',
                  'client_sha256': PIN, 'client_modified': False, 'strings': findings,
                  'references': references, 'named_handshake_methods': methods,
                  'handshake_packet_layout_verified': False}
        (ROOT / 'work/evidence/native_ds_transport_locations.json').write_text(
            json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
