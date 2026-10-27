"""Read fixed native switch-frame enum records from the qualified local PE."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

from offline_received_packet_xrefs import ImmutableImage

ROOT = Path(__file__).resolve().parent.parent
CLIENT_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
RECORDS = {
    'Operation': 0x1cd621c0,
    'SwitchType': 0x1caca698,
    'SwitchWeaponContext': 0x1caca430,
}


def derive(executable):
    result = dict(kind='offline_owned_weapon_switch_timeline_enums_v1',
        client_sha256=CLIENT_SHA, process_access=False, client_launched=False,
        native_methods_invoked=False, enums={})
    with Path(executable).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != CLIENT_SHA:
            raise ValueError('The source-qualified image changed')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            image = ImmutableImage(data)
            for field, rva in RECORDS.items():
                raw = image.read(rva, 56)
                pointer = struct.unpack_from('<Q', raw, 32)[0] - image.image_base
                count, flags, _, form = struct.unpack_from('<4I', raw, 40)
                if flags != 0x45 or form != 2 or not 1 <= count <= 256:
                    raise ValueError('The fixed FEnumParams changed')
                pairs = image.read(pointer, count * 16)
                entries = []
                for start in range(0, len(pairs), 16):
                    text_at, value = struct.unpack_from('<Qq', pairs, start)
                    name = image.read(text_at - image.image_base, 256).split(b'\0', 1)[0].decode('ascii')
                    if '::' not in name or not 0 <= value <= 255:
                        raise ValueError('The fixed switch-frame enum changed')
                    entries.append(dict(name=name, value=value))
                maximum = max(row['value'] for row in entries)
                generated = not any(row['value'] == maximum and
                    row['name'].rsplit('::', 1)[1].endswith('_MAX') for row in entries)
                maximum += int(generated)
                result['enums'][field] = dict(entries=entries,
                    generated_maximum=maximum, generated_max_added=generated,
                    network_version=13, wire_bits=maximum.bit_length(),
                    params_rva=hex(rva), params_sha256=hashlib.sha256(raw).hexdigest(),
                    pairs_rva=hex(pointer), pairs_sha256=hashlib.sha256(pairs).hexdigest())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / 'work/evidence'):
        parser.error('Use a fresh evidence output')
    encoded = (json.dumps(derive(args.exe), indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(encoded).hexdigest())))
