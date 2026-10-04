"""Inspect only seven fixed, named StatelessConnect binding code ranges."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone

SAMPLES = {
    'ds-class-registration.dfcode': (0x13115880, 84),
    'ds-binding-finalizer.dfcode': (0x131162c0, 84),
    'ds-init-from-connectionless.dfcode': (0x1313e540, 16),
    'ds-passed-challenge.dfcode': (0x1313e630, 157),
    'ds-restarted-match.dfcode': (0x1313f120, 96),
    'ds-set-driver.dfcode': (0x1313f500, 16),
    'ds-restart-handshake.dfcode': (0x1313f580, 48),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('trial_directory', type=Path)
    args = parser.parse_args()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    summaries = []
    for name, (rva, size) in SAMPLES.items():
        data = (args.trial_directory / name).read_bytes()
        assert len(data) == size + 32
        magic, actual_rva, actual_size, _private_module_base = struct.unpack('<4Q', data[:32])
        assert magic == 0x0000000145444344 and (actual_rva, actual_size) == (rva, size)
        instructions = list(decoder.disasm(data[32:], rva))
        output = args.trial_directory / (name + '.asm.txt')
        output.write_text('\n'.join(
            f'{i.address:08x} {i.mnemonic:8} {i.op_str}' for i in instructions) + '\n',
            encoding='utf-8')
        summaries.append({'sample': name, 'rva': hex(rva), 'code_bytes': size,
            'code_sha256': hashlib.sha256(data[32:]).hexdigest(),
            'linear_decoded_bytes': sum(i.size for i in instructions),
            'disassembly': output.name})
    report = {'samples': summaries, 'code_bytes': sum(x[1] for x in SAMPLES.values()),
        'handshake_wire_format_verified': False, 'gameplay_server_implemented': False}
    (args.trial_directory / 'ds-binding-code-summary.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
