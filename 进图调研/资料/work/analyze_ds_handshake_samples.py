"""Disassemble only the four fixed named DS code samples in a private trial."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import capstone

SAMPLES = {
    'ds-notify-handshake-binding.dfcode': (0x13ab170, 16),
    'ds-cookie-getter.dfcode': (0x1313f670, 85),
    'ds-challenge-sequence.dfcode': (0x1313f030, 217),
    'ds-reset-challenge.dfcode': (0x1313f360, 129),
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('trial_directory', type=Path)
    args = parser.parse_args()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    summaries = []
    for name, (rva, size) in SAMPLES.items():
        data = (args.trial_directory / name).read_bytes()
        magic, actual_rva, actual_size, _private_module_base = struct.unpack('<4Q', data[:32])
        assert magic == 0x0000000145444344 and (actual_rva, actual_size) == (rva, size)
        assert len(data) == size + 32
        instructions = list(decoder.disasm(data[32:], rva))
        rendered = '\n'.join(f'{i.address:08x} {i.mnemonic:8} {i.op_str}' for i in instructions) + '\n'
        output = args.trial_directory / (name + '.asm.txt')
        output.write_text(rendered, encoding='utf-8')
        summaries.append({'sample': name, 'rva': hex(rva), 'code_bytes': size,
                          'code_sha256': hashlib.sha256(data[32:]).hexdigest(),
                          'linear_decoded_bytes': sum(i.size for i in instructions),
                          'disassembly': output.name})
    (args.trial_directory / 'ds-code-summary.json').write_text(
        json.dumps(summaries, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summaries, indent=2))
