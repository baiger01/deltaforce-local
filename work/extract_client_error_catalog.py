"""Recover client error constants from Lua assignments without executing Lua."""

import hashlib
import json
from pathlib import Path

from lua53_reader import CLIENT_OPS, Reader, instruction


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'work/evidence/weapon_lua/errcode_pb.lua'
OUTPUT = ROOT / 'outputs/df-local-server/protocol/client_error_catalog.json'


def main():
    data = SOURCE.read_bytes()
    reader = Reader(data, allow_client_format1=True)
    function = reader.function()
    if reader.at != len(data) or function['children']:
        raise ValueError('Unexpected generated error module structure')
    constants, registers, rows = function['constants'], {}, {}

    def operand(value):
        return constants[value & 255] if value & 256 else registers.get(value)

    for pc, word in enumerate(function['code'], 1):
        decoded = instruction(word)
        opcode = CLIENT_OPS.get(decoded['op'])
        if opcode == 'LOADK':
            registers[decoded['a']] = constants[decoded['bx']]
        elif opcode == 'MOVE':
            registers[decoded['a']] = registers.get(decoded['b'])
        elif opcode == 'SETTABLE' and decoded['a'] == 1:
            name, code = operand(decoded['b']), operand(decoded['c'])
            if isinstance(name, str) and type(code) is int:
                if name in rows:
                    raise ValueError(f'Duplicate error constant: {name}')
                rows[name] = {'code': code, 'instruction': pc}
        elif opcode not in ('SETTABLE', 'SETTABUP', 'RETURN'):
            registers.pop(decoded['a'], None)
    required = ('DepositSpaceNotEnough', 'DepositCurrencyNotEnough',
                'DepositPropDescNotFound', 'DepositInvalidReq',
                'DepositPropNotFound', 'DepositPropNotEnough', 'DepositInternalError')
    if not all(name in rows for name in required) or len(rows) < 1000:
        raise ValueError('Incomplete error constants')
    report = {'source_pak': 'pak-0-0-pakchunk1-WindowsClient.pak',
              'source_entry': 6809, 'source_file': 'errcode_pb.lua',
              'source_sha256': hashlib.sha256(data).hexdigest(),
              'function_id': function['id'], 'row_count': len(rows), 'rows': rows}
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('errors', len(rows), 'required', {name: rows[name] for name in required})


if __name__ == '__main__':
    main()
