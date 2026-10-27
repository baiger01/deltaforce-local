"""Validate configuration-linked native display strings; never change runtime data."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
PE_SHA = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
UPGRADE_SHA = 'a512e06581e890beccbc03d57fac4960d53647b0f2a0f14e1e5078f0a9a6def2'
LUA = {
    'BlackSiteDevice.lua': ('d1a05e46806f6498e8d680f4838d5b443b24cc821cf8337e591ea73deec5aa1b', ('0.42',)),
    'BlackSitePreviewGain.lua': ('6b3ec6baec03fd3de83c6b24098c9c8cac335f765b114aadfbe84a2e2b43a3dd', ('0.3',)),
    'BlackSiteGainPop.lua': ('86c7a7c292c459f59ed4db5dccc542a7f4fd1e58f45ad7f0c159cddb918588ad', ('0.2',)),
    'BlackSiteGainPopItem.lua': ('6aac3fe14ffa5ab9ccdee877cf5e1d9983f8b5c554c07549fbd4d8e51a90b6ac', ('0.2',)),
    'BlackSiteGainItem.lua': ('08b5599d378032c2992e290cb7a83bdb4768cb135e093a3513c42ea33a281e0c', ('0.1',)),
}


def instructions(blob, address):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return [{'address': ins.address, 'op': ins.mnemonic, 'args': ins.op_str}
            for ins in decoder.disasm(bytes.fromhex(blob), address)]


def field_display(field):
    root = bytes.fromhex(field['root_80_bytes_hex'])
    exact = field['exact_link_candidates']
    if exact.get('read_error'):
        raise ValueError('Live exact chain changed or could not be read')
    reference = bytes.fromhex(exact['reference_64_bytes_hex'])
    entry = bytes.fromhex(exact['entry_64_bytes_hex'])
    if (struct.unpack_from('<Q', root, 24)[0] != exact['reference_address'] or
            struct.unpack_from('<Q', reference, 40)[0] != exact['entry_address'] or
            struct.unpack_from('<Q', entry, 32)[0] != exact['entry_plus_32_shared_string_address']):
        raise ValueError('Live exact display pointer chain differs')
    value = exact['entry_plus_32_shared_string']
    _, count, capacity = struct.unpack('<Qii', bytes.fromhex(exact['shared_string_16_bytes_hex']))
    if not len(value.encode('utf-16-le')) // 2 + 1 == count <= capacity:
        raise ValueError('Exact display FString length differs')
    return {'text': value, 'fstring_address': exact['entry_plus_32_shared_string_address'],
            'pointer_path': [24, 40, 32, 0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-report', type=Path, required=True)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'work/evidence/native-warehouse-text-contract-20261020.json')
    args = parser.parse_args()
    raw = args.live_report.read_bytes()
    live = json.loads(raw)
    if live['native_pe_sha256'] != PE_SHA:
        raise ValueError('Native executable differs from the original source')
    tables = [table for table in live['keybox_rows']['warehouse_descriptions'] if 'rows' in table]
    if len(tables) != 1 or tables[0]['table_name'] != 'SafeHouse/SafeHouseDescription':
        raise ValueError('Expected exactly the identified description table')
    table = tables[0]
    base = live['module_base']
    code = table['text_accessor_code']
    virtual = instructions(code['virtual_code_hex'], code['virtual_target'])
    if (code['helper_address'] != base + 0x10a66300 or
            not any(ins['op'] == 'add' and ins['args'] == 'rcx, 8' for ins in virtual)):
        raise ValueError('Native embedded history accessor differs')
    helper = instructions(code['helper_1024_bytes_hex'], code['helper_address'])
    expected = {0x10a66316: ('mov', 'rcx, qword ptr [rcx + 0x10]'),
                0x10a66399: ('mov', 'rax, qword ptr [rsi + 0x20]'),
                0x10a663af: ('mov', 'qword ptr [r14], rax')}
    for rva, (op, operands) in expected.items():
        address = base + rva
        if not any(ins == {'address': address, 'op': op, 'args': operands} for ins in helper):
            raise ValueError('Native display accessor code differs')
    resolver = next(target for target in code['direct_targets'] if target['address'] == base + 0x10a76730)
    resolver_code = instructions(resolver.get('first_2304_code_bytes', resolver['first_512_code_bytes']),
                                 resolver['address'])
    for rva, op, operands in ((0x10a7674c, 'lea', 'r12, [rcx + 0x28]'),
                              (0x10a76871, 'mov', 'rax, qword ptr [r12]')):
        address = base + rva
        if not any(ins == {'address': address, 'op': op, 'args': operands} for ins in resolver_code):
            raise ValueError('Native cached entry chain differs')
    descriptions = {row['id']: {name: field_display(field) for name, field in row['text_fields'].items()}
                    for row in table['rows']}
    expected_ids = {10100102, 10100104, 10100106, 10100108, 10100110, *range(10100202, 10100211)}
    if set(descriptions) != expected_ids:
        raise ValueError('Description row set differs')
    source_path = ROOT / 'work/evidence/native-warehouse-box-contract-20261020.json'
    source = json.loads(source_path.read_text(encoding='utf-8'))['warehouse_upgrades']
    if source['source']['sha256'] != UPGRADE_SHA:
        raise ValueError('Original upgrade table differs')
    rows, previous_cells, previous_slots, bonus_rows, slot_limit = [], 0, 0, 0, 0
    for row in source['rows']:
        level = row['Level']
        outputs = {int(parts[0]): int(parts[1]) for output in row['UnlockSystemList'].split(';')
                   if output for parts in [output.split(':')]}
        if 2 in outputs:
            text = descriptions[10100100 + level]
            start, end = (int(text[name]['text']) for name in ('StartValue', 'EndValue'))
            if start != previous_cells or end != outputs[2] * 9:
                raise ValueError('Original main-space display does not match the row parameter')
            previous_cells, bonus_rows = end, outputs[2]
        if 3 in outputs:
            text = descriptions[10100200 + level]
            start, end = (int(text[name]['text']) for name in ('StartValue', 'EndValue'))
            if start != previous_slots or end != outputs[3]:
                raise ValueError('Original slot display does not match the slot parameter')
            previous_slots, slot_limit = end, outputs[3]
        rows.append({'level': level, 'source_row': row['source_row'],
                     'serialized_offset': row['serialized_offset'],
                     'unlock_system_list': row['UnlockSystemList'],
                     'earned_bonus_rows': bonus_rows, 'earned_bonus_cells': previous_cells,
                     'earned_extension_box_slot_limit': slot_limit})
    consumers = {}
    for name, (digest, ids) in LUA.items():
        path = ROOT / 'work/evidence/weapon_lua' / name
        blob = path.read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError('Original Lua witness changed: ' + name)
        functions = {fn['id']: fn for fn in walk(Reader(blob, allow_client_format1=True).function())}
        consumers[name] = {'sha256': digest, 'functions': {ident: {
            'serialized_offset': functions[ident]['offset'],
            'instructions': listing(functions[ident]).splitlines()} for ident in ids}}
    report = {'scope': 'Source tables and configuration-linked native display strings only; no runtime edits.',
              'native_pe_sha256': PE_SHA, 'live_report': str(args.live_report),
              'live_report_sha256': hashlib.sha256(raw).hexdigest(), 'pid': live['pid'],
              'description_table': table['table_name'], 'descriptions': descriptions,
              'display_chain': 'FText root+24 -> entry reference+40 -> entry+32 -> shared FString',
              'native_accessor': code, 'resolver_instructions': resolver_code,
              'upgrade_source': source['source'], 'levels': rows, 'consumers': consumers,
              'conclusions': {
                  'type2_unit': 'One parameter unit corresponds to one nine-cell row.',
                  'type2_aggregation': 'Latest completed-level value is the absolute earned bonus; do not sum values.',
                  'type3_aggregation': 'Latest completed-level value is the absolute box-slot limit; do not sum values.',
                  'first_box_slot_completed_warehouse_level': 2,
                  'base_geometry_limit': 'This proves earned bonuses only. Original PropSlotConfig/default9x40 and the existing local9x40 compatibility baseline are separate from a witnessed official new-account capacity.'}}
    args.output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(args.output)
    print(rows)


if __name__ == '__main__':
    main()
