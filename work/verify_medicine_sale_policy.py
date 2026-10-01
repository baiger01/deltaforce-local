"""Verify local sale-policy name anchors against a read-only client export."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from explore_tagged_export import read_row


ROOT = Path(__file__).resolve().parent.parent


def fstring(raw):
    size = struct.unpack_from('<i', raw)[0]
    expected = 4 + (size if size > 0 else -size * 2)
    if size == 0 or len(raw) != expected:
        raise ValueError('Invalid FString length')
    if size < 0:
        if raw[-2:] != b'\0\0':
            raise ValueError('Missing wide FString terminator')
        return raw[4:-2].decode('utf-16le')
    if raw[-1:] != b'\0':
        raise ValueError('Missing FString terminator')
    return raw[4:-1].decode('utf-8')


def verify(payload, policy):
    source = policy['injection_name_source']
    if hashlib.sha256(payload).hexdigest() != source['sha256']:
        raise ValueError('Client export hash does not match the recorded source')
    none, instance, prefix, count = struct.unpack_from('<iiii', payload, 29)
    if (none, instance, prefix, count) != (512, 0, 0, source['row_count']):
        raise ValueError('Unexpected client table header')
    expected = {}
    for item_id, row in {**policy['injections'],
                         **policy['excluded_confirmed_injections']}.items():
        for row_key, offset_key in (('row', 'offset'), ('repeat_row', 'repeat_offset')):
            expected[row[row_key]] = (int(item_id), row['name'], row[offset_key])
    offset, verified = 45, 0
    for index in range(count):
        row_offset = offset
        fields, offset, _ = read_row(payload, offset + 8, none)
        if index not in expected:
            continue
        item_id, name, expected_offset = expected[index]
        if row_offset != expected_offset:
            raise ValueError(f'Row offset mismatch: {index}')
        by_field = {f['field']: f for f in fields}

        def raw(field):
            tag = by_field[field]
            return payload[tag['value_start']:tag['end']]

        actual_id = struct.unpack('<Q', raw(source['raw_product_id_field_index']))[0]
        actual_name = fstring(raw(source['raw_name_field_index']))
        output = fstring(raw(source['raw_product_string_field_index']))
        if (actual_id, actual_name, output) != (item_id, name, f'{item_id}:1;'):
            raise ValueError(f'Client name/ID anchor mismatch: {index}')
        verified += 1
    if verified != len(expected):
        raise ValueError('Missing client anchor rows')
    return verified


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--policy', type=Path, default=(
        ROOT / 'outputs/df-local-server/protocol/medicine_sale_policy.json'))
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding='utf-8'))
    count = verify(args.payload.read_bytes(), policy)
    print(f'client_anchor_rows_verified={count}')


if __name__ == '__main__':
    main()
