"""Extract the installed RecFunction receiver-to-default-preset mapping."""

import hashlib
import json
from pathlib import Path
import struct

from extract_game_item_catalog import scalar
from extract_operator_avatar_catalog import fname, name_map, tags


ROOT = Path(__file__).resolve().parent.parent
STEM = '1.101.37117.36.10_WindowsNoEditor_37127_P.pak.entry-237'
SOURCE = ROOT / 'work/evidence/matched_assets'
OUTPUT = ROOT / 'outputs/df-local-server/protocol/weapon_preset_catalog.json'


def main():
    uasset = (SOURCE / (STEM + '.uasset')).read_bytes()
    uexp = (SOURCE / (STEM + '.uexp')).read_bytes()
    names = name_map(uasset)
    header, offset = tags(uexp, 0, names, len(uexp))
    if not any(tag['name'] == 'RowStruct' for tag in header):
        raise ValueError('Missing RecFunction RowStruct')
    if struct.unpack_from('<i', uexp, offset)[0] != 0:
        raise ValueError('Unexpected RecFunction row prefix')
    count = struct.unpack_from('<i', uexp, offset + 4)[0]
    if not 1 <= count <= 1000:
        raise ValueError('Unexpected RecFunction row count')
    offset += 8
    rows = {}
    preset_to_receiver = {}
    for _ in range(count):
        receiver_id = fname(uexp, offset, names)
        properties, offset = tags(uexp, offset + 8, names, len(uexp))
        fields = {tag['name']: tag for tag in properties}
        if scalar(uexp, fields['RecFunctionId'], names) != int(receiver_id):
            raise ValueError(f'Receiver row ID mismatch: {receiver_id}')
        preset_id = scalar(uexp, fields['DefaultPreset'], names)
        bp_class = fields['BPClass']
        if bp_class['kind'] != 'SoftObjectProperty' or bp_class['size'] != 12:
            raise ValueError(f'Unexpected BPClass field: {receiver_id}')
        row = {
            'receiver_id': int(receiver_id),
            'default_preset_id': preset_id,
            'mp_default_preset_id': scalar(uexp, fields['MPDefaultPreset'], names),
            'bp_class': fname(uexp, bp_class['value_start'], names),
            'is_base_model': scalar(uexp, fields['IsBaseModel'], names),
            'is_base_weapon': scalar(uexp, fields['IsBaseWeapon'], names),
        }
        rows[receiver_id] = row
        if preset_id:
            key = str(preset_id)
            if key in preset_to_receiver:
                raise ValueError(f'Ambiguous default preset: {preset_id}')
            preset_to_receiver[key] = int(receiver_id)
    if offset + 4 != len(uexp) or uexp[offset:] != b'\xc1\x83\x2a\x9e':
        raise ValueError('Unexpected RecFunction table trailer')
    report = {
        'source_table': '/Game/R13N/Common/Base/DataTables/WeaponPart/RecFunctionTable',
        'source_pak': '1.101.37117.36.10_WindowsNoEditor_37127_P.pak',
        'source_uasset_sha256': hashlib.sha256(uasset).hexdigest(),
        'source_uexp_sha256': hashlib.sha256(uexp).hexdigest(),
        'row_count': count,
        'rows': rows,
        'default_preset_to_receiver': preset_to_receiver,
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False,
                                 separators=(',', ':')) + '\n', encoding='utf-8')
    print('receivers', len(rows), 'default presets', len(preset_to_receiver),
          'output_bytes', OUTPUT.stat().st_size)


if __name__ == '__main__':
    main()
