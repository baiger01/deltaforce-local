"""Read owning-weapon relevant cooked class defaults and exact object references."""
import hashlib
import json
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, tags
from recover_economy_pak_access import installed_name_map

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT/'work/evidence/map-system-audit-20261018'
ASSETS = FOLDER/'owning-weapon-character-assets/pak-0-1-pakchunk30-WindowsClient/DeltaForce/Content'


def package(stem):
    header, payload = stem.with_suffix('.uasset').read_bytes(), stem.with_suffix('.uexp').read_bytes()
    names = installed_name_map(header)
    versions = struct.unpack_from('<i', header, 20)[0]
    ec, eo, ic, io, depends = struct.unpack_from('<5i', header, 57+versions*20)
    assert 0 < ec < 2048 and 0 < ic < 2048
    assert depends-eo == ec*104 and eo-io == ic*28
    imports, exports = [], []
    for i in range(ic):
        at = io+i*28
        imports.append(dict(index=-i-1, class_package=fname(header, at, names),
            class_name=fname(header, at+8, names), outer_index=struct.unpack_from('<i', header, at+16)[0],
            name=fname(header, at+20, names), record_offset=at))
    for i in range(ec):
        at = eo+i*104
        cls, sup, template, outer = struct.unpack_from('<4i', header, at)
        size, offset = struct.unpack_from('<qq', header, at+28)
        assert 0 <= size < 1024*1024 and 0 <= offset-len(header) <= len(payload)-size
        exports.append(dict(index=i+1, name=fname(header, at+16, names), class_index=cls,
            super_index=sup, template_index=template, outer_index=outer,
            offset=offset-len(header), size=size, record_offset=at))

    def ref(index, seen=()):
        if index == 0:
            return None
        assert index not in seen and len(seen) < 64
        row = imports[-index-1] if index < 0 else exports[index-1]
        outer = ref(row['outer_index'], (*seen, index))
        return (outer+'.' if outer else '')+row['name']

    selected = []
    for export in exports:
        export['class_path'] = ref(export['class_index'])
        export['super_path'] = ref(export['super_index'])
        export['template_path'] = ref(export['template_index'])
        export['object_path'] = ref(export['index'])
        if not (export['name'].startswith('Default__') or any(
                token in export['name'].lower() for token in ('weapon', 'equipment'))):
            continue
        first, end = export['offset'], export['offset']+export['size']
        try:
            props, after = tags(payload, first, names, end)
        except ValueError as exc:
            selected.append(dict(export=export, tags_decoded=False, parse_error=str(exc)))
            continue
        rows = []
        for tag in props:
            row = dict(tag)
            raw = payload[tag['value_start']:tag['end']]
            row['tag_value_sha256'] = hashlib.sha256(payload[tag['start']:tag['end']]).hexdigest()
            if tag['kind'] == 'ObjectProperty' and len(raw) == 4:
                index = struct.unpack('<i', raw)[0]
                row.update(object_index=index, object_path=ref(index))
            elif tag['kind'] in ('IntProperty', 'UInt32Property') and len(raw) == 4:
                row['value'] = int.from_bytes(raw, 'little', signed=tag['kind']=='IntProperty')
            elif tag['kind'] == 'UInt64Property' and len(raw) == 8:
                row['value'] = int.from_bytes(raw, 'little')
            elif tag['kind'] == 'BoolProperty':
                row['value'] = bool(payload[tag['start']+24])
            elif tag['kind'] in ('NameProperty', 'EnumProperty', 'ByteProperty') and len(raw) == 8:
                row['value'] = fname(payload, tag['value_start'], names)
            rows.append(row)
        selected.append(dict(export=export, tags_decoded=True, properties=rows,
            property_terminator_end=after, remaining_export_bytes=end-after))
    return dict(source_files=[dict(relative_path=stem.with_suffix(s).relative_to(ROOT).as_posix(),
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for s, raw in (('.uasset', header), ('.uexp', payload))],
        import_count=ic, export_count=ec, imports=imports, exports=exports, selected_defaults=selected,
        weapon_related_names=[n for n in names if any(t in n.lower() for t in ('weapon', 'emptyhand', 'equip'))])


if __name__ == '__main__':
    result = dict(kind='offline_owning_weapon_cooked_defaults', process_access=False,
        client_launched=False, game_written=False, production_files_edited=False,
        packages=[package(ASSETS/'BluePrints/Characters/BP_DFMCharacter'),
                  package(ASSETS/'BluePrints/Weapons/WeaponBP/MeleeWeaponBP/BP_EmptyHand')])
    raw = (json.dumps(result, indent=2)+'\n').encode()
    target = FOLDER/'native-owning-weapon-cooked-character-emptyhand-defaults.json'
    with target.open('xb') as output:
        output.write(raw)
    print(json.dumps(dict(output=str(target), sha256=hashlib.sha256(raw).hexdigest())))
