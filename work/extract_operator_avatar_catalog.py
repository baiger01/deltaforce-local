"""Read the installed client's clear CharacterAvatarData table without editing it.

The encrypted PAK index is not needed: the two table payloads were recovered by
sequential FPakEntry traversal and are kept under work/evidence.  This parser
only accepts recognizable Unreal property tags and emits a provenance-marked
catalog of rows and mesh references, not guessed hero/fashion relationships.
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct


ROOT = Path(__file__).resolve().parent.parent
STEM = '1.101.37117.36.524_WindowsNoEditor_37641_P.pak'
EVIDENCE = ROOT / 'work/evidence/character_avatar_tables'
UASSET = EVIDENCE / (STEM + '.entry-115.uasset')
UEXP = EVIDENCE / (STEM + '.next_entry')
OUTPUT = ROOT / 'outputs/df-local-server/protocol/operator_asset_catalog.json'
SUMMARY = ROOT / 'outputs/df-local-server/operator_asset_catalog.md'
KNOWN_NAMES = {
    '88000000025': '威龙', '88000000026': '骇爪',
    '88000000027': '蜂医', '88000000028': '露娜',
    '88000000029': '牧羊人', '88000000030': '红狼',
    '88000000035': '乌鲁鲁', '88000000036': '蛊',
    '88000000037': '深蓝',
}


def i32(data, offset):
    return struct.unpack_from('<i', data, offset)[0]


def fname(data, offset, names):
    index, instance = struct.unpack_from('<ii', data, offset)
    if not 0 <= index < len(names) or not 0 <= instance < 1000000:
        raise ValueError(f'Invalid FName ({index}, {instance}) at {offset}')
    return names[index] if not instance else f'{names[index]}_{instance - 1}'


def name_map(data):
    if len(data) < 49:
        raise ValueError('Truncated Unreal package summary')
    custom_versions = struct.unpack_from('<i', data, 20)[0]
    if not 0 <= custom_versions <= 1024:
        raise ValueError('Invalid Unreal custom version count')
    summary_offset = 41 + custom_versions * 20
    if summary_offset + 8 > len(data):
        raise ValueError('Truncated Unreal name map summary')
    count, offset = struct.unpack_from('<ii', data, summary_offset)
    if not 100 < count < 100000 or not 0 < offset < len(data):
        raise ValueError('Invalid Unreal name map')
    names = []
    for _ in range(count):
        length = i32(data, offset)
        offset += 4
        if not length or abs(length) > 10000:
            raise ValueError('Invalid Unreal name length')
        if length > 0:
            raw = data[offset:offset + length]
            name = raw.rstrip(b'\0').decode('utf-8')
            offset += length
        else:
            raw = data[offset:offset - length * 2]
            name = raw.decode('utf-16le').rstrip('\0')
            offset -= length * 2
        offset += 4  # serialized name hashes
        names.append(name)
    return names


def property_tag(data, offset, names, limit):
    start = offset
    if offset + 8 > limit:
        raise ValueError('Truncated property name')
    name = fname(data, offset, names)
    offset += 8
    if name == 'None':
        return {'name': name, 'start': start, 'end': offset}
    if offset + 16 > limit:
        raise ValueError(f'Truncated tag {name}')
    kind = fname(data, offset, names)
    offset += 8
    size, array_index = struct.unpack_from('<ii', data, offset)
    offset += 8
    if size < 0 or array_index < 0:
        raise ValueError(f'Invalid tag size or index in {name}')
    meta = []
    if kind in ('StructProperty', 'EnumProperty', 'ByteProperty',
                'ArrayProperty', 'SetProperty'):
        meta.append(fname(data, offset, names))
        offset += 8
    elif kind == 'MapProperty':
        meta += [fname(data, offset, names), fname(data, offset + 8, names)]
        offset += 16
    if kind == 'StructProperty':
        offset += 16  # struct GUID
    if kind == 'BoolProperty':
        offset += 1  # bool serialized in tag, not value bytes
    if offset >= limit:
        raise ValueError(f'Truncated tag flags in {name}')
    has_guid = data[offset]
    offset += 1
    if has_guid not in (0, 1):
        raise ValueError(f'Invalid property GUID flag in {name}')
    if has_guid:
        offset += 16
    end = offset + size
    if end > limit:
        raise ValueError(f'Truncated payload in {name}')
    return {'name': name, 'kind': kind, 'size': size, 'array_index': array_index,
            'meta': meta, 'start': start, 'value_start': offset, 'end': end}


def tags(data, start, names, limit):
    offset = start
    result = []
    for _ in range(1000):
        tag = property_tag(data, offset, names, limit)
        offset = tag['end']
        if tag['name'] == 'None':
            return result, offset
        result.append(tag)
    raise ValueError('Unterminated property list')


def value(data, tag, names):
    if tag['kind'] in ('NameProperty', 'EnumProperty', 'ByteProperty') and tag['size'] == 8:
        return fname(data, tag['value_start'], names)
    if tag['kind'] == 'StructProperty' and tag['meta'] == ['SoftObjectPath']:
        return fname(data, tag['value_start'], names)
    if tag['kind'] == 'IntProperty' and tag['size'] == 4:
        return i32(data, tag['value_start'])
    return None


def core_parts(data, tag, names):
    if tag['kind'] != 'ArrayProperty' or tag['meta'] != ['StructProperty']:
        raise ValueError(f'Unexpected CoreParts tag {tag}')
    pos = tag['value_start']
    count = i32(data, pos)
    pos += 4
    if not 0 <= count <= 64:
        raise ValueError('Invalid CoreParts count')
    # Unreal FScriptArray of tagged structs carries a single inner tag even
    # when the array has no elements.
    inner = property_tag(data, pos, names, tag['end'])
    if inner['kind'] != 'StructProperty':
        raise ValueError('CoreParts inner tag is not a struct')
    pos = inner['value_start']
    parts = []
    for _ in range(count):
        child_tags, pos = tags(data, pos, names, tag['end'])
        child = {x['name']: value(data, x, names) for x in child_tags}
        parts.append({'part': child.get('AvatarPart'), 'extra_tag': child.get('ExtraTag'),
                      'mesh_path': child.get('MeshPath'),
                      'attach_socket': child.get('AttachSocket'),
                      'fields': sorted(child)})
    if pos != tag['end']:
        raise ValueError(f'CoreParts consumed {pos - tag["value_start"]} '
                         f'of {tag["size"]} bytes')
    return parts


def view(data, tag, names):
    if tag['kind'] != 'StructProperty':
        raise ValueError(f'Unexpected view type {tag["kind"]}')
    view_tags, end = tags(data, tag['value_start'], names, tag['end'])
    if end != tag['end']:
        raise ValueError(f'View {tag["name"]} has unparsed bytes')
    fields = {x['name']: x for x in view_tags}
    result = {'master_mesh': value(data, fields['MasterMesh'], names) if 'MasterMesh' in fields else None,
              'core_parts': core_parts(data, fields['CoreParts'], names) if 'CoreParts' in fields else [],
              'extra_parts': core_parts(data, fields['ExtraParts'], names) if 'ExtraParts' in fields else [],
              'fields': sorted(fields)}
    return result


def mesh_group(row):
    paths = [part['mesh_path'] for part in row['views'].get('UI', {}).get('core_parts', [])
             if part.get('mesh_path') not in (None, 'None')]
    if not paths:
        return '—'
    # The nearest model group is descriptive, not an ownership or skin mapping.
    for path in paths:
        match = re.search(r'/Hero_HD/([^/]+)/', path)
        if match:
            return match.group(1)
    return paths[0].split('/')[-2]


def main():
    uasset, uexp = UASSET.read_bytes(), UEXP.read_bytes()
    names = name_map(uasset)
    numeric = {i: name for i, name in enumerate(names) if re.fullmatch(r'\d{8,14}', name)}
    sex_idx = names.index('Sex')
    candidates = []
    for name_idx, name in numeric.items():
        needle = struct.pack('<iiii', name_idx, 0, sex_idx, 0)
        for match in re.finditer(re.escape(needle), uexp):
            candidates.append((match.start(), name))
    rows = {}
    rejected = []
    for offset, row_id in sorted(candidates):
        try:
            row_tags, end = tags(uexp, offset + 8, names, len(uexp))
            fields = {x['name']: x for x in row_tags}
            if 'Sex' not in fields or 'CharacterTag' not in fields:
                raise ValueError('Missing row discriminator')
            row = {'id': row_id, 'known_name': KNOWN_NAMES.get(row_id),
                   'sex': value(uexp, fields['Sex'], names),
                   'character_tag': value(uexp, fields['CharacterTag'], names),
                   'skin_id': value(uexp, fields['SkinId'], names) if 'SkinId' in fields else None,
                   'views': {key: view(uexp, fields[key], names) for key in ('UI', 'TPP', 'FPP') if key in fields},
                   'fields': sorted(fields), 'serialized_uexp_offset': offset}
            if row_id in rows:
                raise ValueError(f'Duplicate row ID {row_id}')
            rows[row_id] = row
        except (ValueError, IndexError, struct.error) as exc:
            rejected.append({'id': row_id, 'offset': offset, 'error': str(exc)})
    if rejected:
        raise ValueError(f'{len(rejected)} candidate rows rejected: {rejected[:10]}')
    if not rows:
        raise ValueError('No CharacterAvatarData rows found')
    catalog = {'source_table': '/Game/R13N/Common/PC/DataTables/CharacterAvatarData',
               'source_pak': STEM,
               'source_uasset_sha256': hashlib.sha256(uasset).hexdigest(),
               'source_uexp_sha256': hashlib.sha256(uexp).hexdigest(),
               'interpretation': 'Asset rows only; no HeroFashionData mapping or ownership inferred',
               'row_count': len(rows),
               'counts_by_prefix': dict(Counter(row_id[:3] for row_id in rows)),
               'counts_by_character_tag': dict(Counter(row['character_tag'] for row in rows.values())),
               'rows': dict(sorted(rows.items(), key=lambda item: int(item[0])))}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = [
        '# 当前客户端角色外观资源索引',
        '',
        f'来源：`{STEM}` 中的 `CharacterAvatarData`；只读提取，共 {len(rows)} 行。',
        '下表覆盖全部外观行；完整 UI、第三人称、第一人称部件路径及附加部件见 '
        '[JSON 明细](protocol/operator_asset_catalog.json)。',
        '',
        '已知中文名称只对照[公开角色编号映射]'
        '(https://github.com/luoy-oss/deltaforce_id/blob/main/characters_id_map.json)与'
        '[名称映射](https://github.com/luoy-oss/deltaforce_id/blob/main/characters_name_map.json)的九项；'
        '其余保持未核对，模型目录名不能证明游戏内名称。`CharacterTag=Hero` 是资源标记，'
        '不能单独证明账号可选或外观已拥有。',
        '',
        '| 外观行 ID | 已核对名称 | 资源标记 | 性别标记 | UI 模型组 | UI 部件数 |',
        '| ---: | --- | --- | --- | --- | ---: |',
    ]
    for row_id, row in catalog['rows'].items():
        lines.append('| `{}` | {} | {} | {} | `{}` | {} |'.format(
            row_id, row['known_name'] or '—', row['character_tag'].split('::')[-1],
            row['sex'].split('::')[-1], mesh_group(row),
            len(row['views'].get('UI', {}).get('core_parts', []))))
    lines += [
        '',
        '## 威龙外观核对',
        '',
        '客户端中可确认威龙本体 `88000000025`，以及模型路径含 `M_Dragon` 的多条外观行。'
        '官方说明[凌霄戍卫是威龙外观]'
        '(https://deltaforce.garena.com/zh_tw/news/all/5ET5UV)，但该公告不提供客户端时装 ID。'
        '当前 `CharacterAvatarData` 的 `SkinId` 字段在这些行均为 `None`。'
        '`30000060007` 的模型目录包含 `M_Dragon_Outers_1u_S_HD`，与凌霄戍卫的航天主题相符，'
        '目前仅作为优先核查的候选；必须再与 `HeroFashionData` / `FashionSuitData` 或本地化名称对照，'
        '不能仅凭 Dragon 目录名确定客户端时装 ID。',
        '',
        '| Dragon 外观行 | UI 身体网格 |',
        '| ---: | --- |',
    ]
    for row_id, row in catalog['rows'].items():
        body = next((part['mesh_path'] for part in row['views'].get('UI', {}).get('core_parts', [])
                     if part['part'] == 'ECharacterAvatarPartConfig::Upper'
                     and part.get('mesh_path') not in (None, 'None')), None)
        if body and '/M_Dragon' in body:
            lines.append(f'| `{row_id}` | `{body}` |')
    lines += ['', '这些是已安装资源路径，不等于已通过原客户端完整大厅渲染测试。', '']
    SUMMARY.write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'row_count': len(rows), 'counts_by_prefix': catalog['counts_by_prefix'],
                      'counts_by_character_tag': catalog['counts_by_character_tag'],
                      'sample': {key: rows.get(key) for key in ('88000000025', '88000000027', '30000020003')}},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
