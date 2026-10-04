"""Recover typed static Dam spawn/loot definitions from bounded clear exports.

Associates companions by complete export extents and tag validation, never by
adjacency. PAK entry order in this build does not preserve UAsset/UEXP pairing.
Output is a static catalog, not a native replication or server drop protocol.
"""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct

from extract_operator_avatar_catalog import fname, tags

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'evidence/dam_content_packages'
TARGET = HERE.parent / 'outputs/df-local-server/protocol/dam_gameplay_asset_catalog.json'


def string_at(data, start, limit):
    length = struct.unpack_from('<i', data, start)[0]
    size = length if length >= 0 else -length * 2
    end = start + 4 + size
    if abs(length) > 4096 or end > limit:
        raise ValueError('String outside bounded property')
    raw = data[start + 4:end]
    if length and not raw.endswith(b'\0' if length > 0 else b'\0\0'):
        raise ValueError('Unterminated property string')
    return raw.decode('utf-8' if length >= 0 else 'utf-16le').rstrip('\0'), end


class Package:
    def __init__(self, row, manifest):
        self.row = row
        self.header = self.checked(row)
        self.names = json.loads((SOURCE / f"entry-{row['entry']}.names.json").read_text(encoding='utf-8'))
        field = row['name_map_summary_offset']
        ec, eo, ic, io = struct.unpack_from('<4i', self.header, field + 16)
        depends = struct.unpack_from('<i', self.header, field + 32)[0]
        if (not 0 < ec <= 5000 or not 0 < ic <= 5000 or
                depends - eo != ec * 104 or eo - io != ic * 28):
            raise ValueError('Package export/import boundaries are not the observed layout')
        self.imports = [fname(self.header, io + i * 28 + 20, self.names) for i in range(ic)]
        self.exports = []
        previous_end = len(self.header)
        for i in range(ec):
            at = eo + i * 104
            cls, _super, _template, outer = struct.unpack_from('<4i', self.header, at)
            size, offset = struct.unpack_from('<qq', self.header, at + 28)
            if not 0 <= size <= 8 * 1024 * 1024 or offset != previous_end:
                raise ValueError('Exports are not a complete sequential extent')
            previous_end = offset + size
            self.exports.append({'index': i + 1, 'name': fname(self.header, at + 16, self.names),
                                 'serialized_name_base': self.names[struct.unpack_from('<i', self.header, at + 16)[0]],
                                 'class_index': cls, 'outer_index': outer, 'size': size,
                                 'offset': offset - len(self.header)})
        extent = previous_end - len(self.header)
        matches = [r for r in manifest['records'] if r.get('kind') == 'companion_candidate'
                   and r['uncompressed_bytes'] == extent + 4]
        if len(matches) != 1:
            raise ValueError('Companion extent is missing or ambiguous')
        self.companion = matches[0]
        self.payload = self.checked(self.companion)
        if self.payload[-4:] != b'\xc1\x83\x2a\x9e':
            raise ValueError('Companion package terminator is missing')
        self.property_cache = {}
        # Validate the association against independent typed exports.
        for i in (1, max(1, ec // 2), ec):
            self.properties(i)
        # Name-map order is not package identity: entry zero often names an
        # imported Blueprint. Match the package path to its own root World.
        roots = [e for e in self.exports if e['outer_index'] == 0 and
                 self.object(e['class_index']) == 'World']
        paths = [n for n in self.names if n.startswith('/Game/') and
                 n.rsplit('/', 1)[-1] in {e['serialized_name_base'] for e in roots}]
        if len(roots) != 1 or len(paths) != 1:
            raise ValueError('Own World export does not identify one package path')
        self.package_path = paths[0]
        self.world_export = roots[0]['index']

    @staticmethod
    def checked(row):
        name = row['evidence_file']
        if Path(name).name != name:
            raise ValueError('Evidence path leaves package directory')
        data = (SOURCE / name).read_bytes()
        if len(data) != row['uncompressed_bytes'] or hashlib.sha256(data).hexdigest() != row['payload_sha256']:
            raise ValueError('Payload hash or size differs from capture manifest')
        return data

    def object(self, index):
        if index < 0 and -index <= len(self.imports):
            return self.imports[-index - 1]
        if index > 0 and index <= len(self.exports):
            return self.exports[index - 1]['name']
        if index == 0:
            return None
        raise ValueError('Object reference is outside package')

    def properties(self, index):
        if index not in self.property_cache:
            row = self.exports[index - 1]
            props, end = tags(self.payload, row['offset'], self.names, row['offset'] + row['size'])
            self.property_cache[index] = {p['name']: p for p in props}
        return self.property_cache[index]

    def value(self, tag):
        if tag is None:
            return None
        p, at, kind, size = self.payload, tag['value_start'], tag['kind'], tag['size']
        if kind in ('NameProperty', 'EnumProperty', 'ByteProperty') and size == 8:
            return fname(p, at, self.names)
        if kind in ('ObjectProperty', 'IntProperty') and size == 4:
            result = struct.unpack_from('<i', p, at)[0]
            if kind == 'ObjectProperty':
                self.object(result)
            return result
        if kind == 'Int64Property' and size == 8:
            return struct.unpack_from('<q', p, at)[0]
        if kind == 'StrProperty':
            result, end = string_at(p, at, tag['end'])
            if end != tag['end']:
                raise ValueError('String property has unconsumed bytes')
            return result
        if kind == 'BoolProperty' and size == 0:
            if p[at - 1] != 0 or p[at - 2] not in (0, 1):
                raise ValueError('Unsupported bool property GUID')
            return bool(p[at - 2])
        if kind == 'FloatProperty' and size == 4:
            result = struct.unpack_from('<f', p, at)[0]
            if not math.isfinite(result):
                raise ValueError('Non-finite property value')
            return result
        if kind == 'StructProperty' and tag['meta'] in (['EncVector'], ['Vector'], ['Rotator']) and size == 12:
            values = list(struct.unpack_from('<3f', p, at))
            if not all(math.isfinite(x) and abs(x) < 1e8 for x in values):
                raise ValueError('Non-finite/out of bounds vector')
            return {'serialized_type': tag['meta'][0], 'serialized_float32': values}
        if kind == 'ArrayProperty' and tag['meta'] in (['ObjectProperty'], ['NameProperty']):
            count = struct.unpack_from('<i', p, at)[0]
            stride = 4 if tag['meta'] == ['ObjectProperty'] else 8
            if not 0 <= count <= 1000 or 4 + stride * count != size:
                raise ValueError('Array does not match property extent')
            if stride == 4:
                result = list(struct.unpack_from('<' + str(count) + 'i', p, at + 4))
                for index in result:
                    self.object(index)
                return result
            return [fname(p, at + 4 + i * 8, self.names) for i in range(count)]
        if kind == 'TextProperty' and size >= 13 and p[at + 4] == 11:
            table = fname(p, at + 5, self.names)
            key, end = string_at(p, at + 13, tag['end'])
            # This client's string-table text has a four-byte extension.
            # Independently corroborated by CUE4Parse's GAME_DeltaForce branch:
            # UE4/Objects/Core/i18N/FText.cs, StringTableEntry constructor.
            # Its meaning is not established; preserve it without inventing one.
            if end + 4 != tag['end']:
                raise ValueError('String-table text does not match Delta Force extent')
            return {'string_table': table, 'key': key,
                    'flags': struct.unpack_from('<I', p, at)[0],
                    'delta_force_extension_u32': struct.unpack_from('<I', p, end)[0],
                    'extension_semantics_verified': False}
        return {'unparsed_type': kind, 'serialized_size': size, 'meta': tag['meta']}

    def root_transform(self, actor):
        props = self.properties(actor)
        root = self.value(props.get('RootComponent'))
        if not isinstance(root, int) or root <= 0:
            return None
        root_props = self.properties(root)
        return {'root_component_export': root, 'root_component': self.object(root),
                'relative_location': self.value(root_props.get('RelativeLocation')),
                'relative_rotation': self.value(root_props.get('RelativeRotation')),
                'attach_parent': self.value(root_props.get('AttachParent')),
                'world_coordinates_runtime_verified': False}

    def evidence(self):
        return {'uasset_entry': self.row['entry'], 'uexp_entry': self.companion['entry'],
                'package_path': self.package_path, 'world_export': self.world_export,
                'package_identity': 'root_World_export_base_name_matches_full_package_path',
                'uasset_sha256': self.row['payload_sha256'], 'uexp_sha256': self.companion['payload_sha256'],
                'export_count': len(self.exports), 'companion_association': 'complete_export_extent_and_typed_tags'}


def main():
    manifest = json.loads((SOURCE / 'manifest.json').read_text(encoding='utf-8'))
    result = {'kind': 'static_client_dam_gameplay_asset_catalog', 'map_id': 2201,
              'source_archive_relative_path': manifest['archive_relative_path'],
              'source_archive_size': manifest['archive_size'],
              'source_client_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
              'native_map_entry_fixed': False, 'native_replication_implemented': False,
              'original_server_random_selection_rules_recovered': False,
              'mandel_brick_spawn_or_drop_rules_recovered': False,
              'packages': [], 'spawn_groups': [], 'high_value_containers': [],
              'random_loot_points': [], 'unparsed_packages': []}
    spawn_package = '/Game/Maps/Dam_Iris_Level1/GameplayConfig/Dam_Iris_Level1_GameplayConfig'
    for row in manifest['records']:
        if row.get('kind') != 'uasset' or not row.get('name_map_summary_offset'):
            continue
        content = row.get('content_names', [])
        if not any(name == 'PlayerStarts' or name == 'HighValueBoxInfo' or name.startswith('BP_Loot_RandomObj') for name in content):
            continue
        try:
            pkg = Package(row, manifest)
        except (ValueError, struct.error) as exc:
            result['unparsed_packages'].append({'entry': row['entry'], 'reason': str(exc)})
            continue
        result['packages'].append(pkg.evidence())
        for export in pkg.exports:
            index = export['index']
            props = pkg.properties(index)
            cls = pkg.object(export['class_index'])
            if cls == 'TeamStart' and pkg.package_path == spawn_package:
                ordered = pkg.value(props.get('FixedOrderPlayerStarts'))
                if not isinstance(ordered, list) or len(ordered) != len(set(ordered)):
                    raise ValueError('Team start has invalid ordered player references')
                points = []
                for ref in ordered:
                    point = pkg.exports[ref - 1]
                    if pkg.object(point['class_index']) != 'PlayerStart':
                        raise ValueError('Team spawn references a different actor class')
                    transform = pkg.root_transform(ref)
                    if not transform or not transform['relative_location'] or not transform['relative_rotation']:
                        raise ValueError('Referenced player start has no serialized transform')
                    points.append({'actor': point['name'], 'export': ref,
                                   'tag': pkg.value(pkg.properties(ref).get('PlayerStartTag')),
                                   'transform': transform})
                result['spawn_groups'].append({'package': spawn_package, 'uasset_entry': row['entry'],
                    'actor': export['name'], 'export': index,
                    'group_id': pkg.value(props.get('GroupId')),
                    'team_start_group_id': pkg.value(props.get('TeamStartGroupId')),
                    'orientation': pkg.value(props.get('TeamStartOrientation')),
                    'indoor': pkg.value(props.get('bIsIndoorStart')),
                    'player_starts': points})
            if 'HighValueBoxInfo' in props:
                info = props['HighValueBoxInfo']
                inner, _ = tags(pkg.payload, info['value_start'], pkg.names, info['end'])
                fields = {t['name']: pkg.value(t) for t in inner}
                if fields:
                    result['high_value_containers'].append({'uasset_entry': row['entry'],
                        'package': pkg.package_path,
                        'actor': export['name'], 'export': index, 'class': cls,
                        'explicit_fields': fields, 'class_defaults_not_resolved': True,
                        'transform': pkg.root_transform(index)})
            if cls == 'BP_Loot_RandomObj_C':
                result['random_loot_points'].append({'uasset_entry': row['entry'], 'actor': export['name'],
                    'package': pkg.package_path,
                    'export': index, 'class': cls, 'transform': pkg.root_transform(index),
                    'explicit_fields': {k: pkg.value(v) for k, v in props.items()
                                        if k != 'Loot_Debug_Cube' and any(term in k.lower() for term in
                                            ('loot', 'rate', 'random', 'weight', 'itemspawn', '掉落', 'isblocktospawn'))}})
    groups = result['spawn_groups']
    all_refs = [(g['uasset_entry'], p['export']) for g in groups for p in g['player_starts']]
    if not groups or len(set(all_refs)) != len(all_refs):
        raise ValueError('Spawn catalog is empty or contains multiply assigned points')
    result['counts'] = {'spawn_groups': len(groups), 'player_starts': len(all_refs),
                        'high_value_container_overrides': len(result['high_value_containers']),
                        'random_loot_points': len(result['random_loot_points']),
                        'explicitly_blocked_loot_actors': sum(p['explicit_fields'].get('isBlockToSpawn') is True
                                                            for p in result['random_loot_points']),
                        'packages_validated': len(result['packages'])}
    TARGET.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': result['counts'], 'unparsed_packages': result['unparsed_packages']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
