"""Recover static AI layout candidates from the clear, validated Dam package.

These are serialized template names and weights, not a recovered AI runtime,
selection algorithm, active-event state, or client-compatible replication.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from recover_dam_gameplay_catalog import Package, SOURCE

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / 'outputs/df-local-server/protocol/dam_ai_asset_catalog.json'
PACKAGE = '/Game/Maps/Dam_Iris_Level1/GameplayConfig/Dam_Iris_Level1_AILayoutConfig'


def bounded_config(package, tag):
    if tag['kind'] != 'StrProperty' or not 4 < tag['size'] <= 65540:
        raise ValueError('AI layout is not a bounded serialized string')
    at = tag['value_start']
    count = struct.unpack_from('<i', package.payload, at)[0]
    size = count if count > 0 else -count * 2
    if not count or size + 4 != tag['size'] or at + 4 + size != tag['end']:
        raise ValueError('AI layout string does not fit its property extent')
    data = package.payload[at + 4:tag['end']]
    terminator = b'\0' if count > 0 else b'\0\0'
    if not data.endswith(terminator):
        raise ValueError('AI layout string is not terminated')
    text = data[:-len(terminator)].decode('utf-8' if count > 0 else 'utf-16le')
    if '\0' in text:
        raise ValueError('AI layout contains an embedded terminator')
    return json.loads(text), hashlib.sha256(data).hexdigest()


def candidate_groups(tree):
    result = []

    def visit(node, parents, depth):
        if depth > 8 or not isinstance(node, dict):
            raise ValueError('AI layout tree exceeds observed structure bounds')
        name = node.get('name')
        if not isinstance(name, str) or len(name) > 256:
            raise ValueError('AI layout node name is invalid')
        path = parents + [name]
        if 'data' in node:
            entries = node['data']
            if not isinstance(entries, list) or not 0 < len(entries) <= 128:
                raise ValueError('AI template group is invalid')
            candidates = []
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'path', 'weight'}:
                    raise ValueError('AI template has an unrecognized layout')
                filename, weight = entry['path'], entry['weight']
                if (not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_]+\.umap', filename)
                        or type(weight) is not int or not 0 < weight <= 1000000):
                    raise ValueError('AI template path or explicit weight is invalid')
                candidates.append({'template_filename': filename, 'serialized_weight': weight,
                    'full_package_path_resolved': False, 'runtime_instantiation_verified': False})
            result.append({'serialized_group_path': path, 'candidates': candidates,
                'serialized_weight_sum': sum(c['serialized_weight'] for c in candidates),
                'group_activation_semantics_verified': False})
        children = node.get('children', [])
        if not isinstance(children, list) or len(children) > 128:
            raise ValueError('AI layout children exceed bounds')
        for child in children:
            visit(child, path, depth + 1)
        if len(result) > 256:
            raise ValueError('AI layout group budget exceeded')

    visit(tree, [], 0)
    return result


def export_filter_flags(package, index):
    field = package.row['name_map_summary_offset']
    _, offset, _, _ = struct.unpack_from('<4i', package.header, field + 16)
    flags = struct.unpack_from('<3i', package.header, offset + (index - 1) * 104 + 44)
    if not all(value in (0, 1) for value in flags):
        raise ValueError('Observed export filter booleans are invalid')
    return dict(zip(('forced_export', 'not_for_client', 'not_for_server'), map(bool, flags)))


def main():
    manifest = json.loads((SOURCE / 'manifest.json').read_text(encoding='utf-8'))
    package = Package(next(r for r in manifest['records'] if r['entry'] == 30261), manifest)
    if package.package_path != PACKAGE:
        raise ValueError('AI layout evidence identifies a different map package')
    actors = [e for e in package.exports if package.object(e['class_index']) == 'AILayoutConfigActor']
    if len(actors) != 1:
        raise ValueError('Expected exactly one serialized AI layout actor')
    actor = actors[0]
    properties = package.properties(actor['index'])
    config, checksum = bounded_config(package, properties['JsonConfig'])
    groups = candidate_groups(config)
    exclusion = properties.get('ExcluList')
    result = {'kind': 'static_client_dam_ai_layout_catalog', 'map_id': 2201,
        'source_archive_relative_path': manifest['archive_relative_path'],
        'source_client_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
        'package_evidence': package.evidence(), 'actor': actor['name'],
        'actor_export_filter_flags': export_filter_flags(package, actor['index']),
        'json_config_serialized_sha256': checksum, 'groups': groups,
        'counts': {'groups': len(groups), 'template_candidates': sum(len(g['candidates']) for g in groups),
            'distinct_template_filenames': len(Counter(c['template_filename'] for g in groups for c in g['candidates']))},
        'exclusion_configuration': {'present': exclusion is not None,
            'serialized_bytes': exclusion['size'] if exclusion else 0, 'decoded': False},
        'original_server_ai_selection_algorithm_recovered': False,
        'ai_behavior_or_actor_replication_implemented': False, 'native_playable_map_verified': False,
        'limitations': ['Template names and weights alone do not determine active-event rules or exclusions.',
            'No full package paths, authority-side AI code or behavior trees are claimed from these names.',
            'Export filter flags do not prove the executable contains server code.']}
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': OUT.relative_to(HERE.parent).as_posix(), 'counts': result['counts'],
        'exclusion_configuration': result['exclusion_configuration']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
