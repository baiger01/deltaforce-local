"""Recover default component trees using both sides of serialized socket links."""

import hashlib
import json
from pathlib import Path

from explore_weapon_nodes import SOURCE, rows


ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'outputs/df-local-server/protocol/weapon_component_catalog.json'


def main():
    presets = json.loads((TARGET.parent / 'weapon_preset_catalog.json').read_text())[
        'default_preset_to_receiver']
    items = json.loads((TARGET.parent / 'game_item_catalog.json').read_text())['rows']
    presets = {preset: receiver for preset, receiver in presets.items()
               if items.get(preset, {}).get('name_key')
               and items[preset]['initial_guide_price'] > 0
               and not items[preset]['is_model_only'] and not items[preset]['is_currency']
               and 0 < items[preset]['length'] <= 9 and 0 < items[preset]['width'] <= 40}
    groups = {int(preset): [] for preset in presets}
    for offset, _, values, _ in rows():
        if values[0x7471] in groups:
            groups[values[0x7471]].append((offset, values))
    result = {}
    for preset, records in groups.items():
        if not records:
            continue
        receiver = presets[str(preset)]
        nodes = {}
        for offset, row in records:
            key = row[0x7479]
            signature = (row[0x747c], row[0x7482], row[0x7483])
            if key in nodes and nodes[key]['signature'] != signature:
                raise ValueError(f'Ambiguous node type in preset {preset}')
            nodes.setdefault(key, {'signature': signature, 'offset': offset, 'rows': []})[
                'rows'].append(row)
        roots = [key for key, node in nodes.items() if node['signature'][1] == 0]
        if len(roots) != 1 or nodes[roots[0]]['signature'][0] != receiver:
            raise ValueError(f'Preset/receiver disagreement: {preset}')
        visited = set()

        def build(node_type):
            if node_type in visited:
                raise ValueError('Cycle or repeated weapon component')
            visited.add(node_type)
            node = nodes[node_type]
            item_id = node['signature'][0]
            if str(item_id) not in items:
                raise ValueError(f'Component ID absent from GameItem: {item_id}')
            components = []
            for child_type, child in nodes.items():
                _, parent_type, parent_socket = child['signature']
                if parent_type != node_type:
                    continue
                # The parent names the child node type and its own socket;
                # the child independently names that parent type and socket.
                matches = [row for row in node['rows']
                           if row[0x746d] == child_type and row[0x7487] == parent_socket]
                if len(matches) != 1:
                    raise ValueError(f'Unmatched socket edge in preset {preset}')
                components.append({'slot': parent_socket, 'prop_data': build(child_type)})
            metadata = items[str(item_id)]
            return {'id': item_id, 'num': 1, 'length': metadata['length'],
                    'width': metadata['width'], 'components': components,
                    'weapon': {'load_bullets': []}}

        tree = build(roots[0])
        if len(visited) != len(nodes):
            raise ValueError('Disconnected weapon node tree')
        result[str(receiver)] = {'preset_id': preset, 'prop': tree,
            'node_offsets': {str(key): node['offset'] for key, node in nodes.items()}}
    report = {'source_pak': 'pak-0-0-pakchunk2-WindowsClient.pak', 'source_entry': 4567,
        'source_uexp_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'client_serialization': 'WeaponAssemblyTool.lua function 0.11.0: ChildPartInfos.SocketId -> components.slot',
        'property_indices': {'preset_id': 0x7471, 'item_id': 0x747c, 'node_type': 0x7479,
            'parent_type': 0x7482, 'parent_socket': 0x7483, 'child_type': 0x746d,
            'child_socket': 0x7487}, 'rows': result}
    TARGET.write_text(json.dumps(report, separators=(',', ':')) + '\n', encoding='utf-8')
    print('validated receiver trees', len(result))
    for receiver in ('18010000010', '18020000003', '18050000005', '18070000004'):
        print(receiver, result[receiver])


if __name__ == '__main__':
    main()
