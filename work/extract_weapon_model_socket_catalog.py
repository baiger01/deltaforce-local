"""Recover model-only socket bindings from verified original preset trees."""

from collections import defaultdict
import hashlib
import json
from pathlib import Path

from explore_weapon_nodes import SOURCE, rows
from extract_weapon_components_catalog import recover_tree


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
TARGET = PROTOCOL / 'weapon_model_socket_catalog.json'


def recover_bindings(groups, items, known_receivers):
    bindings = {}
    unavailable = {}
    verified_presets = 0
    for preset, records in sorted(groups.items()):
        roots = {row[0x747c] for _, row in records if row[0x7482] == 0}
        if len(roots) != 1 or next(iter(roots)) not in known_receivers:
            continue
        receiver = next(iter(roots))
        try:
            recover_tree(preset, receiver, records, items)
        except ValueError as error:
            unavailable[str(preset)] = {
                'receiver_id': receiver, 'reason': str(error),
                'row_offsets': [offset for offset, _ in records],
            }
            continue
        verified_presets += 1
        nodes = defaultdict(list)
        for offset, row in records:
            nodes[row[0x7479]].append((offset, row))
        for node_type, node_records in nodes.items():
            row = node_records[0][1]
            model_id, parent_type, slot = row[0x747c], row[0x7482], row[0x7483]
            if (model_id // 1_000_000_000 != 13 or not parent_type
                    or not items[str(model_id)].get('is_model_only')):
                continue
            parent_records = nodes[parent_type]
            parent_template_id = parent_records[0][1][0x747c]
            edges = [offset for offset, parent in parent_records
                     if parent[0x746d] == node_type and parent[0x7487] == slot]
            if len(edges) != 1:
                raise ValueError('Verified tree lost its unique socket edge')
            key = receiver, parent_template_id, slot, model_id
            binding = bindings.setdefault(key, {
                'receiver_id': receiver, 'parent_template_id': parent_template_id,
                'slot': slot, 'model_id': model_id, 'source_presets': [],
            })
            binding['source_presets'].append({
                'preset_id': preset, 'model_node_type': node_type,
                'model_row_offsets': [offset for offset, _ in node_records],
                'parent_socket_row_offsets': edges,
            })
    return [bindings[key] for key in sorted(bindings)], unavailable, verified_presets


def main():
    item_path = PROTOCOL / 'game_item_catalog.json'
    preset_path = PROTOCOL / 'weapon_preset_catalog.json'
    items = json.loads(item_path.read_text(encoding='utf-8'))['rows']
    presets = json.loads(preset_path.read_text(encoding='utf-8'))
    receivers = set(presets['default_preset_to_receiver'].values())
    groups = defaultdict(list)
    for offset, _, values, _ in rows():
        groups[values[0x7471]].append((offset, values))
    bindings, unavailable, verified_presets = recover_bindings(groups, items, receivers)
    report = {
        'source_pak': 'pak-0-0-pakchunk2-WindowsClient.pak', 'source_entry': 4567,
        'source_uexp_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'game_item_catalog_sha256': hashlib.sha256(item_path.read_bytes()).hexdigest(),
        'weapon_preset_catalog_sha256': hashlib.sha256(preset_path.read_bytes()).hexdigest(),
        'selection_rule': ('All original preset groups with a receiver in the original '
                           'DefaultPreset receiver mapping; require recover_tree to '
                           'verify the full tree and both sides of every socket edge; '
                           'select actual GameItem IsModelOnly adapter IDs of main type 13'),
        'scope_limit': ('Evidence of exact bindings present in verified client presets; '
                        'does not prove every native auto-fill rule, authorize arbitrary '
                        'model-only IDs, or establish a barrel-to-stock dependency'),
        'client_sources': [
            {'file': 'WeaponAssemblyTool.lua',
             'sha256': '3934cf763b87e4ea7cfc779b7db5541f913d321898143b1ff51293994a8d91c5',
             'function': '0.11.0', 'offset': 15191,
             'rule': 'Adapter nodes serialize ChildPartInfos.SocketId and node GUID'},
            {'file': 'WeaponAssemblyTool.lua',
             'sha256': '3934cf763b87e4ea7cfc779b7db5541f913d321898143b1ff51293994a8d91c5',
             'function': '0.125.0', 'offset': 84768,
             'consumer': 'FastCheckSimulateByPropInfo', 'pcs': [[5, 10], [11, 22]],
             'rule': 'Virtual parts return before the missing or zero GUID check'},
            {'file': 'WeaponAssemblyTool.lua',
             'sha256': '3934cf763b87e4ea7cfc779b7db5541f913d321898143b1ff51293994a8d91c5',
             'function': '0.103', 'offset': 73626,
             'consumer': 'Desc_To_ItemGUID2IDs', 'pcs': [[24, 40], [43, 49]],
             'rule': 'Virtual parts and pendants are excluded from physical GUID to item IDs'},
            {'file': 'PartSocket.lua',
             'sha256': '11a97764c4c214185ff6ac993f6df644b4a2cfef549bd552e3c57f784d29d7be',
             'function': '0.4', 'offset': 2429,
             'rule': 'GameItem.IsModelOnly marks the attached item as bVirtualPart'},
            {'file': 'FastEquipLogic.lua',
             'source_pak': 'pak-0-0-pakchunk1-WindowsClient.pak',
             'entry_offset': 17059840,
             'sha256': '2201025fb81c87c4440f925acd3922b9fea20137173abc84e68cf7306eb25bf4',
             'function': '0.0', 'offset': 1319, 'consumer': 'FastEquipInLoby',
             'pcs': [[75, 83], [103, 128], [155, 165]],
             'rule': ('Always creates UnEquipPosition with the incoming item source location; '
                      'only nonvirtual recycled parts set prop_id and prop_gid. A location-only '
                      'entry is normal when model recycling has no physical inventory identity')},
        ],
        'verified_source_presets': verified_presets,
        'unavailable_presets': unavailable, 'rows': bindings,
    }
    TARGET.write_text(json.dumps(report, separators=(',', ':')) + '\n', encoding='utf-8')
    print('verified model socket bindings', len(bindings))
    print('verified source presets', verified_presets)
    print('unavailable source presets', len(unavailable))


if __name__ == '__main__':
    main()
