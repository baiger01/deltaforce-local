"""Build the extension-box catalog from verified native rows and Lua witnesses."""

import hashlib
import json
from pathlib import Path

from extract_native_safehouse_catalog import installed_export
from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'work/evidence'
REPORT = EVIDENCE / 'native-warehouse-box-contract-20261020.json'
LUA = EVIDENCE / 'weapon_lua'


def witness(path, ident, first=1, last=10000):
    raw = path.read_bytes()
    function = next(row for row in walk(Reader(raw, allow_client_format1=True).function())
                    if row['id'] == ident)
    return {'file': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'function': ident, 'serialized_offset': function['offset'],
            'instructions': [line for line in listing(function).splitlines()
                             if first <= int(line.split()[0]) <= last]}


def main():
    report = json.loads(REPORT.read_text(encoding='utf-8'))
    source = report['boxes']['source']
    raw, _ = installed_export(source['entry'], source['pak_offset'], pak=source['pak'])
    if hashlib.sha256(raw).hexdigest() != source['sha256']:
        raise ValueError('Installed ExtensionBoxDesc differs from the verified reflection report')
    rows = report['boxes']['rows']
    if len(rows) != 30 or len({row['ItemID'] for row in rows}) != len(rows):
        raise ValueError('Unexpected ExtensionBoxDesc source row identities')
    capacities, current = {}, 0
    for row in sorted(report['warehouse_upgrades']['rows'], key=lambda value: value['Level']):
        for pair in row['UnlockSystemList'].split(';'):
            if pair:
                kind, value = map(int, pair.split(':'))
                if kind == 3:
                    current = value
        capacities[str(row['Level'])] = current
    operation_source = EVIDENCE / 'matched_assets/pak-0-0-pakchunk1-WindowsClient.pak.entry-6681.bin'
    operations = witness(operation_source, '0', 42, 46)
    if not any("'OpreateEquip' K13=1" in line for line in operations['instructions']):
        raise ValueError('Native extension equip enum changed')
    if not any("'OpreateUninstall' K15=2" in line for line in operations['instructions']):
        raise ValueError('Native extension uninstall enum changed')
    slots = json.loads((ROOT / 'outputs/df-local-server/protocol/deposit_slot_catalog.json').read_text(
        encoding='utf-8'))
    catalog = {
        'mapping_status': 'verified_by_native_reflection_and_serialization',
        'source': source, 'native': report['boxes']['native'],
        'serialized_fields': report['boxes']['serialized_fields'],
        'rows': rows,
        'warehouse_device_id': 1010, 'slot_unlock_id': 3,
        'capacity_by_completed_level': capacities, 'maximum_installed': max(capacities.values()),
        'warehouse_upgrade_source': report['warehouse_upgrades']['source'],
        'warehouse_upgrade_rows': report['warehouse_upgrades']['rows'],
        'operations': {'equip': 1, 'uninstall': 2},
        'position_operations': {'add': 1, 'delete': 2, 'modify': 3},
        'slot_contract': {'main_page': 2, 'first_page': 3, 'page_end_exclusive': 20,
                          'slot_multiplier': 1000, 'first_slot_offset': 1,
                          'extension_pos_order_contains': 'equipment_slot_ids',
                          'default_slot_template': 1001,
                          'default_slot_grid': slots['rows']['1001'],
                          'base_main_grid': slots['rows']['2']},
        'special_boxes': {'20090050001': 'Native VIP box is projected at ExtensionVIP98001; '
                          'ordinary warehouse installation does not grant VIP permission.'},
        'limitations': ['Type2 main warehouse expansion units are not reconstructed here.',
                       'Nonempty box removal, replacement, split pages, fishing and VIP '
                       'operations require their separately verified paths.',
                       'Box item restrictions are retained verbatim for the content-move evaluator.'],
        'witnesses': [operations,
            witness(LUA / 'DFMGlobalConst.lua', '0', 608, 622),
            witness(LUA / 'DFMGlobalConst.lua', '0', 823, 837),
            witness(LUA / 'InventoryServer_DepositLogic.lua', '0.17'),
            witness(LUA / 'InventoryServer_DepositLogic.lua', '0.18'),
            witness(LUA / 'InventoryServer_DepositLogic.lua', '0.20'),
            witness(LUA / 'InventoryServer_DepositLogic.lua', '0.21'),
            witness(LUA / 'InventoryServer_Network.lua', '0.11'),
            witness(LUA / 'InventoryServer_Network.lua', '0.5.0', 58, 73),
            witness(LUA / 'InventoryServer_Network.lua', '0.21'),
            witness(LUA / 'InventoryServer_Network.lua', '0.21.0'),
            witness(LUA / 'common_pb.lua', '0', 1389, 1399),
            witness(LUA / 'InventoryServer_Network.lua', '0.40', 75, 121),
            witness(LUA / 'InventoryServer_Network.lua', '0.50'),
            witness(LUA / 'InventoryServer_Network.lua', '0.18'),
            witness(LUA / 'SlotConfig.lua', '0.43'),
            witness(LUA / 'SlotConfig.lua', '0.2'),
            witness(LUA / 'SlotConfig.lua', '0.31'),
            witness(LUA / 'SlotConfig.lua', '0.32'),
            witness(LUA / 'SlotConfig.lua', '0.33'),
            witness(LUA / 'ItemSlot.lua', '0.55', 20, 41),
            witness(LUA / 'ItemSlot.lua', '0.20'),
            witness(LUA / 'ItemSlot.lua', '0.21', 22, 43),
            witness(LUA / 'InventoryServer_Network.lua', '0.17', 5, 12),
            witness(LUA / 'InventoryServer_Network.lua', '0.23', 34, 48),
            witness(LUA / 'ItemOperaTool.lua', '0.44'),
            witness(LUA / 'common_pb.lua', '0', 426, 428),
            witness(LUA / 'ItemBaseTool.lua', '0.4', 1, 55),
            witness(LUA / 'ItemMoveCmd.lua', '0.26', 44, 90),
            witness(LUA / 'ItemOperaTool.lua', '0.42')],
        'evidence_report': {'file': str(REPORT.relative_to(ROOT)),
                            'sha256': hashlib.sha256(REPORT.read_bytes()).hexdigest()},
    }
    output = ROOT / 'outputs/df-local-server/protocol/native_extension_box_catalog.json'
    output.write_text(json.dumps(catalog, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'catalog': str(output), 'boxes': len(rows),
                      'capacity_by_completed_level': capacities}, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
