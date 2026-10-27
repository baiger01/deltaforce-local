"""Pin original extension callback, notification and lazy slot creation paths."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    'InventoryServer_Network.lua': ('d7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc',
                                    ('0.21', '0.21.0', '0.35', '0.43', '0.44', '0.50')),
    'InventoryServer.lua': ('6ee37eece339d7d501b5456170b7369426b02c37514f3cba1cec1858a2b0f147', ('0.18',)),
    'ItemSlot.lua': ('1347f7004f235ab4761cbbaaec6a96d32b0f2058e0610fba1e501d1ea8234639',
                     ('0.2', '0.3', '0.5')),
    'SlotConfig.lua': ('1ab465887508346f090d00caf555b045deb8d5032022821017cbe863c270fc97', ('0.43',)),
    'InventoryServer_DepositLogic.lua': ('594f6ef7896cae11051fd67d365160af4afb699b51c0febb794e7c9dc588bb84',
                                         ('0.21',)),
    'InventoryServer_SortLogic.lua': ('b179130620dd63e41128c69218ad334535aa40e40990d6855933beeb6370bcd9',
                                      ('0.14',)),
    'WarehouseWithTab_HD.lua': ('6442714ffa908c79db4807438021da7be437559d71940b228e56517b0a212cac', ('0.107',)),
    'WarehouseWithTab.lua': ('6d96aa5498bdb6972d237eba3df0cb0d2c9312b81e9c86216ccadceb71a4f88e', ('0.106',)),
    'WarehouseExtSubPanel.lua': ('054697863725a1ea55e1ef4db192fdbdd45991029b4525855c87ad90ee2d93c0', ('0.23',)),
}


def main():
    sources = {}
    for name, (digest, identifiers) in SOURCES.items():
        path = ROOT / 'work/evidence/weapon_lua' / name
        blob = path.read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError('Original extracted Lua changed: ' + name)
        root = Reader(blob, allow_client_format1=True).function()
        if root['source'] != '@' + name:
            raise ValueError('Original source identity differs')
        functions = {fn['id']: fn for fn in walk(root)}
        sources[name] = {'sha256': digest, 'functions': {identifier: {
            'serialized_offset': functions[identifier]['offset'],
            'instructions': listing(functions[identifier]).splitlines()} for identifier in identifiers}}
    report = {'scope': 'Original configuration/consumer evidence only. No runtime or account changes.',
        'sources': sources, 'conclusions': {
            'extension_response': 'ProcessExtItemMoveCmd callback shows tips, saves extension order and invokes its UI event; neither it nor the three UI listeners applies DataChange.',
            'notification_order': '_OnCSDepositChangeNtf unconditionally replaces _extOrder from top-level extension_pos_order. GetAllDepositIds iterates that order without a mapping fallback.',
            'slot_initialization': 'GetSlot lazily constructs ItemSlot. Extension IDs resolve ExtensionDefault1001; Ctor/InitSlot/InitSlotSize initialize the source configured structure.',
            'application_path': 'CSDepositChangeNtf calls ProcessPbDataChange; its MoveSrc/MoveDest handlers preserve the item instance and update the extension mapping.',
            'position_initialization': 'ProcessPbPosChange initializes content page geometry from space when src_prop_id is zero. A separate invented equipment slot initialization is unnecessary.'}}
    target = ROOT / 'work/evidence/native-warehouse-callback-contract-20261020.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(target)


if __name__ == '__main__':
    main()
