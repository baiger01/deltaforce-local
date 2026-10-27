"""Pin the live warehouse title failure to original order-cache consumers.

Read the shadow log and extracted original Lua only. The report contains a
bounded traceback and protocol event summary, without copying the full log.
"""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    'InventoryServer_Network.lua': (
        'd7f83db2ae2cf4902b440131c15648c7b7d4b8b8f5e459231b9eb6ec17dcb0dc',
        ('0.31.0', '0.34', '0.35')),
    'InventoryServer_DepositLogic.lua': (
        '594f6ef7896cae11051fd67d365160af4afb699b51c0febb794e7c9dc588bb84',
        ('0.18', '0.21', '0.22', '0.28')),
    'InventoryServer_SortLogic.lua': (
        'b179130620dd63e41128c69218ad334535aa40e40990d6855933beeb6370bcd9',
        ('0.1.0', '0.2.0', '0.14')),
    'WarehouseWithTab_HD.lua': (
        '6442714ffa908c79db4807438021da7be437559d71940b228e56517b0a212cac',
        ('0.28', '0.30', '0.33', '0.38')),
    'Warehouse.lua': (
        '21c779d28c7ec35ed8e508e1d3830b61262fdf28b648d724007a528f630963d1',
        ('0.18', '0.33')),
    'WarehouseDepositTab_HD.lua': (
        '7613cd431bfcaacbd7a59fe5e23192e8a5fa2d24aba37768d502efe76db88292',
        ('0.10', '0.12', '0.31')),
}


def main():
    sources = {}
    for name, (digest, identifiers) in SOURCES.items():
        blob = (ROOT / 'work/evidence/weapon_lua' / name).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError('Original extracted Lua changed: ' + name)
        root = Reader(blob, allow_client_format1=True).function()
        if root['source'] != '@' + name:
            raise ValueError('Original source identity differs: ' + name)
        functions = {fn['id']: fn for fn in walk(root)}
        sources[name] = {'sha256': digest, 'functions': {identifier: {
            'serialized_offset': functions[identifier]['offset'],
            'first_source_line': functions[identifier]['first_line'],
            'last_source_line': functions[identifier]['last_line'],
            'constants': functions[identifier]['constants'],
            'instructions': listing(functions[identifier]).splitlines(),
        } for identifier in identifiers}}

    log = Path('F:/deltaforce-local-shadow/DeltaForce/Saved/Logs/DeltaForce.log')
    blob = log.read_bytes()
    if blob.startswith(b'\xef\xbb\xbf'):
        blob = blob[3:]
    lines = bytes(value ^ 0x5c for value in blob).decode('utf-8', 'replace').splitlines()
    variable_start = next(index for index, line in enumerate(lines)
                          if '13.33.29:993' in line and 'Variable Detail:' in line)
    trace_start = next(index for index, line in enumerate(lines)
                       if '13.33.29:994' in line and 'stack traceback:' in line)
    witness = [{'decoded_line': index + 1, 'text': lines[index]}
               for index in (*range(variable_start, variable_start + 32),
                             *range(trace_start, trace_start + 27))]
    scroll = [{'decoded_line': index + 1, 'text': line}
              for index, line in enumerate(lines)
              if ('13.33.27:' in line or '13.33.28:' in line)
              and 'InvSlotView:OnSlotScroll_Internal' in line]
    server_log = ROOT / 'work/elevated-native-trials/1792474286351322800.log'
    events = []
    for index, line in enumerate(server_log.read_text(encoding='utf-8').splitlines()):
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (event.get('phase') == 'processed'
                and 'T05:33:' in event.get('observed_at_utc', '')
                and event.get('request_name') in ('CSDepositEquipPropReq',
                    'CSDepositSortMultiplePosReq', 'CSDepositOperateExtensionBoxReq')):
            events.append({'line': index + 1, **{key: event[key] for key in (
                'observed_at_utc', 'request_name', 'prefix_sequence',
                'local_commerce_result', 'local_warehouse_sort_result',
                'local_warehouse_sort_change_count') if key in event}})
    report = {
        'scope': 'Read-only original consumer and live failure evidence. No account/runtime changes.',
        'sources': sources,
        'live': {'client_log': str(log), 'encoding': 'Optional UTF-8 BOM, byte XOR 0x5c, UTF-8',
                 'traceback': witness, 'page_transition': scroll,
                 'server_log': str(server_log), 'events': events},
        'conclusions': {
            'actual_failure': 'Warehouse._RefreshDepositTitle line522 ensure(extItem) fails: extSlotId97001, extSlot exists, extItem=nil. The lifecycle dump self is WarehouseWithTab_HD; SafeBoxAndKeyChainPopWindow is a misleading symbol label.',
            'cache_contract': '_OnCSDepositEquipPropRes success unconditionally assigns _extOrder=res.extension_pos_order before applying deposit_change. An omitted repeated field decodes empty and clears installed normal box navigation.',
            'navigation_contract': 'GetAllDepositIds enumerates GetExtOrder, maps each normal slot through _extMapping and skips Fishing97001. GetDepositIdByIndex returns None outside that list. _SelectDepositTab treats None as FishingContainer97. Its title later requires the actual equipped fishing box.',
            'reproduction': 'Install an ordinary box at3001. Perform a successful ordinary CSDepositEquipPropReq whose reply omits extension_pos_order. Select the existing second warehouse tab, then Escape. The live trial has exactly these events; latest successful equipment reply is13:33:26.770, scroll changes2 to97 at13:33:28.145, ensure fails13:33:29.993.',
            'minimum_server_fix': 'Return the actual committed extension_pos_order in every successful CSDepositEquipPropRes. Preserve the same value in inventory notifications. Do not create a fishing item, fishing mapping, permission or page to repair ordinary box navigation.',
            'sort_excluded': 'SortLogic.DoSortSlots callback0.1.0 applies changes and posts sort events; it does not replace extension order. SetCommonConfig callback0.2.0 only handles local-order dirty state.',
            'long_press_excluded': 'InitDepositTab only enables bHandleLongPress for owned Warehouse/ExtWarehouse paths; Available/Locked do not enable it. An unowned long-press hypothesis is unsupported.',
            'icon_warnings': 'Resource load failures for Common_ItemProp_Icon_0001 and other PaperSprites are separate asset warnings. The traced exception is ensure(nil), and LuaErrorTipsTool99 table-index-nil is a secondary error-reporting failure.',
        },
    }
    target = ROOT / 'work/evidence/native-warehouse-title-failure-contract-20261020.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(target)
    print('Pinned', len(sources), 'original sources and', len(events), 'bounded protocol events')


if __name__ == '__main__':
    main()
