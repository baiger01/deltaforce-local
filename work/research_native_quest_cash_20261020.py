"""Audit installed Currency quest data and read the local account without writes."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
LUA = ROOT / 'work/evidence/weapon_lua'


def witness(name, function_id, first, last):
    path = LUA / name
    raw = path.read_bytes()
    tree = Reader(raw, allow_client_format1=True).function()
    function = next(row for row in walk(tree) if row['id'] == function_id)
    return {
        'file': path.relative_to(ROOT).as_posix(),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'function': function_id,
        'serialized_offset': function['offset'],
        'instructions': [line for line in listing(function).splitlines()
                         if first <= int(line.split()[0]) <= last],
    }


def main():
    paths = {name: PROTOCOL / name for name in (
        'native_quest_catalog.json', 'native_quest_objectives.json')}
    quests = json.loads(paths['native_quest_catalog.json'].read_text(encoding='utf-8'))
    objectives = json.loads(paths['native_quest_objectives.json'].read_text(encoding='utf-8'))
    types = objectives['enums']['QuestObjectiveType']['values']
    assert types['Currency'] == 2 and types['Submit'] == 1
    rows = [row for row in objectives['objectives'] if row['Type'] == types['Currency']]
    assert [(row['ObjectiveID'], row['RequiredCount']) for row in rows] == [
        (4900101, 500000), (4900201, 2000000), (4900301, 10000000),
        (4900401, 25000000), (4900501, 50000000)]
    assert all(row['Param1'] == '17020000010' and not row['Param2']
               and not row['ConditionIDArray'] and not row['PrerequestObjectiveID']
               for row in rows)
    owners = {row['ObjectiveID']: [quest['QuestID'] for quest in quests['quests']
                                  if row['ObjectiveID'] in quest['ObjectiveList']]
              for row in rows}
    compact_fields = ('source_row', 'serialized_offset', 'ObjectiveID', 'Type', 'Param1',
                      'Param2', 'RequiredCount', 'ConditionIDArray', 'PrerequestObjectiveID')
    db = ROOT / 'work/native-test-account/save.sqlite3'
    with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA query_only=ON')
        players = [dict(row) for row in connection.execute(
            'SELECT id,local_name,money FROM players')]
        currencies = [dict(row) for row in connection.execute(
            'SELECT player_id,currency_id,amount FROM native_lobby_currencies '
            'WHERE currency_id=17020000010')]
        progress = [dict(row) for row in connection.execute(
            'SELECT player_id,quest_id,state,accept_time,complete_time,reward_time,'
            'objectives_json FROM native_lobby_quest_progress '
            'WHERE quest_id IN (49001,49002,49003,49004,49005)')]
        physical_currency_rows = connection.execute(
            'SELECT COUNT(*) FROM native_lobby_props WHERE template_id=17020000010'
        ).fetchone()[0]
    for row in progress:
        row['objectives'] = json.loads(row.pop('objectives_json'))
    report = {
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Installed extracted client data and SQLite mode=ro/query_only inspection; '
                 'no live account, original installation or service module was modified.',
        'catalogs': {name: {'file': path.relative_to(ROOT).as_posix(),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                     for name, path in paths.items()},
        'native_objective_source': objectives['source'],
        'currency_rows': [{**{key: row[key] for key in compact_fields},
                           'owner_quest_ids': owners[row['ObjectiveID']]}
                          for row in rows],
        'native_contract': {
            'currency_is_separate_from_submit': 'QuestStruct.AddQuestObjective0.8 adds '
                'only Type Submit1 to _submitObjectiveList. Currency2 is excluded. '
                'GetSubmitObjectives0.31 returns that filtered list.',
            'ordinary_submission_path': 'QuestDetailView0.21 uses only '
                'Get3ItemSubmitInfos(GetSubmitObjectives), then OpenItemSubmitPanel. '
                'Its InventoryServer.GetItemsById lookup does not apply to Currency2.',
            'progress': 'QuestObjectiveStruct0.3 copies server objective.value into num. '
                'QuestObjectiveItem0.10 formats num/numNeeded. This is not a client-side '
                'calculation from current wallet balance.',
            'completed_counter': 'QuestObjectiveItem0.10 PCs72-102 chooses SetType5 '
                'for a finished non-weapon objective, then PCs207-234 still format '
                'the full server num and source numNeeded without a Lua clamp. '
                'Visibility under inherited Blueprint SetType5 is not established; '
                'this is not a verified screenshot of the completed counter.',
            'units': 'QuestObjectiveStruct0.0 copies RequiredCount directly into '
                'numNeeded. The five counts above are integer Haf currency units; '
                'no count-to-money scaling factor is established by this data.',
            'wallet': 'InventoryServer_Network0.5.0 reads deposit response.currency and '
                'currency_limit. InventoryServer_CurrencyLogic0.1 processes each id/num '
                'and emits evtCurrencyDataInit. CurrencyServer0.11 initializes '
                'UnBindBankNote from that event data into _serverDataList.',
            'no_physical_currency_needed': 'Wallet currency records use the currency '
                'protocol list; this audit does not justify inventing a physical '
                'inventory prop for17020000010.',
        },
        'local_reconstruction': {
            'proposed_rule': 'For accepted source Currency2 objectives with empty '
                'additional predicates, resolve decimal Param1 to the actually committed '
                'native_lobby_currencies.amount and compare with RequiredCount. Report '
                'the state-derived count through objective.value and has_completed. '
                'Do not subtract money or wait for CSQuestSubmitPropReq.',
            'status': 'source_supported_local_state_rule_not_recovered_official_server_evaluator',
            'refresh_points': ['quest acceptance', 'quest data read', 'committed currency changes'],
            'implemented_count_policy': 'While accepted, value is the actual integer '
                'wallet balance, including amounts above RequiredCount. It is not '
                'min(balance, RequiredCount). A balance100284911 therefore remains '
                '100284911 in the completion record for threshold500000.',
            'implemented_completion_policy': 'The local evaluator only refreshes '
                'Accepted ordinary quests. Once Completed or Rewarded, later spending '
                'does not reopen the quest or replace its completion-time value. '
                'That saved value can consequently differ from the current wallet. '
                'This latching choice is a qualified local policy, not recovered '
                'official server behavior.',
            'unresolved': 'Official remote evaluator and exact localized objective text '
                'are not present in the inspected chunks. Client evidence disproves '
                'the ordinary manual-submit interpretation, but does not reveal remote '
                'latching or reset policy.',
        },
        'readonly_account_snapshot': {
            'database': db.relative_to(ROOT).as_posix(),
            'query_only': True,
            'players_legacy_money_not_wallet_authority': players,
            'haf_currencies': currencies,
            'cash_quest_progress': progress,
            'physical_haf_rows': physical_currency_rows,
        },
        'witnesses': [
            witness('QuestStruct.lua', '0.8', 19, 28),
            witness('QuestStruct.lua', '0.31', 1, 26),
            witness('QuestDetailView.lua', '0.21', 35, 79),
            witness('QuestObjectiveStruct.lua', '0.0', 14, 18),
            witness('QuestObjectiveStruct.lua', '0.3', 8, 28),
            witness('QuestObjectiveItem.lua', '0.10', 72, 102),
            witness('QuestObjectiveItem.lua', '0.10', 207, 234),
            witness('InventoryServer_Network.lua', '0.5.0', 139, 143),
            witness('InventoryServer_CurrencyLogic.lua', '0.1', 1, 95),
            witness('CurrencyServer.lua', '0.1', 17, 44),
            witness('CurrencyServer.lua', '0.11', 5, 14),
        ],
    }
    output = ROOT / 'work/evidence/native-quest-cash-contract-20261020.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(output), 'currency_objectives': len(rows),
                      'haf_wallets': currencies,
                      'cash_quest_progress': progress,
                      'report_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    main()
