"""Read-only source audit of persistent department/device quest objectives."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
LUA = ROOT / 'work/evidence/weapon_lua'


def read_json(name):
    return json.loads((PROTOCOL / name).read_text(encoding='utf-8'))


def witness(name, function_id, first, last):
    path = LUA / name
    raw = path.read_bytes()
    root = Reader(raw, allow_client_format1=True).function()
    function = next(row for row in walk(root) if row['id'] == function_id)
    return {'file': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'function': function_id, 'serialized_offset': function['offset'],
            'instructions': [line for line in listing(function).splitlines()
                             if first <= int(line.split()[0]) <= last]}


def compact(row, names):
    return {key: row[key] for key in ('source_row', 'serialized_offset', *names)}


def main():
    quests = read_json('native_quest_catalog.json')
    objectives = read_json('native_quest_objectives.json')
    departments = read_json('native_department_catalog.json')
    safehouse = read_json('native_safehouse_catalog.json')
    quest_by_id = {row['QuestID']: row for row in quests['quests']}
    objective_by_id = {row['ObjectiveID']: row for row in objectives['objectives']}
    types = objectives['enums']['QuestObjectiveType']['values']
    reputation = [row for row in objectives['objectives'] if row['Type'] == types['ReputationLevel']]
    devices = [row for row in objectives['objectives'] if row['Type'] == types['UpgradeSafehouseDeviceLevel']]
    assert types['ReputationLevel'] == 21 and types['UpgradeSafehouseDeviceLevel'] == 6
    assert all(row['Param2'] == '' for row in reputation)
    assert all(int(row['Param2']) == row['RequiredCount'] for row in devices)
    assert all(int(row['Param1']) in {upgrade['DeviceId'] for upgrade in safehouse['upgrades']}
               for row in devices)
    assert all(not row['ConditionIDArray'] and row['PrerequestObjectiveID'] == 0
               for row in reputation + devices)
    assert all(not row['MapID'] for row in reputation)
    fields = ('ObjectiveID', 'Type', 'Param1', 'Param2', 'RequiredCount',
              'ShouldMustBeCompleted', 'PrerequestObjectiveID', 'ConditionIDArray')
    owners = {row['ObjectiveID']: [quest['QuestID'] for quest in quests['quests']
                                if row['ObjectiveID'] in quest['ObjectiveList']]
              for row in reputation + devices}
    focused = quest_by_id[41907]
    chain, pending, visited = [], [focused['QuestID']], set()
    while pending:
        quest_id = pending.pop(0)
        if quest_id in visited:
            continue
        visited.add(quest_id)
        row = quest_by_id[quest_id]
        chain.append(compact(row, ('QuestID', 'QuestType', 'PreviousIDList', 'AcceptRequiredLevel')))
        pending.extend(row['PreviousIDList'])
    quality_device_edges = []
    for row in safehouse['upgrades']:
        for part in row['QualityList'].split(';'):
            if part:
                card, level = (int(value) for value in part.split(':'))
                quality_device_edges.append({'quality_id': card, 'required_quality_level': level,
                    **compact(row, ('Id', 'DeviceId', 'Level'))})
    report = {
        'scope': 'Extracted installed client and recovered catalogs read only; no native process, '
                 'account updates, forged gameplay events, or shared service changes.',
        'catalog_sources': {name: {'path': str((PROTOCOL / name).relative_to(ROOT)),
            'sha256': hashlib.sha256((PROTOCOL / name).read_bytes()).hexdigest()}
            for name in ('native_quest_catalog.json', 'native_quest_objectives.json',
                         'native_department_catalog.json', 'native_safehouse_catalog.json')},
        'reputation_objective_contract': {
            'enum_name': 'ReputationLevel', 'enum_value': types['ReputationLevel'],
            'param1': 'Decimal RoleQuality card ID; QuestObjectiveItem 0.8 converts param1 '
                      'to number and looks up ShopServer.GetMerchantStructByPid.',
            'param2': 'Empty in every installed Type21 row; no additional threshold lives here.',
            'required_count': 'Copied to objective.numNeeded by QuestObjectiveStruct 0.0.',
            'client_progress': 'UpdateObjective 0.3 copies server value to num and '
                               'has_completed to bIsFinsih; it does not calculate standing.',
            'local_persistent_proof_policy': 'For accepted Type21 rows with the recovered empty '
                'conditions/prerequest, resolve Param1 to the account cumulative department '
                'balance, calculate its level using the verified curve, and compare that '
                'level with RequiredCount. This reconstructs a local state-derived rule; '
                'the official server evaluator is not included in this source.',
            'rows': [{**compact(row, fields), 'owner_quest_ids': owners[row['ObjectiveID']]}
                     for row in reputation]},
        'device_objective_contract': {
            'enum_name': 'UpgradeSafehouseDeviceLevel', 'enum_value': types['UpgradeSafehouseDeviceLevel'],
            'device_level_enum_name': 'No QuestObjectiveType named DeviceLevel exists.',
            'param1': 'Decimal safehouse device ID; IDs match recovered SafeHouseUpgrade.DeviceId.',
            'param2': 'Decimal target level string in every installed Type6 row.',
            'required_count': 'Equals integer Param2 in every installed Type6 row.',
            'local_persistent_proof_policy': 'Read actually committed owned device level. '
                'An in-progress upgrade does not prove the target level. Comparing the '
                'committed level to RequiredCount is a source-supported local reconstruction, '
                'not recovered official server evaluator code.',
            'rows': [{**compact(row, fields), 'owner_quest_ids': owners[row['ObjectiveID']]}
                     for row in devices]},
        'quest_41907': {
            'quest': compact(focused, ('QuestID', 'QuestType', 'PreviousIDList',
                'AcceptRequiredLevel', 'ObjectiveList', 'ShowCondition', 'QuestConditionIDArray',
                'SpecialType', 'FrozenTimeAfterPreQuestReward')),
            'objectives': [compact(objective_by_id[ident], fields) for ident in focused['ObjectiveList']],
            'ancestor_chain': chain,
            'root_lines': [compact(row, ('QuestLineID', 'RootQuestID', 'OpenLevel', 'OpenLimits'))
                           for row in quests['lines'] if row['RootQuestID'] in visited],
            'interpretation': 'Acceptance requires owned season level35 and predecessor41013 '
                'rewarded under the inspected prerequisite rule. Its related line1006 opens '
                'at season level16. All five required Type21 objectives independently '
                'require the named quality card to reach level4. No objective Param2, '
                'map, prerequisite-objective, or extra condition is configured in these rows.'},
        'eligibility_boundaries': {
            'quest_acceptability': 'QuestServer 0.39 checks cooldown, season level, '
                'Unread/Unaccepted state and additional season quest group timing.',
            'prerequisites': 'QuestStruct 0.47 rejects existing predecessors whose state '
                'is below Rewarded. QuestLineStruct 0.2 uses season level and '
                'QuestServer.IsQuestCompleted(OpenLimits), which compares existing states '
                'against Completed in 0.40.',
            'all_departments_max': 'QuestServer 0.43 reads RoleInfoServer.GetPrestigeMaxLv '
                'and MerchantStruct.GetCurPrestigeLv; inspected call sites are navigation '
                'selection in ShopChooseDepartmentView0.1 and HDIrisSafeHouseUINavLogic2 '
                '0.9, not a proof of an extra41907 acceptance gate.',
            'unknown_server_rules': 'The original remote quest objective evaluator and '
                'account eligibility service are unavailable; absence of further client '
                'checks does not establish absence of remote checks.'},
        'merchant_contract': {
            'card_to_merchant': [{'quality_id': row['card_id'], 'merchant_id': row['merchant_id'],
                'source_refs': row['source_refs']['merchants']} for row in departments['departments']],
            'vip_is_separate': 'MerchantStruct.GetCurPrestigeLv0.6 returns the quality card '
                'level, while ShopServer0.39 independently handles merchant vip_score, '
                'vip_lvl, intimacy and intimacy_lvl changes. No conversion is established.',
            'fetch_consumer': 'ShopServer0.55.0 applies returned merchants by matching '
                'id against source MerchantStruct. This supports five source merchant '
                'identities, not fabricated vip/intimacy progression or extra purchase goods.',
            'local_current_response': 'local_commerce.py currently emits only merchant '
                'id1,vip_lvl1. This audit leaves shared code unchanged.'},
        'quality_usage_contract': {
            'wire': 'RoleQualityUsage(desc:string,type:string,target:uint32).',
            'description_relation': 'RoleInfoServer0.57.0 indexes UsageList{position}Desc '
                'from RoleQuality; recovered RoleQuality only supplies these text fields, '
                'not configured per-slot types/targets.',
            'shop': 'PrestigeUsagePanel0.13.1 type Shop calls Module.Shop.ShowMainPanel(target). '
                'Known card-to-merchant relations identify functional merchant targets, '
                'but do not prove which Shop usage entries or order the official response contains.',
            'safehouse': 'type SafeHouse calls Module.BlackSite.Jump(target,true). '
                'BlackSiteLogic0.4 treats four-digit target as device ID. Recovered '
                'SafeHouseUpgrade.QualityList gives prerequisite edges below; those are '
                'not the missing RoleQualityUsage configuration.',
            'configured_per_card_payload': None,
            'safehouse_quality_prerequisite_edges': quality_device_edges},
        'witnesses': [
            witness('QuestObjectiveStruct.lua', '0.0', 1, 26),
            witness('QuestObjectiveStruct.lua', '0.3', 6, 28),
            witness('QuestObjectiveItem.lua', '0.8', 85, 108),
            witness('QuestObjectiveItem.lua', '0.8', 125, 150),
            witness('QuestServer.lua', '0.39', 1, 46),
            witness('QuestServer.lua', '0.40', 1, 26),
            witness('QuestServer.lua', '0.43', 1, 46),
            witness('QuestStruct.lua', '0.47', 1, 22),
            witness('QuestLineStruct.lua', '0.2', 1, 17),
            witness('MerchantStruct.lua', '0.1', 1, 27),
            witness('MerchantStruct.lua', '0.6', 1, 7),
            witness('ShopServer.lua', '0.39', 34, 54),
            witness('ShopServer.lua', '0.55.0', 22, 34),
            witness('BlackSitePreconditionItem.lua', '0.2', 109, 134),
            witness('BlackSiteLogic.lua', '0.4', 23, 37),
            witness('PrestigeUsagePanel.lua', '0.13.1', 1, 21),
        ],
        'limitations': ['No numeric reputation widths were invented or promoted from test fixtures.',
            'No fabricated map kill, extraction, or interaction events are proposed.',
            'Official per-card quality usage type/target/order remains unrecovered.',
            'Merchant vip progression and official card unlock/disable policy remain unrecovered.'],
    }
    output = ROOT / 'work/evidence/native-quest-standing-contract-20261019.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(output), 'reputation_objectives': len(reputation),
        'device_objectives': len(devices), 'quest_41907_gates': [
            [row['ObjectiveID'], row['Param1'], row['RequiredCount']]
            for row in report['quest_41907']['objectives']],
        'safehouse_quality_edges': len(quality_device_edges)}, indent=2))


if __name__ == '__main__':
    main()
