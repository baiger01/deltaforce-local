"""Preserve installed client evidence for the single-gun submission UI contract."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
LUA = ROOT / 'work/evidence/weapon_lua'
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'


def witness(name, ident, first=1, last=10000):
    path = LUA / name
    raw = path.read_bytes()
    function = next(row for row in walk(Reader(raw, allow_client_format1=True).function())
                    if row['id'] == ident)
    return {'file': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'function': ident, 'serialized_offset': function['offset'],
            'instructions': [line for line in listing(function).splitlines()
                             if first <= int(line.split()[0]) <= last]}


def main():
    catalog = json.loads((PROTOCOL / 'native_quest_catalog.json').read_text(encoding='utf-8'))
    objectives = json.loads((PROTOCOL / 'native_quest_objectives.json').read_text(encoding='utf-8'))
    quest = next(row for row in catalog['quests'] if row['QuestID'] == 50001)
    objective = next(row for row in objectives['objectives'] if row['ObjectiveID'] == 5000101)
    assert quest['ObjectiveList'] == [objective['ObjectiveID']]
    assert objective['Type'] == objectives['enums']['QuestObjectiveType']['values']['Submit']
    assert objective['RequiredCount'] == 1
    report = {
        'scope': 'Installed client chunks and recovered tables inspected read only. '
                 'The native game and preserved account database were not modified.',
        'catalog_sources': {name: {'file': str((PROTOCOL / name).relative_to(ROOT)),
                           'sha256': hashlib.sha256((PROTOCOL / name).read_bytes()).hexdigest()}
                           for name in ('native_quest_catalog.json', 'native_quest_objectives.json')},
        'panel_sources': {'pak': 'pak-0-0-pakchunk1-WindowsClient.pak',
                          'entries': {'ItemsSubmitItem.lua': 4297, 'ItemsSubmitPanel.lua': 4298},
                          'extraction_command': 'work/scan_weapon_tables.py --baseline '
                              '--pak-name pak-0-0-pakchunk1-WindowsClient.pak '
                              '--lua-pattern ItemsSubmit --asset-pattern ^$ --max-entries 7200'},
        'quest': {key: quest[key] for key in ('source_row', 'serialized_offset', 'QuestID', 'ObjectiveList')},
        'objective': {key: objective[key] for key in ('source_row', 'serialized_offset', 'ObjectiveID',
                       'Type', 'Param1', 'Param2', 'ListParam', 'RequiredCount', 'ShouldMustBeCompleted')},
        'source_contract': {
            'submit_objectives': 'QuestStruct.AddQuestObjective0.8 places only Type Submit '
                'into _submitObjectiveList. Type Currency is not a submission objective.',
            'candidate_collection': 'QuestLogic.Get3ItemSubmitInfos0.17 obtains owned items '
                'from InventoryServer.GetItemsById(receiver ID), then keys candidates by '
                'ItemStruct identity. It separately creates one descriptor per objective.',
            'required_preview': 'ItemsSubmitPanel._UpdateRequiredItems0.9 creates a '
                'WeaponSubmitItem in _wtRequiredItemBox for the objective descriptor.',
            'owned_choices': 'ItemsSubmitPanel.UpdateAvailableItems0.12 creates separate '
                'WeaponAvailableItem widgets in _wtAvailableItemBox for owned candidates.',
            'attachment_check': 'ItemsSubmitPanel0.10.0 reads the matching objective listParam '
                'and passes it, receiver ID and owned gid to '
                'Gunsmith.GetWeaponEquippedPartListAndUnequipPartList. It checks that the '
                'unequipped required-part list is empty.',
            'complete_panel': 'ItemsSubmitPanel._RefreshItemSubmitPanel0.10 PCs11-21 closes '
                'the panel when the sufficient objective count equals the descriptor count. '
                'For this one-objective, one-gun quest, one valid submission therefore '
                'removes every displayed candidate/preview from the submission panel.',
            'inventory_projection': 'Current local warehouse projection places each saved '
                'root in one inventory destination and keeps installed parts nested under '
                'the root. The native candidate lookup returns the receiver ID list, '
                'rather than treating required attachments as separate quest objectives.',
        },
        'verification': {'test': 'outputs/df-local-server/tests/test_native_quest_submission_candidates.py',
                         'contract': 'Two owned matching gun roots with the required attachment; '
                             'submitting one completes the objective, deletes only that root '
                             'and its parts, retains the other full gun snapshot, and rejects '
                             'a subsequent attempt to submit the remaining gun.',
                         'fixture_ids_are_diagnostic': True},
        'limitations': ['The official remote inventory evaluator is unavailable.',
                       'Disappearing submission choices alone do not establish that two '
                       'physical guns were consumed; compare owned root snapshots.',
                       'The exact two rows observed by the user require a native screenshot '
                       'or live UI inspection to distinguish requirement preview from '
                       'multiple owned choices.'],
        'witnesses': [witness('QuestStruct.lua', '0.8'),
                      witness('QuestLogic.lua', '0.17', 9, 42),
                      witness('QuestLogic.lua', '0.17', 67, 139),
                      witness('QuestLogic.lua', '0.17.1'),
                      witness('InventoryServer.lua', '0.47'),
                      witness('ItemsSubmitPanel.lua', '0.9'),
                      witness('ItemsSubmitPanel.lua', '0.10'),
                      witness('ItemsSubmitPanel.lua', '0.10.0'),
                      witness('ItemsSubmitPanel.lua', '0.11'),
                      witness('ItemsSubmitPanel.lua', '0.12'),
                      witness('ItemsSubmitItem.lua', '0.1')],
    }
    output = ROOT / 'work/evidence/native-quest-submission-candidates-contract-20261020.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(output), 'witnesses': len(report['witnesses']),
                      'quest_id': quest['QuestID'], 'required_count': objective['RequiredCount']},
                     ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
