"""Read-only reconstruction of the installed ordinary quest abandonment contract."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
LUA = ROOT / 'work/evidence/weapon_lua'


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
    import sys
    sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
    from dfserver.handshake_diagnostic import _candidate_codec

    codec = _candidate_codec()
    protocol = {}
    for name in ('CSQuestGiveUpReq', 'CSQuestGiveUpRes'):
        descriptor = codec.codec.pool.FindMessageTypeByName('pb.' + name)
        protocol[name] = [{'name': field.name, 'number': field.number, 'type': field.type,
                           'label': field.label} for field in descriptor.fields]
    config_raw = (LUA / 'QuestConfig.lua').read_bytes()
    constants = Reader(config_raw, allow_client_format1=True).function()['constants']
    messages = {name: constants[constants.index(name) + 2]
                for name in ('GiveUpQuest', 'GiveUpSubmitQuest')}
    assert '已提交的任务物品将不会返还' in messages['GiveUpSubmitQuest']
    catalog = ROOT / 'outputs/df-local-server/protocol/native_quest_catalog.json'
    quests = json.loads(catalog.read_text(encoding='utf-8'))
    report = {
        'scope': 'Installed client chunks and recovered descriptors read only. No native '
                 'process was started and no account database was updated.',
        'protocol': protocol,
        'catalog': {'file': str(catalog.relative_to(ROOT)),
                    'sha256': hashlib.sha256(catalog.read_bytes()).hexdigest()},
        'source_semantics': {
            'request': 'QuestLogic.DoGiveUpQuest forwards the selected ID to '
                       'QuestServer.GiveUpQuset; the request field is remove_quest_id.',
            'response': 'CSQuestGiveUpRes uses res, not result. The callback resolves '
                        'remove_quest_id and calls GiveUpQuest on that quest.',
            'eligibility': 'QuestDetailPanel._UpdateGiveupBtn shows the button only for '
                           'Accepted and not bShouldAutoAccept. Its click handler refuses '
                           'matching, then asks confirmation with a separate submit warning.',
            'state': 'QuestStruct.GiveUpQuest sets acceptTime=0 and '
                     'UpdateState(QuestState.Unaccepted,true), then resets every objective.',
            'objective_reset': 'QuestObjectiveStruct.ResetObjective sets bAcceptedState=false, '
                               'num=0 and bIsFinsih=false, then emits evtUpdateObjectiveState. '
                               'It does not clear bTracking, spendTime or choice.',
            'underway': 'QuestStruct.UpdateState removes an Accepted quest leaving Accepted '
                        'from the underway set, and emits evtUpdateQuestState.',
            'partial_submissions': 'The original submit warning explicitly states submitted '
                                   'quest items will not be returned. This concerns physical '
                                   'Type1 Submit objectives; Type2 Currency is a wallet '
                                   'condition and is not submitted or debited.',
            'reaccept': 'The ordinary warning explicitly allows reacceptance after abandoning. '
                        'The normal acceptance path still checks its existing prerequisites.',
            'limits': 'The official remote server evaluator is not present. Local support is '
                      'limited to manually accepted Mission/Branch rows without contracts '
                      'or specialised behavior. Daily, seasonal, contract, boss, soldier and '
                      'rebirth lifecycles require their own verified paths.',
        },
        'confirmation_messages': messages,
        'source_examples': [{key: quest[key] for key in ('source_row', 'serialized_offset',
                            'QuestID', 'QuestType', 'ShouldAutoAccept', 'QuestLifeType',
                            'IsContract', 'ObjectiveList')}
                            for quest in quests['quests'] if quest['QuestID'] in (11001, 49001)],
        'witnesses': [witness('QuestLogic.lua', '0.15'),
                      witness('QuestServer.lua', '0.35'),
                      witness('QuestServer.lua', '0.35.0'),
                      witness('cs_quest_editor_pb.lua', '0.80'),
                      witness('cs_quest_editor_pb.lua', '0.82'),
                      witness('QuestDetailPanel.lua', '0.11'),
                      witness('QuestDetailPanel.lua', '0.12'),
                      witness('QuestStruct.lua', '0.21'),
                      witness('QuestStruct.lua', '0.23', 1, 19),
                      witness('QuestStruct.lua', '0.23', 173, 192),
                      witness('QuestObjectiveStruct.lua', '0.5'),
                      witness('QuestConfig.lua', '0', 2722, 2738)],
    }
    output = ROOT / 'work/evidence/native-quest-abandon-contract-20261020.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'report': str(output), 'protocol': protocol,
                      'witnesses': len(report['witnesses'])}, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
