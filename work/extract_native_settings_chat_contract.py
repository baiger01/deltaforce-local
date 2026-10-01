"""Reproduce settings/chat contracts from read-only installed Lua exports."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
PROTOCOL = ROOT / 'outputs/df-local-server/protocol'
EXPORTS = ROOT / 'work/evidence/weapon_lua'
PAK = 'pak-0-0-pakchunk1-WindowsClient.pak'
SOURCES = {'cs_setting_editor_pb.lua': 6766, 'cs_setting_pb.lua': 6767,
           'SystemSettingServer.lua': 6945, 'CloudSettingCoreLogic.lua': 6187,
           'cs_chat_editor_pb.lua': 6672, 'cs_worldchat_editor_pb.lua': 6788,
           'FrontEndChatServer.lua': 6872, 'ChatConfig.lua': 2770,
           'ChatField.lua': 2771, 'ChatModule.lua': 2772}
MESSAGE_NAMES = {'SettingKeyValue', 'RollingNotice', 'CSSettingPutKeyValueReq',
                 'CSSettingPutKeyValueRes', 'CSSettingGetValueByKeyReq', 'CSSettingGetValueByKeyRes',
                 'CSSettingGetValuesByTypeReq', 'CSSettingGetValuesByTypeRes',
                 'CSChatWorldLoadTReq', 'CSChatWorldLoadTRes',
                 'CSChatGetMsgSumyAllChannelReq', 'CSChatGetMsgSumyAllChannelRes',
                 'CSWorldChatGetRoomIDReq', 'CSWorldChatGetRoomIDRes'}


def main():
    sources, functions = {}, {}
    for name, entry in SOURCES.items():
        path = EXPORTS / name
        if not path.exists():
            path = ROOT / 'work/evidence/matched_assets' / f'{PAK}.entry-{entry}.bin'
        raw = path.read_bytes()
        root = Reader(raw, allow_client_format1=True).function()
        if root['source'] != '@' + name:
            raise ValueError('Source entry does not match the observed Lua name')
        sources[name] = {'pak': PAK, 'entry': entry, 'sha256': hashlib.sha256(raw).hexdigest(),
                         'size': len(raw)}
        functions[name] = {function['id']: function for function in walk(root)}
    fields = json.loads((PROTOCOL / 'generated_codec_fields.json').read_text(encoding='utf-8'))
    declarations = json.loads((PROTOCOL / 'generated_class_metadata.json').read_text(encoding='utf-8'))
    messages = [message for message in fields['messages'] if message['name'] in MESSAGE_NAMES]
    if {message['name'] for message in messages} != MESSAGE_NAMES:
        raise ValueError('Expected installed settings/chat message definitions')
    for message in messages:
        name = message['source'].lstrip('@')
        if message['source_sha256'] != sources[name]['sha256']:
            raise ValueError('Codec metadata and installed source export hashes differ')
    config = functions['ChatConfig.lua']['0']
    index = config['constants'].index('DEFAULTINTERVAL')
    interval = config['constants'][index + 1]
    if interval != 20.0:
        raise ValueError('Installed default polling interval changed')
    interval_code = listing(functions['ChatModule.lua']['0.25'])
    if not all(fragment in interval_code for fragment in ('ADD        R2 1 2', "'_localinterval'", "'time'")):
        raise ValueError('Client additive polling interval consumer changed')
    consumer = functions['FrontEndChatServer.lua']['0.53.0.0.0']
    if not all(field in consumer['constants'] for field in ('msg_list', '_worldMsgIndex', 'load_msg_interval', 'new_room_id')):
        raise ValueError('Native world-chat success consumer changed')
    report = {'source_pak': PAK, 'sources': sources, 'messages': messages,
        'declared_services': {message['name']: message['service'] for message in declarations['messages']
                              if message['name'] in MESSAGE_NAMES},
        'settings_consumers': ['SystemSettingServer.lua 0.26.0, 0.28.0, 0.35.0, 0.37.0',
                              'CloudSettingCoreLogic.lua 0.21'],
        'chat_consumers': ['FrontEndChatServer.lua 0.5.0, 0.53.0.0.0',
                           'ChatModule.lua 0.25, 0.38.0', 'ChatField.lua 0.29-0.30',
                           'ChatConfig.lua 0 DEFAULTINTERVAL/PanelToInterval'],
        'polling': {'client_default_interval_seconds': interval, 'response_interval_is_additive': True,
                    'active_panels_can_reduce_the_client_interval': True,
                    'local_offline_response_increment_seconds': 0},
        'local_policy': ['Settings are isolated by local player and key; values are stored verbatim.',
            'A local one-MiB JSON storage bound leaves space for complete type-query envelopes.',
            'No online room is created; native zero sentinels and empty messages retain the read cursor.',
            'The asymmetric RollingNotice codec is usable only through omitted/empty references.',
            'No actual announcements, online history, share-code service or message sending are simulated.']}
    output = PROTOCOL / 'native_settings_chat_contract.json'
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print({'messages': len(messages), 'source_hashes_verified': len(sources),
           'client_default_interval_seconds': interval})


if __name__ == '__main__':
    main()
