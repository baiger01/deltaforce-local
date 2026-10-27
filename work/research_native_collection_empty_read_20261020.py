"""Pin original empty collection read-receipt construction and callback semantics."""

import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    'CollectionLogic.lua': (
        '1c7f07e450f9ae5755f95de0151bee3e7b776a1c4e124b36d32b9b7e92acd3ed',
        ('0.83',)),
    'CollectionServer.lua': (
        '30fd97e50c22998e987b1fdcf8ee7a0e4edfe1ae51b93dc1d6e11ff5e7bf37f2',
        ('0.138', '0.138.0')),
    'CollectionsHangingPagePanel.lua': (
        '2b7db3a7ad803005e17ec8aa70cb584c041e1b2959d9f1d1760f9d19a94b8c47',
        ('0.29', '0.38')),
    'CollectionSafeBoxSkinPagePanel.lua': (
        'af3e235d9863593f44da871c0b47d733de231dbe3a01ee36d3e5376b64c0bdc8',
        ('0.24', '0.26')),
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
    log = ROOT / 'work/elevated-native-trials/1792474286351322800.log'
    events = []
    for index, line in enumerate(log.read_text(encoding='utf-8').splitlines()):
        if not line.startswith('{') or len(line) > 10000:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (event.get('phase') == 'processed'
                and event.get('request_name') == 'CSCollectionUpdateRedPointReq'
                and 'T05:51:' in event.get('observed_at_utc', '')):
            events.append({'line': index + 1, **{key: event[key] for key in (
                'observed_at_utc', 'request_name', 'prefix_sequence',
                'local_commerce_result', 'local_collection_read_request') if key in event}})
    report = {
        'scope': 'Original extracted consumers and existing native trial log only; no service/account changes.',
        'sources': sources,
        'extraction': {'CollectionLogic.lua': {
            'archive': 'pak-0-0-pakchunk1-WindowsClient.pak', 'entry': 2846,
            'source_game': 'F:/WeGameApps/rail_apps/DeltaForce(2001918)',
            'command': 'DF_LOCAL_SOURCE_GAME=<original> python work/scan_weapon_tables.py --baseline --pak-name pak-0-0-pakchunk1-WindowsClient.pak --lua-pattern ^CollectionLogic.lua$ --asset-pattern ^$'}},
        'live': {'server_log': str(log), 'events': events},
        'conclusions': {
            'construction': 'CollectionLogic.RemoveRedDots0.83@87716/source2072-2081 instr11-16 inserts {id=item.id,gid=item.gid} without filtering an empty identity; instr19-24 forwards the list to CollectionServer.UpdateRedDot.',
            'request': 'CollectionServer.UpdateRedDot0.138@134899/source3155-3191 instr1-12 only checks whether the props/pattern lists are empty. Instr14-24 sends props unchanged; a one-element empty identity passes this list-level test.',
            'callback': 'CollectionServer.UpdateRedDot callback0.138.0@135152/source3159-3184 instr12-16 looks up _collectionPropRedDots[propInfo.id] before modifying anything. A missing key jumps to42, leaving redpoints unchanged. A successful empty-identity acknowledgement therefore has no local effect.',
            'live_witness': 'At05:51:24.572606 native sequence2755 has props=[{}], empty prop_ids/patterns/suit IDs and result157016. Nearby real identity requests succeed.',
            'minimum_scope': 'Authenticate normally; normalize missing id/gid to zero for this props identity only, and skip a pair only when both are zero. Do not create a prop read record for0/0. Keep the existing exact ownership checks for every nonzero identity and atomic batch failure for unknown IDs or wrong instance IDs.',
            'negative_scope': 'An id0 with a nonzero gid is not this no-op. No evidence authorizes changes to legacy prop_ids, pattern IDs, mystical suit IDs, granting, or ownership. This is a compatibility policy inferred from the original sender/callback and a native request, not an official server response capture.',
            'default_item_limit': 'Original UI contains id0 randomItemTag placeholders: SafeBox0.24 instr34-39 and Hanging0.29 instr60-65. Their click handlers guard randomItemTag, so these rows do not prove the exact source of sequence2755. Do not label it a confirmed default-skin/no-skin item.',
        },
    }
    target = ROOT / 'work/evidence/native-collection-empty-read-contract-20261020.json'
    target.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(target)
    print('Pinned', len(sources), 'source hashes and', len(events), 'native read requests')


if __name__ == '__main__':
    main()
