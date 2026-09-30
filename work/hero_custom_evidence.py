"""Read-only focused inspection for native hero customization evidence."""

import argparse
import hashlib
import json
from pathlib import Path

from lua53_reader import Reader, listing, walk


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['lua', 'protocol', 'index'])
    parser.add_argument('selectors', nargs='*')
    args = parser.parse_args()
    if args.mode in ('lua', 'index'):
        for selector in args.selectors:
            file_name, _, ids = selector.partition('::')
            source = Path(file_name)
            if not source.is_absolute():
                source = ROOT / file_name if '/' in file_name else ROOT / 'work/evidence/weapon_lua' / file_name
            raw = source.read_bytes()
            reader = Reader(raw, allow_client_format1=True)
            root = reader.function()
            print('SOURCE', file_name, root['source'], 'sha256', hashlib.sha256(raw).hexdigest(),
                  'bytes', len(raw), 'consumed', reader.at)
            selected = ids.split(',') if ids else None
            for fn in walk(root):
                if args.mode == 'index':
                    import re
                    relevant = [c for c in fn['constants'] if isinstance(c, str)
                                and re.search('CS|Accessor|Fashion|Watch|Card|Voice|VO|List|Table|Equip|Belong|Load|Default|Unlock', c)]
                    print(fn['id'], fn['first_line'], fn['last_line'], repr(relevant))
                    continue
                if selected is None or fn['id'] in selected:
                    print('FUNCTION', fn['id'], 'lines', fn['first_line'], fn['last_line'],
                          'offset', fn['offset'], 'params', fn['params'])
                    print('CONSTANTS', repr(fn['constants']))
                    print(listing(fn))
    else:
        source = ROOT / 'outputs/df-local-server/protocol/generated_codec_fields.json'
        data = json.loads(source.read_text(encoding='utf-8'))
        for message in data['messages']:
            if any(message['name'] == s or s.endswith('*') and message['name'].startswith(s[:-1])
                   for s in args.selectors):
                print('MESSAGE', message['name'], 'source', message['source'],
                      'sha256', message['source_sha256'])
                for field in message['fields']:
                    print(field['number'], field['name'], field['codec_category'],
                          'repeated' if field['repeated'] else 'single', field['nested_type'])


if __name__ == '__main__':
    main()
