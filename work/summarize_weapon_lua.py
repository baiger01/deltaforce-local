"""List relevant constants in extracted client Lua chunks without executing them."""

import argparse
from pathlib import Path
import re

from lua53_reader import Reader, listing, walk


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('names', nargs='+')
    parser.add_argument('--terms', default='ammo|bullet|weapon|buy|auction|market|propinfo|itemid|slot|datatable')
    parser.add_argument('--listing')
    args = parser.parse_args()
    pattern = re.compile(args.terms, re.IGNORECASE)
    root = Path(__file__).with_name('evidence') / 'weapon_lua'
    for name in args.names:
        path = root / name
        function = Reader(path.read_bytes(), allow_client_format1=True).function()
        print('FILE', name, flush=True)
        for child in walk(function):
            if args.listing:
                if child['id'] == args.listing:
                    print('CONSTANTS', repr(child['constants']))
                    print(listing(child))
                continue
            hits = [value for value in child['constants']
                    if isinstance(value, str) and pattern.search(value)]
            if hits:
                print(child['id'], child['first_line'], child['last_line'],
                      ', '.join(hits[:20]), flush=True)


if __name__ == '__main__':
    main()
