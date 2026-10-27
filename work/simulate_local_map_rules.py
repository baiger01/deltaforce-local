"""Generate deterministic local Dam world state; does not contact the game."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'outputs/df-local-server'))
from dfserver.legacy_ds_local_map_rules import simulate_local_map_rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'outputs/df-local-server/protocol/local-map-rules/example.json')
    parser.add_argument('--seed', type=lambda value: int(value, 0), required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sources', type=Path, default=ROOT/'outputs/df-local-server/protocol/local-map-rules/sources.json')
    parser.add_argument('--items', type=Path, default=ROOT/'outputs/df-local-server/protocol/game_item_catalog.json')
    args = parser.parse_args()
    try:
        result = simulate_local_map_rules(args.sources.read_bytes(), args.items.read_bytes(), args.config.read_bytes(), seed=args.seed)
        raw = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
        if args.output is None:
            print(raw.decode(), end='')
        else:
            with args.output.open('xb') as stream:
                stream.write(raw)
            print(json.dumps(dict(path=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
                                  objects=len(result['world_objects']), config_sha256=result['config_sha256'])))
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
