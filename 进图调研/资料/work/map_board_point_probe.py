"""Build an isolated, bounded point-ID probe for the local map board.

This is diagnostic data: it does not claim these entries are the client's
actual WorldEntranceConfig mappings.
"""

import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--first", type=int, required=True)
    parser.add_argument("--last", type=int, required=True)
    parser.add_argument("--map-id", type=int, default=2201)
    parser.add_argument("--match-mode-id", type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.first <= args.last <= 64:
        parser.error("point IDs must be within 1..64")
    if args.match_mode_id in (1, 31100003):
        parser.error("this match mode ID is a placeholder or the client's safehouse mode")
    rows = [
        {
            "point_id": point_id,
            "map_id": args.map_id,
            "match_mode_id": args.match_mode_id,
            "match_mode_type": match_mode_type,
            "min_level": 1,
            "sub_mode": 10,
        }
        for point_id in range(args.first, args.last + 1)
        for match_mode_type in (1, 3)
    ]
    payload = {
        "evidence": "Diagnostic sweep only; rows are candidate point IDs, not verified mappings.",
        "operations": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
