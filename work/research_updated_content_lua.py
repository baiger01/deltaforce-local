"""Re-read selected current installed Lua chunks without executing game Lua."""
import argparse
import hashlib
import json
from pathlib import Path
import re

import oodle_payload_reader
from lua53_reader import Reader, listing, walk
from recover_economy_pak_access import pak_footer
from scan_weapon_tables import parse_entry, decode_content

ROOT = Path(__file__).resolve().parent.parent
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
INDEX = ROOT / "outputs/df-local-server/protocol/pak_baseline_lua_probe.json"
TARGETS = re.compile(r"ActivityConfig|ActivityServer|ActivityExchange|ActivityUniversalExchange|cs_activity_pb|cs_shop_pb|ShopServer|MysteryExchangeLogic|ActivityConst|GameItemStruct", re.I)


def derive(pattern=TARGETS):
    oodle_payload_reader.PATH = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"
    index_raw = INDEX.read_bytes()
    rows = [r for r in json.loads(index_raw)["recovered_lua_metadata"]
            if pattern.search(r.get("source_name") or "")]
    result = []
    for row in rows:
        path = GAME / "DeltaForce/Content/Paks" / row["archive"]
        footer = pak_footer(path)
        with path.open("rb") as stream:
            entry = parse_entry(stream, row["entry_offset"], footer["offset"],
                                variant="observed_permutation")
            payload = decode_content(stream, row["entry_offset"], entry, footer["methods"])
        if payload is None:
            raise ValueError("Selected current Lua payload unavailable")
        chunk = payload[row["lua_offset"]:row["lua_offset"] + row["length"]]
        digest = hashlib.sha256(chunk).hexdigest()
        reader = Reader(chunk, allow_client_format1=True)
        tree = reader.function()
        if reader.at != len(chunk):
            raise ValueError("Current Lua extent changed; re-index required")
        result.append(dict(source_name=row["source_name"], archive=row["archive"],
            entry_offset=row["entry_offset"], lua_offset=row["lua_offset"], length=len(chunk),
            current_sha256=digest, historical_sha256=row["sha256"],
            matches_historical_chunk=digest == row["sha256"],
            archive_footer_sha256=footer["footer_sha256"],
            functions=[dict(function_id=f["id"], first_line=f["first_line"],
                last_line=f["last_line"], constants=f["constants"], locals=f["locals"],
                listing=listing(f).splitlines()) for f in walk(tree)]))
    return dict(kind="updated_client_selected_lua_research", source_index_sha256=hashlib.sha256(index_raw).hexdigest(),
        sources=result, game_files_modified=False, lua_executed=False, process_accessed=False,
        hotfix_override_absence_proven=False, source_qualification="Actual current baseline payload bytes; historical index is a locator only")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pattern", default=TARGETS.pattern)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Fresh evidence output required")
    report = derive(re.compile(args.pattern, re.I))
    raw = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        sources=len(report["sources"]), changed=[r["source_name"] for r in report["sources"] if not r["matches_historical_chunk"]])))
