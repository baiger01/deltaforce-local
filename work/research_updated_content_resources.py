"""Validate current resource directories using historical asset-access constants.

Historical code is a candidate source for asset decryption only. Each current
archive must independently pass index hashes. No key material is serialized.
"""
import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
import re

from recover_economy_pak_access import (native_keys, pak_footer, validate_index,
    directory_index, entry_offset, decode_entry)
from scan_weapon_tables import parse_entry
import oodle_payload_reader

ROOT = Path(__file__).resolve().parent.parent
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = ROOT / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"


class HistoricalAssetCandidateCode:
    def __init__(self):
        raw = (CACHE / "manifest.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
            raise ValueError("Historical asset candidate manifest changed")
        self.manifest = json.loads(raw)
        self.blocks = sorted((int(b["rva"], 16), b) for s in self.manifest["sections"] for b in s["blocks"])

    def read(self, rva, size):
        if not 0 < size <= 8192:
            raise ValueError("Bounded historical candidate read required")
        result, at = bytearray(), rva
        for first, b in self.blocks:
            end = first + b["bytes"]
            if end <= at or first >= rva + size:
                continue
            if first > at or not b["available"]:
                raise ValueError("Unavailable historical candidate code")
            p = CACHE / b["file"]
            if p.resolve().parent != CACHE.resolve():
                raise ValueError("Historical block escaped cache")
            raw = p.read_bytes()
            if len(raw) != b["bytes"] or hashlib.sha256(raw).hexdigest() != b["code_sha256"]:
                raise ValueError("Historical candidate block changed")
            take = min(end, rva + size)
            result.extend(raw[at - first:take - first])
            at = take
        if at != rva + size:
            raise ValueError("Incomplete historical candidate range")
        return bytes(result)


def access():
    cache = HistoricalAssetCandidateCode()
    tree = ast.parse(inspect.getsource(native_keys))
    # The old GUID literals moved in the updated image. Keep only constant
    # key-array candidates and qualify each association against current hashes.
    class CandidatesOnly(ast.NodeTransformer):
        def visit_If(self, node):
            if ast.unparse(node.test) == "pending is None or not candidates":
                node.test = ast.parse("pending is None", mode="eval").body
            return self.generic_visit(node)

        def visit_Assign(self, node):
            if any(isinstance(t, ast.Name) and t.id == "guid_text" for t in node.targets):
                node.value = ast.parse("format(len(keys), '032x')", mode="eval").body
            return node

    tree = ast.fix_missing_locations(CandidatesOnly().visit(tree))
    namespace = dict(native_keys.__globals__)
    exec(compile(tree, "<historical constant candidates only>", "exec"), namespace)
    class NoHistoricalLiterals:
        def read(self, at, size):
            return bytes(size)
    keys, provenance = namespace["native_keys"](cache, NoHistoricalLiterals())
    provenance.pop("distinct_bootstrap_guids", None)
    provenance.pop("immutable_guid_literal_rva_count", None)
    provenance["historical_guid_associations_discarded"] = True
    return list(dict.fromkeys(keys.values())), provenance


def derive(paks, pattern, asset_output=None):
    if asset_output:
        asset_output = asset_output.resolve()
    oodle_payload_reader.PATH = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"
    keys, provenance = access()
    reports = []
    for name in paks:
        path = GAME / "DeltaForce/Content/Paks" / name
        footer = pak_footer(path)
        public = clear = key = None
        for candidate in keys:
            public, clear, key = validate_index(path, footer, {footer["guid"]: candidate})
            if clear is not None:
                break
        if clear is None:
            raise ValueError("Current archive candidate failed verification")
        public.pop("registered_guid_found", None)
        public["historical_guid_literal_binding_verified"] = False
        public["historical_candidate_association_verified_by_current_index_hash"] = True
        details, files, encoded = directory_index(path, footer, clear, key)
        matches = []
        with path.open("rb") as stream:
            for name, location in files:
                if not pattern.search(name):
                    continue
                pos = entry_offset(encoded, location)
                row = dict(asset=name, encoded_offset=location, entry_offset=pos)
                if asset_output:
                    entry = parse_entry(stream, pos, footer["offset"], variant="observed_permutation")
                    content, valid = decode_entry(stream, pos, entry, footer["methods"], key)
                    relative = Path(*[p for p in name.split("/") if p not in ("..", ".", "")])
                    target = asset_output / path.stem / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists():
                        if target.read_bytes() != content:
                            raise ValueError("Existing research extraction differs")
                    else:
                        with target.open("xb") as output:
                            output.write(content)
                    row.update(decoded_bytes=len(content), decoded_sha256=hashlib.sha256(content).hexdigest(),
                        archive_payload_sha1_valid=valid, output=str(target.relative_to(ROOT)))
                matches.append(row)
        reports.append(dict(archive=path.name, validation=public, directory=details, matches=matches))
    return dict(kind="updated_resource_selected_research", historical_manifest_sha256=MANIFEST_SHA,
        historical_code_used_only_as_asset_access_candidate=True, key_provenance=provenance,
        archives=reports, keys_disclosed=False, native_protocol_compatibility_verified=False,
        game_files_modified=False, process_accessed=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pak", action="append", required=True)
    parser.add_argument("--find", required=True)
    parser.add_argument("--asset-output", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Fresh research evidence required")
    if args.asset_output and not args.asset_output.resolve().is_relative_to(ROOT / "work/evidence"):
        parser.error("Research extraction must stay in evidence")
    report = derive(args.pak, re.compile(args.find, re.I), args.asset_output)
    raw = (json.dumps(report, indent=2) + "\n").encode("ascii")
    with args.output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps(dict(output=str(args.output), sha256=hashlib.sha256(raw).hexdigest(),
        matched=sum(len(r["matches"]) for r in report["archives"]))))
