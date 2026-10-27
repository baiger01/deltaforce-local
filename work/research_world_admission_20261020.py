"""Read original installed PAK tables in memory; never write the peer or game.

This research entry point prints source-qualified table facts to stdout. Keys,
decrypted archives and full client code are never printed or persisted.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys


sys.dont_write_bytecode = True
PEER = Path("E:/新建文件夹/DSH/deltaforce-map-appearance")
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
sys.path.insert(0, str(PEER / "work"))

from offline_received_packet_xrefs import ImmutableImage, literal_candidates
from parse_economy_installed_tables import parse_table
from portable_native_code_cache import CodeCache
from recover_economy_pak_access import (
    decode_entry, directory_index, entry_offset, native_keys, pak_footer,
    validate_index, installed_name_map, fstring,
)
from scan_weapon_tables import parse_entry
from extract_operator_avatar_catalog import fname
import oodle_payload_reader
from lua53_reader import Reader, walk, listing
from analyze_portable_native_code import analyze

# The peer's configured migration folder is absent. Use the original installed
# compression-only DLL in this research process, without changing peer config.
oodle_payload_reader.PATH = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"


class MemorySource:
    def __init__(self, content, label):
        self.content, self.label = content, label

    def read_bytes(self):
        return self.content

    def __str__(self):
        return self.label


def digest(content):
    return hashlib.sha256(content).hexdigest()


def soft_references(value, names):
    if isinstance(value, list):
        return [soft_references(v, names) for v in value]
    if not isinstance(value, dict):
        return value
    if value.get("serialized_kind") in ("SoftObjectProperty", "SoftClassProperty"):
        raw = bytes.fromhex(value["serialized_hex"])
        name = fname(raw, 0, names)
        subpath, at = fstring(raw, 8)
        if at != len(raw):
            raise ValueError("A soft reference did not consume its exact source payload")
        return name + ((":" + subpath) if subpath else "")
    return {key: soft_references(v, names) for key, v in value.items()}


def import_reference(header, index):
    names = installed_name_map(header)
    versions = struct.unpack_from("<i", header, 20)[0]
    _, _, count, first = struct.unpack_from("<4i", header, 57 + versions * 20)

    def resolve(item, depth=0):
        if depth > 16 or not -count <= item < 0:
            raise ValueError("An external table object reference exceeds its import chain")
        at = first + (-item - 1) * 28
        outer = struct.unpack_from("<i", header, at + 16)[0]
        name = fname(header, at + 20, names)
        return ((resolve(outer, depth + 1) + ".") if outer else "") + name

    at = first + (-index - 1) * 28
    return dict(import_index=index, class_name=fname(header, at + 8, names), path=resolve(index))


def native_research(args):
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    strings, records, hook_candidates, rip_candidates = [], [], [], []
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        section_rva, section_size = 0x14D03000, 131049984
        raw = image.read(section_rva, section_size)
        for spec in args.immutable_record:
            first, amount = [int(part, 0) for part in spec.split(":")]
            if not 0 < amount <= 8192:
                raise ValueError("Use a bounded explicit immutable record")
            content = image.read(first, amount)
            records.append(dict(rva=hex(first), bytes=amount, sha256=digest(content),
                qwords=[dict(offset=hex(at), value=hex(struct.unpack_from("<Q", content, at)[0]),
                    image_rva=hex(struct.unpack_from("<Q", content, at)[0]-image.image_base))
                    for at in range(0, amount-7, 8)]))
        for term in args.immutable_string:
            for encoding, step in (("ascii", 1), ("utf-16-le", 2)):
                needle, at = term.encode(encoding), 0
                while True:
                    at = raw.find(needle, at)
                    if at < 0:
                        break
                    low, high = at, at + len(needle)
                    zero = b"\0" * step
                    while low >= step and at - low < 512 and raw[low-step:low] != zero:
                        low -= step
                    while high + step <= len(raw) and high - at < 1024 and raw[high:high+step] != zero:
                        high += step
                    text = raw[low:high].decode(encoding, errors="replace")
                    if text.isprintable() and re.search(args.immutable_filter, text):
                        strings.append(dict(term=term, encoding=encoding, rva=hex(section_rva+low),
                            bytes=high-low, sha256=digest(raw[low:high]), text=text))
                    at += len(needle)
                    if len(strings) > 512:
                        raise ValueError("Narrow the immutable literal query")
        for hook in args.native_hook_id:
            number = int(hook, 0)
            needle = b"\xb9" + struct.pack("<I", number)
            for section in cache.manifest["sections"]:
                previous = b""
                for block in section["blocks"]:
                    if not block["available"]:
                        previous = b""
                        continue
                    content = (cache.folder / block["file"]).read_bytes()
                    if len(content) != block["bytes"] or digest(content) != block["code_sha256"]:
                        raise ValueError("Native hook search block changed")
                    first = int(block["rva"], 16) - len(previous)
                    window, at = previous + content, 0
                    while True:
                        at = window.find(needle, at)
                        if at < 0:
                            break
                        entry = image.containing(first + at)
                        hook_candidates.append(dict(hook_id=hex(number), instruction_rva=hex(first+at),
                            encoded=needle.hex(), pdata_function=hex(entry[0]) if entry else None,
                            instruction_boundary_verified=False))
                        at += len(needle)
                    previous = content[-4:]
        targets = {int(value, 0) for value in args.native_rip_target}
        if targets:
            for section in cache.manifest["sections"]:
                previous = b""
                for block in section["blocks"]:
                    if not block["available"]:
                        previous = b""
                        continue
                    content = (cache.folder / block["file"]).read_bytes()
                    if len(content) != block["bytes"] or digest(content) != block["code_sha256"]:
                        raise ValueError("Native RIP target search block changed")
                    first = int(block["rva"], 16) - len(previous)
                    for at, target, encoded in literal_candidates(previous + content, first, targets):
                        entry = image.containing(at)
                        rip_candidates.append(dict(instruction_rva=hex(at), target_rva=hex(target),
                            encoded=encoded.hex(), pdata_function=hex(entry[0]) if entry else None,
                            instruction_boundary_verified=False))
                    previous = content[-6:]
    native = analyze(CACHE, MANIFEST_SHA, GAME,
        [int(value, 0) for value in args.native_function], args.native_literal,
        {int(value, 0) for value in args.native_call_target},
        spans=[tuple(int(part, 0) for part in value.split(":")) for value in args.native_span])
    print(json.dumps(dict(kind="readonly_world_admission_native_research",
        reviewed_at_utc=datetime.now(timezone.utc).isoformat(),
        research_script_sha256=digest(Path(__file__).read_bytes()),
        analysis_helper_sha256=digest((PEER/"work/analyze_portable_native_code.py").read_bytes()),
        immutable_string_section=dict(rva=hex(section_rva), bytes=section_size, sha256=digest(raw)),
        strings=strings, immutable_records=records, hook_candidates=hook_candidates,
        rip_candidates=rip_candidates,
        analysis=native), ensure_ascii=True, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--path-pattern")
    parser.add_argument("--row", default=".*")
    parser.add_argument("--fields", default="")
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--lua-terms", default="EntranceIdx|WorldEntranceConfig|MatchModeDataConfig|MapConfig|SubWorldName|R13N")
    parser.add_argument("--lua-function")
    parser.add_argument("--lua-listing", action="store_true")
    parser.add_argument("--lua-line-pattern")
    parser.add_argument("--immutable-string", action="append", default=[])
    parser.add_argument("--immutable-filter", default=".*")
    parser.add_argument("--immutable-record", action="append", default=[])
    parser.add_argument("--native-function", action="append", default=[])
    parser.add_argument("--native-literal", action="append", default=[])
    parser.add_argument("--native-call-target", action="append", default=[])
    parser.add_argument("--native-span", action="append", default=[])
    parser.add_argument("--native-hook-id", action="append", default=[])
    parser.add_argument("--native-rip-target", action="append", default=[])
    parser.add_argument("--text-pattern", default="DataTable|Datatable|Redirect|R13N|MapConfig|MatchModeDataConfig")
    args = parser.parse_args()
    if args.immutable_string or args.immutable_record or args.native_function or args.native_literal or args.native_call_target or args.native_span or args.native_hook_id or args.native_rip_target:
        native_research(args)
        return
    names = args.name or ["MapConfig", "MatchModeDataConfig", "WorldEntranceConfig"]
    wanted = re.compile(args.path_pattern or (r"/(?:" + "|".join(re.escape(n) for n in names)
        + r")\.(?:umap|uasset|uexp|csv|bin|db|sqlite|lua|ini)$"), re.I)
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image:
        keys, provenance = native_keys(cache, ImmutableImage(image))
    source_pins = {"peer/work/" + name: digest((PEER / "work" / name).read_bytes()) for name in (
        "recover_economy_pak_access.py", "parse_economy_installed_tables.py",
        "scan_weapon_tables.py", "portable_native_code_cache.py",
        "oodle_payload_reader.py", "offline_received_packet_xrefs.py",
        "extract_operator_avatar_catalog.py", "lua53_reader.py",
        "analyze_portable_native_code.py",
    )}
    reports, tables, lua_blocks, text_files = [], [], [], []
    total_files = 0
    original_paks = sorted((GAME / "DeltaForce/Content/Paks").glob("*.pak"))
    if not original_paks:
        raise ValueError("The explicit original installation has no PAKs")
    for path in original_paks:
        footer = pak_footer(path)
        public, clear, key = validate_index(path, footer, keys)
        if clear is None or public.get("index_sha1_valid") is not True:
            raise ValueError("An original PAK index failed qualification: " + path.name)
        details, files, encoded = directory_index(path, footer, clear, key)
        total_files += len(files)
        matches = [(name, location) for name, location in files if wanted.search(name)]
        report = dict(pak=str(path), footer_sha256=public["footer_sha256"],
            primary_sha256=public["decoded_index_sha256"],
            secondary_indices=details["secondary_indices"],
            directory_files=len(files), matches=[name for name, _ in matches])
        reports.append(report)
        if args.scan_only or not matches:
            continue
        assets = {}
        with path.open("rb") as stream:
            for name, location in matches:
                if not name.endswith((".uasset", ".uexp", ".lua", ".ini")):
                    continue
                pos = entry_offset(encoded, location)
                entry = parse_entry(stream, pos, footer["offset"], variant="observed_permutation")
                content, valid = decode_entry(stream, pos, entry, footer["methods"], key)
                if not valid:
                    raise ValueError("Selected original payload SHA1 failed: " + name)
                assets[name] = (content, dict(pak=str(path), indexed_path=name,
                    encoded_offset=location, physical_offset=pos,
                    compressed_sha1_valid=True, bytes=len(content), decoded_sha256=digest(content)))
        for name, (content, source) in assets.items():
            if name.endswith(".ini"):
                encoding = "utf-16" if content[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
                lines = content.decode(encoding).splitlines()
                selected = [{"line": i+1, "text": line} for i, line in enumerate(lines)
                    if re.search(args.text_pattern, line)]
                text_files.append(dict(source=source, encoding=encoding,
                    line_count=len(lines), selected_pattern=args.text_pattern, selected_lines=selected))
            if not name.endswith(".lua"):
                continue
            reader = Reader(content, allow_client_format1=True)
            tree = reader.function()
            if reader.at != len(content):
                raise ValueError("Selected Lua did not parse to exact EOF")
            functions = []
            for function in walk(tree):
                hits = [v for v in function["constants"] if isinstance(v, str) and re.search(args.lua_terms, v)]
                if not hits or (args.lua_function and not re.search(args.lua_function, function["id"])):
                    continue
                row = dict(function_id=function["id"], first_line=function["first_line"],
                    last_line=function["last_line"], matched_constants=hits)
                if args.lua_listing:
                    lines = listing(function).splitlines()
                    if args.lua_line_pattern:
                        selected = {j for i, line in enumerate(lines) if re.search(args.lua_line_pattern, line)
                            for j in range(max(0, i-2), min(len(lines), i+3))}
                        lines = [lines[i] for i in sorted(selected)]
                        row["listing_is_filtered"] = True
                    row["listing"] = lines
                functions.append(row)
            lua_blocks.append(dict(source=source, lua_executed=False, parsed_to_exact_eof=True,
                function_count=sum(1 for _ in walk(tree)), selected_functions=functions))
        for name, (header, header_source) in assets.items():
            if not name.endswith(".uasset"):
                continue
            companion = name[:-7] + ".uexp"
            if companion not in assets:
                raise ValueError("Exact same-index table companion is missing")
            body, body_source = assets[companion]
            try:
                result = parse_table(MemorySource(header, name), MemorySource(body, companion))
            except ValueError as error:
                tables.append(dict(source_header=header_source, source_body=body_source,
                    parse_status="refused", reason=str(error)))
                continue
            all_rows = result["rows"]
            result["all_rows_canonical_sha256"] = digest(json.dumps(all_rows, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True).encode("ascii"))
            result["field_names"] = sorted({field for row in all_rows.values() for field in row["fields"]})
            result["rows"] = {key: row for key, row in all_rows.items() if re.search(args.row, key)}
            names_in_header = installed_name_map(header)
            result["rows"] = soft_references(result["rows"], names_in_header)
            for row in result["rows"].values():
                value = row["fields"].get("LevelSubsystemConfig")
                if type(value) is int and value < 0:
                    row["resolved_object_references"] = {"LevelSubsystemConfig": import_reference(header, value)}
            result["selected_pattern"] = args.row
            result["selected_row_count"] = len(result["rows"])
            selected_fields = set(args.fields.split(",")) if args.fields else None
            if selected_fields:
                for row in result["rows"].values():
                    row["fields"] = {k: v for k, v in row["fields"].items() if k in selected_fields}
            tables.append(dict(source_header=header_source, source_body=body_source,
                parse_status="parsed", result=result))
    out = dict(kind="readonly_original_pak_admission_table_research",
        reviewed_at_utc=datetime.now(timezone.utc).isoformat(),
        research_script_sha256=digest(Path(__file__).read_bytes()),
        original_game_root=str(GAME), client_sha256=cache.manifest["client_sha256"],
        cache_manifest_sha256=MANIFEST_SHA, process_access=False, client_launched=False,
        packets_sent=False, files_written=False, peer_written=False, key_material_disclosed=False,
        key_derivation_provenance=provenance, source_pins=source_pins,
        oodle_codec_sha256=digest(oodle_payload_reader.PATH.read_bytes()),
        pak_count=len(reports), directory_file_count=total_files,
        all_primary_and_secondary_sha1_valid=True,
        matching_paks=[row for row in reports if row["matches"]], tables=tables,
        lua_blocks=lua_blocks, text_files=text_files)
    print(json.dumps(out, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
