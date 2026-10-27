"""Disk-only F interaction research. Write evidence only in this checkout."""
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
ROOT = Path(__file__).resolve().parent.parent
PEER = ROOT.parent / "deltaforce-map-appearance"
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
OUT = ROOT / "work/evidence/gameplay-f-interaction-research-20261021.json"
sys.path.insert(0, str(PEER / "work"))
from analyze_portable_native_code import analyze
from offline_received_packet_xrefs import ImmutableImage
from portable_native_code_cache import CodeCache


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--strings")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--literal", action="append", default=[])
    parser.add_argument("--call", action="append", default=[])
    parser.add_argument("--record", action="append", default=[])
    parser.add_argument("--hook", action="append", default=[])
    parser.add_argument("--pointer", action="append", default=[])
    parser.add_argument("--pak-package", action="append", default=[])
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--view", action="store_true")
    parser.add_argument("--pattern")
    args = parser.parse_args()
    if args.verify:
        verify()
        return
    if not args.label:
        parser.error("--label is required when collecting or viewing evidence")
    if args.view:
        result = json.loads(OUT.read_text("utf-8"))["queries"][args.label]
        display(result, args)
        return
    cache = CodeCache(CACHE, MANIFEST, GAME)
    result = {"at_utc": datetime.now(timezone.utc).isoformat()}
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        if args.pointer:
            result["immutable_pointer_candidates"] = []
            for value in args.pointer:
                target = int(value, 0)
                needle = struct.pack("<Q", target + image.image_base)
                at = data.find(needle)
                while at >= 0:
                    for base, size, backing, _ in image.sections:
                        if backing <= at < backing+size:
                            result["immutable_pointer_candidates"].append({"target_rva": hex(target),
                                "pointer_rva": hex(base+at-backing), "instruction_or_vtable_role_unqualified": True})
                    at = data.find(needle, at+1)
        if args.strings:
            raw = image.read(0x14D03000, 131049984)
            result["immutable_string_section"] = {"rva": "0x14d03000", "bytes": len(raw), "sha256": sha(raw)}
            rows = []
            pattern = re.compile(args.strings)
            for encoding, matcher in (("ascii", rb"[\x20-\x7e]{4,}"),
                                       ("utf-16-le", rb"(?:[\x20-\x7e]\0){4,}")):
                for match in re.finditer(matcher, raw):
                    text = match.group().decode(encoding)
                    if pattern.search(text):
                        rows.append({"rva": hex(0x14D03000 + match.start()), "encoding": encoding, "text": text})
            result["strings"] = rows
        if args.record:
            result["records"] = []
            for spec in args.record:
                start, size = (int(v, 0) for v in spec.split(":"))
                if not 0 < size <= 8192:
                    raise ValueError("Use an explicit bounded immutable record")
                raw = image.read(start, size)
                qwords = []
                for i in range(0, size-7, 8):
                    value = struct.unpack_from("<Q", raw, i)[0]
                    row = {"offset": hex(i), "raw": hex(value), "rva": hex(value - image.image_base)}
                    try:
                        target = image.read(value-image.image_base, 384)
                    except ValueError:
                        target = b""
                    for encoding, end in (("ascii", target.find(b"\0")), ("utf-16-le", next((j for j in range(0,len(target)-1,2) if target[j:j+2] == b"\0\0"), -1))):
                        if end <= 2:
                            continue
                        try:
                            text = target[:end].decode(encoding)
                        except UnicodeDecodeError:
                            continue
                        if all(c.isprintable() for c in text):
                            row["literal_candidate"] = text
                            break
                    qwords.append(row)
                result["records"].append({"rva": hex(start), "bytes": size, "sha256": sha(raw), "qwords": qwords})
        if args.hook:
            needles = {int(v, 0): b"\xb9" + struct.pack("<I", int(v, 0)) for v in args.hook}
            result["hook_candidates"] = []
            for section in cache.manifest["sections"]:
                previous = b""
                for block in section["blocks"]:
                    if not block["available"]:
                        previous = b""
                        continue
                    raw = (cache.folder / block["file"]).read_bytes()
                    if len(raw) != block["bytes"] or sha(raw) != block["code_sha256"]:
                        raise ValueError("Hook-search cache block changed")
                    start, window = int(block["rva"], 16) - len(previous), previous + raw
                    for number, needle in needles.items():
                        at = window.find(needle)
                        while at >= 0:
                            entry = image.containing(start + at)
                            result["hook_candidates"].append({"id": hex(number), "instruction_rva": hex(start+at),
                                "pdata": hex(entry[0]) if entry else None, "instruction_boundary_verified": False})
                            at = window.find(needle, at+1)
                    previous = raw[-4:]
    if args.function or args.literal or args.call:
        result["native"] = analyze(CACHE, MANIFEST, GAME, [int(v, 0) for v in args.function],
                                    args.literal, {int(v, 0) for v in args.call})
    if args.source:
        result["source_snapshot"] = []
        for value in args.source:
            path = Path(value).resolve(strict=True)
            raw = path.read_bytes()
            result["source_snapshot"].append({"path": str(path), "bytes": len(raw), "sha256": sha(raw),
                                             "text": raw.decode("utf-8-sig")})
    if args.pak_package:
        result["original_packages"] = pak_packages(cache, exe, args.pak_package)
    doc = json.loads(OUT.read_text("utf-8")) if OUT.exists() else {
        "kind": "readonly_gameplay_f_interaction_research_20261021", "client_sha256": cache.manifest["client_sha256"],
        "cache_manifest_sha256": MANIFEST, "snapshot_is_atomic": False, "process_access": False,
        "game_launched": False, "packets_sent": False, "database_opened": False,
        "game_or_peer_written": False, "native_execution_claimed": False, "queries": {}}
    doc["queries"][args.label] = result
    doc["helper_sha256"] = sha(Path(__file__).read_bytes())
    OUT.write_text(json.dumps(doc, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    display(result, args)


def display(result, args):
    if args.compact:
        for fn in result.get("native", {}).get("functions", []):
            print("FUNCTION", fn["span_start"], fn["span_bytes"], fn["code_sha256"], "covered", fn["linear_decode_covers_extent"])
            for ins in fn["instructions"]:
                suffix = " ".join(ref.get("immutable_literal_candidate", "") for ref in ins.get("rip_references", []))
                line = " ".join((ins["rva"], ins["mnemonic"], ins["operands"], suffix))
                if not args.pattern or re.search(args.pattern, line):
                    print(line)
        rest = {k: v for k, v in result.items() if k != "native"}
        native = {k: v for k, v in result.get("native", {}).items() if k != "functions"}
        print(json.dumps({**rest, **native}, ensure_ascii=True, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=True, indent=2))


def verify():
    """Replay identities and selected instruction boundaries; never run handlers."""
    doc = json.loads(OUT.read_text("utf-8"))
    if doc["helper_sha256"] != sha(Path(__file__).read_bytes()):
        raise ValueError("Collect the final source snapshot after modifying this helper")
    if doc["cache_manifest_sha256"] != MANIFEST or any(doc[k] is not False for k in (
            "snapshot_is_atomic", "process_access", "game_launched", "packets_sent",
            "database_opened", "game_or_peer_written", "native_execution_claimed")):
        raise ValueError("Read-only evidence provenance changed")
    cache = CodeCache(CACHE, MANIFEST, GAME)
    if doc["client_sha256"] != cache.manifest["client_sha256"]:
        raise ValueError("Original executable identity changed")
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    functions, immutable, sources, packages, unwinds = {}, {}, {}, {}, {}
    for query in doc["queries"].values():
        for fn in query.get("native", {}).get("functions", []):
            key = (int(fn["span_start"], 16), fn["span_bytes"], fn["code_sha256"])
            functions[key] = fn
        for record in query.get("records", []):
            immutable[(int(record["rva"], 16), record["bytes"])] = record["sha256"]
        section = query.get("immutable_string_section")
        if section:
            immutable[(int(section["rva"], 16), section["bytes"])] = section["sha256"]
        for source in query.get("source_snapshot", []):
            sources[source["path"]] = source
        for package in query.get("original_packages", {}).get("packages", []):
            packages[package["header"]["path"]] = package
    by_start = {}
    for (start, size, digest), fn in functions.items():
        raw = b"".join(cache.read(at, min(8192, start+size-at))
                       for at in range(start, start+size, 8192))
        if sha(raw) != digest or not fn["linear_decode_covers_extent"]:
            raise ValueError("Native span identity/coverage changed: " + hex(start))
        at, decoded = start, bytearray()
        for ins in fn["instructions"]:
            chunk = bytes.fromhex(ins["bytes"])
            if int(ins["rva"], 16) != at or not chunk:
                raise ValueError("Disassembly instruction boundary changed")
            at += len(chunk)
            decoded.extend(chunk)
        if bytes(decoded) != raw or at != start+size or fn["decoded_bytes"] != size:
            raise ValueError("Disassembly does not match cached bytes")
        by_start[start] = fn
        for fragment in fn["pdata_fragments"]:
            unwinds[(int(fragment["unwind_rva"], 16), fragment["metadata_bytes"])] = fragment["metadata_sha256"]
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        for (start, size), digest in {**immutable, **unwinds}.items():
            if sha(image.read(start, size)) != digest:
                raise ValueError("Immutable EXE metadata/record changed: " + hex(start))
    for path, source in sources.items():
        raw = Path(path).read_bytes()
        if len(raw) != source["bytes"] or sha(raw) != source["sha256"]:
            raise ValueError("Current source snapshot changed: " + path)
        if raw.decode("utf-8-sig") != source["text"]:
            raise ValueError("Source text differs from its byte pin")
    if packages:
        names = [Path(path).stem for path in packages]
        replay = pak_packages(cache, exe, names)
        actual = {p["header"]["path"]: p for p in replay["packages"]}
        if actual != packages:
            raise ValueError("Original package decode, index, fields or inheritance changed")
    edges = ((0xc1f6d80, 0xc1c0000), (0xc1f6d80, 0x13060960),
             (0xc1b80d0, 0xc1dad90), (0xc1dad90, 0xc1d6110),
             (0xc1dad90, 0xc202680), (0xc1f9b20, 0xc1fa020),
             (0xc1fa020, 0xc1d6110), (0xc24e210, 0xc24c480),
             (0xc24e210, 0xc265cb0), (0xc24e210, 0xc2494a0),
             (0xc113210, 0xc1e5070), (0xc113210, 0xc19cf50),
             (0xc19cf50, 0xc1ac570), (0xc1a89f0, 0xc1abfe0),
             (0xc028950, 0xc05e300))
    for caller, callee in edges:
        if not any(ins.get("direct_target_rva") == hex(callee) and ins["mnemonic"] == "call"
                   for ins in by_start[caller]["instructions"]):
            raise ValueError("Claimed direct call edge missing: " + hex(caller) + " -> " + hex(callee))
    count = {ins["rva"]: ins for ins in by_start[0xc028950]["instructions"]}
    for address, mnemonic, operands in (("0xc0289bb", "test", "edx, edx"),
            ("0xc0289cd", "ja", "0xc028ac8"), ("0xc0289d5", "sub", "eax, edx"),
            ("0xc0289d7", "mov", "dword ptr [rbx + 0x38], eax")):
        if (count[address]["mnemonic"], count[address]["operands"]) != (mnemonic, operands):
            raise ValueError("ConsumeCount branch/write boundary changed")
    print(json.dumps({"status": "PASS", "native_spans": len(functions),
        "immutable_records_and_sections": len(immutable), "unwind_records": len(unwinds),
        "source_snapshots": len(sources), "original_packages_redecoded": len(packages),
        "direct_call_edges": len(edges), "count_boundary_checks": 4,
        "native_execution_claimed": False, "evidence_sha256": sha(OUT.read_bytes())}, indent=2))


def pak_packages(cache, exe, names):
    from parse_economy_dam_ai_templates import InstalledWorld
    from recover_economy_pak_access import (native_keys, pak_footer, validate_index,
        directory_index, entry_offset, decode_entry)
    from scan_weapon_tables import parse_entry
    from extract_operator_avatar_catalog import fname
    import oodle_payload_reader
    oodle_payload_reader.PATH = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"

    class MemoryWorld(InstalledWorld):
        @staticmethod
        def checked_record(record):
            raw = record["content"]
            if len(raw) != record["bytes"] or sha(raw) != record["decoded_sha256"]:
                raise ValueError("Original in-memory package identity changed")
            return raw

    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        keys, provenance = native_keys(cache, ImmutableImage(data))
    result = {"source": str(GAME), "pak_count": 0, "directory_file_count": 0,
              "all_index_and_payload_sha1_valid": True, "packages": [], "key_material_disclosed": False,
              "key_derivation_provenance": provenance}
    wanted = re.compile(r"/(?:" + "|".join(re.escape(n) for n in names) + r")\.(?:uasset|uexp)$", re.I)
    for pak in sorted((GAME / "DeltaForce/Content/Paks").glob("*.pak")):
        footer = pak_footer(pak)
        public, clear, key = validate_index(pak, footer, keys)
        if clear is None or public.get("index_sha1_valid") is not True:
            raise ValueError("Original PAK index failed: " + pak.name)
        details, files, encoded = directory_index(pak, footer, clear, key)
        result["pak_count"] += 1
        result["directory_file_count"] += len(files)
        selected = [(p, loc) for p, loc in files if wanted.search(p)]
        if not selected:
            continue
        assets = {}
        with pak.open("rb") as stream:
            for path, location in selected:
                pos = entry_offset(encoded, location)
                entry = parse_entry(stream, pos, footer["offset"], variant="observed_permutation")
                raw, valid = decode_entry(stream, pos, entry, footer["methods"], key)
                if not valid:
                    raise ValueError("Original selected PAK payload failed: " + path)
                assets[path] = {"path": path, "content": raw, "bytes": len(raw),
                    "decoded_sha256": sha(raw), "physical_offset": pos, "encoded_offset": location}
        for path, header in assets.items():
            if not path.endswith(".uasset"):
                continue
            body = assets[path[:-7]+".uexp"]
            package = MemoryWorld(header, body)
            exports = []
            versions = struct.unpack_from("<i", package.header, 20)[0]
            export_offset = struct.unpack_from("<i", package.header, 41+versions*20+20)[0]
            for export in package.exports:
                super_index = struct.unpack_from("<i", package.header, export_offset+(export["index"]-1)*104+4)[0]
                fields = {}
                for name, tag in package.properties(export["index"]).items():
                    value = package.decoded(tag)
                    if tag["kind"] == "StructProperty" and tag["meta"] == ["GameplayTagContainer"]:
                        raw = package.payload[tag["value_start"]:tag["end"]]
                        count, = struct.unpack_from("<i", raw)
                        if not 0 <= count <= 64 or len(raw) != 4+8*count:
                            raise ValueError("Asset tag-container extent changed")
                        value = {"tag_names": [fname(raw, 4+i*8, package.names) for i in range(count)]}
                    fields[name] = {"value": value, "kind": tag["kind"], "offset": tag["value_start"], "bytes": tag["size"]}
                exports.append({**export, "super_index": super_index, "super_path": package.full_object(super_index),
                                "class_path": package.full_object(export["class_index"]),
                                "properties": fields})
            result["packages"].append({"pak": str(pak), "index_sha256": public["decoded_index_sha256"],
                "source": package.source, "header": {k:v for k,v in header.items() if k != "content"},
                "body": {k:v for k,v in body.items() if k != "content"}, "exports": exports})
    return result


if __name__ == "__main__":
    main()
