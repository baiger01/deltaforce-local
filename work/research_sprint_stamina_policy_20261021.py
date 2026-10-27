"""Disk-only exact Sprint policy pointer registration and referenced curve research."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
PEER = Path("E:/新建文件夹/DSH/deltaforce-map-appearance")
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
OLD = {
    "work/research_sprint_stamina_20261021.py": "0eac8e849053b0bf7602661bf72ed0663ef5b9d8283bdae9aed2cc641530ab79",
    "work/evidence/gameplay-sprint-stamina-research-20261021.json": "ba75c6dba242cef350812aff77eb448470fbf6b2cb4e628916647b488df14d08",
    "docs/GAMEPLAY_SPRINT_STAMINA_RESEARCH_20261021.md": "1f60f91d586150390bda27eeb0a99f528c66652cc4b98214ad6d8448e8a5bcc5",
    "work/research_sprint_stamina_config_20261021.py": "2e07ae50b5e311494781eb518d04f3395d54f892f32a235bcb47110106fcaafc",
    "work/evidence/gameplay-sprint-stamina-config-20261021.json": "83d62cc3f092f4b8a815a89a165efa3782087c4a8e07cab35e8b45fc44995336",
    "docs/GAMEPLAY_SPRINT_STAMINA_CONFIG_RESEARCH_20261021.md": "f6e9e69551f060aa169cc56114ff7869410035ef18cd31d7b192e0040b771003",
}
READER = PEER / "work/evidence/skill-flow-research-20261020-v1/UAssetAPI/UAssetAPI/UnrealTypes/Objects/Engine/FRichCurveKey.cs"
FUNCTIONS = (0x36DA80, 0x36DA10, 0x45F0DE0, 0x14B4E590, 0x14B4E540,
             0x133C63C0, 0x133C6980, 0x133C95C0, 0x133C89F0)
RECORDS = ((0x14D422E0, 16), (0x14EC8340, 4), (0x15E09D70, 64),
           (0x15E09DB0, 64), (0x15E09DF0, 80), (0x15E09E40, 80),
           (0x1D813390, 72), (0x1B5EAF90, 72), (0x1B5EAE08, 384),
           (0x1D812958, 56), (0x1B5EA8C0, 128))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(raw)
    return result.hexdigest()


def initialize():
    sys.dont_write_bytecode = True
    for name, expected in OLD.items():
        if file_sha(ROOT / name) != expected:
            raise ValueError("Frozen previous research changed: " + name)
    sys.path.insert(0, str(ROOT / "work"))
    import research_sprint_stamina_config_20261021 as config
    import research_sprint_stamina_20261021 as native
    config.load_helpers()
    for name, expected in native.HELPERS.items():
        if file_sha(PEER / "work" / name) != expected:
            raise ValueError("Native helper changed: " + name)
    return config, native


def parse_curve(header, payload):
    from recover_economy_pak_access import installed_name_map
    from extract_operator_avatar_catalog import fname, tags, property_tag
    names = installed_name_map(header)
    versions = struct.unpack_from("<i", header, 20)[0]
    ec, eo, ic, io, depends = struct.unpack_from("<5i", header, 57 + versions * 20)
    if ec != 1 or depends - eo != 104 or eo - io != ic * 28:
        raise ValueError("A single exact CurveFloat export is required")
    cls, sup, template, outer = struct.unpack_from("<4i", header, eo)
    if not -ic <= cls < 0 or fname(header, io + (-cls-1)*28 + 20, names) != "CurveFloat" or outer != 0:
        raise ValueError("Referenced asset is not the root CurveFloat")
    size, offset = struct.unpack_from("<qq", header, eo + 28)
    first, end = offset - len(header), offset - len(header) + size
    props, after = tags(payload, first, names, end)
    curve, = props
    if curve["name"] != "FloatCurve" or curve["kind"] != "StructProperty" or curve["meta"] != ["RichCurve"]:
        raise ValueError("Exact RichCurve property identity changed")
    fields, curve_after = tags(payload, curve["value_start"], names, curve["end"])
    if curve_after != curve["end"] or {row["name"] for row in fields} != {"Keys", "Orders"}:
        raise ValueError("RichCurve fields or exact tagged extent changed")
    key_tag, = [row for row in fields if row["name"] == "Keys"]
    count = struct.unpack_from("<i", payload, key_tag["value_start"])[0]
    inner = property_tag(payload, key_tag["value_start"] + 4, names, key_tag["end"])
    if (key_tag["meta"] != ["StructProperty"] or inner["meta"] != ["RichCurveKey"] or
            not 0 < count <= 16 or inner["size"] != count * 27 or inner["end"] != key_tag["end"]):
        raise ValueError("RichCurveKey serialized layout/extent differs from the pinned reader")
    keys = []
    labels = ("InterpMode", "TangentMode", "TangentWeightMode", "Time", "Value",
              "ArriveTangent", "ArriveTangentWeight", "LeaveTangent", "LeaveTangentWeight")
    for index in range(count):
        at = inner["value_start"] + 27 * index
        raw = payload[at:at+27]
        keys.append({"offset": at, "raw_hex": raw.hex(), "sha256": sha(raw),
                     "decoded": dict(zip(labels, struct.unpack("<BBBffffff", raw))),
                     "time_float_bits": hex(struct.unpack_from("<I", raw, 3)[0]),
                     "value_float_bits": hex(struct.unpack_from("<I", raw, 7)[0])})
    order_tag, = [row for row in fields if row["name"] == "Orders"]
    if order_tag["meta"] != ["IntProperty"]:
        raise ValueError("Unexpected curve key order type")
    order_count = struct.unpack_from("<i", payload, order_tag["value_start"])[0]
    if order_count != count or order_tag["size"] != 4 + count * 4:
        raise ValueError("Curve key order count/size mismatch")
    return {"class": "CurveFloat", "object_name": fname(header, eo + 16, names),
            "export_record_offset": eo, "export_offset": first, "export_bytes": size,
            "property_terminator_end": after, "export_trailer_hex": payload[after:end].hex(),
            "float_curve_tag": curve, "keys_tag": key_tag, "keys_inner_tag": inner,
            "keys": keys, "orders": list(struct.unpack_from("<" + "i" * count, payload, order_tag["value_start"] + 4)),
            "float_curve_exact_eof": True,
            "serialization_reference": "Pinned UAssetAPI FRichCurveKey reader: three bytes, then six float32 values; native UHT fixes names/types separately.",
            "axis_to_overload_mapping_recovered": False, "native_evaluation_executed": False}


def exact_rip_queries(cache, image):
    from analyze_portable_native_code import function_fragments
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    hits, read_bytes, previous = [], 0, b""
    targets = {0x1DDEFC18, 0x1DDEFC30}
    for first, size, block in cache.blocks:
        if not block["available"]:
            previous = b""
            continue
        raw = (cache.folder / block["file"]).read_bytes()
        if len(raw) != size or sha(raw) != block["code_sha256"]:
            raise ValueError("Current frozen search block changed")
        read_bytes += len(raw)
        window, base = previous + raw, first - len(previous)
        for match in re.finditer(rb"[\x40-\x4f][\x89\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", window):
            offset = match.start()
            if offset + 7 > len(window):
                continue
            target = base + offset + 7 + struct.unpack_from("<i", window, offset + 3)[0]
            if target not in targets:
                continue
            address = base + offset
            fragments = function_fragments(image, address)
            start, end = fragments[0][0], fragments[-1][1]
            code = b"".join(cache.read(at, min(8192, end-at)) for at in range(start, end, 8192))
            ins = next((row for row in md.disasm(code, start) if row.address == address), None)
            if ins is None or not any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and ins.address + ins.size + op.mem.disp == target for op in ins.operands):
                raise ValueError("Exact RIP candidate is not on its function's instruction boundary")
            hits.append({"instruction_rva": hex(address), "target_rva": hex(target),
                         "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str,
                         "function_rva": hex(start), "instruction_boundary_verified": True})
        previous = raw[-6:]
    return {"targets": [hex(at) for at in sorted(targets)], "available_code_bytes_searched": read_bytes,
            "syntax_scope": "REX + MOV load/store or LEA, ModRM RIP-relative disp32; not an exhaustive instruction-set absence proof",
            "hits": hits}


def read_curve_source(config, cache, image):
    from recover_economy_pak_access import native_keys, pak_footer, validate_index, directory_index, entry_offset, decode_entry
    from scan_weapon_tables import parse_entry
    cdo = config.parse_configuration()
    reference, = [row for row in cdo["other_properties"] if row["name"] == "OverloadStaminaChangeCurve"]
    package = reference["object_path"].split(".")[0]
    target = "../../../DeltaForce/Content/" + package.removeprefix("/Game/")
    targets = {target + ext for ext in (".uasset", ".uexp")}
    key_map, _ = native_keys(cache, image)
    prior = json.loads((ROOT / "work/evidence/gameplay-sprint-stamina-config-20261021.json").read_text(encoding="utf-8"))
    inventory = sorted(path.name for path in config.PAKS.glob("*.pak"))
    if inventory != prior["installed_source"]["inventory"]:
        raise ValueError("Pinned current PAK inventory changed")
    blobs, hits, index_checks, ranges = {}, [], [], []
    for name in inventory:
        path = config.PAKS / name
        foot = pak_footer(path)
        meta, clear, key = validate_index(path, foot, key_map)
        if clear is None:
            raise ValueError("Current primary index failed validation")
        directory, files, encoded = directory_index(path, foot, clear, key)
        index_checks.append({"pak": name, "primary_sha1_valid": meta["index_sha1_valid"],
                             "secondary_sha1_valid": all(row["sha1_valid"] for row in directory["secondary_indices"])})
        for asset, location in files:
            if asset not in targets:
                continue
            pos = entry_offset(encoded, location)
            with path.open("rb") as stream:
                entry = parse_entry(stream, pos, foot["offset"], variant="observed_permutation")
                if not 0 < entry["uncompressed"] <= 4096 or entry["method"] != 0:
                    raise ValueError("Exact curve no longer has its bounded uncompressed storage")
                raw, valid = decode_entry(stream, pos, entry, foot["methods"], key)
                if not valid:
                    raise ValueError("Original curve source SHA1 validation failed")
                extent = entry["header_size"] + ((entry["compressed"] + 15) // 16 * 16 if entry["flags"] & 1 else entry["compressed"])
                stream.seek(pos)
                source = stream.read(extent)
            suffix = Path(asset).suffix
            if suffix in blobs:
                raise ValueError("Curve package has a competing exact-path PAK entry")
            blobs[suffix] = raw
            ranges.append({"path": path.as_posix(), "offset": pos, "bytes": extent, "sha256": sha(source)})
            hits.append({"pak": name, "path": asset, "physical_offset": pos, "decoded_bytes": len(raw),
                         "decoded_sha256": sha(raw), "decoded_hex": raw.hex(), "source_sha1_valid": True,
                         "encrypted": bool(entry["flags"] & 1), "compression_method": "None"})
    if len(hits) != 2:
        raise ValueError("A unique exact curve asset pair is required")
    return {"component_reference": reference, "target_package": package, "inventory": inventory,
            "index_checks": index_checks, "assets": hits,
            "source_range_pins": prior["installed_source"]["source_range_pins"] + ranges,
            "decoded_curve": parse_curve(blobs[".uasset"], blobs[".uexp"]),
            "compression_codec_executed": False, "crypto_material_disclosed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-evidence", type=Path)
    parser.add_argument("--verify", type=Path)
    opts = parser.parse_args()
    config, native = initialize()
    from recover_economy_pak_access import CodeCache, ImmutableImage
    from analyze_portable_native_code import analyze
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    executable = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        if opts.verify:
            evidence = json.loads(opts.verify.read_text(encoding="utf-8"))
            checks = [file_sha(Path(row["path"])) == row["sha256"] for row in evidence["source_pins"]]
            for row in evidence["code_pins"]:
                first, size = int(row["rva"], 16), row["bytes"]
                raw = b"".join(cache.read(at, min(8192, first+size-at)) for at in range(first, first+size, 8192))
                checks.append(sha(raw) == row["sha256"])
            checks += [sha(image.read(int(row["rva"], 16), row["bytes"])) == row["sha256"] for row in evidence["record_pins"]]
            for row in evidence["curve_source"]["source_range_pins"]:
                with Path(row["path"]).open("rb") as source:
                    source.seek(row["offset"])
                    raw = source.read(row["bytes"])
                checks.append(len(raw) == row["bytes"] and sha(raw) == row["sha256"])
            assets = {Path(row["path"]).suffix: bytes.fromhex(row["decoded_hex"]) for row in evidence["curve_source"]["assets"]}
            checks.append(parse_curve(assets[".uasset"], assets[".uexp"]) == evidence["curve_source"]["decoded_curve"])
            checks.append(sorted(path.name for path in config.PAKS.glob("*.pak")) == evidence["curve_source"]["inventory"])
            print(json.dumps({"kind": "sprint_stamina_policy_source_validation", "checks": len(checks), "all_match": all(checks)}))
            raise SystemExit(0 if all(checks) else 1)
        if not opts.emit_evidence:
            print(json.dumps(exact_rip_queries(cache, image), indent=2))
            return
        target = opts.emit_evidence.resolve()
        if target.exists() or target.parent != (ROOT / "work/evidence").resolve():
            parser.error("Use a new evidence file inside this repository's work/evidence")
        rip = exact_rip_queries(cache, image)
        records = [{"rva": hex(at), "bytes": size, "sha256": sha(image.read(at, size)), "hex": image.read(at, size).hex()} for at, size in RECORDS]
        curve = read_curve_source(config, cache, image)
    analysis = analyze(CACHE, MANIFEST_SHA, GAME, list(FUNCTIONS), [], set())
    sources = [Path(__file__).resolve(), ROOT / "AGENTS.md", PEER / "AGENTS.md", executable, CACHE / "manifest.json", READER]
    sources += [ROOT / name for name in OLD]
    sources += [PEER / "work" / name for name in dict.fromkeys((*config.HELPERS, *native.HELPERS))]
    sources += list(config.REPORT_PINS)
    result = {"kind": "disk_only_sprint_stamina_policy_research", "version": 1,
              "as_of_utc": datetime.now(timezone.utc).isoformat(), "client_sha256": file_sha(executable),
              "cache_manifest_sha256": MANIFEST_SHA,
              "scope": {"process_access": False, "game_launched": False, "network_access": False,
                        "database_access": False, "gameplay_native_methods_executed": False,
                        "configuration_executed": False, "compression_codec_executed": False,
                        "peer_files_written": False, "original_installation_written": False, "shadow_modified": False},
              "source_pins": [{"path": path.as_posix(), "bytes": path.stat().st_size, "sha256": file_sha(path)} for path in sources],
              "code_pins": [{"rva": row["span_start"], "bytes": row["span_bytes"], "sha256": row["code_sha256"], "full_semantic_recovery_claimed": False} for row in analysis["functions"]],
              "record_pins": records, "native_analysis": analysis, "exact_rip_queries": rip,
              "policy": {"duration": {"name": "Sprint.ConsecutiveSprintPenaltyDuration", "registration": "0x36da80",
                                       "name_literal": "0x15e09e40", "default_float_rva": "0x14ec8340",
                                       "default_float_bits": "0x3f800000", "default_float": 1.0,
                                       "data_pointer_store": "0x36dae5 -> 0x1ddefc30", "consumer": "0x45f24d8 / 0x45f250b"},
                         "enabled": {"name": "Sprint.ConsecutiveSprintPenalty", "registration": "0x36da10",
                                     "name_literal": "0x15e09db0", "default_argument": 0,
                                     "data_pointer_store": "0x36da70 -> 0x1ddefc18", "consumer": "0x45f0e4e / 0x45f0e7c"},
                         "effective_runtime_values_observed": False,
                         "world_time_field_units_independently_qualified": False},
              "curve_source": curve,
              "remaining": ["Effective console values and runtime override sources are unobserved; registration defaults do not prove active session policy.",
                            "Qualify the native curve input normalization, current runtime attribute multipliers, and full selected-consumption gates separately.",
                            "No complete fatigue system, authority transaction, result replication or native gameplay acceptance is claimed."],
              "native_runtime_acceptance_claimed": False}
    raw = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with target.open("xb") as output:
        output.write(raw)
    print(json.dumps({"path": target.as_posix(), "sha256": sha(raw), "source_files": len(sources),
                      "code_pins": len(result["code_pins"]), "record_pins": len(records),
                      "pak_ranges": len(curve["source_range_pins"]), "curve_keys": len(curve["decoded_curve"]["keys"])}))


if __name__ == "__main__":
    main()
