"""Read exact SOL Pawn stamina CDO maps and requalify their installed PAK source."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
PEER = Path("E:/新建文件夹/DSH/deltaforce-map-appearance")
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
BASE = PEER / "work/evidence/map-system-audit-20261018"
PAKS = GAME / "DeltaForce/Content/Paks"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
CACHE = PEER / "work/native-code-cache/1792259162856698600"
STORAGE = BASE / "native-owning-weapon-character-source-storage.json"
SEARCH = BASE / "native-owning-weapon-character-all-baseline-directory-search.json"
STEM = BASE / "owning-weapon-character-assets/pak-0-1-pakchunk30-WindowsClient/DeltaForce/Content/BluePrints/Characters/BP_DFMCharacter"
TARGET = "../../../DeltaForce/Content/BluePrints/Characters/BP_DFMCharacter"
HELPERS = {
    "audit_owning_weapon_cooked_defaults.py": "d7d5f0ac0ea65449010c70b4ff482ec915494f59b52fe6d42bc6fa9813457189",
    "extract_operator_avatar_catalog.py": "596089d56b7727ebcb85e9060db15c01e31bc0530114140f2ba54423fdde3537",
    "recover_economy_pak_access.py": "834c0caabf81316c690a9297207c04181b78ff0d73dea69708f0ee5519de91a0",
    "recover_owning_weapon_character_assets.py": "c3c0d78900746d39284666bc02cc18e25c80e1816a54dfb366c038cc3e95144c",
    "scan_weapon_tables.py": "1c462bd80bd02d91b790c8d40ab2524663d47bc5b57445c49a9d702c18a2d160",
    "oodle_payload_reader.py": "076551c0f6d6c09b9c8799913ac67c76b9791932693e0b478a86c97857c12197",
}
REPORT_PINS = {
    STORAGE: "14ab0b1b7d3415f25f9c6c52008605658f033b623a9ef115a5360aa1a8aca8a3",
    SEARCH: "dbe4766fd33ff0101a87722a0e4391fbff7ade66f224e84165eeb0e5ef224a92",
    BASE / "native-owning-weapon-cooked-character-emptyhand-defaults.json": "e935d6eab000430da6933ce6578e2fea6a40e9897849c14597c734bf742dc543",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(raw)
    return value.hexdigest()


def load_helpers():
    sys.dont_write_bytecode = True
    for path, expected in [(PEER / "work" / name, value) for name, value in HELPERS.items()] + list(REPORT_PINS.items()):
        if file_sha(path) != expected:
            raise ValueError("Pinned read-only source changed: " + str(path))
    sys.path.insert(0, str(PEER / "work"))


def parse_configuration():
    from audit_owning_weapon_cooked_defaults import package
    from extract_operator_avatar_catalog import tags, fname
    from recover_economy_pak_access import installed_name_map
    storage = json.loads(STORAGE.read_text(encoding="utf-8"))
    for row in storage["assets"]:
        path = STEM.with_suffix(Path(row["path"]).suffix)
        if file_sha(path) != row["decoded_sha256"]:
            raise ValueError("Stored exact Pawn package differs from its extraction witness")
    parsed = package(STEM)
    header, payload = STEM.with_suffix(".uasset").read_bytes(), STEM.with_suffix(".uexp").read_bytes()
    names = installed_name_map(header)
    exports = {row["index"]: row for row in parsed["exports"]}
    cls, default, component = (exports[index] for index in (46, 47, 119))
    if (cls["super_path"] != "/Script/SOL.SOLCharacter" or default["class_index"] != 46 or
            component["class_path"] != "/Script/GPGameplay.GPStaminaDataComponent" or
            component["outer_index"] != 47 or component["name"] != "GPStaminaData"):
        raise ValueError("Exact SOL Pawn/component source identity changed")
    cdo_props, _ = tags(payload, default["offset"], names, default["offset"] + default["size"])
    binding, = [row for row in cdo_props if row["name"] == "GPStaminaDataComp"]
    if binding["kind"] != "ObjectProperty" or struct.unpack_from("<i", payload, binding["value_start"])[0] != 119:
        raise ValueError("Pawn stamina object reference changed")
    props, after = tags(payload, component["offset"], names, component["offset"] + component["size"])
    if after != component["offset"] + component["size"] - 4 or payload[after:after+4] != bytes(4):
        raise ValueError("Component tagged-property terminator/trailer changed")
    result = {"class_export": cls, "cdo_export": default, "component_export": component,
              "pawn_component_reference": dict(binding, object_index=119),
              "component_terminator_end": after, "trailer_hex": payload[after:after+4].hex(),
              "maps": [], "other_properties": []}
    for tag in props:
        if tag["kind"] != "MapProperty":
            row = dict(tag)
            if tag["kind"] == "FloatProperty" and tag["size"] == 4:
                row["value"] = struct.unpack_from("<f", payload, tag["value_start"])[0]
            elif tag["kind"] == "EnumProperty" and tag["size"] == 8:
                row["value"] = fname(payload, tag["value_start"], names)
            elif tag["kind"] == "ObjectProperty" and tag["size"] == 4:
                index = struct.unpack_from("<i", payload, tag["value_start"])[0]
                imported = parsed["imports"][-index-1]
                outer = parsed["imports"][-imported["outer_index"]-1]
                row.update(object_index=index, object_path=outer["name"] + "." + imported["name"])
            result["other_properties"].append(row)
            continue
        if tag["meta"] != ["EnumProperty", "StructProperty"]:
            raise ValueError("Unexpected stamina map wire types")
        start = tag["value_start"]
        removed, count = struct.unpack_from("<ii", payload, start)
        if removed != 0 or not 0 < count <= 32:
            raise ValueError("Map remove/add header outside the recovered scope")
        cursor, rows, seen = start + 8, [], set()
        independent = tag["name"] == "StaminaIndependentChangeConfig"
        expected = {"bIsInstant", "InstantValue", "DurationValue", "bCanTriggerUnderLowStamina"} if independent else {"DurationValue"}
        for _ in range(count):
            key_at, key = cursor, fname(payload, cursor, names)
            if key in seen:
                raise ValueError("Duplicate stamina map key")
            seen.add(key)
            fields, cursor = tags(payload, cursor + 8, names, tag["end"])
            if {field["name"] for field in fields} != expected or len(fields) != len(expected):
                raise ValueError("Serialized stamina struct fields differ from the qualified type")
            decoded = []
            for field in fields:
                row = dict(field)
                if field["kind"] == "FloatProperty" and field["size"] == 4:
                    row["value"] = struct.unpack_from("<f", payload, field["value_start"])[0]
                elif field["kind"] == "BoolProperty" and field["size"] == 0 and payload[field["start"]+24] in (0, 1):
                    row["value"] = bool(payload[field["start"]+24])
                else:
                    raise ValueError("Unexpected stamina struct field type")
                row["serialized_tag_sha256"] = sha(payload[field["start"]:field["end"]])
                decoded.append(row)
            rows.append({"key": key, "key_offset": key_at, "end": cursor,
                         "serialized_row_sha256": sha(payload[key_at:cursor]), "fields": decoded})
        if cursor != tag["end"]:
            raise ValueError("Stamina map did not consume its exact serialized extent")
        result["maps"].append(dict(tag, removed_count=removed, row_count=count,
                                   exact_eof=True, rows=rows))
    return result


def codec():
    import pefile
    path = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[0, 1])
    allowed = {"kernel32.dll", "ntdll.dll", "msvcrt.dll", "ucrtbase.dll", "advapi32.dll",
               "vcruntime140.dll", "vcruntime140_1.dll", "user32.dll"}
    imports = {entry.dll.decode("ascii").lower() for entry in pe.DIRECTORY_ENTRY_IMPORT}
    if pe.FILE_HEADER.Machine != 0x8664 or any(name not in allowed and not name.startswith("api-ms-win-") for name in imports):
        raise ValueError("Unexpected pure compression codec dependencies")
    lib = ctypes.WinDLL(str(path), winmode=0x1000)
    fn = lib.OodleLZ_Decompress
    fn.restype = ctypes.c_ssize_t
    fn.argtypes = [ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_ssize_t,
                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t,
                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t, ctypes.c_int]
    return fn


def qualify_installed_source():
    from recover_economy_pak_access import (CodeCache, ImmutableImage, native_keys, pak_footer,
                                           validate_index, directory_index, entry_offset, decrypt_block)
    from scan_weapon_tables import parse_entry
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    executable = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        keys, key_provenance = native_keys(cache, ImmutableImage(data))
    old = json.loads(SEARCH.read_text(encoding="utf-8"))
    inventory = sorted(path.name for path in PAKS.glob("*.pak"))
    if inventory != sorted(Path(row["pak"]).name for row in old["paks"]):
        raise ValueError("Installed PAK inventory differs from the pinned source search")
    targets = {TARGET + suffix for suffix in (".uasset", ".uexp")}
    ranges, hits, index_checks = [], [], []
    fn = None

    def pin_range(path, offset, size):
        with path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(size)
        if len(raw) != size:
            raise ValueError("Truncated installed PAK source interval")
        ranges.append({"path": path.as_posix(), "offset": offset, "bytes": size, "sha256": sha(raw)})

    for name in inventory:
        path = PAKS / name
        footer = pak_footer(path)
        index_meta, clear, key = validate_index(path, footer, keys)
        if clear is None or index_meta.get("index_sha1_valid") is not True:
            raise ValueError("Installed primary PAK index failed validation")
        directory, files, encoded = directory_index(path, footer, clear, key)
        index_checks.append({"pak": name, "primary_sha1_valid": True,
                             "secondary_sha1_valid": all(row["sha1_valid"] for row in directory["secondary_indices"]),
                             "directory_file_count": directory["directory_file_count"]})
        pin_range(path, path.stat().st_size - min(512, path.stat().st_size), min(512, path.stat().st_size))
        pin_range(path, footer["offset"], (footer["size"] + 15) // 16 * 16)
        for secondary in directory["secondary_indices"]:
            pin_range(path, secondary["offset"], (secondary["bytes"] + 15) // 16 * 16)
        for asset, location in files:
            if asset not in targets:
                continue
            pos = entry_offset(encoded, location)
            with path.open("rb") as stream:
                entry = parse_entry(stream, pos, footer["offset"], variant="observed_permutation")
                if not 0 < entry["uncompressed"] < 256 * 1024 or footer["methods"][entry["method"]-1] != "Oodle":
                    raise ValueError("Exact Pawn asset exceeds the qualified codec/size scope")
                blocks, encrypted = [], []
                for first, end in entry["blocks"]:
                    amount = end - first
                    stream.seek(pos + first)
                    raw = stream.read((amount + 15) // 16 * 16 if entry["flags"] & 1 else amount)
                    encrypted.append(raw)
                    compressed = decrypt_block(raw, key)[:amount] if entry["flags"] & 1 else raw
                    expected = min(entry["block_size"], entry["uncompressed"] - sum(map(len, blocks)))
                    if not 0 < expected < 256 * 1024:
                        raise ValueError("Codec output bound changed")
                    fn = fn or codec()
                    source, output = ctypes.create_string_buffer(compressed), ctypes.create_string_buffer(expected + 256)
                    actual = fn(source, len(compressed), output, expected, 1, 0, 0, None, 0, None, None, None, 0, 3)
                    if actual != expected:
                        raise ValueError("Pure codec output length mismatch")
                    blocks.append(output.raw[:expected])
                decoded = b"".join(blocks)
                if hashlib.sha1(b"".join(encrypted)).digest() != entry["sha1"]:
                    raise ValueError("Exact Pawn compressed-source SHA1 mismatch")
                stored = STEM.with_suffix(Path(asset).suffix).read_bytes()
                if decoded != stored:
                    raise ValueError("Installed exact Pawn asset differs from the parsed extraction")
            pin_range(path, pos, entry["header_size"])
            for first, end in entry["blocks"]:
                amount = end - first
                pin_range(path, pos + first, (amount + 15) // 16 * 16 if entry["flags"] & 1 else amount)
            hits.append({"pak": name, "path": asset, "physical_offset": pos,
                         "bytes": len(decoded), "decoded_sha256": sha(decoded),
                         "compressed_sha1_valid": True, "matches_stored_extraction": True})
    if len(hits) != 2 or {row["path"] for row in hits} != targets:
        raise ValueError("A unique exact Pawn package pair across the current PAK inventory is required")
    return {"inventory": inventory, "index_checks": index_checks, "exact_path_matches": hits,
            "source_range_pins": ranges, "key_reconstruction_provenance": key_provenance,
            "crypto_material_disclosed": False, "pure_compression_codec_used": True,
            "gameplay_native_methods_executed": False}, executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-evidence", type=Path)
    parser.add_argument("--verify", type=Path)
    opts = parser.parse_args()
    load_helpers()
    config = parse_configuration()
    if opts.verify:
        evidence = json.loads(opts.verify.read_text(encoding="utf-8"))
        checks = [{"path": row["path"], "matches": file_sha(Path(row["path"])) == row["sha256"]} for row in evidence["source_pins"]]
        for row in evidence["installed_source"]["source_range_pins"]:
            with Path(row["path"]).open("rb") as stream:
                stream.seek(row["offset"])
                raw = stream.read(row["bytes"])
            checks.append({"range_path": row["path"], "offset": row["offset"], "matches": len(raw) == row["bytes"] and sha(raw) == row["sha256"]})
        current = sorted(path.name for path in PAKS.glob("*.pak"))
        checks += [{"name": "installed_pak_inventory", "matches": current == evidence["installed_source"]["inventory"]},
                   {"name": "reparsed_configuration", "matches": config == evidence["configuration"]}]
        result = {"kind": "sprint_stamina_config_source_validation", "checks": len(checks),
                  "all_match": all(row["matches"] for row in checks), "failures": [row for row in checks if not row["matches"]]}
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["all_match"] else 1)
    if not opts.emit_evidence:
        print(json.dumps(config, indent=2))
        return
    target = opts.emit_evidence.resolve()
    if target.exists() or target.parent != (ROOT / "work/evidence").resolve():
        parser.error("Use a new evidence file in this repository's work/evidence")
    installed, executable = qualify_installed_source()
    sources = [Path(__file__).resolve(), ROOT / "AGENTS.md", PEER / "AGENTS.md", executable,
               STEM.with_suffix(".uasset"), STEM.with_suffix(".uexp"), CACHE / "manifest.json",
               GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll",
               ROOT / "work/evidence/gameplay-sprint-stamina-research-20261021.json"]
    sources += [PEER / "work" / name for name in HELPERS] + list(REPORT_PINS)
    result = {"kind": "disk_only_exact_sol_pawn_stamina_config_research", "version": 1,
              "as_of_utc": datetime.now(timezone.utc).isoformat(), "client_sha256": file_sha(executable),
              "cache_manifest_sha256": MANIFEST_SHA,
              "scope": {"process_access": False, "game_launched": False, "network_access": False,
                        "database_access": False, "gameplay_native_methods_executed": False,
                        "peer_files_written": False, "original_installation_written": False,
                        "shadow_modified": False, "configuration_executed": False},
              "source_pins": [{"path": path.as_posix(), "bytes": path.stat().st_size, "sha256": file_sha(path)} for path in sources],
              "configuration": config, "installed_source": installed,
              "limitations": ["These are serialized BP_DFMCharacter CDO component values, not observed runtime attribute multipliers.",
                              "The exact package pair is unique across the 257 currently indexed Content/Paks files; other runtime override mechanisms are not qualified.",
                              "Full UpdateStamina gates, penalties, authority transactions and result replication remain separate dependencies."],
              "native_runtime_acceptance_claimed": False}
    raw = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with target.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"path": target.as_posix(), "sha256": sha(raw), "source_files": len(sources),
                      "paks": len(installed["inventory"]), "source_ranges": len(installed["source_range_pins"]),
                      "map_rows": sum(row["row_count"] for row in config["maps"])}))


if __name__ == "__main__":
    main()
