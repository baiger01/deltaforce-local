"""Bounded disk-only Sprint stamina queries; never execute native client code."""
import argparse
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
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
CLIENT_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
HELPERS = {
    "portable_native_code_cache.py": "2372b9603d6d6e12a3afc57ac1765f8aaca408d0c2794a8d81eaec3337fa399e",
    "analyze_portable_native_code.py": "c08ed72d4969f43178de962b836a62fb472d23beb11ac01a7f7269f8792eeafd",
    "offline_received_packet_xrefs.py": "4151dd221d6ad09bd83cebdb2ab2016e688aa05624727488ac8fbfc5f500ed77",
    "snapshot_native_image_code.py": "62405c35a3839d5eb67cf2cdde41606d6a82f2501fd84d7b3671adec864e15ae",
}
FINAL_FUNCTIONS = (
    0xAB8A250, 0xAC85270, 0xABFDBB0, 0x45F0DE0, 0x4575B90,
    0x45C5D10, 0x45FD770, 0x449DD20, 0x608DB70, 0x6090750,
    0x6091580, 0x608EDF0, 0x5FC62B0, 0x5FC7A20, 0x5FC6270,
    0x5FC79F0, 0x608EF10, 0x608EEB0, 0x608E490, 0x608E460,
    0x2FE60A0, 0x39E5A80,
)
FINAL_SPANS = ((0x608E8B0, 13), (0xEC25E0, 5), (0xD903B0, 4),
               (0x31838C0, 8), (0x603FBD0, 8))
FINAL_RECORDS = (
    (0x186B21A0, 24), (0x15E0B940, 8), (0x16787990, 320),
    (0x16785480, 40), (0x167855E0, 56), (0x16785618, 56),
    (0x1CD06AF8, 56), (0x1CD06B30, 56), (0x1665CC10, 0x950),
    (0x1CD4E590, 80), (0x16787688, 32), (0x167875D8, 40),
    (0x16787600, 40), (0x16787628, 40),
    (0x1CD4E130, 80), (0x1CD4E0E0, 80),
    (0x167871E0, 32), (0x167870B8, 8),
    (0x16787120, 56), (0x16787158, 40), (0x16787180, 40),
    (0x167871A8, 56), (0x16787090, 40),
    (0x16784640, 64), (0x16784588, 64), (0x16784610, 48), (0x167846C8, 48),
    (0x1661C220, 40), (0x1661C1C0, 40),
    (0x1661C2B0, 40), (0x1661C280, 40),
    (0x16784720, 40), (0x167846F8, 40),
    (0x14EC2700, 16), (0x14EDD80C, 4),
)
CONTRACT = {
    "request_stamina_change": {
        "body": "0x4575b90", "exec": "0x6090750",
        "parameters": {"rcx": "UGPStaminaDataComponent receiver", "dl": "StaminaChangeType",
                       "xmm2": "DeltaSeconds", "r9d": "ChangeCount"},
        "parameter_uht_records": ["0x16787628", "0x16787600", "0x167875d8"],
    },
    "sprint_penalty_request": {
        "caller": "0x45f0de0", "callsite": "0x45f2571",
        "receiver": "qword [Sprint receiver + 0x120] (StaminaData UHT 0x16785480)",
        "type": 18, "enum": "EStaminaIndependentChangeType::EStaminaIndependentChange_SprintPenalty",
        "enum_name_value_pair": "0x1665cf00", "delta_seconds": 0,
        "change_count": "min_signed32(previous counter + 1, 13) - 3, only if updated counter > 3",
        "counter_member": "0x144", "previous_time_member": "0x140",
        "time_test": "float(world + 0x610 double) - previous_time < dynamic threshold loaded through 0x1ddefc30",
        "other_branch": "counter = 1; both branches store the sampled float time",
        "threshold_value_recovered": False,
    },
    "independent_config": {
        "component_member": "0x118", "entry_stride": 28, "value_offset_in_entry": 4,
        "value_type": "FStaminaIndependentChangeInfo", "value_bytes": 16,
        "map_value_uht_type_binding": "0x167846c8 -> struct getter 0x608e490",
        "struct_descriptor": "0x1cd4e130", "property_list": "0x167871e0",
        "fields": {"bIsInstant": 0, "InstantValue": 4, "DurationValue": 8, "bCanTriggerUnderLowStamina": 12},
        "delta_branch": "bIsInstant ? float(ChangeCount) * InstantValue : DeltaSeconds * DurationValue",
        "negative_multiplier_attribute": "GPAttributeSetSpeed + 0x168 StaminaIndependentNegativeChangeRate (applied only when > 0)",
        "positive_multiplier_attribute": "GPAttributeSetSpeed + 0x178 (name not independently qualified here; applied only when > 0)",
        "actual_mode_row_values_recovered": False,
    },
    "continuous_update": {
        "class_getter": "0x608db70", "constructor_thunk": "0x608e8b0",
        "constructor": "0x449dd20", "primary_vtable": "0x15e0b608",
        "tick_slot": "0x338", "tick_method": "0x45c5d10", "callsite": "0x45c5e29",
        "update_body": "0x45fd770", "delta_passed_in": "xmm1",
        "exclusive_config_member": "0x168", "entry_stride": 16, "value_offset_in_entry": 4,
        "value_type": "FStaminaExclusiveChangeInfo", "value_bytes": 4,
        "map_value_uht_type_binding": "0x16784610 -> struct getter 0x608e460",
        "struct_descriptor": "0x1cd4e0e0", "property_list": "0x167870b8", "value_field": "DurationValue +0",
        "enum_name_value_table": "0x1665cc10",
        "enum_values": {"Normal": 0, "Sprint": 1, "StandRun": 2, "SuperSprint": 3, "SwimmingSprint": 4},
        "sprint_selection_branch": "0x4603359..0x460336d chooses Sprint=1 or SuperSprint=3 by Sprint+0x101 after earlier gates",
        "sprint_delta_branch": "delta_seconds * selected exclusive DurationValue * GPAttributeSetSpeed.StaminaSprintChangeRate(+0x148)",
        "sprint_read": "0x46010c1 reads Sprint+0x102 (bSprinting); action writes at 0xab8b99e / 0xabff2e1",
        "bounded_commit": "0x4606609..0x46066a6 uses lower limit component+0x10c and MaxStamina attribute+0x128; passes candidate with Stamina descriptor 0x39e5a80 to 0x2fe73d0",
        "recovery_cooldown_tick": "0x45c5e2e..0x45c5e54 subtracts delta_seconds from component+0x1ec while +0x1ea is false; sets flag true when <= 0",
        "complete_selection_or_update_semantics_recovered": False,
    },
    "registration_removal_boundary": "No new full registration/removal contract claimed; pointer wrapper refresh/re-encoding is not a stamina registration operation.",
}
REMAINING = (
    "Recover actual same-mode component configuration rows for independent SprintPenalty and exclusive Sprint/SuperSprint, their signs, rate values and overrides.",
    "Qualify the dynamic repeat-start threshold behind 0x1ddefc30 and its effective runtime/config source; do not guess the console variable value.",
    "Finish all UpdateStamina selection/recovery/overload/buff/fatigue gates, including 0x1cbd17da/0x1cbd17d9 mode decisions, then the resulting transaction and interruptions.",
    "Close character/FSM lifecycle binding and any registration/removal semantics, then authority result replication; pointer decoding is not registration proof.",
    "Validate natural start/stop and continuous stamina only in a separately authorized native trial; this evidence executes no native methods.",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(raw)
    return value.hexdigest()


def integer(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function", type=integer, action="append", default=[])
    parser.add_argument("--span", action="append", default=[])
    parser.add_argument("--window", action="append", default=[])
    parser.add_argument("--calls", action="store_true")
    parser.add_argument("--search-call", type=integer, action="append", default=[])
    parser.add_argument("--literal", action="append", default=[])
    parser.add_argument("--record", action="append", default=[])
    parser.add_argument("--emit-evidence", type=Path)
    parser.add_argument("--verify", type=Path)
    opts = parser.parse_args()
    if opts.emit_evidence and not (opts.function or opts.span or opts.record):
        opts.function = list(FINAL_FUNCTIONS)
        opts.span = [f"{hex(first)}:{size}" for first, size in FINAL_SPANS]
        opts.record = [f"{hex(first)}:{size}" for first, size in FINAL_RECORDS]
    sys.dont_write_bytecode = True
    for name, expected in HELPERS.items():
        if digest((PEER / "work" / name).read_bytes()) != expected:
            raise ValueError("Read-only helper changed: " + name)
    sys.path.insert(0, str(PEER / "work"))
    from analyze_portable_native_code import analyze
    from offline_received_packet_xrefs import ImmutableImage
    from portable_native_code_cache import CodeCache
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    executable = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    windows = [tuple(integer(v) for v in item.split(":")) for item in opts.window]
    records = [tuple(integer(v) for v in item.split(":")) for item in opts.record]
    spans = [tuple(integer(v) for v in item.split(":")) for item in opts.span]
    if any(not 0 < end - first <= 16384 for first, end in windows):
        parser.error("Windows are start:end with a maximum size of 16384")
    if any(not 0 < size <= 4096 for _, size in records):
        parser.error("Records are rva:size with a maximum size of 4096")
    if any(not 0 < size <= 16384 for _, size in spans):
        parser.error("Spans are rva:size with a maximum size of 16384")
    with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        if opts.verify:
            evidence = json.loads(opts.verify.read_text(encoding="utf-8"))
            checks = []
            for pin in evidence["source_pins"]:
                checks.append({"path": pin["path"], "matches": file_digest(Path(pin["path"])) == pin["sha256"]})
            for pin in evidence["code_pins"]:
                first, size = int(pin["rva"], 16), pin["bytes"]
                raw = b"".join(cache.read(at, min(8192, first + size - at)) for at in range(first, first + size, 8192))
                checks.append({"rva": pin["rva"], "matches": digest(raw) == pin["sha256"]})
            for pin in evidence["record_pins"]:
                checks.append({"record_rva": pin["rva"], "matches": digest(image.read(int(pin["rva"], 16), pin["bytes"])) == pin["sha256"]})
            result = {"kind": "sprint_stamina_source_validation", "checks": checks, "all_match": all(row["matches"] for row in checks)}
            print(json.dumps(result, indent=2))
            raise SystemExit(0 if result["all_match"] else 1)
        if opts.emit_evidence:
            if image.read(0x1665CF00, 16) != struct.pack("<QQ", image.image_base + 0x1665D4A0, 18):
                raise ValueError("SprintPenalty enum pair changed")
            if image.read(0x1665CC20, 16) != struct.pack("<QQ", image.image_base + 0x1665CCA0, 1):
                raise ValueError("Exclusive Sprint enum pair changed")
        record_rows = []
        for first, size in records:
            raw = image.read(first, size)
            record_rows.append({"rva": hex(first), "bytes": size, "sha256": digest(raw), "hex": raw.hex()})
    result = analyze(CACHE, MANIFEST_SHA, GAME, opts.function, opts.literal, set(opts.search_call), spans)
    if opts.emit_evidence:
        output = opts.emit_evidence.resolve()
        if output.exists() or output.parent != (ROOT / "work/evidence").resolve():
            parser.error("Use a new evidence file inside this repository's work/evidence")
        if file_digest(executable) != CLIENT_SHA:
            raise ValueError("Original installed client image changed")
        sources = [ROOT / "AGENTS.md", PEER / "AGENTS.md", CACHE / "manifest.json", Path(__file__).resolve(), executable]
        sources += [PEER / "work" / name for name in HELPERS]
        evidence = {
            "kind": "disk_only_sprint_stamina_research", "version": 1,
            "as_of_utc": datetime.now(timezone.utc).isoformat(), "client_sha256": CLIENT_SHA,
            "cache_manifest_sha256": MANIFEST_SHA,
            "scope": {"process_access": False, "native_code_executed": False, "game_launched": False,
                      "shadow_modified": False, "peer_files_written": False, "network_access": False, "database_access": False},
            "source_pins": [{"path": path.as_posix(), "bytes": path.stat().st_size, "sha256": file_digest(path)} for path in sources],
            "code_pins": [{"rva": row["span_start"], "bytes": row["span_bytes"], "sha256": row["code_sha256"],
                           "full_semantic_recovery_claimed": False} for row in result["functions"]],
            "record_pins": record_rows, "native_analysis": result,
            "recovered_contract": CONTRACT, "remaining_dependencies": list(REMAINING),
            "native_runtime_acceptance_claimed": False,
        }
        raw = (json.dumps(evidence, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        with output.open("xb") as dest:
            dest.write(raw)
        print(json.dumps({"path": output.as_posix(), "sha256": digest(raw), "functions": len(result["functions"]), "records": len(record_rows)}))
        return
    for row in record_rows:
        print(json.dumps(row))
    for function in result["functions"]:
        print("FUNCTION", function["span_start"], function["span_bytes"], function["code_sha256"])
        for ins in function["instructions"]:
            at = int(ins["rva"], 16)
            if windows and not any(first <= at < end for first, end in windows):
                continue
            if opts.calls and ins["mnemonic"] not in ("call", "ret"):
                continue
            print(ins["rva"], ins["bytes"], ins["mnemonic"], ins["operands"], json.dumps(ins.get("rip_references", []), ensure_ascii=False))
    for key in ("immutable_literal_locations", "immutable_pointer_candidates", "literal_xref_candidates", "direct_call_candidates"):
        for row in result[key]:
            print(key, json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    main()
