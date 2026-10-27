"""Qualify the SOL terminal MetaRuntime dependency from immutable local sources.

Never attaches to a process, launches a client, executes Lua, sends packets, or
writes the game/peer. Only --output writes a new research evidence artifact.
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
import research_world_admission_20261020 as r

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "work/evidence/gameplay-terminal-hook-research-20261021.json"
FUNCTIONS = [0xB845590, 0xCC5DD00, 0x10C8E260, 0x72DD20, 0xCBD18D0,
             0x10C8E410, 0x1092E1E0, 0x109C93E0, 0x109C95D0,
             0x10C89210, 0x10931710, 0x10C897A0]
TERMINAL = re.compile(r"OnPlayerMatchOver|SettlementComponent|65af|6569", re.I)
ASSETS = re.compile(r"/MetaDorian/(?:MetaDorian(?:Driver|Entry)|MetaDorianImpl/[^/]+)\.lua$", re.I)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def native():
    analysis = r.analyze(r.CACHE, r.MANIFEST_SHA, r.GAME, FUNCTIONS, [], set(),
                         spans=[(0x2F6A3B0, 8)])
    assert all(f["linear_decode_covers_extent"] for f in analysis["functions"])
    cache = r.CodeCache(r.CACHE, r.MANIFEST_SHA, r.GAME)
    exe = r.GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    records = []
    with exe.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = r.ImmutableImage(data)
        for stub, name in [(0x6569, "UDFMSettlementComponent::OnPlayerMatchOver_ES"),
                           (0x65AF, "UDFMSettlementComponent::OnPlayerMatchOver_BS")]:
            at = 0x1D036860 + (stub - 1) * 16
            raw = image.read(at, 16)
            number, pointer = struct.unpack("<QQ", raw)
            text = image.read(pointer - image.image_base, len(name) + 1)
            if number != stub or text != name.encode("ascii") + b"\0":
                raise ValueError("Exact immutable stub registration changed")
            records.append(dict(stub_id=hex(stub), name=name, record_rva=hex(at),
                                record_sha256=digest(raw), name_rva=hex(pointer-image.image_base),
                                name_with_nul_sha256=digest(text),
                                flag_rva=hex(0x1E0B1720+stub)))
        slot = image.read(0x1A8F6428+0x440, 8)
        if struct.unpack("<Q", slot)[0]-image.image_base != 0xB845590:
            raise ValueError("Actual SOL terminal vtable slot changed")
    return dict(analysis=analysis, module_id=167, module_name="DFMGameplay",
                module_registration_rva="0x72dd20", stub_count=0xD64C,
                stub_name_table_rva="0x1d036860", stub_flag_base_rva="0x1e0b1720",
                exact_stub_records=records,
                sol_primary_vtable_slot=dict(vtable_rva="0x1a8f6428", offset="0x440",
                                             target_rva="0xb845590", sha256=digest(slot)))


def packages():
    cache = r.CodeCache(r.CACHE, r.MANIFEST_SHA, r.GAME)
    exe = r.GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with exe.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        keys, provenance = r.native_keys(cache, r.ImmutableImage(data))
    paks, scripts, names = [], [], set()
    for path in sorted((r.GAME / "DeltaForce/Content/Paks").glob("*.pak")):
        footer = r.pak_footer(path)
        public, clear, key = r.validate_index(path, footer, keys)
        if clear is None or public.get("index_sha1_valid") is not True:
            raise ValueError("Original PAK primary index verification failed")
        details, files, encoded = r.directory_index(path, footer, clear, key)
        names.update(name for name, _ in files)
        matches = [(name, location) for name, location in files if ASSETS.search(name)]
        paks.append(dict(pak=path.name, footer_sha256=public["footer_sha256"],
                         primary_sha256=public["decoded_index_sha256"],
                         secondary_indices=details["secondary_indices"],
                         directory_files=len(files), matches=[name for name, _ in matches]))
        with path.open("rb") as source:
            for name, location in matches:
                offset = r.entry_offset(encoded, location)
                entry = r.parse_entry(source, offset, footer["offset"], variant="observed_permutation")
                raw, valid = r.decode_entry(source, offset, entry, footer["methods"], key)
                if not valid:
                    raise ValueError("Selected original Lua payload SHA1 failed")
                reader = r.Reader(raw, allow_client_format1=True)
                tree = reader.function()
                if reader.at != len(raw):
                    raise ValueError("Selected Lua did not parse to exact EOF")
                functions = list(r.walk(tree))
                terminal_hits, numeric_hits, binding_candidates = [], [], []
                for function in functions:
                    const = function["constants"]
                    hits = [c for c in const if isinstance(c, str) and TERMINAL.search(c)]
                    numbers = [c for c in const if type(c) in (int, float) and c in (0x6569, 0x65AF)]
                    identity = dict(function_id=function["id"], serialized_offset=function["offset"],
                                    first_line=function["first_line"], last_line=function["last_line"])
                    if hits:
                        terminal_hits.append(dict(**identity, constants=hits))
                    if numbers:
                        numeric_hits.append(dict(**identity, constants=numbers))
                    if "AddDorianFunction" in const:
                        lines = r.listing(function).splitlines()
                        selected = {j for i, line in enumerate(lines) if "AddDorianFunction" in line
                                    for j in range(max(0, i-2), min(len(lines), i+8))}
                        binding_candidates.append(dict(**identity, selected_listing=[lines[i] for i in sorted(selected)]))
                record = dict(indexed_path=name, pak=path.name, encoded_offset=location,
                              physical_offset=offset, bytes=len(raw), decoded_sha256=digest(raw),
                              compressed_sha1_valid=True, parsed_to_exact_eof=True,
                              lua_executed=False, function_count=len(functions),
                              terminal_string_hits=terminal_hits, terminal_numeric_id_hits=numeric_hits,
                              binding_candidate_functions=binding_candidates)
                if name.endswith(("/MetaDorianEntry.lua", "/MetaDorianDriver.lua")):
                    record["functions"] = [dict(function_id=f["id"], first_line=f["first_line"],
                        last_line=f["last_line"], constants=f["constants"], listing=r.listing(f).splitlines())
                        for f in functions]
                scripts.append(record)
    entry = next(s for s in scripts if s["indexed_path"].endswith("/MetaDorianEntry.lua"))
    paths = [c for c in entry["functions"][0]["constants"] if isinstance(c, str)
             and c.startswith("MetaDorian.MetaDorianImpl.")]
    priority = [{"lua_module": value,
                 "indexed_path": "../../../DeltaForce/Content/LuaSource/"+value.replace(".", "/")+".lua",
                 "present_in_original_pak_indices": "../../../DeltaForce/Content/LuaSource/"+value.replace(".", "/")+".lua" in names}
                for value in paths]
    # Original loose filenames are bounded to the installation; mounted/cache
    # priority and encoded Lua cache names cannot be established from this list.
    loose = []
    pattern = re.compile(r"Dorian|HotPatch|MetaHotfix", re.I)
    for path in r.GAME.rglob("*"):
        if path.is_file() and pattern.search(path.name):
            loose.append(path.relative_to(r.GAME).as_posix())
    return dict(pak_count=len(paks), directory_file_count=sum(p["directory_files"] for p in paks),
                all_primary_and_secondary_sha1_valid=True, source_paks=paks,
                key_derivation_provenance=provenance, key_material_disclosed=False,
                selected_scripts=scripts, entry_priority_paths=priority,
                selected_original_loose_filename_pattern=pattern.pattern,
                matching_original_loose_filenames=sorted(loose),
                loose_filename_scan_is_encoded_cache_or_mount_inventory=False)


def collect():
    pins = [ROOT / "work/research_world_admission_20261020.py",
            ROOT / "docs/GAMEPLAY_WORLD_RESEARCH_20261020.md",
            ROOT / "work/evidence/gameplay-world-research-20261020.json"]
    pins += [r.PEER / "work" / name for name in (
        "analyze_portable_native_code.py", "portable_native_code_cache.py",
        "snapshot_native_image_code.py", "offline_received_packet_xrefs.py",
        "recover_economy_pak_access.py", "scan_weapon_tables.py", "lua53_reader.py",
        "oodle_payload_reader.py")]
    result = dict(kind="readonly_gameplay_terminal_hook_research_20261021",
                  reviewed_at_utc=datetime.now(timezone.utc).isoformat(),
                  helper_sha256=file_digest(__file__), source_pins={str(p): file_digest(p) for p in pins},
                  original_game_root=str(r.GAME), cache_folder=str(r.CACHE),
                  cache_manifest_sha256=r.MANIFEST_SHA,
                  process_access=False, client_launched=False, packets_sent=False,
                  original_or_peer_written=False, database_accessed=False,
                  lua_executed=False, native_gameplay_acceptance_claimed=False,
                  native=native(), packages=packages())
    result["conclusion"] = dict(
        recovered="SOL terminal slot enters DFMGameplay MetaRuntime module 167 stubs 26031/25961, whose manager invokes the Lua stub handler installed by UMetaDorianManager::Init",
        not_recovered="An actual active binding from either exact stub to a terminal producer and its producer body",
        entry_is_runtime_mount_selection_proof=False,
        no_keyword_hit_proves_code_absence=False,
        dedicated_server_implementation_absence_or_presence_proved=False,
        blueprint_or_other_delegate_producer_excluded=False,
        next_dependency="Same-build mounted MetaDorian release implementation and exact module/stub-to-alias binding, or the actual DS-only implementation of this slot")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.output == args.verify:
        parser.error("Choose --output (new evidence only) or --verify (no writes)")
    result = collect()
    if args.verify:
        previous = json.loads(OUTPUT.read_text(encoding="utf-8"))
        result.pop("reviewed_at_utc")
        previous.pop("reviewed_at_utc")
        if result != previous:
            raise ValueError("Recomputed immutable terminal-hook evidence differs")
        print(json.dumps(dict(status="verified", evidence=str(OUTPUT), sha256=file_digest(OUTPUT))))
    else:
        raw = (json.dumps(result, ensure_ascii=True, indent=2)+"\n").encode("ascii")
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        with OUTPUT.open("xb") as target:
            target.write(raw)
        print(json.dumps(dict(status="written", evidence=str(OUTPUT), bytes=len(raw), sha256=digest(raw))))


if __name__ == "__main__":
    main()
