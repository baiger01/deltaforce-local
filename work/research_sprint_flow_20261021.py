"""Read-only Sprint source queries against the pinned installed image and cache."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

PEER = Path("E:/新建文件夹/DSH/deltaforce-map-appearance")
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
CLIENT_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
CODE_PINS = (
    ("input_consumer", 0x4EEB740, 39058, "b5d2324bab2ace17d4619bdaa79fb48eb9ab8eea714fa197830cea6887315f93"),
    ("saved_move_capture", 0x475FA50, 5583, "8720d49355d0faffc77fd2b241a23a4e2b4088a4fe91d8b99fe7530703d3524a"),
    ("saved_move_flags", 0x469B7E0, 644, "aa4dc6167ef9fea9a42685d43bfeede276cce2200680a7794f23f48750a9e25e"),
    ("flags_to_movement", 0x47D7840, 616, "c31eb31abfc525d6ecbaa6e3c1e8e9ec6fe0f53836b2fb9ac6a94503ce88d97d"),
    ("new_server_move_exec", 0x5FCB570, 216, "3ab17f2aabff162976c43127c65879449371932d2f94c15f184fc6b03f18b049"),
    ("new_server_move_validate", 0x46D0EF0, 23, "df76584a8e92559898daad676f686029706d11b18b48aae536011cf1764499d2"),
    ("new_server_move_implementation", 0x46D01C0, 3366, "1f5b79066c6ce573dd46cbdac699eb6e77b76d9fcb5307e458a5cd2035cd7219"),
    ("sol_move_override", 0xB0483E0, 1851, "d7b2ce8f563f1dedbc0e949356af424db413c561b641594ee6c058dd200b9fce"),
    ("gp_move_wrapper", 0x476EEB0, 2208, "dcc872f92416b0ec9b47ab5cad1a3af432036dbf8aa34ab4208c0265c3a58104"),
    ("ue_move", 0x12738170, 2256, "aff1b65f3d046940bcb7bc9e6ea0056bec9fbd42027b125dda6c00d61ee9ebaf"),
    ("move_autonomous", 0x48367C0, 711, "0d0c2e96706dfc5247a24f5a3b766a16f7a54bb0624701cefeb1a907946874cf"),
    ("sol_class_getter", 0x104D2E50, 178, "c93c37dc204d665dcee321910f381381ab80ae78e8ecbaba661b06c68bf2db3c"),
    ("sol_ctor_bounded", 0x104D41E0, 80, "4804a5c6aa36b9d5b83650b6f2645ef9884bbb03a1a8e4b0ff98bea3ed24971e"),
    ("sprint_action_getter", 0xCE8AA50, 178, "10ee85adec1bdcd50242a767f17141901562a18c2c0115e4a45eb6253fb8f6ed"),
    ("sprint_action_ctor", 0xCE8BB70, 128, "975084d61027c0294c047a00b41465815a5cb699a61c4d8d7bc60cbd7dfc42da"),
    ("sprint_action_slot_330", 0xAB8A250, 12265, "de2137c42c4355bf1f9bccf9c11c27a1feeecfbbc86a8f937322f716ed594331"),
    ("sprint_action_slot_338", 0xAC85270, 2947, "29179a10d8eda8ec4a4c971d115bc17fc60863ac8f570b95fd14dec927a8d91f"),
    ("sprint_action_slot_340", 0xABFDBB0, 18530, "f59231f46017667a558f42ab317e986aff188887a6773f3b59abddd5a149b6a0"),
    ("request_stamina_change", 0x4575B90, 3483, "e6cdbec03aacba6cbef7165b3a4a32a661323869df25944baeaf1f5d948041c3"),
    ("stamina_request_helper", 0x45F0DE0, 6182, "00b9583bb1c69d15377c36f4be747ad6d90e01395a16f659b0d35a05d00a4e69"),
    ("move_serializer", 0x4D11810, 1235, "aebfae7274d9d5799536ae70aeae85806e42e045a49f2f1d31cc7dbe41a26018"),
)
HELPERS = {
    "portable_native_code_cache.py": "2372b9603d6d6e12a3afc57ac1765f8aaca408d0c2794a8d81eaec3337fa399e",
    "analyze_portable_native_code.py": "c08ed72d4969f43178de962b836a62fb472d23beb11ac01a7f7269f8792eeafd",
    "offline_received_packet_xrefs.py": "4151dd221d6ad09bd83cebdb2ab2016e688aa05624727488ac8fbfc5f500ed77",
    "snapshot_native_image_code.py": "62405c35a3839d5eb67cf2cdde41606d6a82f2501fd84d7b3671adec864e15ae",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--member", type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--target", type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--pointer", type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--literal", action="append", default=[])
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--emit-evidence", action="store_true")
    parser.add_argument("--byte-field-only", action="store_true")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    for name, expected in HELPERS.items():
        if sha((PEER / "work" / name).read_bytes()) != expected:
            raise ValueError("Read-only helper changed: " + name)
    sys.path.insert(0, str(PEER / "work"))
    from analyze_portable_native_code import function_fragments
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_REG_RBP, X86_REG_RSP
    from offline_received_packet_xrefs import ImmutableImage
    from portable_native_code_cache import CodeCache
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    executable = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    if args.verify:
        evidence = json.loads(args.verify.read_text(encoding="utf-8"))
        checks = []
        for pin in evidence["source_pins"]:
            actual = sha(Path(pin["path"]).read_bytes())
            checks.append({"path": pin["path"], "matches": actual == pin["sha256"]})
        for pin in evidence["code_pins"]:
            start, size = int(pin["rva"], 16), pin["bytes"]
            code = b"".join(cache.read(at, min(8192, start + size - at))
                            for at in range(start, start + size, 8192))
            checks.append({"rva": pin["rva"], "matches": sha(code) == pin["sha256"]})
        with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            image = ImmutableImage(data)
            for pin in evidence["record_pins"]:
                checks.append({"record_rva": pin["rva"], "matches":
                               sha(image.read(int(pin["rva"], 16), pin["bytes"])) == pin["sha256"]})
        print(json.dumps({"kind": "sprint_source_validation", "checks": checks,
                          "all_match": all(c["matches"] for c in checks)}, indent=2))
        if not all(c["matches"] for c in checks):
            raise SystemExit(1)
        return
    with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        if args.emit_evidence:
            relative_sources = [
                "AGENTS.md", "work/portable_movement_wire.py", "work/portable_movement_runtime.py",
                "work/portable_movement_binding.py", "work/portable_movement_clock_epoch.py",
                "work/portable_source_guard.py", "work/portable_map_bootstrap.py", "work/portable_map_vitals_probe.py",
                "outputs/df-local-server/dfserver/legacy_ds_movement.py",
                "outputs/df-local-server/dfserver/legacy_ds_control_connection.py",
                "outputs/df-local-server/dfserver/game_server_probe.py",
                "work/evidence/map-system-audit-20261018/ai-runtime-research-20261020-world-movement-owner-functions-v1.json",
                "work/evidence/map-system-audit-20261018/ai-runtime-research-20261020-world-movement-params-fields-v1.json",
                "work/evidence/model-init-chain-20261018/native-gp-sprint-actual-ability-gates.json",
                "work/evidence/model-init-chain-20261018/native-current-sprint-permission-findings-v1.json",
                "work/evidence/skill-flow-research-20261020-v1/atom-basepose-metadata.json",
                "work/evidence/skill-flow-research-20261020-v1/atom-basepose-bytecode.json",
                "work/evidence/skill-flow-research-20261020-v1/skill-flow-integration-graph-v2.json",
            ]
            relative_sources += ["work/" + name for name in HELPERS]
            sources = [PEER / name for name in relative_sources] + [CACHE / "manifest.json", Path(__file__).resolve()]
            meta = json.loads((PEER / relative_sources[15]).read_text(encoding="utf-8"))
            sources += [PEER / item["relative_path"] for item in meta["source_files"]]
            pins = []
            for name, start, size, expected in CODE_PINS:
                code = b"".join(cache.read(at, min(8192, start+size-at))
                                for at in range(start, start+size, 8192))
                if sha(code) != expected:
                    raise ValueError("Recovered native source changed: " + name)
                pins.append({"name": name, "rva": hex(start), "bytes": size, "sha256": expected,
                             "full_semantic_recovery_claimed": False})
            records = []
            for name, start, size in (("sol_movement_slots_9e8_9f0", 0x1A8F1CB8, 16),
                                      ("sol_movement_slot_a40", 0x1A8F1D10, 8),
                                      ("sol_movement_slots_b98_ba0", 0x1A8F1E68, 16),
                                      ("sprint_action_slots_330_338_340", 0x186B21A0, 24),
                                      ("new_server_move_native_registration", 0x16666E60, 608),
                                      ("new_server_move_uht", 0x1CD08550, 80)):
                raw = image.read(start, size)
                records.append({"name": name, "rva": hex(start), "bytes": size, "sha256": sha(raw)})
            evidence = {"kind": "disk_only_character_sprint_flow_research", "version": 1,
                        "as_of_utc": datetime.now(timezone.utc).isoformat(), "client_sha256": CLIENT_SHA,
                        "cache_manifest_sha256": MANIFEST_SHA,
                        "scope": {"process_access": False, "game_launched": False, "shadow_modified": False,
                                  "peer_files_written": False, "network_access": False, "database_access": False},
                        "source_pins": [{"path": p.as_posix(), "bytes": p.stat().st_size,
                                         "sha256": sha(p.read_bytes())} for p in sources],
                        "code_pins": pins, "record_pins": records,
                        "recovered_contract": {"sprint_intent_mask": "0x4", "move_flags_bits": 32,
                            "movement_native_member": "0x9b0", "saved_move_native_member": "0x369",
                            "capture": ["0x475fb54", "0x475fb5b"],
                            "encode": ["0x469b85d", "0x469b860", "0x469b867"],
                            "decode": ["0x47d7925", "0x47d7927", "0x47d792a", "0x47d792c"],
                            "native_rpc_exec": "0x5fcb570", "validation_slot": "0xb98", "implementation_slot": "0xba0",
                            "native_dispatch": ["0x46d01c0", "0xb0483e0", "0x476eeb0", "0x12738170", "0x48367c0", "0x47d7840"],
                            "action_intent_set": "0xab8ac12", "action_intent_clear": "0xabfe552",
                            "action_sprinting_set": "0xab8b99e", "action_sprinting_clear": "0xabff2e1"},
                        "production_boundary": {"new_server_move_decoded": True, "position_claim_acceptance": True,
                            "sprint_intent_executed": False, "sprint_stamina_authority": False,
                            "sprint_start_stop_result_producer": False, "native_runtime_acceptance_claimed": False},
                        "remaining_dependencies": [
                            "Qualify natural Sprint pressed/released values and exact input object virtual+0x480 target/event mapping.",
                            "Close saved-move packed return -> GPMoveParams.MoveFlags generation store and actual request slice.",
                            "Recover the complete SprintExecuteAction entry/update/exit gating and RequestStaminaChange request arguments, configuration selection and fatigue transitions.",
                            "Recover authority consumption/recovery tick, interruption and result replication layouts; bWantsToSprint is intent, not an authoritative result.",
                            "Implement same-admission sprint/FSM/stamina transactions and normal movement simulation/correction, then validate natural input in an authorized native trial."],
                        "replay": "python -B work/research_sprint_flow_20261021.py --verify work/evidence/gameplay-sprint-flow-research-20261021.json"}
            print(json.dumps(evidence, indent=2))
            return
        literal_rvas = set()
        for literal in args.literal:
            for encoding in ("ascii", "utf-16le"):
                needle, offset = literal.encode(encoding) + (b"\0" if encoding == "ascii" else b"\0\0"), 0
                while True:
                    at = data.find(needle, offset)
                    if at < 0:
                        break
                    for first, size, backing, _ in image.sections:
                        if backing <= at < backing + size:
                            literal_rvas.add(first+at-backing)
                            print(json.dumps({"literal": literal, "encoding": encoding,
                                              "record_rva": hex(first+at-backing)}))
                    offset = at + 1
        for pointer in args.pointer:
            needle, offset = struct.pack("<Q", image.image_base + pointer), 0
            while True:
                at = data.find(needle, offset)
                if at < 0:
                    break
                for first, size, backing, _ in image.sections:
                    if backing <= at < backing + size:
                        print(json.dumps({"pointer_target": hex(pointer), "record_rva": hex(first+at-backing)}))
                offset = at + 8
        candidates = set()
        for first, size, block in cache.blocks:
            if not block["available"]:
                continue
            raw = (CACHE / block["file"]).read_bytes()
            if len(raw) != size or sha(raw) != block["code_sha256"]:
                raise ValueError("Cached executable block changed")
            if literal_rvas:
                for prefix in (b"\x48\x8d\x0d", b"\x48\x8d\x15", b"\x4c\x8d\x05", b"\x4c\x8d\x0d"):
                    offset = 0
                    while True:
                        at = raw.find(prefix, offset)
                        if at < 0 or at + 7 > size:
                            break
                        target = first+at+7+struct.unpack_from("<i", raw, at+3)[0]
                        if target in literal_rvas:
                            candidates.add(first+at)
                        offset = at + 1
            for member in args.member:
                needle, offset = struct.pack("<I", member), 0
                while True:
                    at = raw.find(needle, offset)
                    if at < 0:
                        break
                    qualified = not args.byte_field_only
                    if args.byte_field_only:
                        for before in range(2, 5):
                            if at < before:
                                continue
                            ins = next(decoder.disasm(raw[at-before:at+8], first+at-before), None)
                            if ins and any(op.type == X86_OP_MEM and op.mem.disp == member and op.size == 1
                                           and op.mem.base not in (X86_REG_RBP, X86_REG_RSP)
                                           for op in ins.operands):
                                qualified = True
                    if qualified:
                        candidates.add(first + at)
                    offset = at + 1
            for target in args.target:
                offset = 0
                while True:
                    at = raw.find(b"\xe8", offset)
                    if at < 0 or at + 5 > size:
                        break
                    if first + at + 5 + struct.unpack_from("<i", raw, at + 1)[0] == target:
                        candidates.add(first + at)
                    offset = at + 1
        seen = set()
        for candidate in sorted(candidates):
            if image.containing(candidate) is None:
                continue
            try:
                fragments = function_fragments(image, candidate)
            except ValueError as error:
                print(json.dumps({"candidate": hex(candidate), "unresolved_extent": str(error)}))
                continue
            start, size = fragments[0][0], fragments[-1][1] - fragments[0][0]
            if start in seen:
                continue
            seen.add(start)
            code = b"".join(cache.read(at, min(8192, start + size - at))
                            for at in range(start, start + size, 8192))
            matches = []
            for ins in decoder.disasm(code, start):
                if any(op.type == X86_OP_MEM and op.mem.disp in args.member and (
                        not args.byte_field_only or op.size == 1 and op.mem.base not in (X86_REG_RBP, X86_REG_RSP))
                       for op in ins.operands) or any(
                        op.type == X86_OP_MEM and ins.address+ins.size+op.mem.disp in literal_rvas
                        for op in ins.operands) or (
                        ins.mnemonic == "call" and any(op.type == X86_OP_IMM and op.imm in args.target
                                                       for op in ins.operands)):
                    matches.append({"rva": hex(ins.address), "bytes": ins.bytes.hex(),
                                    "mnemonic": ins.mnemonic, "operands": ins.op_str})
            if matches:
                print(json.dumps({"start": hex(start), "bytes": size,
                                  "sha256": sha(code), "matches": matches}))
    print(json.dumps({"client_sha256": CLIENT_SHA, "manifest_sha256": MANIFEST_SHA,
                      "process_access": False, "game_launched": False,
                      "native_code_executed": False, "files_written": False}))


if __name__ == "__main__":
    main()
