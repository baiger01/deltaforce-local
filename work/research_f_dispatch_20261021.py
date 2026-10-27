"""Disk-only follow-up of F dispatch and box-to-search scheduling."""
import json
import mmap
import re
import struct
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import research_f_interaction_20261021 as base

OUT = base.ROOT / "work/evidence/gameplay-f-dispatch-research-20261021.json"
base.OUT = OUT

BRANCHES = (
    (0x4e11180, 0x4e111e7, 0x517bd10, "call"),
    (0x4e11180, 0x4e111f4, 0x32e4000, "call"),
    (0x4e11180, 0x4e1120d, 0xd96400, "call"),
    (0x4d88580, 0x4d8d110, 0x4cea1f0, "call"),
    (0x4d88580, 0x4d8d16e, 0x4cea1f0, "call"),
    (0x601c390, 0x601c3a5, 0x4d1ec10, "jmp"),
    (0x601c3b0, 0x601c3c5, 0x4d1ecc0, "jmp"),
    (0xcdd6130, 0xcdd613e, 0xb6a8f40, "jmp"),
    (0xb6cec60, 0xb6cee32, 0x4d13e20, "jmp"),
    (0x4d9a920, 0x4d9c249, 0x4d48710, "call"),
    (0x87ae820, 0x87ae9cd, 0xe6e8e0, "call"),
    (0x87ae820, 0x87aea85, 0xe6e8e0, "call"),
    (0xb6e68a0, 0xb6e788c, 0x73fee20, "call"),
    (0xb6e68a0, 0xb6e8245, 0x73fee20, "call"),
    (0xb6e68a0, 0xb6e825c, 0xd96400, "call"),
    (0x9359990, 0x93599f9, 0x87c4ef0, "call"),
    (0x9359a10, 0x9359a79, 0x87c5260, "call"),
    (0x87c4ef0, 0x87c512b, 0x8789110, "call"),
    (0x87c5260, 0x87c5485, 0x8789f80, "call"),
    (0xb481ee0, 0xb483bfd, 0xc1f6750, "call"),
    (0xc1db360, 0xc1dba20, 0xc1f6750, "call"),
    (0xc1c9040, 0xc1c936e, 0xbfd05e0, "call"),
)
INSTRUCTIONS = (
    (0x4e11180, 0x4e111f1, "mov", "rcx, rbx"),
    (0x4e11180, 0x4e11206, "lea", "rcx, [rax + 0x648]"),
    (0x4d88580, 0x4d8d0ba, "lea", "rax, [rip - 0x6e4b1]"),
    (0x4d88580, 0x4d8d0f7, "mov", "r9d, 0x8f"),
    (0x4d88580, 0x4d8d102, "xor", "r8d, r8d"),
    (0x4d88580, 0x4d8d115, "lea", "rax, [rip - 0x6e45c]"),
    (0x4d88580, 0x4d8d152, "mov", "r9d, 0x90"),
    (0x4d88580, 0x4d8d15d, "mov", "r8d, 1"),
    (0x4d1ec10, 0x4d1ec66, "mov", "edx, 0x8f"),
    (0x4d1ec10, 0x4d1ec71, "call", "qword ptr [rax + 0x438]"),
    (0x4d1ecc0, 0x4d1ed16, "mov", "edx, 0x90"),
    (0x4d1ecc0, 0x4d1ed21, "call", "qword ptr [rax + 0x438]"),
    (0xb6a8f40, 0xb6a8f58, "lea", "rax, [rip + 0xc4533b9]"),
    (0xb6a8f40, 0xb6a8f5f, "mov", "qword ptr [rbx], rax"),
    (0x4d13e20, 0x4d13ea3, "movsxd", "rsi, dword ptr [rdi + 0x4b8]"),
    (0x4d13e20, 0x4d13ec9, "lea", "rcx, [rdi + 0x4b0]"),
    (0x4d13e20, 0x4d13f0a, "mov", "word ptr [rax + rsi*2], cx"),
    (0x4d9a920, 0x4d9ab49, "lea", "r12, [r15 + 0x4b0]"),
    (0x4d48710, 0x4d49fcc, "movzx", "eax, byte ptr [r8 + rax + 0x4d4c120]"),
    (0x4d48710, 0x4d49fd5, "mov", "ecx, dword ptr [r8 + rax*4 + 0x4d4bdfc]"),
    (0x4d48710, 0x4d49fe0, "jmp", "rcx"),
    (0x4d48710, 0x4d4b2b3, "call", "qword ptr [rax + 0x6d8]"),
    (0xb6e68a0, 0xb6e6e01, "mov", "eax, 0x8f"),
    (0xb6e68a0, 0xb6e789d, "mov", "eax, 0x90"),
    (0xb6e68a0, 0xb6e7891, "lea", "rcx, [rax + 0x1fa8]"),
    (0xb6e68a0, 0xb6e824a, "lea", "rcx, [rax + 0x1fb8]"),
    (0xb6e68a0, 0xb6e8255, "mov", "dword ptr [rbp + 0x67], 1"),
    (0x87ae820, 0x87ae91c, "lea", "rax, [rip + 0x165cd]"),
    (0x87ae820, 0x87ae9bf, "lea", "rcx, [rbx + 0x1fa8]"),
    (0x87ae820, 0x87ae9d2, "lea", "rax, [rip + 0x16887]"),
    (0x87ae820, 0x87aea77, "lea", "rcx, [rbx + 0x1fb8]"),
    (0x87c4ef0, 0x87c5123, "cmp", "eax, 1"),
    (0x87c5260, 0x87c547d, "cmp", "eax, 1"),
    (0xd96400, 0xd96553, "call", "qword ptr [r9 + 0x220]"),
)
POINTERS = ((0x17afc750, 0xb6cec60), (0x17afc9f0, 0xb6e68a0),
            (0x175e74d0, 0x1735f630), (0x175e74d8, 0x9359990),
            (0x175e74e0, 0x1735f848), (0x175e74e8, 0x9359a10))


def with_code_references(original, targets, members=(), spans=(), indirects=(), records=()):
    def collect(folder, manifest, game, functions, literals, calls):
        result = original(folder, manifest, game, functions, literals, calls,
                          member_offsets=members, spans=spans)
        from offline_received_packet_xrefs import literal_candidates
        cache = base.CodeCache(folder, manifest, game)
        if records:
            result["cache_records"] = []
            for first, size in records:
                if not 0 < size <= 8192:
                    raise ValueError("Use a bounded cache data record")
                raw = cache.read(first, size)
                result["cache_records"].append({"rva": hex(first), "bytes": size,
                    "sha256": base.sha(raw), "hex": raw.hex()})
        if not targets and not indirects:
            return result
        exe = game / cache.manifest["plan"]["client_relative_to_game_root"]
        rows = []
        indirect_rows = []
        checked = 0
        with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            image = base.ImmutableImage(data)
            for section in cache.manifest["sections"]:
                previous = b""
                for block in section["blocks"]:
                    if not block["available"]:
                        previous = b""
                        continue
                    raw = (cache.folder / block["file"]).read_bytes()
                    if len(raw) != block["bytes"] or base.sha(raw) != block["code_sha256"]:
                        raise ValueError("Code-reference search block changed")
                    checked += len(raw)
                    first = int(block["rva"], 16)-len(previous)
                    for at, target, encoded in literal_candidates(previous+raw, first, set(targets)):
                        entry = image.containing(at)
                        rows.append({"instruction_rva": hex(at), "target_rva": hex(target),
                            "bytes": encoded.hex(), "pdata_function": hex(entry[0]) if entry else None,
                            "instruction_boundary_verified": False})
                    for offset in indirects:
                        pattern = rb"\xff[\x90-\x97]" + re.escape(struct.pack("<I", offset))
                        for match in re.finditer(pattern, previous+raw):
                            at = first+match.start()
                            entry = image.containing(at)
                            indirect_rows.append({"instruction_rva": hex(at), "member_offset": hex(offset),
                                "bytes": match.group().hex(), "pdata_function": hex(entry[0]) if entry else None,
                                "instruction_boundary_verified": False})
                    previous = raw[-6:]
        result["code_reference_candidates"] = rows
        result["indirect_call_candidates"] = indirect_rows
        result["code_reference_bytes_checked"] = checked
        return result
    return collect


def verify():
    doc = json.loads(OUT.read_text("utf-8"))
    if doc["helper_sha256"] != base.sha(Path(__file__).read_bytes()):
        raise ValueError("Follow-up helper identity changed")
    if doc["cache_manifest_sha256"] != base.MANIFEST:
        raise ValueError("Cache manifest identity changed")
    if doc["collector_dependency_sha256"] != base.sha(Path(base.__file__).read_bytes()):
        raise ValueError("Base collector source changed")
    for key in ("snapshot_is_atomic", "process_access", "game_launched", "packets_sent",
                "database_opened", "game_or_peer_written", "native_execution_claimed"):
        if doc[key] is not False:
            raise ValueError("Disk-only provenance changed: " + key)
    cache = base.CodeCache(base.CACHE, base.MANIFEST, base.GAME)
    if doc["client_sha256"] != cache.manifest["client_sha256"]:
        raise ValueError("Executable identity changed")
    functions, immutable, unwinds, cache_records = {}, {}, {}, {}
    for query in doc["queries"].values():
        for fn in query.get("native", {}).get("functions", []):
            functions[(int(fn["span_start"], 16), fn["span_bytes"], fn["code_sha256"])] = fn
        for row in query.get("records", []):
            immutable[(int(row["rva"], 16), row["bytes"])] = row["sha256"]
        row = query.get("immutable_string_section")
        if row:
            immutable[(int(row["rva"], 16), row["bytes"])] = row["sha256"]
        for row in query.get("native", {}).get("cache_records", []):
            cache_records[(int(row["rva"], 16), row["bytes"])] = row
    by_start = {}
    for (start, size, digest), fn in functions.items():
        raw = b"".join(cache.read(at, min(8192, start+size-at))
                       for at in range(start, start+size, 8192))
        if base.sha(raw) != digest:
            raise ValueError("Native identity changed: " + hex(start))
        at, decoded = start, bytearray()
        for ins in fn["instructions"]:
            chunk = bytes.fromhex(ins["bytes"])
            if int(ins["rva"], 16) != at or not chunk:
                raise ValueError("Instruction boundary changed")
            at += len(chunk)
            decoded.extend(chunk)
        if bytes(decoded) != raw[:len(decoded)] or fn["decoded_bytes"] != len(decoded):
            raise ValueError("Linear decode prefix does not match cache")
        if fn["linear_decode_covers_extent"] is not (len(decoded) == size):
            raise ValueError("Linear decode extent qualification changed")
        by_start[start] = fn
        for row in fn["pdata_fragments"]:
            unwinds[(int(row["unwind_rva"], 16), row["metadata_bytes"])] = row["metadata_sha256"]
    exe = base.GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    for (first, size), row in cache_records.items():
        raw = cache.read(first, size)
        if base.sha(raw) != row["sha256"] or raw.hex() != row["hex"]:
            raise ValueError("Cache data record changed")
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = base.ImmutableImage(data)
        for (start, size), digest in {**immutable, **unwinds}.items():
            if base.sha(image.read(start, size)) != digest:
                raise ValueError("Immutable metadata changed: " + hex(start))
        for address, target in POINTERS:
            actual, = struct.unpack("<Q", image.read(address, 8))
            if actual-image.image_base != target:
                raise ValueError("Claimed immutable pointer changed")
    claims = doc.get("verified_claims", {})
    for row in claims.get("branches", []):
        fn = by_start[int(row["caller"], 16)]
        ins = next(i for i in fn["instructions"] if i["rva"] == row["instruction"])
        if ins["mnemonic"] != row["mnemonic"] or ins.get("direct_target_rva") != row["callee"]:
            raise ValueError("Direct branch claim changed")
    for row in claims.get("instructions", []):
        fn = by_start[int(row["function"], 16)]
        ins = next(i for i in fn["instructions"] if i["rva"] == row["rva"])
        if (ins["mnemonic"], ins["operands"]) != (row["mnemonic"], row["operands"]):
            raise ValueError("Instruction claim changed")
    action_map = cache.read(0x4d4c120, 0x182)
    jump_table = cache.read(0x4d4bdfc, 0x324)
    for action in (0x8f, 0x90):
        index = action_map[action-1]
        target, = struct.unpack_from("<I", jump_table, index*4)
        if (index, target) != (70, 0x4d4b2a9):
            raise ValueError("Interact action switch route changed")
    print(json.dumps({"status": "PASS", "native_spans": len(functions),
        "immutable_records_and_sections": len(immutable), "unwind_records": len(unwinds),
        "incomplete_linear_decode_spans": sum(not f["linear_decode_covers_extent"] for f in functions.values()),
        "cache_data_records": len(cache_records), "pointer_claims": len(POINTERS), "switch_routes": 2,
        "direct_branch_claims": len(claims.get("branches", [])),
        "instruction_claims": len(claims.get("instructions", [])),
        "native_execution_claimed": False, "evidence_sha256": base.sha(OUT.read_bytes())}, indent=2))


if __name__ == "__main__":
    code_targets = []
    members = []
    spans = []
    indirects = []
    records = []
    while "--code-ref" in sys.argv:
        index = sys.argv.index("--code-ref")
        code_targets.append(int(sys.argv[index+1], 0))
        del sys.argv[index:index+2]
    while "--code-range" in sys.argv:
        index = sys.argv.index("--code-range")
        first, end = (int(v, 0) for v in sys.argv[index+1].split(":"))
        if first % 8 or end % 8 or not 0 < end-first <= 8192:
            raise ValueError("Use a bounded aligned immutable pointer range")
        code_targets.extend(range(first, end, 8))
        del sys.argv[index:index+2]
    while "--member-lea" in sys.argv:
        index = sys.argv.index("--member-lea")
        members.append(int(sys.argv[index+1], 0))
        del sys.argv[index:index+2]
    while "--span" in sys.argv:
        index = sys.argv.index("--span")
        spans.append(tuple(int(v, 0) for v in sys.argv[index+1].split(":")))
        del sys.argv[index:index+2]
    while "--indirect-offset" in sys.argv:
        index = sys.argv.index("--indirect-offset")
        indirects.append(int(sys.argv[index+1], 0))
        del sys.argv[index:index+2]
    while "--cache-record" in sys.argv:
        index = sys.argv.index("--cache-record")
        records.append(tuple(int(v, 0) for v in sys.argv[index+1].split(":")))
        del sys.argv[index:index+2]
    if code_targets or members or spans or indirects or records:
        base.analyze = with_code_references(base.analyze, code_targets, members, spans, indirects, records)
    base.verify = verify
    base.main()
    if "--verify" not in sys.argv and "--view" not in sys.argv:
        doc = json.loads(OUT.read_text("utf-8"))
        doc["kind"] = "readonly_gameplay_f_dispatch_research_20261021"
        doc["helper_sha256"] = base.sha(Path(__file__).read_bytes())
        doc["collector_dependency_sha256"] = base.sha(Path(base.__file__).read_bytes())
        doc["verified_claims"] = {
            "branches": [{"caller": hex(a), "instruction": hex(b), "callee": hex(c), "mnemonic": d}
                         for a, b, c, d in BRANCHES],
            "instructions": [{"function": hex(a), "rva": hex(b), "mnemonic": c, "operands": d}
                             for a, b, c, d in INSTRUCTIONS],
            "immutable_pointers": [{"address": hex(a), "target_rva": hex(b)} for a, b in POINTERS],
            "action_switch": {"map_rva": "0x4d4c120", "jump_table_rva": "0x4d4bdfc",
                "routes": [{"action": hex(a), "map_index": 70, "target_rva": "0x4d4b2a9"}
                           for a in (0x8f, 0x90)]}}
        OUT.write_text(json.dumps(doc, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
