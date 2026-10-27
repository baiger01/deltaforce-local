"""Disk-only panel receiver identity and virtual dispatch research."""
import json
import mmap
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
import research_f_dispatch_20261021 as dispatch
base = dispatch.base
OUT = base.ROOT / "work/evidence/gameplay-f-receiver-research-20261021.json"
base.OUT = OUT
BRANCHES = (
    (0x87EDE80, 0x87EE01D, 0x87E33D0, "call"),
    (0x87E33D0, 0x87E343F, 0x92D36D0, "call"),
    (0xCF95890, 0xCF958AE, 0x10EA6820, "call"),
    (0xCF958C0, 0xCF958DE, 0x10EA6820, "call"),
    (0xCDDE1A0, 0xCDDE1A0, 0x80698E0, "jmp"),
    (0x80698E0, 0x80698E0, 0xCDDE8F0, "jmp"),
    (0xCDDE6A0, 0xCDDE6AE, 0xBACE020, "jmp"),
    (0xBB92D70, 0xBB92E82, 0xCDE3B00, "call"),
    (0xCDE3B00, 0xCDE3B30, 0x10EAA0C0, "call"),
    (0x7753D0, 0x7753E4, 0x10B56070, "jmp"),
    (0xBBA44C0, 0xBBA484D, 0x60A4DA0, "call"),
    (0xBBA44C0, 0xBBA4855, 0x12704230, "call"),
    (0xBB4F500, 0xBB50237, 0xBB0E4A0, "call"),
    (0xCEBA830, 0xCEBA876, 0x10EAA0C0, "call"),
    (0x7AB700, 0x7AB714, 0x10B56070, "jmp"),
)
INSTRUCTIONS = (
    (0x87EDE80, 0x87EE00A, "lea", "rcx, [rdi + 0x318]"),
    (0x87EDE80, 0x87EE017, "mov", "rdx, rax"),
    (0x87E33D0, 0x87E3403, "mov", "r13, rdx"),
    (0x87E33D0, 0x87E340A, "mov", "rsi, rcx"),
    (0x87E33D0, 0x87E3429, "mov", "r8, rdx"),
    (0x87E33D0, 0x87E361F, "movups", "xmm0, xmmword ptr [rax + 0x18]"),
    (0x87E33D0, 0x87E3623, "movups", "xmmword ptr [rsi + 0x520], xmm0"),
    (0x87E33D0, 0x87E362A, "mov", "r15, qword ptr [rsi + 0x520]"),
    (0x87E33D0, 0x87E7178, "mov", "r14, qword ptr [rsi + 0x528]"),
    (0x87E33D0, 0x87E71D0, "mov", "dword ptr [rsi + 0x530], 2"),
    (0x87E33D0, 0x87E71DA, "mov", "qword ptr [rsi + 0x518], r14"),
    (0x878A400, 0x878B069, "mov", "rcx, qword ptr [rsi + 0x518]"),
    (0x878A400, 0x878B070, "mov", "r8, qword ptr [rsi + 0x540]"),
    (0x878A400, 0x878B077, "mov", "rdx, qword ptr [rsi + 0x538]"),
    (0x878A400, 0x878B081, "call", "qword ptr [rax + 0x490]"),
    (0xBACE020, 0xBACE044, "mov", "qword ptr [rbx], rax"),
    (0xBB92D70, 0xBB92E06, "mov", "r15, qword ptr [rsi + 0x1f8]"),
    (0xBB92D70, 0xBB92E6D, "mov", "r9, qword ptr [rsi + 0xe8]"),
    (0xBB92D70, 0xBB92E7A, "mov", "qword ptr [rsp + 0x20], rsi"),
    (0xBB92D70, 0xBB92E95, "call", "qword ptr [rax + 0x4a0]"),
    (0xCDE3B00, 0xCDE3B40, "call", "qword ptr [rbx + 0x220]"),
    (0xBBA44C0, 0xBBA4864, "lea", "rcx, [rdi + 0x320]"),
    (0xBBA44C0, 0xBBA498E, "mov", "r8, qword ptr [rbp + 0x80]"),
    (0xBBA44C0, 0xBBA4995, "mov", "rdx, r15"),
    (0xBBA44C0, 0xBBA499D, "mov", "rcx, rdi"),
    (0xBBA44C0, 0xBBA49CA, "call", "qword ptr [rax + 0x458]"),
    (0xBB4F500, 0xBB50359, "call", "qword ptr [rax + 0x8d0]"),
    (0xCEBA830, 0xCEBA886, "call", "qword ptr [rbx + 0x220]"),
)
POINTERS = (
    (0x1D22D780, 0x18814D90), (0x18814DA0, 0x18814CA0),
    (0x18814CC8, 0xCF958C0), (0x1D22D7D0, 0x18814EE8),
    (0x18814EE8, 0x18814E88), (0x18814EB0, 0xCDDE1A0),
    (0x16CDF490, 0xBB92D70), (0x16CDF4A0, 0xBBA44C0),
    (0x1A680290, 0xBB4E140), (0x1A680298, 0xBB4F500),
    (0x1A6802D0, 0xFFCE530), (0x1A680710, 0xCEBA830),
    (0x18700510, 0x60A7E30), (0x18700570, 0x1242AFD0),
    (0x187005A8, 0xCDDE1A0),
)
U32_VALUES = ((0x18814CC4, 0x18), (0x18814EAC, 8),
              (0x1D22D770, 0x40), (0x1D22D7C0, 0x10),
              (0x1870050C, 0x10), (0x1870056C, 8), (0x187005A4, 0),
              (0x1D1EA168, 0x48), (0x1D1EA180, 0x220CC0))
RIP_TARGETS = (
    (0xCF95890, 0xCF958A0, 0x1D22D750),
    (0xCF958C0, 0xCF958D0, 0x1D22D7A0),
    (0xBACE020, 0xBACE03D, 0x16CDF000),
    (0x7753D0, 0x7753D6, 0x185BE120),
    (0x7753D0, 0x7753DD, 0x1E0D7160),
    (0xCDE3B00, 0xCDE3B1A, 0x1E0D7160),
    (0x7AB700, 0x7AB706, 0x186FB5C0),
    (0x7AB700, 0x7AB70D, 0x1E0EA608),
    (0xCEBA830, 0xCEBA85C, 0x1E0EA608),
    (0xCEB6DB0, 0xCEB6DC0, 0x1D1EA140),
)
SAVED_RPC = base.PEER / "work/native-client-tests/1792548525430131600/world-interaction-rpc-metadata.json"


def saved_rpc_metadata():
    raw = SAVED_RPC.read_bytes()
    source = json.loads(raw)
    if source["client_sha256"] != "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0":
        raise ValueError("Saved RPC metadata build changed")
    owner, = (r for r in source["owners"] if r["scope"] == "InteractorComponent")
    cache = owner["existing_driver_class"]
    if owner["class_path"] != "/Script/SOL.SOLInteractorComponent" or cache["exclusive_index_maximum"] != 168:
        raise ValueError("Saved SOL owner identity or field maximum changed")
    names = {70: "ServerExecuteInteractableCompByTag", 71: "ServerExecuteInteractByTag", 72: "ServerInteractAction"}
    fields = [r for n in cache["cache_nodes"] for r in n["fields"] if r["rep_index"] in names]
    if len(fields) != 3 or any(r["descriptor_name"] != names[r["rep_index"]] or
                              r["descriptor_representation"] != 1 for r in fields):
        raise ValueError("Saved RPC field identity changed")
    layouts = [{k: r[k] for k in ("network_index", "function_name", "layout_status", "layout_table_read")}
               for r in owner["rpc_functions"]]
    return {"source": str(SAVED_RPC), "source_sha256": base.sha(raw),
        "qualification": "saved_nonatomic_metadata_only_no_current_process_access",
        "observed_at_utc": source["observed_at_utc"], "client_sha256": source["client_sha256"],
        "scope": owner["scope"], "class_path": owner["class_path"],
        "snapshot_atomic": cache["snapshot_atomic"], "exclusive_index_maximum": 168,
        "fields": fields, "exported_rpc_layout_observations": layouts,
        "field_70_function_rep_layout_exported": any(r["network_index"] == 70 for r in layouts)}


def saved_consumer_sources():
    result = []
    for relative, ranges in (
            ("work/portable_world_interact_request.py", ((94, 96), (144, 146), (160, 168))),
            ("work/portable_world_loot_dispatch.py", ((132, 157),))):
        path = base.PEER / relative
        raw = path.read_bytes()
        lines = raw.decode("utf-8").splitlines()
        result.append({"path": str(path), "sha256": base.sha(raw),
            "snippets": [{"first_line": first, "last_line": end,
                "lines": lines[first-1:end]} for first, end in ranges]})
    if "field.rep_index not in (71, 72)" not in result[0]["snippets"][2]["lines"][6]:
        raise ValueError("Pinned decoder field gate changed")
    if "interactions.decode_field(field" not in result[1]["snippets"][0]["lines"][9]:
        raise ValueError("Pinned loot dispatcher decoder call changed")
    return result


def writes(original, offsets, first, end):
    def collect(folder, manifest, game, functions, literals, calls):
        result = original(folder, manifest, game, functions, literals, calls)
        cache = base.CodeCache(folder, manifest, game)
        exe = game / cache.manifest["plan"]["client_relative_to_game_root"]
        rows = []
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
                        raise ValueError("Member writer search block changed")
                    checked += len(raw)
                    start = int(block["rva"], 16)-len(previous)
                    for offset in offsets:
                        pattern = rb"[\x40-\x4f]?[\x89\xc7][\x80-\xbf]" + re.escape(struct.pack("<I", offset))
                        for match in re.finditer(pattern, previous+raw):
                            at = start+match.start()
                            if not first <= at < end:
                                continue
                            entry = image.containing(at)
                            rows.append({"instruction_rva": hex(at), "member_offset": hex(offset),
                                "bytes": match.group().hex(), "pdata_function": hex(entry[0]) if entry else None,
                                "instruction_boundary_verified": False})
                    previous = raw[-8:]
        result["member_write_candidates"] = rows
        result["member_write_bytes_checked"] = checked
        result["member_write_search_rva_range"] = [hex(first), hex(end)]
        return result
    return collect


def verify():
    doc = json.loads(OUT.read_text("utf-8"))
    if doc["helper_sha256"] != base.sha(Path(__file__).read_bytes()):
        raise ValueError("Receiver helper changed")
    for path, digest in doc["collector_dependencies"].items():
        if base.sha(Path(path).read_bytes()) != digest:
            raise ValueError("Collector dependency changed")
    if doc["cache_manifest_sha256"] != base.MANIFEST:
        raise ValueError("Manifest identity changed")
    if doc.get("saved_rpc_metadata") != saved_rpc_metadata():
        raise ValueError("Saved RPC metadata evidence changed")
    if doc.get("saved_consumer_sources") != saved_consumer_sources():
        raise ValueError("Read-only consumer source evidence changed")
    for key in ("snapshot_is_atomic", "process_access", "game_launched", "packets_sent",
                "database_opened", "game_or_peer_written", "native_execution_claimed"):
        if doc[key] is not False:
            raise ValueError("Disk-only provenance changed")
    cache = base.CodeCache(base.CACHE, base.MANIFEST, base.GAME)
    functions, immutable, unwinds, records = {}, {}, {}, {}
    for query in doc["queries"].values():
        for fn in query.get("native", {}).get("functions", []):
            functions[(int(fn["span_start"], 16), fn["span_bytes"], fn["code_sha256"])] = fn
        for row in query.get("records", []):
            immutable[(int(row["rva"], 16), row["bytes"])] = row["sha256"]
        if row := query.get("immutable_string_section"):
            immutable[(int(row["rva"], 16), row["bytes"])] = row["sha256"]
        for row in query.get("native", {}).get("cache_records", []):
            records[(int(row["rva"], 16), row["bytes"])] = row
    by_start = {}
    for (start, size, digest), fn in functions.items():
        raw = b"".join(cache.read(at, min(8192, start+size-at)) for at in range(start, start+size, 8192))
        if base.sha(raw) != digest:
            raise ValueError("Native range changed")
        at, decoded = start, bytearray()
        for ins in fn["instructions"]:
            chunk = bytes.fromhex(ins["bytes"])
            if at != int(ins["rva"], 16) or not chunk:
                raise ValueError("Instruction boundary changed")
            at += len(chunk)
            decoded.extend(chunk)
        if bytes(decoded) != raw[:len(decoded)] or fn["decoded_bytes"] != len(decoded):
            raise ValueError("Native decode prefix changed")
        if fn["linear_decode_covers_extent"] is not (len(decoded) == size):
            raise ValueError("Decode extent qualification changed")
        by_start[start] = fn
        for row in fn["pdata_fragments"]:
            unwinds[(int(row["unwind_rva"], 16), row["metadata_bytes"])] = row["metadata_sha256"]
    exe = base.GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = base.ImmutableImage(data)
        for (first, size), digest in {**immutable, **unwinds}.items():
            if base.sha(image.read(first, size)) != digest:
                raise ValueError("Immutable record changed")
        for address, target in POINTERS:
            value, = struct.unpack("<Q", image.read(address, 8))
            if value-image.image_base != target:
                raise ValueError("Immutable pointer claim changed")
        for address, expected in U32_VALUES:
            if struct.unpack("<I", image.read(address, 4))[0] != expected:
                raise ValueError("Reflected layout claim changed")
    for (first, size), row in records.items():
        raw = cache.read(first, size)
        if base.sha(raw) != row["sha256"] or raw.hex() != row["hex"]:
            raise ValueError("Cache record changed")
    for caller, instruction, callee, mnemonic in BRANCHES:
        ins = next(i for i in by_start[caller]["instructions"] if i["rva"] == hex(instruction))
        if ins["mnemonic"] != mnemonic or ins.get("direct_target_rva") != hex(callee):
            raise ValueError("Direct branch claim changed")
    for function, address, mnemonic, operands in INSTRUCTIONS:
        ins = next(i for i in by_start[function]["instructions"] if i["rva"] == hex(address))
        if (ins["mnemonic"], ins["operands"]) != (mnemonic, operands):
            raise ValueError("Instruction claim changed")
    for function, address, target in RIP_TARGETS:
        ins = next(i for i in by_start[function]["instructions"] if i["rva"] == hex(address))
        raw = bytes.fromhex(ins["bytes"])
        if "[rip " not in ins["operands"] or address+len(raw)+struct.unpack("<i", raw[-4:])[0] != target:
            raise ValueError("RIP-relative target claim changed")
    print(json.dumps({"status": "PASS", "native_spans": len(functions),
        "unwind_records": len(unwinds), "immutable_records": len(immutable), "cache_records": len(records),
        "incomplete_linear_decode_spans": sum(not f["linear_decode_covers_extent"] for f in functions.values()),
        "direct_branches": len(BRANCHES), "instruction_claims": len(INSTRUCTIONS), "pointer_claims": len(POINTERS),
        "reflected_layout_claims": len(U32_VALUES), "rip_target_claims": len(RIP_TARGETS),
        "saved_rpc_metadata_sources": 1,
        "consumer_source_files": 2,
        "native_execution_claimed": False, "evidence_sha256": base.sha(OUT.read_bytes())}, indent=2))


if __name__ == "__main__":
    code_targets, members, spans, indirects, records, write_offsets = [], [], [], [], [], []
    first, end = 0, 0x20000000
    for flag, destination in (("--code-ref", code_targets), ("--member-lea", members),
                              ("--indirect-offset", indirects), ("--member-write", write_offsets)):
        while flag in sys.argv:
            index = sys.argv.index(flag)
            destination.append(int(sys.argv[index+1], 0))
            del sys.argv[index:index+2]
    for flag, destination in (("--span", spans), ("--cache-record", records)):
        while flag in sys.argv:
            index = sys.argv.index(flag)
            destination.append(tuple(int(v, 0) for v in sys.argv[index+1].split(":")))
            del sys.argv[index:index+2]
    if "--search-range" in sys.argv:
        index = sys.argv.index("--search-range")
        first, end = (int(v, 0) for v in sys.argv[index+1].split(":"))
        del sys.argv[index:index+2]
    base.analyze = dispatch.with_code_references(base.analyze, code_targets, members, spans, indirects, records)
    if write_offsets:
        base.analyze = writes(base.analyze, write_offsets, first, end)
    base.verify = verify
    base.main()
    if "--verify" not in sys.argv and "--view" not in sys.argv:
        doc = json.loads(OUT.read_text("utf-8"))
        doc["kind"] = "readonly_gameplay_f_receiver_research_20261021"
        doc["helper_sha256"] = base.sha(Path(__file__).read_bytes())
        doc["collector_dependencies"] = {str(Path(m.__file__)): base.sha(Path(m.__file__).read_bytes())
                                          for m in (base, dispatch)}
        doc["claims"] = {"direct_branches": [[hex(a), hex(b), hex(c), d] for a, b, c, d in BRANCHES],
            "instructions": [[hex(a), hex(b), c, d] for a, b, c, d in INSTRUCTIONS],
            "pointers": [[hex(a), hex(b)] for a, b in POINTERS]}
        doc["claims"]["u32_values"] = [[hex(a), hex(b)] for a, b in U32_VALUES]
        doc["claims"]["rip_targets"] = [[hex(a), hex(b), hex(c)] for a, b, c in RIP_TARGETS]
        doc["saved_rpc_metadata"] = saved_rpc_metadata()
        doc["saved_consumer_sources"] = saved_consumer_sources()
        OUT.write_text(json.dumps(doc, ensure_ascii=True, indent=2)+"\n", encoding="utf-8")
