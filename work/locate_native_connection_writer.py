"""Offline exact SendRawBunch-log xrefs in a complete private code cache.

No process, kernel API, launcher, SDK, heap, or live-vtable access.
Byte-pattern candidates become evidence only at reachable instruction boundaries
inside a source-pinned .pdata root. Cache coverage is not a decryption claim.
"""
import argparse
from bisect import bisect_right
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from read_native_control_code import Image
from snapshot_native_image_code import validate_plan, SOURCE_SHA, TOTAL_BYTES, KNOWN_SENDERS

ROOT = Path(__file__).resolve().parent.parent
CACHE_ROOT = ROOT / "work/native-code-cache"
ANCHOR_PATH = ROOT / "work/evidence/native-connection-writer-static-anchors.json"
ANCHOR_SHA = "c3186d68f11a0f7626f889b09d751f600278cd293714677df1cba65be0727834"
PDATA_SHA = "aae32c4f1cc7196c7a2b78a4adc4e5dae29e5a200ad7415ab2ed69f06cd70d5e"
TARGET_RVA = 0x1b1d9810
TARGET_BYTES = 132
TARGET_SHA = "3a47f7f1859c1f7aa4c06bbaacf28fd5433ae892e01118255dac03e8eb132e3a"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CANDIDATES = 64
LEA_PATTERN = re.compile(rb"\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}", re.S)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_int(value):
    return type(value) is int


def validate_manifest(manifest, plan):
    """Pure schema/coverage checks, never imports or calls process functions."""
    if (manifest.get("kind") != "private_file_backed_executable_code_cache" or
            manifest.get("status") != "code_cache_complete" or
            manifest.get("complete") is not True or
            manifest.get("scope_coverage_complete") is not True or
            manifest.get("client_sha256") != SOURCE_SHA or manifest.get("plan") != plan):
        raise ValueError("A complete source-pinned code-cache manifest is required")
    for key in ("process_memory_written", "live_data_object_read", "original_game_modified",
                "reconstructed_executable", "native_complete_decode_claimed"):
        if manifest.get(key) is not False:
            raise ValueError("Cache qualification flag mismatch")
    sections = manifest.get("sections")
    if not isinstance(sections, list) or len(sections) != len(plan["sections"]):
        raise ValueError("Exact executable section coverage required")
    blocks = []
    for section, expected in zip(sections, plan["sections"]):
        first, length = int(expected["rva"], 16), expected["file_backed_code_bytes"]
        if (section.get("index") != expected["index"] or section.get("rva") != expected["rva"] or
                section.get("bytes") != length or section.get("available_bytes") != length or
                section.get("unavailable_bytes") != 0 or not isinstance(section.get("blocks"), list)):
            raise ValueError("Section coverage metadata mismatch")
        cursor = first
        for row in section["blocks"]:
            amount = row.get("bytes")
            if (not strict_int(amount) or not 0 < amount <= plan["maximum_RPM_bytes"] or
                    row.get("rva") != hex(cursor) or row.get("available") is not True or
                    cursor + amount > first + length or
                    not re.fullmatch("[0-9a-f]{64}", str(row.get("code_sha256", ""))) or
                    row.get("file") != f'section_{expected["index"]:02d}_rva_{cursor:08x}.code'):
                raise ValueError("Code block bounds, hash, or filename mismatch")
            blocks.append((cursor, amount, row["file"], row["code_sha256"]))
            cursor += amount
        if cursor != first + length:
            raise ValueError("Missing executable code interval")
    if (len(blocks) > plan["maximum_region_split_RPM_count"] or
            manifest.get("actual_RPM_count") != len(blocks) or
            manifest.get("RPM_requested_bytes") != TOTAL_BYTES or
            manifest.get("saved_code_bytes") != TOTAL_BYTES or manifest.get("unavailable_bytes") != 0):
        raise ValueError("Cache total read/coverage accounting mismatch")
    comparisons = manifest.get("known_sender_comparisons")
    if not isinstance(comparisons, list) or len(comparisons) != len(KNOWN_SENDERS):
        raise ValueError("Saved-native sender comparisons required")
    for row, (name, rva, length, digest) in zip(comparisons, KNOWN_SENDERS):
        if (row.get("name") != name or row.get("rva") != hex(rva) or row.get("bytes") != length or
                row.get("available") is not True or row.get("extra_live_reads") != 0 or
                row.get("matches_saved_native_sample") is not True or
                row.get("expected_code_sha256") != digest or row.get("cache_code_sha256") != digest):
            raise ValueError("Known native sender identity mismatch")
    return blocks


class Cache:
    def __init__(self, folder, plan):
        self.folder = Path(folder).resolve()
        if self.folder.parent != CACHE_ROOT.resolve() or not self.folder.is_dir():
            raise ValueError("Cache must be a single private cache child directory")
        path = self.folder / "manifest.json"
        if not 0 < path.stat().st_size <= MAX_MANIFEST_BYTES:
            raise ValueError("Manifest size out of bounds")
        payload = path.read_bytes()
        self.manifest_sha = sha(payload)
        self.manifest = json.loads(payload)
        self.blocks = validate_manifest(self.manifest, plan)
        self.starts = [row[0] for row in self.blocks]

    def block(self, row):
        _, length, filename, expected = row
        path = self.folder / filename
        if path.resolve().parent != self.folder or path.stat().st_size != length:
            raise ValueError("Code block escapes private cache or has wrong length")
        data = path.read_bytes()
        if sha(data) != expected:
            raise ValueError("Code block SHA mismatch")
        return data

    def read(self, rva, length):
        if not strict_int(length) or length <= 0:
            raise ValueError("Positive code length required")
        cursor, end, result = rva, rva + length, bytearray()
        while cursor < end:
            index = bisect_right(self.starts, cursor) - 1
            if index < 0:
                raise ValueError("Code RVA is not covered")
            row = self.blocks[index]
            if not row[0] <= cursor < row[0] + row[1]:
                raise ValueError("Code read crosses an excluded image interval")
            high = min(end, row[0] + row[1])
            data = self.block(row)
            result.extend(data[cursor-row[0]:high-row[0]])
            cursor = high
        return bytes(result)

    def exact_lea_candidates(self):
        candidates, previous_end, tail = [], None, b""
        for row in self.blocks:
            data = self.block(row)
            if previous_end != row[0]:
                tail = b""
            combined, start = tail + data, row[0] - len(tail)
            for match in LEA_PATTERN.finditer(combined):
                starts = [match.start()]
                if match.start() and 0x40 <= combined[match.start()-1] <= 0x4f:
                    starts.insert(0, match.start()-1)
                for at in starts:
                    instruction = combined[at:match.end()]
                    rva = start + at
                    target = rva + len(instruction) + struct.unpack("<i", instruction[-4:])[0]
                    candidate = {"rva": rva, "bytes": instruction.hex()}
                    if target == TARGET_RVA and candidate not in candidates:
                        candidates.append(candidate)
                        if len(candidates) > MAX_CANDIDATES:
                            raise ValueError("Exact anchor candidate budget exceeded")
            previous_end, tail = row[0]+row[1], data[-6:]
        return candidates


def root_for_instruction(image, rva):
    low, high = 0, image.unwind_count
    while low < high:
        middle = (low+high)//2
        if image.unwind_entry(middle)[0] <= rva:
            low = middle+1
        else:
            high = middle
    if low == 0:
        raise ValueError("Candidate has no containing unwind fragment")
    entry = image.unwind_entry(low-1)
    if not entry[0] <= rva < entry[1]:
        raise ValueError("Candidate is outside .pdata fragments")
    visited = set()
    for _ in range(32):
        if entry in visited:
            raise ValueError("Unwind parent cycle")
        visited.add(entry)
        head = image.data(entry[2], 4)
        flags, count = head[0], head[2]
        if flags & 7 != 1:
            raise ValueError("Unsupported unwind version")
        if flags >> 3 & 4:
            if flags >> 3 != 4:
                raise ValueError("Mixed chained unwind flags")
            parent = struct.unpack("<III", image.data(entry[2]+4+4*((count+1)//2), 12))
            lo, hi = 0, image.unwind_count
            while lo < hi:
                mid = (lo+hi)//2
                if image.unwind_entry(mid)[0] < parent[0]:
                    lo = mid+1
                else:
                    hi = mid
            if lo >= image.unwind_count or image.unwind_entry(lo) != parent:
                raise ValueError("Unwind parent is not an exact immutable entry")
            entry = parent
        else:
            root, length, fragments = image.function_span(entry[0])
            if not any(a <= rva < b for a, b in fragments):
                raise ValueError("Candidate does not belong to resolved contiguous root")
            return root, length, fragments
    raise ValueError("Unwind parent budget exceeded")


def reachable_instructions(code, root):
    """Decode only root-reachable direct CFG paths; no speculative jump-table targets."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    pending, decoded, occupied, limitations = [root], {}, {}, []
    end = root + len(code)
    while pending:
        address = pending.pop()
        if not root <= address < end or address in decoded:
            continue
        if address in occupied:
            raise ValueError("CFG target enters the middle of a decoded instruction")
        instruction = next(decoder.disasm(code[address-root:], address, count=1), None)
        if instruction is None or instruction.address + instruction.size > end:
            limitations.append({"rva": hex(address), "reason": "invalid_or_truncated_instruction"})
            continue
        if any(byte in occupied for byte in range(address, address+instruction.size)):
            raise ValueError("Overlapping native instruction paths")
        decoded[address] = instruction
        for byte in range(address, address+instruction.size):
            occupied[byte] = address
        if instruction.group(capstone.CS_GRP_RET) or instruction.mnemonic in ("int3", "ud2"):
            continue
        next_address = address + instruction.size
        if instruction.group(capstone.CS_GRP_JUMP):
            operand = instruction.operands[0] if len(instruction.operands) == 1 else None
            if operand is not None and operand.type == X86_OP_IMM:
                if root <= operand.imm < end:
                    pending.append(operand.imm)
            else:
                limitations.append({"rva": hex(address), "reason": "indirect_branch_not_followed"})
            if instruction.mnemonic != "jmp":
                pending.append(next_address)
        else:
            pending.append(next_address)
    return decoded, limitations


def analyze(game_root, cache_folder, output_dir):
    plan = validate_plan(game_root)
    anchor_bytes = ANCHOR_PATH.read_bytes()
    if sha(anchor_bytes) != ANCHOR_SHA:
        raise ValueError("Static anchor evidence SHA mismatch")
    cache = Cache(cache_folder, plan)
    output = Path(output_dir).resolve()
    if output.parent != (ROOT/"work/evidence").resolve() or output.exists():
        raise ValueError("Output must be a new direct evidence child directory")
    executable = Path(game_root)/plan["client_relative_to_game_root"]
    report = {"kind": "offline_exact_connection_writer_log_xrefs", "client_sha256": SOURCE_SHA,
              "cache_manifest_sha256": cache.manifest_sha, "cache": cache.folder.relative_to(ROOT).as_posix(),
              "anchor_evidence_sha256": ANCHOR_SHA, "log_rva": hex(TARGET_RVA), "log_sha256": TARGET_SHA,
              "process_accessed": False, "live_heap_or_vtable_read": False,
              "runtime_instance_class_or_vptr_verified": False, "wire_format_verified": False,
              "playable_map_verified": False, "byte_candidates": [], "native_roots": []}
    with executable.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        if sha(raw) != SOURCE_SHA:
            raise ValueError("Immutable PE changed during offline analysis")
        image = Image(raw)
        pdata = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if (pdata.VirtualAddress, pdata.Size) != (0x1e5d1000, 15300936) or sha(image.data(pdata.VirtualAddress, pdata.Size)) != PDATA_SHA:
            raise ValueError("Immutable unwind directory pin mismatch")
        if sha(image.data(TARGET_RVA, TARGET_BYTES)) != TARGET_SHA:
            raise ValueError("Exact writer-log pin mismatch")
        candidates = cache.exact_lea_candidates()
        roots = {}
        for candidate in candidates:
            row = {"rva": hex(candidate["rva"]), "bytes": candidate["bytes"], "reachable_instruction_boundary_verified": False}
            report["byte_candidates"].append(row)
            try:
                root, length, fragments = root_for_instruction(image, candidate["rva"])
                if root[0] not in roots:
                    code = cache.read(root[0], length)
                    decoded, limitations = reachable_instructions(code, root[0])
                    roots[root[0]] = (root, fragments, code, decoded, limitations)
                _, _, code, decoded, _ = roots[root[0]]
                instruction = decoded.get(candidate["rva"])
                if (instruction is None or instruction.mnemonic != "lea" or
                        bytes(instruction.bytes).hex() != candidate["bytes"] or
                        not any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and
                                instruction.address+instruction.size+op.mem.disp == TARGET_RVA
                                for op in instruction.operands)):
                    row["reason"] = "not_a_confirmed_root_reachable_exact_log_LEA"
                    continue
                row.update(reachable_instruction_boundary_verified=True, root_rva=hex(root[0]),
                           assembly=instruction.mnemonic+" "+instruction.op_str)
            except ValueError as error:
                row["reason"] = str(error)
        output.mkdir()
        for rva, (root, fragments, code, decoded, limitations) in sorted(roots.items()):
            confirmed = [row for row in report["byte_candidates"] if row.get("root_rva") == hex(rva)]
            if not confirmed:
                continue
            stem = f"writer_log_root_{rva:08x}"
            payload = struct.pack("<4Q", 0x145444344, rva, len(code), image.base)+code
            (output/(stem+".dfcode")).write_bytes(payload)
            text = [f"{i.address:08x} {bytes(i.bytes).hex():24s} {i.mnemonic} {i.op_str}" for i in sorted(decoded.values(), key=lambda i:i.address)]
            (output/(stem+".cfg.asm.txt")).write_text("\n".join(text)+"\n", encoding="utf-8")
            report["native_roots"].append({"root": list(map(hex,root)), "fragments": [list(map(hex,f)) for f in fragments],
                "complete_metadata_span_bytes": len(code), "complete_native_span_saved": True,
                "code_sha256": sha(code), "file_sha256": sha(payload), "file": stem+".dfcode",
                "header_base_is_preferred_PE_base_not_live_module_base": True,
                "root_reachable_instruction_count": len(decoded), "CFG_limitations": limitations,
                "confirmed_log_references": confirmed, "role_evidence": "Exact root-reachable UNetConnection::SendRawBunch logging instruction",
                "actual_connection_static_table_ownership_verified": False})
    (output/"result.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-root", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.game_root, args.cache, args.output_dir)
    print(json.dumps({"confirmed_native_roots": len(result["native_roots"]),
                      "exact_byte_candidates": len(result["byte_candidates"]),
                      "process_accessed": False}))
