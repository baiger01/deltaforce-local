"""Disk-only bounded skill serializer source queries; output is stdout JSON."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

PEER = Path("E:/新建文件夹/DSH/deltaforce-map-appearance")
GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = PEER / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
HELPERS = {
    "portable_native_code_cache.py": "2372b9603d6d6e12a3afc57ac1765f8aaca408d0c2794a8d81eaec3337fa399e",
    "analyze_portable_native_code.py": "c08ed72d4969f43178de962b836a62fb472d23beb11ac01a7f7269f8792eeafd",
    "offline_received_packet_xrefs.py": "4151dd221d6ad09bd83cebdb2ab2016e688aa05624727488ac8fbfc5f500ed77",
    "snapshot_native_image_code.py": "62405c35a3839d5eb67cf2cdde41606d6a82f2501fd84d7b3671adec864e15ae",
}

CONTRACT_CODE_PINS = (
    (0x10EA6330, 956, "63ea432a3f842fd97b42cfd6db9e551a9c412b7e4a2234a0784c5d985c7bc897"),
    (0x10EA6820, 491, "d0216ff87aae5de8488f49709df7602022835fdbb62050c4fc743696f3b6aec6"),
    (0x10CF6370, 302, "26bc1635c74d46c1926c4141dd6f613209a992f3938b0f41e3cd9540524a5e6d"),
    (0x10D03CB0, 2849, "0d9966373ca481bae56f9fc7c925991660ad667eaa3a0f03856b1a524baa7fc3"),
    (0x10CF7980, 13, "8b1e309a8c8c68fc15228cb4f840e49537f6ee9d3438c27d7de9e8b79d6d3407"),
    (0x10E3E530, 251, "fec9ee253c30d2765d0c95e8a7c173829e0b863a0e61e66600aaf7384c9ccf22"),
    (0x10EA37F0, 160, "37efb0e0113534e4431a60a105a281256ce8e2eecd82f11f0a756b334bd5e881"),
    (0x10EA3A58, 209, "5a8bc0b156231c70a683ab5a56e2df76c71681b427035df1388ad14907414317"),
    (0x10EA41AA, 341, "6bb8c9846aee1f774657aecc7417b0404d2fe4621729570d9b610c3b9a766f97"),
    (0x10EA4401, 258, "8183d6839f7c531442e44a1aa2f133c5b71deb9a53c95d5b3719e244c9987f99"),
    (0x10EA50EB, 229, "cb18cb98617c68d99e8f4c00912336b889704fd96561dfb4b18cf07a57ed665f"),
    (0x12DB2CB0, 838, "109d3a2cbbcaaf4b58494c2f68628595c343d2c1a2b6c62b93b7c8754968acc6"),
    (0x12D9B1E0, 1047, "ef0130a4bf816617cf188fc566c5502ec3471c9dd69ecd5e92d5752350583d69"),
    (0x4A24E50, 1155, "0e63c118d5d5bf1326030e3b7eba58754b886489a5b0c26032ccdf6a70539a93"),
    (0x12DC23F0, 499, "a062bf2c85124dcd4191b2530ea3917f992c3800f042cbba8e0378b141dbe187"),
    (0x10E8EBE0, 106, "de22cc24de8a11838462d7977b4b8b8f0ce41d601e8b4902ca113fb06fe5e009"),
    (0x10E8ED20, 193, "d9eaa90e1b5f244ffcd5913f4a2b2d829f1db277bd7e7c73b946f2cf178ec666"),
    (0x10E8E960, 308, "35733fc8ddc202cf747fdf5baaddcc037e23f8eab95fbacc03e4cb58be7f03eb"),
    (0x10D02490, 536, "e9564ce3b255a42839c37f392d0aba3e1e3a2006661d584986b7c68fd4d2c51a"),
    (0x10D026B0, 1973, "636287e1fb8bcd8bdaaeb542591e182476e46efb187b1750a11efb37354f84db"),
    (0x10CF8E80, 461, "768becf3b5888a00c846a12174a831e8564bdb226ee325a00a8ad15e197f901b"),
    (0x60804A0, 163, "7f9ad16d2a261b104838d09f12cdc56a6cd6468a175bf05d07df2e65a76cfe9f"),
    (0x109929F0, 59, "d04267aa1f3ccc071a45286c3132905f46d42aafcd5182a7762ad45f02a80cf1"),
    (0x12893300, 256, "f2d9e3f21d7321e46826373b6900164a5010199b36988e857666cf88901aa7de"),
    (0x10E272C0, 96, "33ec326ab4661f8c5bfc230b833a43f4a08c7e11c0e3f9b9087b248a8b15b4eb"),
    (0x128932E9, 26, "db2880cdc30257b91b892eeb7442461df574255016134d2472da6c95c6a35f92"),
    (0x10D01A10, 165, "c95354963c9836b97b133b2804f93e9f79841524e334c17ab633ed123bb4f308"),
    (0x10E70F20, 180, "d5583ad046141937f0101e74316c3e91f8ca874b17dae8915f385dfc6f432740"),
    (0x10D01AF0, 313, "6de6472a62006c865bf06dc09389d136c86f74b63fbed3ac12171a00448bf00e"),
    (0x12BBB3C0, 4447, "924b84752b45f037288a5182c24d98f1bc83cb75563a5beda4b29d455737adfd"),
    (0x12DB93C0, 1493, "7f008691df365b1b05d312cbb48a7fcb0e6a7cd575da9be359d9723607d42696"),
    (0x10E5CE20, 136, "7cef0669d3492a5ca7467c973a305f17886443568ce49fc5f863c3d1e01ebe66"),
    (0x286BF70, 96, "b467e80802b4d423db586946750d50f7e028e4172910cdf4721a5a875b14deda"),
    (0x10E8CFC0, 32, "eebadf8d277ac325b16a109ebd71b7b5fe4f15a51ffaac027ef61170e27c9548"),
    (0xE28C10, 16, "89d3216c769fcd545aa3b1bee8b90dff05e616faed942b55b5813e47ac0bbc16"),
    (0x10D02470, 27, "abc6262784c23a83a078030370919f296a8a7c41e44e2018f2fcc24897037221"),
    (0x607F150, 53, "bc1439ece2eb2ff0dfbeddc02ca321fab17e2447db630029665dfa1c5b5b8291"),
    (0x6083DC0, 47, "cee0f05ff356dfa527aeaa713169a20718945b1784b2629aad53947e905777ab"),
    (0xD5F3A0, 8, "d1d1518eea6fec63280f66d520b80b2f92e1af361a428c4917d283fdb06d8df7"),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_contract(cache, image, decoder):
    verified = []
    for rva, size, expected in CONTRACT_CODE_PINS:
        code = cache.read(rva, size)
        if digest(code) != expected:
            raise ValueError("Contract code changed at " + hex(rva))
        verified.append({"rva": hex(rva), "bytes": size, "sha256": expected})

    def ascii_at(pointer):
        return image.read(pointer - image.image_base, 256).split(b"\0", 1)[0].decode("ascii")

    def declaration(rva, size):
        raw = image.read(rva, size)
        words = struct.unpack("<" + "Q" * (size // 8), raw)
        count = words[7] & 0xFFFFFFFF
        if not 0 < count <= 64:
            raise ValueError("Declaration field count changed")
        pointers = image.read(words[6] - image.image_base, count * 8)
        fields = []
        for pointer, in struct.iter_unpack("<Q", pointers):
            record = image.read(pointer - image.image_base, 0x38)
            data = struct.unpack_from("<5Q", record)
            gen = data[3] & 0xFFFFFFFF
            item = {"name": ascii_at(data[0]), "gen": gen,
                    "offset": data[4] >> 32, "flags": hex(data[2]),
                    "record_rva": hex(pointer - image.image_base),
                    "record_sha256": digest(record)}
            if gen == 0x4C:
                setter = struct.unpack_from("<Q", record, 0x30)[0] - image.image_base
                ins = next(decoder.disasm(cache.read(setter, 8), setter))
                if ins.mnemonic != "mov" or "byte ptr [rcx" not in ins.op_str:
                    raise ValueError("Bool setter changed")
                item["offset"] = ins.operands[0].mem.disp
                item["setter"] = hex(setter)
            fields.append(item)
        return {"rva": hex(rva), "sha256": digest(raw), "array_rva": hex(words[6] - image.image_base),
                "array_sha256": digest(pointers), "fields": fields}

    f30 = declaration(0x1CD48650, 80)
    f31 = declaration(0x1CD486A0, 80)
    args = declaration(0x1CD4B390, 72)
    order30 = [p["name"] for p in reversed(f30["fields"])]
    order31 = [p["name"] for p in reversed(f31["fields"])]
    if order30 != ["skillid", "args"] or order31 != ["skillid", "ExcuteID"]:
        raise ValueError("Native head-insertion parameter order changed")
    expected = ["pressed", "cancel", "ExcuteID", "Target", "TargetUid", "bTryAddAmmo",
                "AddAmmoWeapon", "PlayerInput", "Int32Value1", "ScanableActor",
                "GetLocAndDirSuccess", "ScanableCamLoc", "ScanableCamDir"]
    args_order = sorted(args["fields"], key=lambda p: (p["offset"], p["name"]))
    if [p["name"] for p in args_order] != expected:
        raise ValueError("Recursive struct offset/name ordering changed")
    ops = struct.unpack("<37Q", image.read(0x16777E58, 37 * 8))
    if any(ops[slot // 8] - image.image_base != 0xD5F3A0 for slot in (0x10, 0x60, 0x98)):
        raise ValueError("SkillEventArgs ops capability slots changed")
    if cache.read(0xD5F3A0, 3) != b"\x32\xc0\xc3":
        raise ValueError("False ops predicate changed")
    if cache.read(0x10D03FCA, 6) != bytes.fromhex("0f8425010000"):
        raise ValueError("HasNetSerializer false branch changed")
    if cache.read(0x10D0405A, 6) != bytes.fromhex("810b00040000"):
        raise ValueError("Struct NetSerialize flag writer changed")
    if ops[0x120 // 8] - image.image_base != 0xE28C10:
        raise ValueError("Struct computed property flags changed")
    if cache.read(0xE28C10, 11) != bytes.fromhex("48b80000000010000000c3"):
        raise ValueError("Computed property flags now require requalification")
    default_rva, default_size = 0x1E2F8090, 12
    virtual_tail = [(index, section) for index, section in enumerate(image.sections)
                    if section[0] + section[1] <= default_rva and
                    default_rva + default_size <= section[0] + section[3]]
    if len(virtual_tail) != 1:
        raise ValueError("Default vector left its unique PE zero-filled virtual tail")
    section_index, section = virtual_tail[0]
    nt = struct.unpack_from("<I", image.data, 0x3C)[0]
    section_table = nt + 24 + struct.unpack_from("<H", image.data, nt + 20)[0]
    header_at = section_table + section_index * 40
    section_header = bytes(image.data[header_at:header_at + 40])
    if digest(section_header) != "ed2877ebeeb8311a5300fc409c1534a1327705ddff08d4ebf968eb68a22ba660":
        raise ValueError("Default-vector PE section header changed")
    # The PE loader supplies zero bytes beyond SizeOfRawData, not file reads.
    loader_default = bytes(default_size)
    default_vector = struct.unpack("<3f", loader_default)
    constructor_defaults = {
        "source": "PE loader-zeroed constant globals copied by native60804a0",
        "constant_rva": hex(default_rva), "constant_bytes": default_size,
        "loader_initialized_bytes_hex": loader_default.hex(),
        "loader_initialized_bytes_sha256": digest(loader_default),
        "vector_xyz": default_vector,
        "source_default_vectors": {name: default_vector for name in
                                   ("PlayerInput", "ScanableCamLoc", "ScanableCamDir")},
        "scalar_defaults": {"pressed": False, "cancel": False, "ExcuteID": 0,
                            "TargetUid": 0, "bTryAddAmmo": False, "Int32Value1": -1,
                            "GetLocAndDirSuccess": False},
        "null_weak_reference_defaults": {"fields": ["Target", "AddAmmoWeapon", "ScanableActor"],
                                         "object_index": -1, "object_serial": 0},
        "section_header_file_offset": hex(header_at),
        "section_header_hex": section_header.hex(),
        "section_header_sha256": digest(section_header),
        "section_virtual_zero_begin": hex(section[0] + section[1]),
        "section_virtual_end": hex(section[0] + section[3]),
        "current_runtime_values_observed": False,
        "all_runtime_alias_mutations_excluded": False,
    }
    source = PEER / "work/evidence/model-init-chain-20261018/native-map-plain-vector-value-contract-v1.json"
    vector_raw = source.read_bytes()
    if digest(vector_raw) != "fd74fc9ab3aeb5def87ba704b8613d9654b47a3091ef9fa3a9d2c58e29314ac6":
        raise ValueError("Plain vector source contract changed")
    vector = json.loads(vector_raw)
    for relative, expected_sha in vector["sources"].items():
        if digest((PEER / relative).read_bytes()) != expected_sha:
            raise ValueError("Vector source changed: " + relative)
    if vector["static_getter_rva"] != "0x10ed3750" or vector["value_bits"] != 96:
        raise ValueError("Plain vector contract changed")
    leaf_kind = {0x4C: "bool:1bit", 3: "signed32:rawLE32", 14: "PackageMapObjectReference", 25: "Vector:rawLE3xf32"}
    for field in args_order:
        field["wire_leaf"] = leaf_kind[field["gen"]]
    return {
        "kind": "source_derived_first_skill_parameter_contract",
        "observed_rpc_parameter_wire": False,
        "native_gameplay_verified": False,
        "field30": {"parameter_order": order30, "args_has_native_netserializer": False,
                    "grammar": ["Pskill:1", "optional signed32 skillid", "Pargs:1", "all args leaves if Pargs"],
                    "args_leaves_without_individual_presence_handles_or_alignment": args_order,
                    "minimum_present_args_bits_with_null_references": 412,
                    "both_present_null_reference_payload_bits": 446,
                    "omitted_args": "Apply source-qualified constructor defaults; preserve absence, Int32Value1 is -1 and all three vectors are positive zero.",
                    "constructor_defaults": constructor_defaults},
        "field31": {"parameter_order": order31,
                    "grammar": ["Pskill:1", "optional signed32 skillid", "Pexec:1", "optional signed32 ExcuteID"],
                    "extent_bits": [2, 34, 66], "omitted_int32": 0},
        "object_reference_nonterminal": {
            "grammar": ["packed uint32 GUID", "if nonzero and (GUID==1 or export_mode): flags:u8",
                        "if flags&1: recursive Outer reference, FString, optional raw32 checksum when flags&4"],
            "null_guid_has_no_suffix": True,
            "ordinary_nonexport_existing_guid_has_no_flags_or_suffix": True,
            "package_map_profile_is_explicit": True,
            "unmapped_reference_is_not_object_creation_or_authorization": True},
        "vector_contract_sha256": digest(vector_raw),
        "declaration_sources": {"field30": f30, "field31": f31, "args": args},
        "code_pins": verified,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function", type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--code", nargs=2, type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--record", nargs=2, type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--cache-record", nargs=2, type=lambda v: int(v, 0), action="append", default=[])
    parser.add_argument("--filter")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--verify-contract", action="store_true")
    args = parser.parse_args()
    for name, expected in HELPERS.items():
        if digest((PEER / "work" / name).read_bytes()) != expected:
            raise ValueError("Offline helper changed: " + name)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(PEER / "work"))
    from analyze_portable_native_code import function_fragments
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    from offline_received_packet_xrefs import ImmutableImage
    from portable_native_code_cache import CodeCache

    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pattern = re.compile(args.filter) if args.filter else None
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as raw:
        image = ImmutableImage(raw)
        if args.verify_contract:
            contract = verify_contract(cache, image, decoder)
            if args.compact:
                print(json.dumps({"kind": contract["kind"],
                    "field30_order": contract["field30"]["parameter_order"],
                    "field30_args_order": [p["name"] for p in contract["field30"]["args_leaves_without_individual_presence_handles_or_alignment"]],
                    "field30_both_present_null_reference_bits": 446,
                    "field30_constructor_defaults": contract["field30"]["constructor_defaults"],
                    "field31": contract["field31"], "verified_code_ranges": len(contract["code_pins"]),
                    "vector_contract_sha256": contract["vector_contract_sha256"],
                    "declaration_hashes": {k: v["sha256"] for k, v in contract["declaration_sources"].items()},
                    "observed_rpc_parameter_wire": False}, indent=2))
            else:
                print(json.dumps(contract, indent=2))
        ranges = []
        for rva in args.function:
            if image.containing(rva) is None:
                raise ValueError("No pdata: use an explicit bounded --code range")
            fragments = function_fragments(image, rva)
            ranges.append((rva, fragments[0][0], fragments[-1][1] - fragments[0][0],
                           [image.unwind(entry) for entry in fragments]))
        for rva, size in args.code:
            if not 0 < size <= 16384:
                raise ValueError("Explicit code range exceeds bound")
            ranges.append((rva, rva, size, []))
        for query, start, size, pdata in ranges:
            code = b"".join(cache.read(at, min(8192, start + size - at))
                            for at in range(start, start + size, 8192))
            instructions = []
            covered = 0
            for ins in decoder.disasm(code, start):
                covered += ins.size
                row = {"rva": hex(ins.address), "bytes": ins.bytes.hex(),
                       "mnemonic": ins.mnemonic, "operands": ins.op_str}
                if ins.mnemonic in ("call", "jmp") and len(ins.operands) == 1:
                    if ins.operands[0].type == X86_OP_IMM:
                        row["target"] = hex(ins.operands[0].imm)
                refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
                        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
                if refs:
                    row["rip_refs"] = [hex(at) for at in refs]
                if pattern is None or pattern.search(json.dumps(row)):
                    instructions.append(row)
            result = {"query": hex(query), "start": hex(start), "bytes": size,
                      "code_sha256": digest(code), "decoded_bytes": covered, "pdata": pdata}
            if args.compact:
                print(json.dumps(result))
                for row in instructions:
                    print(row["rva"], row["bytes"], row["mnemonic"], row["operands"],
                          row.get("rip_refs", []))
            else:
                print(json.dumps(dict(result, instructions=instructions), indent=2))
        for rva, size in args.cache_record:
            if not 0 < size <= 4096:
                raise ValueError("Cached record exceeds bound")
            data = cache.read(rva, size)
            result = {"cache_record_rva": hex(rva), "bytes": size,
                      "sha256": digest(data), "raw_hex": data.hex()}
            if size % 4 == 0:
                result["dwords"] = [hex(v[0]) for v in struct.iter_unpack("<I", data)]
            print(json.dumps(result, indent=2))
        for rva, size in args.record:
            if not 0 < size <= 4096:
                raise ValueError("Immutable record exceeds bound")
            data = image.read(rva, size)
            result = {"record_rva": hex(rva), "bytes": size,
                      "sha256": digest(data), "raw_hex": data.hex()}
            if size % 8 == 0:
                result["qwords"] = [hex(v[0]) for v in struct.iter_unpack("<Q", data)]
            if b"\0" in data:
                try:
                    text = data.split(b"\0", 1)[0].decode("ascii")
                    if text and text.isprintable():
                        result["first_ascii_string"] = text
                except UnicodeDecodeError:
                    pass
            print(json.dumps(result, indent=2))
    print(json.dumps({"process_access": False, "game_launched": False,
                      "native_code_executed": False, "files_written": False,
                      "script_sha256": digest(Path(__file__).read_bytes()),
                      "cache_manifest_sha256": MANIFEST_SHA}))


if __name__ == "__main__":
    main()
