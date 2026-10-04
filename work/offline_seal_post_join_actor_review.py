"""Seal post-Join native evidence from saved code and immutable PE only."""
import hashlib
import json
import mmap
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from offline_received_packet_xrefs import CLIENT, ROOT, SOURCE_SHA, ImmutableImage, validated_range, sha

PIN = "0dc6c0bb1c4ac55f437f07fde93ac2575425d008892e1ff6e6cac9385e4568cf"
EVIDENCE = ROOT / "work/evidence"
SOURCES = (
    "native-post-join-receive-player-roots.json",
    "native-post-join-set-actor-roots.json",
    "native-post-join-init-new-actor-roots.json",
    "native-post-join-seamless-gate-roots.json",
    "native-post-join-serialize-new-actor-full-roots.json",
    "native-post-join-guid-transform-full-roots.json",
    "native-post-join-guid-transform-roots.json",
    "native-post-join-class-serializer-helpers.json",
    "native-post-join-player-class-rotator-roots.json",
    "native-post-join-player-ctor-transform-roots.json",
    "native-post-join-pc-open-rotator-full-roots.json",
    "native-post-join-engine-player-class-xrefs.json",
    "native-post-join-typed-method-anchors.json",
    "native-wire-writer-summary.json",
    "native-post-join-inbunch-reader-constructor.json",
    "native-bitreader-and-packetinfo-fragments.json",
)


def main():
    sources, roots = [], {}
    for name in SOURCES:
        path = EVIDENCE / name
        value = json.loads(path.read_text(encoding="utf-8"))
        source_sha = value.get("client_sha256", value.get("source_client_sha256"))
        if source_sha != SOURCE_SHA:
            raise ValueError(f"Wrong image source: {name}")
        sources.append({"path": path.relative_to(ROOT).as_posix(), "sha256": sha(path.read_bytes())})
        for record in value.get("roots", []):
            if "code_relative_path" not in record:
                continue
            raw = (ROOT / record["code_relative_path"]).read_bytes()
            magic, version, rva, length, base = struct.unpack("<4sIQQQ", raw[:32])
            if (magic, version, base) != (b"DCDE", 1, 0x140000000) or length != len(raw) - 32:
                raise ValueError("Invalid saved-code header")
            if rva != int(record["begin"], 16) or length != record["bytes"]:
                raise ValueError("Saved-code span mismatch")
            if sha(raw) != record["file_sha256"] or sha(raw[32:]) != record["code_sha256"]:
                raise ValueError("Saved-code SHA mismatch")
            if sha((ROOT / record["asm_relative_path"]).read_bytes()) != record["asm_sha256"]:
                raise ValueError("Saved asm SHA mismatch")
            roots[rva] = record
    groups = {}
    for label, starts in {
        "SerializeNewActor": (0x12bcb060, 0x12bccc2f, 0x12bccde9),
        "GUID_reader": (0x12bbb3c0, 0x12bbb44d, 0x12bbc50c),
        "optional_vector": (0x12bab4b0, 0x12bab52c, 0x12bab56c, 0x12bab65a),
        "short_rotator": (0x10ab83a0, 0x10ab83aa, 0x10ab85a2),
        "ActorChannel_ProcessBunch": (0x128611e0, 0x12861215, 0x12861dda,
            0x12861e63, 0x128620bb, 0x1286241c, 0x12862434),
    }.items():
        pieces = [roots[start] for start in starts]
        for previous, next_piece in zip(pieces, pieces[1:]):
            if previous["end_exclusive"] != next_piece["begin"]:
                raise ValueError("Noncontiguous claimed complete function")
        joined = b"".join((ROOT / record["code_relative_path"]).read_bytes()[32:] for record in pieces)
        groups[label] = {"begin": pieces[0]["begin"], "end_exclusive": pieces[-1]["end_exclusive"],
            "bytes": len(joined), "concatenated_code_sha256": sha(joined), "fragments": pieces}
    leaves, constants, slots = [], [], []
    folder = ROOT / "work/native-code-cache/1790902501634810000"
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    with CLIENT.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SOURCE_SHA:
            raise ValueError("Immutable executable identity differs")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            image = ImmutableImage(mapped)
            for rva, length, label in ((0x19d9520, 10, "OnActorChannelOpen_typed_adapter"),
                    (0x116a7e0, 10, "HandleClientPlayer_typed_adapter"),
                    (0x133ad7e0, 20, "PlayerController_registration_ctor_thunk"),
                    (0x2c08e70, 4, "Archive_EngineNetVersion_setter")):
                if image.containing(rva) is not None:
                    raise ValueError("Leaf unexpectedly has pdata")
                code = validated_range(folder, rva, length, PIN)
                decoded = list(decoder.disasm(code, rva))
                if not decoded or decoded[-1].address + decoded[-1].size != rva + length:
                    raise ValueError("Leaf exact boundary mismatch")
                stem = EVIDENCE / f"native-post-join-leaf-{rva:x}"
                data = struct.pack("<4sIQQQ", b"DCDE", 1, rva, length, image.image_base) + code
                stem.with_suffix(".dfcode").write_bytes(data)
                asm = "\n".join(f"0x{i.address:x}: {i.mnemonic} {i.op_str}" for i in decoded) + "\n"
                stem.with_suffix(".asm.txt").write_text(asm, encoding="utf-8")
                leaves.append({"label": label, "rva": hex(rva), "bytes": length,
                    "code_sha256": sha(code), "file_sha256": sha(data),
                    "code_path": stem.with_suffix(".dfcode").relative_to(ROOT).as_posix(),
                    "asm": asm.splitlines(), "scope": "exact leaf, not inferred pdata function"})
            for rva, size, label in ((0x14ec8324, 4, "compressed_vector_float32_multiplier"),
                    (0x1d5995b8, 12, "default_scale_vector"),
                    (0x14f8d21c, 4, "short_rotator_loading_multiplier")):
                raw = image.read(rva, size)
                constants.append({"label": label, "rva": hex(rva), "bytes": size,
                    "raw_hex": raw.hex(), "sha256": sha(raw),
                    "float32": list(struct.unpack("<" + "f" * (size // 4), raw))})
            for table, offsets in ((0x1b221ff0, (0x3d8, 0x700, 0x998, 0xc98, 0xd48, 0xe08)),
                    (0x1b1d63f0, (0x2c0,)), (0x1b148470, (0x60, 0x68, 0x70, 0x78))):
                for offset in offsets:
                    raw = image.read(table + offset, 8)
                    slots.append({"table_rva": hex(table), "slot": hex(offset), "bytes_hex": raw.hex(),
                        "target_rva": hex(struct.unpack("<Q", raw)[0] - image.image_base), "sha256": sha(raw)})
    result = {
        "kind": "post_join_actor_creation_native_prerequisites",
        "client_sha256": SOURCE_SHA, "cache_manifest_sha256": PIN,
        "sources": sources, "complete_function_groups": groups,
        "exact_leaf_sources": leaves, "immutable_constants": constants, "static_virtual_slots": slots,
        "actor_open_order": [
            {"field": "actor_object_reference", "operation": "PackageMap.v260 / GUID_reader",
             "anchors": ["12bcb174", "12bcde29", "12bbb459"]},
            {"branch": "GUID nonzero and bit0 clear is dynamic; existing actor/deletion/static paths differ",
             "anchors": ["12bcb2b0", "12bcb2b9", "12bcb549", "12bcb552"]},
            {"field": "archetype_object_reference", "operation": "PackageMap.v260; expected Object class",
             "anchors": ["12bcca2d", "12bcca50"]},
            {"field": "level_object_reference", "when": "loading connection+1528 >= 5",
             "operation": "PackageMap.v260; expected Level class", "anchors": ["12bcca69", "12bcca90"]},
            {"field": "location_optional_vector", "anchor": "12bcce11"},
            {"field": "rotation_present", "operation": "1bit", "anchor": "12bcce26"},
            {"field": "rotation_value", "when": "rotation_present", "operation": "10ab4e20 -> 10ab83a0",
             "anchor": "12bcce3d"},
            {"field": "scale_optional_vector", "anchor": "12bcce7a"},
            {"field": "velocity_optional_vector", "anchor": "12bccea2"},
        ],
        "ordinary_guid_reference": {
            "profile": "GUIDCache+152=false, guid !=1; export mode excluded",
            "encoding": "archive.v78(&u32), one packed_u32; no prefix, suffix or alignment bits",
            "reader": {"root": "12bbb3c0", "packed_call": "12bbb459",
                "skip_flags_gate": ["12bbb57b", "12bbb598"], "flag0_skip": "12bbb639",
                "return": ["12bbc024", "12bbc4e2"]},
            "writer": {"root": "12bbc520", "packed_call": "12bbc5de",
                "skip_flags_gate": "12bbc6bb", "flag0_skip": "12bbc727", "return": "12bbcaca"},
            "packed_writer_static_binding": "native-wire-writer-summary.json v78=10b4c310; low continuation bit, 7 payload bits, no alignment",
            "reader_v78_concrete_binding": "ReceivedPacket12b9b40c ->FInBunch constructor1283e990;1283e9b0/9b7 writes vptr1b148470; immutable slot78=10b4c190 (376bytes) has low continuation bit and 7 payload bits, unaligned reads",
            "reader_version_propagation": "FInBunch ctor1283ea0e/ea14 ->2c08e70 mov[archive+54],edx;ret, so conn+1528 and FInBunch archive+54 share the same initialization value",
            "guid0": "null reference; returns after packed_u32", "guid1": "special path form; forbidden in restricted ordinary codec",
            "unresolved_nonzero_guid": "returns null object / validation failure, not object creation"},
        "guid_path_form": {
            "eligibility": "guid==1 OR GUIDCache+152=true reads u8 flags",
            "flag_bit0": {"when_true": ["recursive outer GUID_reader", "FString via109ea340", "u32 checksum if flags bit2"],
                "anchors": ["12bbb635", "12bbb65a", "12bbb672", "12bbb677"]},
            "flag_bit1": {"physical": "one stored flag, passed as both stack booleans into12bc5a30",
                "name_or_policy_not_inferred": True, "anchors": ["12bbbef4", "12bbbf0b"]},
            "recursion": "depth>16 sets archive error and returns null",
            "minimum_full_export_bunch_envelope_not_recovered": True,
            "class_cdo_paths_crc_and_guid_dictionary_not_invented": True},
        "optional_vector": {
            "root": "12bab4b0", "present": "1bit archive.v68 @12bab4e2",
            "absent": "copy caller default 3xfloat32 @12bab671; scale immutable default (1,1,1); location/velocity defaults in BSS not observed live",
            "present_profile": "archive+54<13 implies compressed=true; >=13 reads compressed 1bit @12bab510",
            "compressed": {"B": "boundedInt(max24), 0<=B<=23 @12bab593", "bias": "1<<(B+1) @12bab5bc",
                "component_maximum": "1<<(B+2) @12bab5c4", "components": "x,y,z boundedInt(component_maximum) @12bab5cc/5dd/5ee",
                "decoded_float": "float32(float32(encoded_component-bias)*float32(0.1))",
                "integer_range": "[-2^(B+1), 2^(B+1)-1]",
                "minimum_width": "B=0 is legal; each component is 2 bits",
                "maximum_width": "B=23; each component is 25 bits; uint32 shift does not overflow",
                "bounds": "reject truncation/B>=24, invalid component, nonfinite requested coordinates; root reader itself delegates archive bounds/error",
                "writer_rounding_and_minimal_B": "1dd2370 not reviewed; restricted encoder may accept exact B + integer components rather than claim native float quantization policy"},
            "raw": {"root": "10e15b0", "code_sha256": "a3ca3e7e5b71c60bc7179e4ffdd90b0d912f0ab933cb838047cabbcf033e79f6",
                "operation": "three consecutive 4-byte words with archive endian alternative10b4b540", "implement_now": False}},
        "rotation": {"presence_anchor": "12bcce26", "absent": "caller-supplied client default; not labeled runtime (0,0,0)",
            "present_format": "10ab83a0 sequential three (component_nonzero 1bit then u16 if true); each decoded u16 multiplied by native float32 constant",
            "anchors": ["10ab845f", "10ab84d6", "10ab853c", "10ab85a2"], "restricted_codec_support": "absent only"},
        "player_controller_binding": {
            "actual_class_literal": {"rva": "1b5d6232", "utf16": "PlayerController", "getter": "133af220", "literal_xref": "133af25b"},
            "generated_constructor_chain": ["133af28a stores133ad7e0 at registration stack+48", "133ad7ee ->12d1d8a0", "12d1d8bd/8c6 writes static vtable1b221ff0"],
            "typed_adapter": "OnActorChannelOpen 6Q APlayerController*,FInBunch*,UNetConnection* at1b2abe10 ->19d9520 ->v3d8",
            "base_native_target": "1b221ff0+3d8 ->12d4ddb0, complete392bytes",
            "extra_after_generic_actor_header": "u8 player index stored PC+524 @12d4dde3 or12d4de05; no alignment inserted by caller",
            "bind_condition": "conn+58 driver nonnull and conn==driver+98; index0 ->conn.v2c0(PC,conn) @12d4de48",
            "handle_client_player": {"base_conn_ctor_vtable": "1b1d63f0", "slot2c0": "12b91a80, complete1036bytes",
                "actions": ["PC+568=connection @12b91bd5", "PC.vc98(LocalPlayer) @12b91bdc", "connection+15c=3 @12b91ca9", "connection+30/+a8=PC @12b91cb4/cb8"]},
            "derived_game_class_override_vptr_not_observed": True,
            "does_not_create_or_possess_pawn": True,
            "pawn_followup": "typed ClientRestart adapter2358250 ->v998; base PC table ->12d2ddd0 (1709bytes), includes Pawn+3a8=PC @12d2e3f6 and AcknowledgePossession vd48; RPC field exports/layout not recovered"},
        "project_next_stage_gate": {"root": "742a4b0..742a8d6", "bytes": 1062,
            "checks": ["stage+48 nonnull", "subsystem+438==4", "stage+90 nonzero", "stage+91 nonzero"],
            "actual_log": "Connected && bLevelStreamingReady && bLevelPhysicsReady",
            "native_all_players_ready_callback": "7407b60..7407c5e, 254bytes; actual log OnDSNotifyAllPlayerReady; network RPC layout unknown"},
        "implementation_boundary": {
            "can_write_now": ["restricted ordinary packed GUID references with explicit preexported registry contract", "compressed optional vectors using explicit B and integer components", "rotation absent", "separate evidenced base PC u8 tail"],
            "cannot_claim_now": ["actor GUID paths/CDO/archetype resolved", "full package export envelope", "game PC/Pawn RepLayout/RPC compatibility", "Pawn possession", "project ready RPC", "playable map"],
            "no_actor_send_integrated": True},
        "policy": {"only_saved_native_cache_and_immutable_PE": True, "process_accessed": False,
            "live_heap_read": False, "game_launched": False, "server_modified": False,
            "runner_or_reader_modified": False, "native_actor_acceptance": False, "playable_map": False}}
    output = EVIDENCE / "native-post-join-actor-prerequisites.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json.loads(output.read_text(encoding="utf-8"))
    print(json.dumps({"path": output.relative_to(ROOT).as_posix(), "sha256": sha(output.read_bytes()),
        "validated_roots": len(roots), "complete_groups": {key: value["bytes"] for key,value in groups.items()}}))


if __name__ == "__main__":
    main()
