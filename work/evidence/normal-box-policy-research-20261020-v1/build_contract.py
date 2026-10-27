"""Reproduce bounded normal SafeBox policy evidence from installed sources.

Only the installed compression codec is loaded. Client code is disassembled from
the pre-existing pinned offline cache; no game process is opened or launched.
"""
import hashlib
import json
import mmap
from pathlib import Path, PurePosixPath
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "work"))

from analyze_portable_native_code import analyze
from offline_received_packet_xrefs import ImmutableImage
from parse_economy_dam_ai_templates import InstalledWorld
from portable_native_code_cache import CodeCache
from recover_economy_pak_access import (
    decode_entry, directory_index, entry_offset, native_keys, pak_footer,
    validate_index,
)
from scan_weapon_tables import parse_entry
import oodle_payload_reader

GAME = Path("F:/WeGameApps/rail_apps/DeltaForce(2001918)")
CACHE = ROOT / "work/native-code-cache/1792259162856698600"
MANIFEST_SHA = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
CLIENT_SHA = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
OLD = ROOT / "work/evidence/map-system-audit-20261018"
STORAGE = OLD / "native-economy-box-grid-config-storage.json"
OUTPUT = HERE / "normal-box-policy-contract-v2.json"

EXPECTED = {
    "BP_Interact_AnimSwitcherContainer": (
        "3682edd4f57abd57144007112f61f18cd1d83c814571d41424abe13173ee3638",
        "23af2b15fdd0f8e88eef015b1337b4987da01ba5a7fe5445b6aa08701b400caf"),
    "BP_Interactor_ContainerBoxBase": (
        "37311c2e6a67ca547b44422abfb9b5e88420b13bb2e9f5ea356d79e126dbf44b",
        "b04850f7a4c3c7efcb6bc25b972ec0dccc7c6419a4d23ce123b12f1797b819f7"),
    "BP_InteractorContainer_BoxBase": (
        "be5100817d2c398506afeff25e1499b4c140efb938f1c76a6807ee4b27fdd384",
        "5af51b6af0d621a2814b29213010910a87b2359726c2003bfba890ba7a550bc2"),
    "BP_InventoryPickupOpenBoxBase": (
        "f71f2022bac19899b0444bc9ff0e4b1ebbdd5b7d38063bb2f13a6b9b49fb9ce0",
        "9f76af5c1fa7adfa1974ce18d3452e68bc8651f32ef999177d53edc66d9c7fd3"),
    "BP_Interactor_Container_SafeBox": (
        "8da4241c723f9648d0c25d6897c161ee5a845404d962877c347f53ca4d8743b6",
        "ed3b2ebb63ae68e6ef36e53872fb6fdffd049448c827db16080467d959688f60"),
    "InnerLoot_x14_y31_8": (
        "49feb6dbda88f22fc21dcc1af4d6650fe029a1684b84c8896ccb01a1a60f7253",
        "1bed59909bf7d992252ef83ade8436daf3f0242dadc470f5d0da3f3e427dda8e"),
    "Loot_x14_y30_2": (
        "69eb02692aec1860ffa509dd0e470dc33a83820526b8ffff88e1137ea0025e18",
        "58a668eee737d3199d3f434f531fc73b7f3c0e9d07722ff6950d02b8cc193f0a"),
}
POLICY_PROPERTIES = (
    "bIsNormalSafeBox", "bIsKeyBox", "bIsOpened", "bIsOpening", "bHasOpened",
    "OpeningPlayerId", "OpenCostSeconds", "OpenStartTime", "PwdDigitsNum",
    "bUseRandomSafeBoxPwd", "SafeBoxPwd", "RealSafeBoxPwd", "SafeBoxCodeID",
    "LootLimit", "CapacityLength", "CapacityWidth", "BoxID", "BoxLevel",
    "BaseItemSearchTime", "BaseBoxSearchTime", "InteractorTag", "InteractableTags",
)
ACTOR_EXPORTS = {"InnerLoot_x14_y31_8": (50, 51), "Loot_x14_y30_2": (69,)}
FUNCTIONS = {
    "InventoryPickup_OpenBox_constructor": 0xC195210,
    "CanOpenThisBox": 0xC1A9460,
    "CheckIfNeedVerifySafeBoxCode": 0xC1AAD70,
    "InitSafeBoxPwd": 0xC1D20D0,
    "OpenThisBoxInner": 0xC1E2C30,
    "OnIsOpenedReplicate": 0xC1DAA60,
    "HasSearchedByPlayer": 0xC04F720,
    "InteractorGeneratePasswordComponent_static_class": 0xCF91BD0,
    "InteractorGeneratePasswordComponent_constructor": 0xBA5CE50,
    "InteractorGeneratePasswordComponent_owner_authority_lifecycle": 0xBA6B200,
    "InteractorGeneratePasswordComponent_GetPasswordArray": 0xBA84C60,
    "InteractorGeneratePasswordComponent_VerifyPwd": 0xBACABA0,
    "InteractorGeneratePasswordComponent_OnRep_Password": 0xBAA2870,
}
FUNCTION_HASHES = {
    "InventoryPickup_OpenBox_constructor": "108075bf30bcfe0e9d4fd6f358689e96e9e416952fa60a3f66f9ceb5889a462b",
    "CanOpenThisBox": "0ac3b0c435cdc3fbcf4a1f5cbe5d7ce16ea0dc164de62fcf423ad93dd0259b03",
    "CheckIfNeedVerifySafeBoxCode": "2fe5f8e10b05110c135b915dc8eeffcdbf86f49df96ef2bd1aa1804ff3308971",
    "InitSafeBoxPwd": "33c6c18a6b73398cf69a4e9b6216cee193be0821abef314a739959cc7125caae",
    "OpenThisBoxInner": "829aff68a68eb49664c445e0705672106af7b585366d558f8679d8b39577412c",
    "HasSearchedByPlayer": "81bf1b355ec7f6167fca2a5e6359eaee94c310f7aa43a6cfe04440523f1b5f74",
    "InteractorGeneratePasswordComponent_owner_authority_lifecycle": "1a802c373d363d7dfe5e8f5642cc8f74f70d13aa2373f074c23a6eb82f9f42b6",
    "InteractorGeneratePasswordComponent_VerifyPwd": "679e81d951cf2ed803e98d48dadefa365ccdec3466d61a730cf6814d5551db06",
    "InteractorGeneratePasswordComponent_OnRep_Password": "8330ebf6edb749148b6c55294e0f23898bdfdbcecd47c934ecd32c1a7c738dcd",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_pin(path):
    raw = path.read_bytes()
    return dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


class MemoryWorld(InstalledWorld):
    @staticmethod
    def checked_record(record):
        raw = record["data"]
        if len(raw) != record["bytes"] or sha(raw) != record["decoded_sha256"]:
            raise ValueError("In-memory entry changed")
        return raw


def export_record(pkg, index):
    row = pkg.exports[index-1]
    versions = struct.unpack_from("<i", pkg.header, 20)[0]
    table = struct.unpack_from("<i", pkg.header, 41+versions*20+20)[0]
    at = table+(index-1)*104
    cls, sup, template, outer = struct.unpack_from("<4i", pkg.header, at)
    values = {
        name: dict(serialized_kind=tag["kind"], value=pkg.decoded(tag),
                   payload_offset=tag["value_start"], payload_bytes=tag["size"])
        for name, tag in pkg.properties(index).items()
    }
    return dict(
        export=index, name=row["name"], class_name=pkg.full_object(cls),
        super_name=pkg.full_object(sup) if sup else None,
        template_name=pkg.full_object(template) if template else None,
        outer_name=pkg.full_object(outer) if outer else None,
        export_metadata_offset=at, export_metadata_bytes=104,
        export_metadata_sha256=sha(pkg.header[at:at+104]),
        payload_offset=row["offset"], payload_bytes=row["size"],
        payload_sha256=sha(pkg.payload[row["offset"]:row["offset"]+row["size"]]),
        serialized_properties=values,
        policy_properties_not_serialized=[name for name in POLICY_PROPERTIES if name not in values],
        omission_means_inherit_not_arbitrary_zero=True,
    )


def literal(image, pointer):
    raw = image.read(pointer-image.image_base, 256)
    for encoding, step in (("ascii", 1), ("utf-16-le", 2)):
        end = next((i for i in range(0, len(raw)-step+1, step)
                    if raw[i:i+step] == bytes(step)), len(raw))
        try:
            value = raw[:end].decode(encoding)
        except UnicodeDecodeError:
            continue
        if value and all(c.isprintable() for c in value):
            return value
    raise ValueError("Native declaration name is not a bounded string")


def main():
    if OUTPUT.exists():
        raise ValueError("Use a fresh evidence output")
    storage = json.loads(STORAGE.read_text(encoding="utf8"))
    if not storage["all_primary_indices_sha1_valid"] or not storage["all_secondary_indices_sha1_valid"]:
        raise ValueError("Unqualified input PAK scope")
    cache = CodeCache(CACHE, MANIFEST_SHA, GAME)
    if cache.manifest["client_sha256"] != CLIENT_SHA:
        raise ValueError("Client differs")
    exe = GAME / cache.manifest["plan"]["client_relative_to_game_root"]
    oodle_payload_reader.PATH = GAME / "DeltaForce/Binaries/Win64/oo2core_8_win64.dll"
    with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = ImmutableImage(data)
        keys, key_provenance = native_keys(cache, image)
        registrations = []
        for address, name, wrapper in (
            (0x18854E60, "CanOpenThisBox", 0xCFC2900),
            (0x18854E70, "CheckIfNeedVerifySafeBoxCode", 0xCFC2950),
            (0x18854F10, "InitSafeBoxPwd", 0xCFC3290),
            (0x18855070, "OpenThisBoxInner", 0xCFC47A0),
            (0x18854F80, "OnIsOpenedReplicate", 0xCFC3C20),
        ):
            raw = image.read(address, 16)
            name_ptr, exec_ptr = struct.unpack("<QQ", raw)
            if literal(image, name_ptr) != name or exec_ptr-image.image_base != wrapper:
                raise ValueError("Function registration differs: "+name)
            registrations.append(dict(name=name, record_rva=hex(address), record_sha256=sha(raw),
                                      exec_rva=hex(wrapper), exec_first_32_bytes=cache.read(wrapper, 32).hex(),
                                      implementation_rva=hex(FUNCTIONS[name])))
        params = image.read(0x1D2BD458, 56)
        words = struct.unpack("<7Q", params)
        pair_rva, count = words[4]-image.image_base, words[5] & 0xFFFFFFFF
        if count != 4 or pair_rva != 0x18B1F590:
            raise ValueError("LootLimit enum declaration differs")
        pairs = image.read(pair_rva, count*16)
        entries = [dict(name=literal(image, pointer), value=value)
                   for pointer, value in struct.iter_unpack("<Qq", pairs)]
        expected_enum = ["Both", "OnlySource", "OnlyTarget", "None"]
        if [r["name"] for r in entries] != ["ELootLimitType::ELootLimitType_"+n for n in expected_enum]:
            raise ValueError("LootLimit names differ")
        enum = dict(name="ELootLimitType", params_rva="0x1d2bd458", params_bytes=56,
                    params_sha256=sha(params), pairs_rva=hex(pair_rva), pairs_bytes=len(pairs),
                    pairs_sha256=sha(pairs), entries=entries, lock_state=False)
        component_raw = image.read(0x1880F840, 80)
        component_values = struct.unpack("<10Q", component_raw)
        if component_values[0]-image.image_base != 0xCF91BD0:
            raise ValueError("Password component class declaration changed")
        component_properties = []
        property_array = image.read(component_values[5]-image.image_base, 4*8)
        for pointer, in struct.iter_unpack("<Q", property_array):
            raw = image.read(pointer-image.image_base, 56)
            name_ptr, _, flags, kind, offset = struct.unpack_from("<5Q", raw)
            component_properties.append(dict(name=literal(image, name_ptr),
                native_member_offset=hex(offset >> 32), record_rva=hex(pointer-image.image_base),
                record_sha256=sha(raw), property_flags=hex(flags), native_gen_flags=hex(kind & 0xFFFFFFFF)))
        component_functions_raw = image.read(0x188125E0, 48)
        component_functions = [dict(name=literal(image, name_ptr), exec_rva=hex(exec_ptr-image.image_base))
            for name_ptr, exec_ptr in struct.iter_unpack("<QQ", component_functions_raw)]
        component_vtable = image.read(0x17B8AD78, 0x410)
        if struct.unpack_from("<Q", component_vtable, 0x320)[0]-image.image_base != 0xBA6B200:
            raise ValueError("Password component lifecycle vtable changed")
        component = dict(
            name="InteractorGeneratePasswordComponent", class_declaration_rva="0x1880f840",
            class_declaration_bytes=80, class_declaration_sha256=sha(component_raw),
            static_class_getter_rva="0xcf91bd0", native_constructor_rva="0xba5ce50",
            native_constructor_binding="static class function 0xcf91c35 loads thunk 0xcf93500; thunk 0xcf9350e jumps to 0xba5ce50",
            constructor_thunk_rva="0xcf93500", constructor_thunk_bytes=20,
            constructor_thunk_sha256=sha(cache.read(0xCF93500, 20)),
            property_pointer_array_rva=hex(component_values[5]-image.image_base),
            property_pointer_array_sha256=sha(property_array), properties=component_properties,
            native_function_table_rva="0x188125e0", native_function_table_sha256=sha(component_functions_raw),
            native_functions=component_functions,
            vtable_rva="0x17b8ad78", vtable_bytes=len(component_vtable), vtable_sha256=sha(component_vtable),
            owner_authority_lifecycle_slot="0x320", owner_authority_lifecycle_rva="0xba6b200",
            native_VerifyPassword_state_present=True,
            full_native_open_requirement_fully_traced=False,
            original_native_passwordless_baseline_qualified=False,
            local_unlock_rule_selection_required=True,
        )

    scan, selected = [], {}
    for old in storage["paks"]:
        path = Path(old["pak"])
        footer = pak_footer(path)
        public, clear, key = validate_index(path, footer, keys)
        if clear is None or public["decoded_index_sha256"] != old["decoded_index_sha256"]:
            raise ValueError("PAK primary index differs: "+str(path))
        details, files, encoded = directory_index(path, footer, clear, key)
        if details["secondary_indices"] != old["secondary_indices"]:
            raise ValueError("PAK secondary indices differ: "+str(path))
        hits = [(name, location) for name, location in files
                if PurePosixPath(name).stem in EXPECTED and name.endswith((".uasset", ".umap", ".uexp"))]
        public.update(details)
        public["matching_entries"] = []
        with path.open("rb") as stream:
            for name, location in hits:
                pos = entry_offset(encoded, location)
                entry = parse_entry(stream, pos, footer["offset"], variant="observed_permutation")
                raw, compressed_valid = decode_entry(stream, pos, entry, footer["methods"], key)
                if not compressed_valid:
                    raise ValueError("Selected entry SHA1 differs: "+name)
                stream.seek(pos)
                header = stream.read(entry["header_size"])
                record = dict(path=name, source_pak=str(path), encoded_offset=location,
                              physical_offset=pos, bytes=len(raw), decoded_sha256=sha(raw),
                              entry_header_bytes=len(header), entry_header_sha256=sha(header),
                              compressed_sha1_valid=True, declared_compressed_sha1=entry["sha1"].hex(),
                              compression=footer["methods"][entry["method"]-1] if entry["method"] else "None",
                              encrypted=bool(entry["flags"] & 1))
                if name in selected:
                    raise ValueError("Selected source has multiple PAK versions: "+name)
                selected[name] = dict(record, data=raw)
                public["matching_entries"].append(record)
        scan.append(public)
    if len(selected) != len(EXPECTED)*2:
        raise ValueError("Exact fourteen source entries required")

    packages = []
    for name, digests in EXPECTED.items():
        headers = [r for p, r in selected.items() if PurePosixPath(p).stem == name and p.endswith((".uasset", ".umap"))]
        if len(headers) != 1:
            raise ValueError("Nonunique package header: "+name)
        header = headers[0]
        payload = selected[str(PurePosixPath(header["path"]).with_suffix(".uexp"))]
        if (header["decoded_sha256"], payload["decoded_sha256"]) != digests:
            raise ValueError("Previously researched package changed: "+name)
        pkg = MemoryWorld(header, payload)
        if name in ACTOR_EXPORTS:
            ids = ACTOR_EXPORTS[name]
            chosen = [export_record(pkg, i) for i in ids]
            components = [export_record(pkg, e["index"]) for e in pkg.exports if e["outer_index"] in ids]
            if any("BP_Interactor_Container_SafeBox_C_" not in e["name"] for e in chosen):
                raise ValueError("Selected SafeBox actor export changed")
        else:
            chosen = [export_record(pkg, e["index"]) for e in pkg.exports
                      if e["name"].startswith("Default__") or e["name"] == name+"_C"]
            components = [export_record(pkg, e["index"]) for e in pkg.exports
                          if name == "BP_Interactor_Container_SafeBox" and e["index"] not in {r["export"] for r in chosen}]
        packages.append(dict(package=name, source=pkg.source, source_pak=header["source_pak"],
                             exports=chosen, component_exports=components))

    native = analyze(CACHE, MANIFEST_SHA, GAME, list(FUNCTIONS.values()), [], set())
    for row, name in zip(native["functions"], FUNCTIONS):
        row["qualified_name"] = name
        if name in FUNCTION_HASHES and row["code_sha256"] != FUNCTION_HASHES[name]:
            raise ValueError("Previously researched native function changed: "+name)
    pins = [source_pin(path) for path in (
        STORAGE,
        OLD / "native-economy-door-container-component-defaults-and-tags-v1.json",
        OLD / "native-economy-loaded-level1-container-door-catalog-v2.json",
        OLD / "native-economy-openbox-class-declarations.json",
        ROOT / "work/native-client-tests/1792478435036855300/economy-loaded-interactors.json",
        Path(__file__),
        *[ROOT / "work" / (module+".py") for module in (
            "analyze_portable_native_code", "offline_received_packet_xrefs", "parse_economy_dam_ai_templates",
            "portable_native_code_cache", "recover_economy_pak_access", "scan_weapon_tables",
            "oodle_payload_reader", "extract_operator_avatar_catalog", "parse_economy_installed_tables",
            "recover_dam_gameplay_catalog")],
    )]
    result = dict(
        kind="source_qualified_normal_safebox_defaults_and_verification_policy_v2",
        client_sha256=CLIENT_SHA, cache_manifest_sha256=MANIFEST_SHA,
        process_access=False, client_launched=False, game_files_modified=False,
        runtime_modules_modified=False, key_material_disclosed=False,
        reproducible_command="../deltaforce-local/.venv/Scripts/python.exe work/evidence/normal-box-policy-research-20261020-v1/build_contract.py",
        source_pins=pins, key_reconstruction_provenance=key_provenance,
        pak_scope=dict(source_manifest_count=len(storage["paks"]), revalidated_count=len(scan),
                       selected_entry_count=len(selected), selected_package_count=len(packages),
                       duplicate_selected_paths=False,
                       absence_scope="All PAK paths in the pinned original storage report, including saved shadow patches"),
        validated_paks=scan, packages=packages, native=native,
        native_function_registrations=registrations, loot_limit_enum=enum,
        separate_generate_password_component=component,
        qualification=dict(native_SafeBoxPwd_empty_default=True,
                           native_component_VerifyPassword_state_present=True,
                           native_fully_passwordless_box_claim=False,
                           explicit_local_unlock_rule_required=True,
                           provisional_artifact_superseded="normal-box-policy-contract.json"),
        source_facts=[
            dict(fact="Normal SafeBox child CDO overrides bIsNormalSafeBox=true, capacity 4x4, BoxID=920; its four Blueprint parent CDOs and the three selected actor exports contain no password/opening/loot-limit overrides.",
                 evidence="packages[].exports; policy_properties_not_serialized lists omissions explicitly; generated class super_name and CDO template_name preserve inheritance provenance"),
            dict(fact="Native constructor initializes bIsKeyBox=false, bIsOpened=false, bIsOpening=false, OpeningPlayerId=0, OpenCostSeconds=2.0, PwdDigitsNum=4, bUseRandomSafeBoxPwd=false, SafeBoxPwd=[], RealSafeBoxPwd=[], SafeBoxCodeID=0.",
                 evidence="constructor 0xc195210: 0xc195229, 0xc195372, 0xc195378, 0xc1953ef, 0xc19540c..0xc19542e"),
            dict(fact="InitSafeBoxPwd authority branch skips random generation when bUseRandomSafeBoxPwd=false and copies SafeBoxPwd into RealSafeBoxPwd; the inherited empty password therefore remains empty after initialization.",
                 evidence="InitSafeBoxPwd 0xc1d212b role==3, 0xc1d2138 random flag, 0xc1d23c0..0xc1d23ce copy"),
            dict(fact="The SafeBox also has a separate native InteractorGeneratePasswordComponent. Its child component CDO export18 sets PasswordEveryBodyNum=2; its native constructor sets PasswordNum=3. Empty native SafeBoxPwd does not establish that the complete native box policy is passwordless.",
                 evidence="SafeBox package component export18; component constructor 0xba5ce90..0xba5ce9a; separate_generate_password_component"),
            dict(fact="The component lifecycle function at vtable slot0x320 validates its owner and requires owner role3, generates numeric VerifyPassword at component+0x108, and calls OnRep_Password. VerifyPwd compares supplied int32 to that field. OnRep_Password broadcasts OnGenPwdComplete with the generated int32 when bound.",
                 evidence="0xba6b30a authority test; 0xba6b317..0xba6b47e generation; 0xba6b40b state write; 0xba6b491 calls 0xbaa2870; 0xbacac00 comparison; 0xbaa28cc..0xbaa28e2 delegate"),
            dict(fact="CheckIfNeedVerifySafeBoxCode returns true only when RealSafeBoxPwd.Num == PwdDigitsNum and PwdDigitsNum > 0; the normal empty baseline returns false.",
                 evidence="0xc1aadc3..0xc1aade0"),
            dict(fact="CanOpenThisBox normal branch admits a closed box only when OpeningPlayerId==0. This predicate is a mutable box-state check; admission, current actor binding and accepted movement range remain independent server conditions.",
                 evidence="0xc1a94c0..0xc1a9535; this is not an unconditional permission oracle"),
            dict(fact="OpenThisBoxInner authority branch sets bIsOpened=true and dispatches virtual slot 0xaa0. OnIsOpenedReplicate dispatches the same slot using current bIsOpened.",
                 evidence="native functions OpenThisBoxInner and OnIsOpenedReplicate; saved class replication layout pin has bIsOpened field 116 at native offset 0x2492"),
            dict(fact="LootLimit baseline 0 denotes Both; OnlySource=1, OnlyTarget=2, None=3. This is a transfer-direction enum, not password or lock state.",
                 evidence="constructor 0xc195372; loot_limit_enum immutable declaration"),
            dict(fact="HasSearchedByPlayer returns true immediately for IsInContainer=false. The existing explicit instant-search local seed uses this native state; timed per-player search would require IsInContainer=true and qualified SearchedPlayers updates.",
                 evidence="HasSearchedByPlayer 0xc04f77e jumps to true at 0xc04f7c2 when item+0x5f0==0"),
        ],
        integration_design=dict(
            policy_authority="Persist a per-room per-actor box state seeded once from these defaults, with source contract hash and actor binding; retain finite contents and revision across reloads.",
            authorization_inputs=["current admission/room identity", "current live actor binding", "accepted movement position and source-qualified range", "registered per-box state and selected action tag", "OpeningPlayerId owner and opened/opening state", "password/key requirements from qualified baseline", "LootLimit transfer direction"],
            normal_open="Require an explicit locally selected unlock rule recorded in durable policy identity. The native normal box has a separate generated VerifyPassword component, so native SafeBoxPwd=[] must not silently mean fully passwordless. Atomically claim a closed unowned box, evaluate the local rule and finite opening/search timing, commit opened state, then publish native bIsOpened field 116. An already opened box may be browsed without reseeding or rerunning CanOpenThisBox.",
            transfer="Keep finite contents in the same transaction domain as player inventory; reject direction forbidden by LootLimit; require current box access and distance; replay identifiers must preserve quantities.",
            terminal="Do not require terminal authority to construct or use normal box dispatch. Terminal operations must reject when a dedicated terminal authority is absent.",
            tests=["missing local unlock rule rejects initialization", "closed unowned box opens only after selected local unlock rule", "second opener cannot claim owned box", "opened browse does not reseed", "stale/foreign/distant binding rejects", "all four transfer directions follow enum", "duplicate pickup preserves total quantity", "reload preserves opened state and remaining contents and local rule identity", "normal open works with no terminal authority", "terminal operation rejects with no terminal authority"],
        ),
        limitations=["Static cooked/default and saved native-code evidence; no new live interaction was performed.",
                     "Normal branches are qualified; hotfix dispatcher branches are not execution proof.",
                     "Baseline omission does not prove absence of later runtime mutation; local authority owns and validates such mutations.",
                     "No bHasOpened transition or terminal/extraction policy is inferred here.",
                     "Separate component VerifyPassword generation and verification are qualified; the complete native UI/RPC path requiring its result has not been traced. Any local simplified unlock rule must be explicit and may not be represented as original native passwordless policy.",
                     "Actor SavePos is not accepted as an actual world position in this contract."],
    )
    encoded = (json.dumps(result, indent=2, ensure_ascii=False)+"\n").encode("utf8")
    with OUTPUT.open("xb") as stream:
        stream.write(encoded)
    print(json.dumps(dict(output=str(OUTPUT), sha256=sha(encoded), bytes=len(encoded),
                          paks=len(scan), packages=len(packages), functions=len(native["functions"]))))


if __name__ == "__main__":
    main()
