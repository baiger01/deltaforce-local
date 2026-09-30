"""Build our partial SDK provider from fixed-version interface metadata."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
EXPECTED = "9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723"
KNOWN = {"RailNeedRestartAppForCheckingEnvironment", "RailInitialize", "RailFinalize", "RailFactory",
         "RailFireEvents", "RailRegisterEvent", "RailUnregisterEvent"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main(args):
    stage, source = args.stage.resolve(), args.sdk.resolve()
    assert stage.name == "sdk-local-provider-stage" and stage.is_relative_to((ROOT / "work").resolve())
    assert digest(source) == EXPECTED
    abi = json.loads((ROOT / "outputs/sdk-call-observer/identity-abi.json").read_text(encoding="utf-8"))
    assert abi["source_sha256"] == EXPECTED
    optional_file = HERE / "optional-content-abi.json"
    optional = json.loads(optional_file.read_text(encoding="utf-8"))
    assert optional["source_sha256"] == EXPECTED and optional["factory_slot"] == 19 and optional["vtable_entries"] == 14
    abi["interfaces"]["IRailDlcHelper"] = optional["methods"]
    expansion_file = HERE / "expansion-content-abi.json"
    expansion = json.loads(expansion_file.read_text(encoding="utf-8"))
    assert expansion["source_sha256"] == EXPECTED and expansion["factory_slot"] == 34 and expansion["vtable_entries"] == 8
    abi["interfaces"]["IRailExpansionPack"] = expansion["methods"]
    zone_file = HERE / "zone-helper-abi.json"
    zone = json.loads(zone_file.read_text(encoding="utf-8"))
    assert zone["source_sha256"] == EXPECTED and zone["factory_slot"] == 27 and zone["vtable_entries"] == 4
    abi["interfaces"]["IRailZoneServerHelper"] = zone["methods"]
    zone_server_file = HERE / "zone-server-abi.json"
    zone_server = json.loads(zone_server_file.read_text(encoding="utf-8"))
    assert zone_server["source_sha256"] == EXPECTED and zone_server["vtable_entries"] == 15
    abi["interfaces"]["IRailZoneServer"] = zone_server["methods"]
    account_file = HERE / "local-account-interface-abi.json"
    account = json.loads(account_file.read_text(encoding="utf-8"))
    assert account["source_sha256"] == EXPECTED and account["factory_slot"] == 32 and account["vtable_entries"] == 10
    abi["interfaces"]["IRailThirdPartyAccountLoginHelper"] = account["methods"]
    account_info_file = HERE / "local-account-info-abi.json"
    account_info = json.loads(account_info_file.read_text(encoding="utf-8"))
    assert account_info["sdk_metadata_sha256"] == EXPECTED and account_info["native_size"] == 344
    stage.mkdir(parents=True, exist_ok=True)
    generated = []
    tables = []
    for interface, array, count, prefix in (("IRailFactory", "factory_table", 36, "factory"),
                                           ("IRailPlayer", "player_table", 24, "player"),
                                           ("IRailGame", "game_table", 21, "game"),
                                           ("IRailDlcHelper", "dlc_table", 14, "dlc"),
                                           ("IRailSystemHelper", "system_table", 3, "system"),
                                           ("IRailExpansionPack", "expansion_table", 8, "expansion"),
                                           ("IRailZoneServerHelper", "zone_helper_table", 4, "zone_helper"),
                                           ("IRailZoneServer", "zone_server_table", 15, "zone_server"),
                                           ("IRailThirdPartyAccountLoginHelper", "local_account_table", 10, "local_account")):
        methods = {m["slot_index"]: m["method"] for m in abi["interfaces"][interface]}
        assert set(methods) == set(range(count)), interface
        for slot in range(count):
            assert methods[slot].replace("_", "").isalnum()
            function = f"{prefix}_unknown_{slot}"
            generated.append(f'static void {function}(void) {{ DFLocalUnsupportedExport("unsupported_{prefix}_{methods[slot]}"); }}')
            tables.append(f"    SET_SLOT({array}, {slot}, {function});")
    generated += ["static void set_unknown_slots(void) {", *tables, "}"]
    pe = pefile.PE(str(source), fast_load=True)
    pe.parse_data_directories(directories=[0])
    definition = ["LIBRARY rail_api64", "EXPORTS"]
    exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
    assert len(exports) == 5762 and pe.FILE_HEADER.Machine == 0x8664
    exported = set()
    for i, symbol in enumerate(exports):
        assert symbol.name and not symbol.forwarder
        name = symbol.name.decode("ascii")
        assert name.replace("_", "").isalnum() and len(name) < 260
        target = name
        if name not in KNOWN:
            target = f"df_unsupported_export_{i}"
            generated.append(f'void {target}(void) {{ DFLocalUnsupportedExport("unsupported_export_{name}"); }}')
        definition.append(f"    {name}={target} @{symbol.ordinal}")
        exported.add(name)
    assert KNOWN <= exported
    for i, name in enumerate(("DFLocalAuthorize", "DFLocalRefresh")):
        definition.append(f"    {name} @{60000+i}")
    include = stage / "provider_slots.inc"
    include.write_text("\n".join(generated) + "\n", encoding="ascii")
    def_file = stage / "provider.def"
    def_file.write_text("\n".join(definition) + "\n", encoding="ascii")
    binary = stage / "rail_api64.dll"
    subprocess.run([str(args.compiler.resolve()), "cc", "-target", "x86_64-windows-gnu", "-O2",
        "-Wall", "-Wextra", "-Werror", "-shared", "-I", str(stage), str(HERE / "provider.c"),
        str(def_file), "-lwinhttp", "-o", str(binary)], check=True, timeout=240)
    rebuilt = pefile.PE(str(binary), fast_load=True)
    rebuilt.parse_data_directories(directories=[0,1])
    symbols = {s.name.decode("ascii"): s for s in rebuilt.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    assert set(symbols) == exported | {"DFLocalAuthorize", "DFLocalRefresh"}
    for symbol in exports:
        actual = symbols[symbol.name.decode("ascii")]
        assert actual.ordinal == symbol.ordinal and not actual.forwarder
    imports = [m.dll.decode("ascii") for m in rebuilt.DIRECTORY_ENTRY_IMPORT]
    assert not any("rail" in name.lower() or "gcloud" in name.lower() for name in imports)
    record = {"sdk_metadata_sha256":EXPECTED, "provider_sha256":digest(binary), "original_export_mapping_verified":5762,
        "provider_source_sha256":digest(HERE / "provider.c"),
        "builder_source_sha256":digest(Path(__file__).resolve()),
        "abi_metadata_sha256":digest(ROOT / "outputs/sdk-call-observer/identity-abi.json"),
        "optional_content_abi_sha256":digest(optional_file),
        "expansion_content_abi_sha256":digest(expansion_file),
        "zone_helper_abi_sha256":digest(zone_file),
        "zone_server_abi_sha256":digest(zone_server_file),
        "local_account_interface_abi_sha256":digest(account_file),
        "local_account_info_abi_sha256":digest(account_info_file),
        "compiler_sha256":digest(args.compiler.resolve()),
        "generated_slot_source_sha256":digest(include), "export_definition_sha256":digest(def_file),
        "implemented_sdk_exports":sorted(KNOWN), "imports":imports,
        "original_sdk_loaded":False, "unsupported_calls_stop_with_diagnostics":True,
        "local_account_transport":"authenticated loopback identity v1",
        "licensing_methods_implemented":False, "native_event_delivery_complete":False,
        "event_registration_and_pump":"bounded listener registry; deferred local catalogs 17006/32001 and authenticated local account login 30001",
        "local_optional_catalog_entries":0, "vendor_dlc_ownership_asserted":False,
        "local_distribution_id":"df-local",
        "local_expansion_catalog_entries":0,
        "local_root_zone_id":1, "local_zone_server_addresses_implemented":True,
        "local_zone_languages":["zh-CN"],
        "local_account_info_implemented":True, "vendor_third_party_account_asserted":False,
        "local_account_channel_id":10000,
        "legacy_client_account_type_selector":1,
        "legacy_client_channel_label":"QQ",
        "legacy_client_derived_login_channel":2,
        "identity_and_session_issuer":"df-local",
        "official_qq_identity_or_ticket_supplied":False,
        "player_game_action_report": "explicitly unavailable without process termination; no action payload read",
        "own_provider_observes_supplied_client_callback_module_relative_offsets":True,
        "absolute_application_addresses_recorded_in_public_report":False,
        "full_process_memory_dump_recorded":False,
        "bounded_code_samples_possible_when_test_opted_in":True,
        "runtime_code_sample_maximum_total_bytes":7272,
        "runtime_code_samples_in_source_release":False,
        "local_game_endpoint":"127.0.0.1:65010",
        "game_client_tested":False, "original_lobby_compatible":False}
    (stage / "build-record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    main(parser.parse_args())
