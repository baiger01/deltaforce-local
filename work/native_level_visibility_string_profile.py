"""Sealed current-build static qualification for string-only PC fields 83/84.

The saved ClassNetCache supplies field indices. Static UHT and offline native
reports supply the parameter and default serializer grammar. No captured
visibility body, current PackageMap override, dispatch, or actor readiness is
claimed. Callers retain admission, receipt, exact field boundaries, and state.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath

from dfserver import legacy_ds_level_visibility as _codec
from dfserver.legacy_ds_level_visibility import (
    CLASS_PATH, SHIPPING_SHA256, SERVER_FUNCTION_FLAGS, LevelVisibilityProfile,
    VisibilityDecodeError,
)


SPEC_PATH = "work/evidence/level-visibility-string-reclosure-20261020-v1/string-profile.json"
SPEC_SHA256 = "b449d4e1b154e92c460cb13abdabe629d86cf4b9814fdf10a6912189bd2298bb"
RUNTIME_METADATA_PATH = "work/native-client-tests/1792460999986794500/owned-gameplay-metadata.json"
CACHE_SHA256 = "dfd5c279d7db45842cee2bbc485ac8bf3cab03e4249ef5fe36bc9e8d6cd14754"
MODULES = ("work/native_level_visibility_string_profile.py",
           "outputs/df-local-server/dfserver/transport/native/legacy_ds_level_visibility.py")
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
AUDIT = "work/evidence/map-system-audit-20261018/"
FRESH = "work/evidence/level-visibility-string-reclosure-20261020-v1/"


def _read(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("Visibility evidence requires a plain project-relative path")
    try:
        path = (root / relative).resolve(strict=True)
        if (not path.is_relative_to(root) or not path.is_file()
                or not 0 < path.stat().st_size <= MAX_SOURCE_BYTES):
            raise ValueError("Visibility source is missing or exceeds its bound")
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError("Visibility source grew beyond its bound")
    except OSError as error:
        raise ValueError("Visibility source could not be read") from error
    return raw, hashlib.sha256(raw).hexdigest()


def _validate(spec):
    if (spec.get("kind") != "static_source_qualified_pc_level_visibility_string_profile_v1"
            or spec.get("client_sha256") != SHIPPING_SHA256
            or spec.get("cache_manifest_sha256") != CACHE_SHA256
            or spec.get("class_path") != CLASS_PATH
            or type(spec.get("exclusive_index_maximum")) is not int
            or spec["exclusive_index_maximum"] != 245
            or spec.get("internal_ack") is not False or spec.get("export_mode") is not False):
        raise ValueError("Visibility profile differs from the fixed native build")
    functions = spec.get("functions")
    if type(functions) is not list or len(functions) != 2:
        raise ValueError("Exactly two visibility declarations are required")
    for row, name, index, size, kind, flags, records in zip(functions,
            ("ServerUpdateLevelVisibility", "ServerUpdateMultipleLevelsVisibility"),
            (83, 84), (20, 16), (25, 22), (0x108001, 0x208001), (1, 2)):
        if (row.get("name") != name or any(type(row.get(key)) is not int or row[key] != value
                for key, value in (("rep_index", index), ("function_flags", SERVER_FUNCTION_FLAGS),
                    ("parameter_struct_size", size), ("parameter_parent_count", 1),
                    ("generation_type", kind), ("field_class_flags", flags),
                    ("uht_record_count_including_inner", records)))):
            raise ValueError("Visibility field, parameter type, or flags changed")
    rules = spec.get("wire_rules", {})
    expected = {
        "parameter_presence_bits": 1, "parameter_present_required": True,
        "bool_presence_bypass_class_mask": 0x20000,
        "multiple_array_count": "unaligned_raw_uint16",
        "struct_order": ["file_name_omitted_bit", "visible_bit", "package_name", "conditional_file_name"],
        "omitted_filename_loading_behavior": "copy_full_package_name_pair",
        "fname_string_branch": "hardcoded_false_bit_signed_fstring_length_payload_raw_uint32_number",
        "accepted_string_subset": "bounded_canonical_ASCII_or_valid_UTF16LE_terminated",
        "fname_identity": "preserve_full_text_and_number_pair",
        "hardcoded_names_supported": False, "parameter_termination": "exact_eof",
        "transaction_id_field_present": False,
    }
    if rules != expected or any(type(rules[key]) is not type(value) for key, value in expected.items()):
        raise ValueError("Visibility string parameter grammar changed")
    qualification = spec.get("qualification", {})
    positive = ("saved_current_build_class_net_cache_observed", "static_parameter_declarations_verified",
                "native_parameter_presence_grammar_recovered", "native_struct_serializer_chain_recovered",
                "native_fname_fstring_array_string_grammar_recovered")
    negative = ("actual_string_fixture_eof_verified", "runtime_function_parameter_layout_observed",
                "runtime_package_map_override_observed", "native_dispatch_verified",
                "level_visibility_transaction_ack_proven", "scene_ready_verified",
                "owner_visibility_proves_live_actor", "historical_metadata_is_current_admission_proof")
    if (set(qualification) != set(positive + negative)
            or any(qualification.get(key) is not True for key in positive)
            or any(qualification.get(key) is not False for key in negative)):
        raise ValueError("Visibility qualification exceeds the recovered evidence")


def _validate_runtime_metadata(data):
    if (data.get("kind") != "owned_gameplay_existing_metadata_observation"
            or data.get("status") != "observed" or data.get("client_sha256") != SHIPPING_SHA256
            or any(data.get(key) is not True for key in ("identities_and_fields_rechecked",
                "selected_roots_rechecked", "process_identity_rechecked"))
            or any(data.get(key) is not False for key in ("process_memory_written",
                "native_methods_invoked", "native_layouts_constructed", "packets_sent"))):
        raise ValueError("Saved PC metadata identity or read-only scope changed")
    objects = data.get("objects")
    if type(objects) is not list or not 1 <= len(objects) <= 64:
        raise ValueError("Saved PC metadata exceeds its object bound")
    controllers = [row for row in objects if row.get("class_path") == CLASS_PATH]
    if len(controllers) != 1:
        raise ValueError("Exactly one saved primary PC class is required")
    cache = controllers[0].get("existing_driver_class", {})
    if (cache.get("exclusive_index_maximum") != 245 or cache.get("cache_status") != "exported_existing"
            or cache.get("native_getter_invoked") is not False):
        raise ValueError("Saved primary PC ClassNetCache changed")
    wanted = {"ServerUpdateLevelVisibility": (83, 479880546),
              "ServerUpdateMultipleLevelsVisibility": (84, 2690763957)}
    found = {}
    for node in cache.get("cache_nodes", []):
        for row in node.get("fields", []):
            name = row.get("descriptor_name")
            if name in wanted:
                if (name in found or (row.get("rep_index"), row.get("checksum")) != wanted[name]
                        or row.get("descriptor_representation") != 1
                        or row.get("incompatible") is not False):
                    raise ValueError("Saved PC visibility field identity changed")
                found[name] = row
    if set(found) != set(wanted):
        raise ValueError("Saved primary PC visibility fields are missing")


def _qwords(report, rva):
    rows = [row for row in report["records"] if row["rva"] == rva]
    if len(rows) != 1:
        raise ValueError("Native declaration record is missing or duplicated")
    return {row["offset"]: int(row["value"], 16) for row in rows[0]["qwords"]}


def _function(report, rva):
    rows = [row for row in report["functions"] if row["requested_rva"] == rva]
    if len(rows) != 1:
        raise ValueError("Native function instruction source is missing or duplicated")
    row = rows[0]
    # The property builder ends in a switch data table. Only its preceding
    # instruction sites are used; the table is separately sealed as raw data.
    builder_with_data = (rva == "0x10ea37f0" and row.get("span_start") == rva
                         and row.get("span_bytes") == 8768 and row.get("decoded_bytes") == 8626)
    if row.get("linear_decode_covers_extent") is not True and not builder_with_data:
        raise ValueError("Native function instruction extent is not closed")
    return {item["rva"]: item for item in row["instructions"]
            if rva != "0x10ea37f0" or int(item["rva"], 16) < 0x10EA59A0}


def _instruction(report, function, at, mnemonic, operands):
    row = _function(report, function).get(at, {})
    if row.get("mnemonic") != mnemonic or row.get("operands") != operands:
        raise ValueError("Native visibility serializer instruction changed")


def _validate_artifacts(spec, artifacts):
    _validate_runtime_metadata(artifacts[RUNTIME_METADATA_PATH])
    uht = artifacts[AUDIT + "native-level-visibility-uht-records-recheck-v1.json"]
    props = artifacts[AUDIT + "native-level-visibility-property-records-and-exec-table-v1.json"]
    for row in spec["functions"]:
        record = _qwords(uht, row["function_record_rva"])
        if (record["0x28"] != row["parameter_struct_size"] or record["0x40"] != SERVER_FUNCTION_FLAGS
                or record["0x30"] - 0x140000000 != int(row["parameter_pointer_array_rva"], 16)
                or record["0x38"] & 0xFFFFFFFF != row["uht_record_count_including_inner"]):
            raise ValueError("Native visibility UHT function declaration changed")
        parameter = _qwords(props, row["parameter_record_rva"])
        if (parameter["0x18"] & 0x3F != row["generation_type"]
                or parameter["0x20"] != 1):
            raise ValueError("Native visibility parameter kind changed")
    record = _qwords(uht, "0x1d80af10")
    if (record["0x20"], record["0x28"]) != (20, 4):
        raise ValueError("Native visibility struct size or alignment changed")
    for at, offset in (("0x1b5d3918", 0), ("0x1b5d38f0", 8)):
        field = _qwords(props, at)
        if field["0x18"] & 0x3F != 20 or field["0x20"] != (offset << 32) | 1:
            raise ValueError("Native visibility FName member declaration changed")
    inner = _qwords(props, "0x1b5d3df8")
    if inner["0x18"] & 0x3F != 25 or inner["0x28"] != 0x1533ACA80:
        raise ValueError("Native visibility array struct inner declaration changed")
    cppops = artifacts[AUDIT + "native-level-visibility-struct-cppops-recheck-v1.json"]
    tables = [row for row in cppops["vtables"] if row["rva"] == "0x1b5d7bd0"]
    if (len(tables) != 1 or [row["target_rva"] for row in tables[0]["entries"]
            if row["slot"] == "0x70"] != ["0x133af3e0"]):
        raise ValueError("Native visibility struct CppOps serializer changed")
    builder = artifacts[AUDIT + "native-client-set-rotation-property-grammar-dispatch.json"]
    _instruction(builder, "0x10ea37f0", "0x10ea4e62", "call", "0x10e643d0")
    _instruction(builder, "0x10ea37f0", "0x10ea5103", "call", "0x10e98af0")
    # This code-cache span is a switch data table, not decoded instructions.
    switch = artifacts[FRESH + "native-array-property-class-and-switch.json"]
    span = [row for row in switch["functions"] if row["requested_rva"] == "0x10ea59f8"]
    raw = bytes.fromhex("4a4eea10434fea102050ea10eb50ea10")
    if (len(span) != 1 or span[0]["span_bytes"] != len(raw)
            or span[0]["code_sha256"] != hashlib.sha256(raw).hexdigest()
            or int.from_bytes(raw[:4], "little") != 0x10EA4E4A
            or int.from_bytes(raw[12:16], "little") != 0x10EA50EB):
        raise ValueError("Native visibility property-generation switch data changed")
    _instruction(artifacts[FRESH + "native-property-class-getters.json"],
                 "0x10e98af0", "0x10e98b47", "mov", "r9d, 0x108001")
    _instruction(artifacts[FRESH + "native-array-property-actual-class-getter.json"],
                 "0x10e643d0", "0x10e64427", "mov", "r9d, 0x208001")
    wire = artifacts[AUDIT + "native-level-visibility-wire-name-array-recheck-v1.json"]
    _instruction(wire, "0x10cf7080", "0x10cf709e", "call", "qword ptr [rax + 0x278]")
    _instruction(wire, "0x10cf7080", "0x10cf70b0", "call", "0x10e05bc0")
    _instruction(wire, "0x10e03830", "0x10e03836", "jmp", "0x10e05bc0")
    _instruction(wire, "0x10e05bc0", "0x10e05c94", "call", "0x109ea340")
    _instruction(wire, "0x10e05bc0", "0x10e05ccd", "mov", "r8d, 4")
    _instruction(wire, "0x12dc20b0", "0x12dc2125", "mov", "r8d, 2")
    _instruction(wire, "0x133af3e0", "0x133af3e5", "jmp", "0x12d4c0d0")
    _instruction(wire, "0x109ea340", "0x109ea3cf", "jns", "0x109ea426")
    serializer = artifacts[AUDIT + "native-level-visibility-server-consumers-recheck-v1.json"]
    for at, operation, operands in (
            ("0x12d4c138", "movzx", "eax, byte ptr [rbx + 0x10]"),
            ("0x12d4c14e", "call", "qword ptr [rax + 0x68]"),
            ("0x12d4c162", "call", "qword ptr [rax + 0x68]"),
            ("0x12d4c16e", "call", "qword ptr [rax + 0x50]"),
            ("0x12d4c186", "call", "qword ptr [rax + 0x50]"),
            ("0x12d4c194", "mov", "qword ptr [rsi], rax")):
        _instruction(serializer, "0x12d4c0d0", at, operation, operands)
    reader = artifacts[AUDIT + "native-economy-interaction-normal-rpc-object-receive-v1.json"]
    _instruction(reader, "0x12db93c0", "0x12db9679", "shr", "rcx, 0x11")
    _instruction(reader, "0x12db93c0", "0x12db96cf", "inc", "qword ptr [r13 + 0xa8]")
    _instruction(reader, "0x12db93c0", "0x12db96e1", "je", "0x12db98ad")
    _instruction(artifacts[AUDIT + "native-owned-weapon-rpc-struct-receive-and-netserialize-v1.json"],
                 "0x10e8ee50", "0x10e8ee91", "call", "qword ptr [rax + 0x70]")
    _instruction(artifacts[AUDIT + "native-world-item-move-rpc-recursive-enum-source-v1.json"],
                 "0x12dc23f0", "0x12dc24ad", "call", "0x12dc20b0")


def qualified_level_visibility_sources(root):
    """Recheck bounded repo artifacts and return their complete current seals."""
    root = Path(root).resolve(strict=True)
    raw, digest = _read(root, SPEC_PATH)
    if digest != SPEC_SHA256:
        raise ValueError("Visibility string profile source seal changed")
    try:
        spec = json.loads(raw)
        _validate(spec)
        files = spec.get("source_files")
        if type(files) is not list or not 1 <= len(files) <= 64:
            raise ValueError("Visibility source list exceeds its bound")
        pins, artifacts, total = {SPEC_PATH: digest}, {}, len(raw)
        for row in files:
            relative = row["relative_path"]
            raw, actual = _read(root, relative)
            total += len(raw)
            if total > MAX_TOTAL_BYTES or actual != row["sha256"] or relative in pins:
                raise ValueError("Visibility source identity changed or budget exceeded")
            pins[relative] = actual
            artifacts[relative] = json.loads(raw)
            if relative.startswith((AUDIT, FRESH)):
                report = artifacts[relative]
                if (report.get("client_sha256") != SHIPPING_SHA256
                        or report.get("process_access") is not False
                        or report.get("client_launched") is not False
                        or report.get("cache_manifest_sha256", CACHE_SHA256) != CACHE_SHA256):
                    raise ValueError("Visibility native source build or offline scope changed")
        _validate_artifacts(spec, artifacts)
        for relative in MODULES:
            raw, pins[relative] = _read(root, relative)
            total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Visibility source budget exceeded")
        if (Path(__file__).resolve() != (root / MODULES[0]).resolve()
                or Path(_codec.__file__).resolve() != (root / MODULES[1]).resolve()):
            raise ValueError("Visibility helper or codec was imported from another checkout")
    except (TypeError, KeyError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError("Visibility source is not a qualified static declaration") from error
    return pins


def load_level_visibility_profile(root, sealed_sources):
    """Return a static profile only after rechecking the caller's source seals."""
    if type(sealed_sources) is not dict:
        raise ValueError("An explicit caller-sealed visibility source dictionary is required")
    pins = qualified_level_visibility_sources(root)
    if any(sealed_sources.get(relative) != digest for relative, digest in pins.items()):
        raise ValueError("Visibility sources changed after caller sealing")
    return LevelVisibilityProfile(CLASS_PATH, 245, 83, 84, SERVER_FUNCTION_FLAGS, SPEC_SHA256,
                                  runtime_package_map_override_observed=False,
                                  actual_string_fixture_eof_verified=False)


def decode_string_parameters(raw, bit_count, *, rep_index, profile):
    """Decode only the sealed string branch with an exact parameter boundary."""
    if (type(profile) is not LevelVisibilityProfile or profile.source_sha256 != SPEC_SHA256
            or profile.actual_string_fixture_eof_verified is not False
            or profile.runtime_package_map_override_observed is not False):
        raise VisibilityDecodeError("The current static string visibility profile is required")
    return _codec.decode_level_visibility_parameters(raw, bit_count, rep_index=rep_index,
                                                     profile=profile)


qualified_sources = qualified_level_visibility_sources
loadProfile = load_level_visibility_profile
