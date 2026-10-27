"""Pure diagnostic Pawn Role/ordinary-reference content factory.

Role value, receiving destination and field handle come from one sealed current
official summary. References come only from the caller's current local Actors.
No account value, GUID, object address, Role business meaning, eight-bit fallback,
native dispatch, process access or packet delivery is selected or inferred.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
from dfserver import legacy_ds_byte_scalar as byte_codec
from dfserver import legacy_ds_bit_archive as bit_archive
from dfserver import legacy_ds_actor_content as actor_content
from dfserver import legacy_ds_rep_layout_refs as reference_codec
from dfserver import legacy_ds_scalar_serializers as scalar_serializers
from dfserver.legacy_ds_byte_scalar import ByteEnumField, NativeByteEnumBinding
from dfserver.legacy_ds_rep_layout_refs import ObjectReference
import native_initial_associations as associations
import native_player_state_initialization as player_states
import native_pawn_role_state as role_source
import native_role_byte_metadata as metadata_source

SUMMARY_PATH = "work/playable-state-observations/1791383498451517700/summary.json"
SUMMARY_SHA256 = "021dac21d75f0d2a1b61b4b4cae2b4685d44ea5062bafa901fb3abb018020d96"
SUMMARY_BYTES = 15863
MODULE_PATH = "work/native_pawn_initial_role_profile.py"
PAWN_CLASS = "BP_DFMCharacter_C"
MAX_SOURCE_BYTES, MAX_TOTAL_BYTES = 32 * 1024 * 1024, 96 * 1024 * 1024


class PawnInitialRoleProfileError(ValueError):
    pass


def _read(root, relative, expected=None):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or "\0" in relative or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise PawnInitialRoleProfileError("plain_project_relative_source_required")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise PawnInitialRoleProfileError("source_outside_project_or_missing")
        before = path.stat()
        if not 0 < before.st_size <= MAX_SOURCE_BYTES:
            raise PawnInitialRoleProfileError("bounded_source_file_required")
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        after = path.stat()
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise PawnInitialRoleProfileError("source_changed_during_read")
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise PawnInitialRoleProfileError("source_sha256_mismatch")
        return raw
    except OSError:
        raise PawnInitialRoleProfileError("source_unavailable") from None


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _summary_field(summary):
    """Validate complete scalar/source/header records, then derive one field."""
    try:
        restart = summary["restart_local_state_observation"]
        bundle = summary["extended_playable_state_observation"]
        role = bundle["pawn_role_state_observation"]
        metadata = summary["role_byte_metadata_observation"]
        if (summary.get("status") != "metadata_export_complete" or summary.get("stage_label") != "official-born"
                or restart.get("source_client_sha256") != role_source.SHIPPING_SHA256
                or restart.get("source_relative_path") != "work/evidence/map-entry-next-20261007/restart-local-state-read-profile.json"
                or restart.get("source_sha256") != "50d1af064830b09c271a59c079d37d03cc6c5d48f21c838ae7b4630061e40e6e"
                or bundle.get("status") != "completed_observations"
                or role.get("kind") != "source_qualified_existing_typed_pawn_role_observation"
                or role.get("status") != "observed" or role.get("source_profile_sha256") != role_source.SOURCE_SHA256
                or role.get("source_offset") != role_source.ROLE_OFFSET or type(role.get("source_offset")) is not int
                or role.get("source_bytes") != 1 or type(role.get("source_bytes")) is not int
                or role.get("field_storage") != "raw_uint8"
                or any(role.get(key) is not True for key in ("selected_pawn_weak_identity_initialized",
                    "identity_and_role_bytes_rechecked", "source_and_image_rechecked"))
                or not _int(role.get("role_raw"), 0, 255)):
            raise PawnInitialRoleProfileError("complete_source_qualified_current_role_required")
        if (metadata.get("kind") != "source_qualified_role_byte_metadata_observation"
                or metadata.get("status") != "observed" or metadata.get("source_profile_sha256") != metadata_source.SOURCE_SHA256
                or type(metadata.get("layout_flags_raw")) is not int or metadata["layout_flags_raw"] != 2
                or any(metadata.get(key) is not True for key in ("normal_receiver_remap_enabled",
                    "receiver_destination_is_normal_actor_path_contract", "current_pawn_layout_selection_is_caller_contract",
                    "image_source_records_and_enum_metadata_rechecked"))
                or metadata.get("actual_receiver_dispatch_observed") is not False
                or metadata.get("role_value_sent") is not False):
            raise PawnInitialRoleProfileError("qualified_normal_actor_role_metadata_required")
        fields = metadata.get("fields")
        if type(fields) is not dict or set(fields) != {"Role", "RemoteRole"}:
            raise PawnInitialRoleProfileError("qualified_role_pair_header_required")
        candidates = []
        for name, field in fields.items():
            if (type(field) is not dict or not _int(field.get("wire_handle"), 1, 65535)
                    or not _int(field.get("destination_offset"), 0, 65535)
                    or field.get("destination_field") not in {"Role", "RemoteRole"}
                    or field.get("parent_remap_applied") is not True
                    or field["destination_field"] == name
                    or field.get("enum_status") != "typed_enum_values_observed"
                    or not _int(field.get("enum_value_count"), 1, 64)
                    or not _int(field.get("enum_maximum"), 0, 256)
                    or not _int(field.get("wire_bit_count"), 0, 8)):
                raise PawnInitialRoleProfileError("observed_byte_enum_header_required")
            binding = NativeByteEnumBinding(role_source.SHIPPING_SHA256,
                metadata_source.BYTE_SERIALIZER_RVA, True, field["enum_maximum"])
            if byte_codec.qualified_byte_bit_count(binding) != field["wire_bit_count"]:
                raise PawnInitialRoleProfileError("byte_enum_bit_width_mismatch")
            if field["destination_field"] == "Role" and field["destination_offset"] == role["source_offset"]:
                candidates.append((name, field, binding))
        if len(candidates) != 1 or len({field["wire_handle"] for field in fields.values()}) != 2:
            raise PawnInitialRoleProfileError("unique_current_role_destination_required")
        name, header, binding = candidates[0]
        value = role["role_raw"]
        if value >= 1 << header["wire_bit_count"]:
            raise PawnInitialRoleProfileError("observed_role_not_exactly_representable")
        return ByteEnumField(header["wire_handle"], value, binding), {
            "source_wire_field": name, "destination_field": "Role", "destination_offset": role["source_offset"],
            "wire_handle": header["wire_handle"], "wire_bit_count": header["wire_bit_count"],
            "observed_raw_role": value, "observed_enum_maximum": header["enum_maximum"]}
    except PawnInitialRoleProfileError:
        raise
    except Exception:
        raise PawnInitialRoleProfileError("current_role_summary_schema_refused") from None


def _reference_handles(root):
    try:
        reference_spec = associations._spec(_read(root, associations.SPEC_PATH, associations.SPEC_SHA256))
        state_spec = player_states._spec(_read(root, player_states.SPEC_PATH, player_states.SPEC_SHA256))
        controller = [row for row in reference_spec["property_profiles"] if row["class_name"] == PAWN_CLASS and row["field_name"] == "Controller"]
        states = [row for row in state_spec["profiles"] if row["class_name"] == PAWN_CLASS and row["field_name"] == "PlayerState"]
        if len(controller) != 1 or len(states) != 1 or controller[0]["asset_path"] != states[0]["asset_path"]:
            raise PawnInitialRoleProfileError("exact_pawn_reference_profiles_required")
        handles = tuple(sorted((controller[0]["wire_handle_derived_from_consumer_counter"], states[0]["wire_handle"])))
        if len(set(handles)) != 2:
            raise PawnInitialRoleProfileError("distinct_pawn_reference_handles_required")
        return handles
    except PawnInitialRoleProfileError:
        raise
    except Exception:
        raise PawnInitialRoleProfileError("pawn_reference_source_schema_refused") from None


def qualified_source_pins(root):
    """Seal the exact safe summary, observed schema sources and existing codecs."""
    try:
        root = Path(root).resolve(strict=True)
        raw = _read(root, SUMMARY_PATH, SUMMARY_SHA256)
        if len(raw) != SUMMARY_BYTES:
            raise PawnInitialRoleProfileError("fixed_summary_byte_count_mismatch")
        _summary_field(json.loads(raw))
        _reference_handles(root)
        pins = {SUMMARY_PATH: SUMMARY_SHA256, associations.SPEC_PATH: associations.SPEC_SHA256,
                player_states.SPEC_PATH: player_states.SPEC_SHA256}
        reference_spec = associations._spec(_read(root, associations.SPEC_PATH, associations.SPEC_SHA256))
        sources = [(row["relative_path"], row["sha256"]) for row in reference_spec["source_pins"]]
        for row in reference_spec["exact_native_code_roots"]:
            sources.extend(((row["code_relative_path"], row["file_sha256"]),
                            (row["asm_relative_path"], row["asm_sha256"])))
        if not 1 <= len(sources) <= 96:
            raise PawnInitialRoleProfileError("bounded_ordinary_reference_source_list_required")
        total = 0
        for relative, expected in sources:
            contents = _read(root, relative, expected)
            total += len(contents)
            if total > MAX_TOTAL_BYTES or relative in pins and pins[relative] != expected:
                raise PawnInitialRoleProfileError("ordinary_reference_source_bound_or_pin_conflict")
            pins[relative] = expected
        for qualify in (role_source.qualified_source_pins, metadata_source.qualified_source_pins,
                        player_states.qualified_player_state_source_pins):
            for relative, digest in qualify(root).items():
                if relative in pins and pins[relative] != digest:
                    raise PawnInitialRoleProfileError("source_pin_conflict")
                pins[relative] = digest
        imported = ((MODULE_PATH, Path(__file__)),
            ("work/native_initial_associations.py", Path(associations.__file__)),
            ("outputs/df-local-server/dfserver/legacy_ds_byte_scalar.py", Path(byte_codec.__file__)),
            ("outputs/df-local-server/dfserver/legacy_ds_bit_archive.py", Path(bit_archive.__file__)),
            ("outputs/df-local-server/dfserver/legacy_ds_actor_content.py", Path(actor_content.__file__)),
            ("outputs/df-local-server/dfserver/legacy_ds_rep_layout_refs.py", Path(reference_codec.__file__)),
            ("outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py", Path(scalar_serializers.__file__)))
        for relative, module in imported:
            raw = _read(root, relative)
            if raw != module.read_bytes():
                raise PawnInitialRoleProfileError("imported_module_source_mismatch")
            pins[relative] = hashlib.sha256(raw).hexdigest()
        return pins
    except PawnInitialRoleProfileError:
        raise
    except Exception:
        raise PawnInitialRoleProfileError("pawn_role_source_qualification_refused") from None


def _seal(root, source_pins):
    pins = qualified_source_pins(root)
    if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
        raise PawnInitialRoleProfileError("caller_pawn_role_source_seal_required")
    return pins


def load_pawn_initial_role_field(root, source_pins):
    """Derive the field from sealed same-source metadata, never an enum default."""
    root = Path(root).resolve(strict=True)
    before = _seal(root, source_pins)
    field, header = _summary_field(json.loads(_read(root, SUMMARY_PATH, SUMMARY_SHA256)))
    if _seal(root, source_pins) != before:
        raise PawnInitialRoleProfileError("pawn_role_sources_changed_during_preparation")
    return field, header


def build_pawn_initial_role_reference_content(root, *, references, source_pins, normal_actor_receive_contract):
    """Merge one Role field and the caller's two local dynamic reference fields."""
    if normal_actor_receive_contract is not True:
        raise PawnInitialRoleProfileError("explicit_normal_actor_receive_path_contract_required")
    root = Path(root).resolve(strict=True)
    before = _seal(root, source_pins)
    field, header = _summary_field(json.loads(_read(root, SUMMARY_PATH, SUMMARY_SHA256)))
    if (type(references) is not tuple or len(references) != 2 or
            any(type(reference) is not ObjectReference for reference in references) or
            tuple(reference.handle for reference in references) != _reference_handles(root)):
        raise PawnInitialRoleProfileError("exact_caller_pawn_reference_fields_required")
    try:
        block = byte_codec.build_byte_reference_content((field,), references)
    except Exception:
        raise PawnInitialRoleProfileError("role_reference_content_construction_refused") from None
    if _seal(root, source_pins) != before:
        raise PawnInitialRoleProfileError("pawn_role_sources_changed_during_preparation")
    info = {"kind": "source_qualified_diagnostic_pawn_role_reference_content", "status": "prepared",
        **header, "source_summary_relative_path": SUMMARY_PATH, "source_summary_sha256": SUMMARY_SHA256,
        "reference_fields_count": len(references), "payload_bits": block.payload_bit_count,
        "payload_sha256": hashlib.sha256(block.payload).hexdigest(), "diagnostic_only": True,
        "normal_actor_receive_path_is_caller_source_contract": True, "actual_receiver_dispatch_observed": False,
        "role_enum_business_mapping_inferred": False, "permanent_role_default_selected": False,
        "official_actor_guid_or_account_value_selected": False, "native_reference_assignment_verified": False,
        "native_role_assignment_verified": False, "role_value_sent": False, "packet_produced_or_sent": False,
        "process_accessed": False, "native_methods_invoked": False, "memory_written": False, "playable_map_verified": False}
    return block, info
