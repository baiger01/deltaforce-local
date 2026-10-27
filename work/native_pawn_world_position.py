"""Callback-only direct-subset root-component world translation of a typed Pawn.

Only the shared source-qualified packed-reference direct subset and Scene
translation tag FFFF are supported. No guessed mask, runtime callback decoder,
native call, process open, reference sweep, write, or WorldOrigin addition occurs.
The caller owns current PC/Pawn selection and the existing read-only session.
"""
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import struct

import native_connection_binding as _binding
import native_packed_object_reference as _packed
from native_connection_binding import (
    SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _pointer, _identity,
    ConnectionBindingObservationError,
)

SOURCE_PATH = "work/evidence/map-entry-next-20261007/pawn-world-position-direct-subset-read-profile.json"
SOURCE_SHA256 = "5e9573ac68725496291a884dd29ac0a62379af7b4acdb3c7b055fa77195db7f2"
MODULE_PATH = "work/native_pawn_world_position.py"
DEPENDENCY_PATH = "work/native_connection_binding.py"
ROOT_OFFSET, ROOT_BYTES = 0x180, 8
TRANSLATION_OFFSET, TRANSLATION_BYTES = 0x220, 16
METADATA_OFFSET, METADATA_BYTES, PLAIN_TAG = 0x240, 4, 0xFFFF
MAX_READ_CALLS, MAX_READ_BYTES, MAX_IDENTITY_CALLS = 6, 56, 4


class PawnWorldPositionObservationError(ConnectionBindingObservationError):
    pass


def _read_source(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or "\0" in relative or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise PawnWorldPositionObservationError("invalid_source_path")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise PawnWorldPositionObservationError("source_outside_root_or_missing")
        before = path.stat()
        if not 0 < before.st_size <= 128 * 1024:
            raise PawnWorldPositionObservationError("source_byte_bound")
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        after = path.stat()
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise PawnWorldPositionObservationError("source_changed_during_read")
        return raw
    except OSError:
        raise PawnWorldPositionObservationError("source_missing_or_unreadable") from None


def qualified_source_pins(root):
    """Pin complete Actor root and Scene world-location consumers/declarations."""
    try:
        root = Path(root).resolve(strict=True)
        raw = _read_source(root, SOURCE_PATH)
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise PawnWorldPositionObservationError("fixed_profile_sha256_mismatch")
        profile = json.loads(raw)
        if (profile.get("kind") != "source_qualified_direct_subset_pawn_root_world_position_read_profile"
                or profile.get("client_sha256") != SHIPPING_SHA256
                or type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE
                or profile.get("required_base_classes") != ["Pawn", "SceneComponent"]
                or profile.get("root_field") != {"offset": "0x180", "bytes": 8,
                    "storage": "packed_encoded_reference", "accepted_direct_subsets": [
                        "payload_zero", "normalized_mode_zero", "normalized_mode_two_active_zero"]}
                or profile.get("translation_field") != {"offset": "0x220", "bytes": 16,
                    "returned_f32_lanes": [0, 1, 2]}
                or profile.get("metadata_field") != {"offset": "0x240", "bytes": 4,
                    "accepted_tag_u16": 65535}):
            raise PawnWorldPositionObservationError("fixed_position_type_or_offset_schema_changed")
        rows = profile.get("source_files")
        if type(rows) is not list or len(rows) != 6:
            raise PawnWorldPositionObservationError("fixed_source_list_changed")
        pins = {SOURCE_PATH: SOURCE_SHA256}
        for row in rows:
            relative, expected = row.get("relative_path"), row.get("sha256")
            if relative in pins:
                raise PawnWorldPositionObservationError("duplicate_source_path")
            raw = _read_source(root, relative)
            if len(raw) != row.get("bytes") or hashlib.sha256(raw).hexdigest() != expected:
                raise PawnWorldPositionObservationError("fixed_source_sha256_mismatch")
            pins[relative] = expected
        dependency = profile.get("packed_reference_decoder_dependency", {})
        if (dependency.get("module_relative_path") != _packed.MODULE_PATH
                or dependency.get("profile_relative_path") != _packed.SOURCE_PATH
                or dependency.get("source_pins_from_dependency_qualified_source_pins_required") is not True
                or dependency.get("runtime_callback_or_packed_field_rewrite_reproduced") is not False):
            raise PawnWorldPositionObservationError("fixed_packed_decoder_dependency_changed")
        try:
            dependency_pins = _packed.qualified_source_pins(root)
        except _packed.PackedReferenceError:
            raise PawnWorldPositionObservationError("packed_decoder_source_qualification_refused") from None
        if any(relative in pins and pins[relative] != digest for relative, digest in dependency_pins.items()):
            raise PawnWorldPositionObservationError("packed_decoder_source_pin_conflict")
        pins.update(dependency_pins)
        for relative, imported in ((MODULE_PATH, Path(__file__)),
                                   (DEPENDENCY_PATH, Path(_binding.__file__))):
            raw = _read_source(root, relative)
            if raw != imported.read_bytes():
                raise PawnWorldPositionObservationError("imported_source_module_mismatch")
            pins[relative] = hashlib.sha256(raw).hexdigest()
        return pins
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, json.JSONDecodeError):
        raise PawnWorldPositionObservationError("source_qualification_refused") from None


def observe_pawn_world_position(session, module_base, *, pawn_address, object_identity, source_pins):
    """Read at most six fixed spans/56 bytes and four initialized identities.

    Repeated raw bytes and identities establish bounded consistency, not an
    atomic snapshot. The caller rechecks its current PC/Pawn relationship.
    Unsupported representations never produce a coordinate or guessed pointer.
    """
    reads = read_bytes = identity_calls = 0
    reference_header = None
    try:
        project = Path(__file__).resolve().parent.parent
        pins = qualified_source_pins(project)

        def check_caller_pins():
            if (type(source_pins) is not dict or
                    any(source_pins.get(path) != digest for path, digest in pins.items())):
                raise PawnWorldPositionObservationError("caller_source_seal_missing_or_changed")

        check_caller_pins()
        base, pawn = _pointer(module_base), _pointer(pawn_address)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS or pawn + ROOT_OFFSET + ROOT_BYTES - 1 > MAX_ADDRESS:
            raise PawnWorldPositionObservationError("invalid_qualified_span")
        if not callable(getattr(session, "read", None)) or not callable(object_identity):
            raise PawnWorldPositionObservationError("controlled_read_and_identity_callbacks_required")

        def check_image():
            if (getattr(session, "module_sha256", None) != SHIPPING_SHA256
                    or type(getattr(session, "module_size", None)) is not int
                    or session.module_size != IMAGE_SIZE):
                raise PawnWorldPositionObservationError("pinned_image_qualification_required")

        def identity(address, expected):
            nonlocal identity_calls
            if identity_calls >= MAX_IDENTITY_CALLS:
                raise PawnWorldPositionObservationError("identity_budget_exhausted")
            identity_calls += 1
            try:
                row = object_identity(address, expected)
            except Exception:
                raise PawnWorldPositionObservationError("controlled_identity_callback_refused") from None
            if type(row) is not dict:
                raise PawnWorldPositionObservationError("typed_identity_record_required")
            if "client_sha256" in row and row["client_sha256"] != SHIPPING_SHA256:
                raise PawnWorldPositionObservationError("identity_source_mismatch")
            if type(row.get("serial")) is not int or type(row.get("object_index")) is not int:
                raise PawnWorldPositionObservationError("exact_identity_scalar_types_required")
            value = _identity(row, address, expected)
            if value[2] == 0:
                reason = "pawn_weak_identity_uninitialized" if expected == "Pawn" else "root_scene_weak_identity_uninitialized"
                raise PawnWorldPositionObservationError(reason)
            if "weak_identity_initialized" in row and row["weak_identity_initialized"] is not True:
                raise PawnWorldPositionObservationError("weak_identity_flag_mismatch")
            if "key" in row and row["key"] != struct.pack("<iI", value[1], value[2]).hex():
                raise PawnWorldPositionObservationError("weak_identity_key_mismatch")
            return value

        def read(address, size):
            nonlocal reads, read_bytes
            if (type(address) is not int or size not in (ROOT_BYTES, METADATA_BYTES, TRANSLATION_BYTES)
                    or not 0x10000 <= address <= MAX_ADDRESS or address + size - 1 > MAX_ADDRESS):
                raise PawnWorldPositionObservationError("invalid_fixed_read_span")
            if reads >= MAX_READ_CALLS or read_bytes + size > MAX_READ_BYTES:
                raise PawnWorldPositionObservationError("fixed_read_budget_exhausted")
            reads += 1
            read_bytes += size
            try:
                raw = session.read(address, size)
            except Exception:
                raise PawnWorldPositionObservationError("controlled_read_callback_refused") from None
            if type(raw) is not bytes or len(raw) != size:
                raise PawnWorldPositionObservationError("incomplete_fixed_position_read")
            return raw

        check_image()
        pawn_before = identity(pawn, "Pawn")
        root_first = read(pawn + ROOT_OFFSET, ROOT_BYTES)
        original_root = struct.unpack("<Q", root_first)[0]
        try:
            reference_header = _packed.safe_reference_header(original_root, source_pins=source_pins)
            scene = _packed.decode_direct_reference(original_root, source_pins=source_pins)
        except _packed.PackedReferenceError as error:
            if str(error) == "packed_runtime_callback_required":
                reason = "root_runtime_callback_required"
            elif str(error) == "packed_direct_pointer_invalid":
                reason = "invalid_direct_root_reference"
            else:
                reason = "root_packed_reference_decoder_refused"
            raise PawnWorldPositionObservationError(reason) from None
        if scene == 0:
            raise PawnWorldPositionObservationError("root_component_missing")
        scene = _pointer(scene)
        if scene + METADATA_OFFSET + METADATA_BYTES - 1 > MAX_ADDRESS:
            raise PawnWorldPositionObservationError("invalid_root_scene_span")
        scene_before = identity(scene, "SceneComponent")
        metadata_first = read(scene + METADATA_OFFSET, METADATA_BYTES)
        if struct.unpack_from("<H", metadata_first)[0] != PLAIN_TAG:
            raise PawnWorldPositionObservationError("translation_encoded_or_unsupported")
        payload_first = read(scene + TRANSLATION_OFFSET, TRANSLATION_BYTES)
        payload_second = read(scene + TRANSLATION_OFFSET, TRANSLATION_BYTES)
        metadata_second = read(scene + METADATA_OFFSET, METADATA_BYTES)
        root_second = read(pawn + ROOT_OFFSET, ROOT_BYTES)
        scene_after = identity(scene, "SceneComponent")
        pawn_after = identity(pawn, "Pawn")
        if qualified_source_pins(project) != pins:
            raise PawnWorldPositionObservationError("source_seal_changed_during_observation")
        check_caller_pins()
        check_image()
        if pawn_before != pawn_after:
            raise PawnWorldPositionObservationError("pawn_identity_changed")
        if scene_before != scene_after:
            raise PawnWorldPositionObservationError("root_scene_identity_changed")
        if root_first != root_second:
            raise PawnWorldPositionObservationError("pawn_root_reference_bytes_changed")
        if metadata_first != metadata_second:
            raise PawnWorldPositionObservationError("scene_translation_metadata_bytes_changed")
        if payload_first != payload_second:
            raise PawnWorldPositionObservationError("scene_translation_payload_bytes_changed")
        x, y, z = struct.unpack_from("<fff", payload_first)
        if not all(math.isfinite(value) for value in (x, y, z)):
            raise PawnWorldPositionObservationError("world_position_xyz_nonfinite")
        result = {"status": "observed", "world_position_xyz": {"x": x, "y": y, "z": z},
            "selected_pawn_weak_identity_initialized": True,
            "root_scene_weak_identity_initialized": True,
            "root_reference_original_plain": original_root == scene,
            "root_reference_direct_subset": True, "translation_plain_tag_ffff": True,
            "identities_and_raw_fields_rechecked": True, "source_and_image_rechecked": True,
            "selection": "caller_selected_current_typed_pawn_root_scene_component",
            "coordinate_meaning": "root_component_world_translation_in_client_coordinate_space"}
    except (ValueError, OSError, TypeError) as error:
        reason = str(error) if isinstance(error, ConnectionBindingObservationError) else "controlled_observation_refused"
        result = {"status": "refused", "refusal_reason": reason}
    if reference_header is not None:
        result["root_reference_header"] = reference_header
    result.update(kind="source_qualified_direct_subset_pawn_root_world_position_observation",
        source_profile_sha256=SOURCE_SHA256, root_source_offset=ROOT_OFFSET,
        translation_source_offset=TRANSLATION_OFFSET, metadata_source_offset=METADATA_OFFSET,
        read_calls=reads, read_bytes=read_bytes, identity_callbacks=identity_calls,
        native_getter_invoked=False, memory_written=False, new_process_opened=False,
        encoded_pointer_decoded=False, encoded_translation_decoded=False,
        runtime_reference_callback_invoked=False, packed_reference_field_written=False,
        pointer_mask_guessed=False,
        arbitrary_object_scan_performed=False, snapshot_is_atomic=False,
        native_serial_continuity_proved=False, world_origin_added=False,
        global_position_inferred=False, spawn_position_inferred=False,
        level_transform_verified=False, cause_of_white_fog_inferred=False, playable_map_verified=False)
    return result


observe_pawn_world_position_state = observe_pawn_world_position
