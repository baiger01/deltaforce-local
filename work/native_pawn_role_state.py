"""Callback-only one-byte Actor.GetLocalRole observation on a typed Pawn.

The caller selects the current Pawn and owns its existing read-only session.
This module opens no process, calls no native method, follows no references,
and writes no memory. Raw Role has no inferred enum meaning or causal claim.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct

import native_connection_binding as _binding
from native_connection_binding import (
    SHIPPING_SHA256, IMAGE_SIZE, MAX_ADDRESS, _pointer, _identity,
    ConnectionBindingObservationError,
)

SOURCE_PATH = "work/evidence/map-entry-next-20261007/pawn-role-read-profile.json"
SOURCE_SHA256 = "48f8cbb7bdb2b2ad5bc68b7527b36e74b080ce2f82a185f7cd9d1c7cdfdec1c9"
MODULE_PATH = "work/native_pawn_role_state.py"
DEPENDENCY_PATH = "work/native_connection_binding.py"
ROLE_OFFSET, ROLE_BYTES = 0x130, 1
MAX_READ_CALLS, MAX_READ_BYTES, MAX_IDENTITY_CALLS = 2, 2, 2


class PawnRoleObservationError(ConnectionBindingObservationError):
    pass


def _read_source(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative
            or "\0" in relative or PurePosixPath(relative).is_absolute()
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise PawnRoleObservationError("invalid_source_path")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise PawnRoleObservationError("source_outside_root_or_missing")
        before = path.stat()
        if not 0 < before.st_size <= 128 * 1024:
            raise PawnRoleObservationError("source_byte_bound")
        with path.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        after = path.stat()
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise PawnRoleObservationError("source_changed_during_read")
        return raw
    except OSError:
        raise PawnRoleObservationError("source_missing_or_unreadable") from None


def qualified_source_pins(root):
    """Check the fixed typed AActor declaration, eight-byte getter, and helpers."""
    try:
        root = Path(root).resolve(strict=True)
        raw = _read_source(root, SOURCE_PATH)
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise PawnRoleObservationError("fixed_profile_sha256_mismatch")
        profile = json.loads(raw)
        if (profile.get("kind") != "source_qualified_existing_typed_pawn_role_read_profile"
                or profile.get("client_sha256") != SHIPPING_SHA256
                or type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE
                or profile.get("required_base_class") != "Pawn"
                or profile.get("field") != {"name": "Actor.GetLocalRole", "offset": "0x130",
                                             "bytes": 1, "storage": "raw_uint8"}
                or profile.get("typed_declaration", {}).get("argument_types") != ["AActor *"]):
            raise PawnRoleObservationError("fixed_role_type_or_offset_schema_changed")
        rows = profile.get("source_files")
        if type(rows) is not list or len(rows) != 3:
            raise PawnRoleObservationError("fixed_source_list_changed")
        pins = {SOURCE_PATH: SOURCE_SHA256}
        for row in rows:
            relative, expected = row.get("relative_path"), row.get("sha256")
            if relative in pins:
                raise PawnRoleObservationError("duplicate_source_path")
            raw = _read_source(root, relative)
            if len(raw) != row.get("bytes") or hashlib.sha256(raw).hexdigest() != expected:
                raise PawnRoleObservationError("fixed_source_sha256_mismatch")
            if relative.endswith(".2f6a330.code") and raw != bytes.fromhex("0fb68130010000c3"):
                raise PawnRoleObservationError("fixed_getter_bytes_changed")
            pins[relative] = expected
        for relative, imported in ((MODULE_PATH, Path(__file__)),
                                   (DEPENDENCY_PATH, Path(_binding.__file__))):
            raw = _read_source(root, relative)
            if raw != imported.read_bytes():
                raise PawnRoleObservationError("imported_source_module_mismatch")
            pins[relative] = hashlib.sha256(raw).hexdigest()
        return pins
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, json.JSONDecodeError):
        raise PawnRoleObservationError("source_qualification_refused") from None


def observe_pawn_role_state(session, module_base, *, pawn_address, object_identity, source_pins):
    """Read two single bytes and two initialized identities, with source/image checks.

    The caller rechecks its current PC/Pawn relationship outside this call.
    Repeated bytes and identity are bounded checks, not an atomic snapshot.
    """
    reads = identity_calls = 0
    try:
        root = Path(__file__).resolve().parent.parent
        pins = qualified_source_pins(root)
        if (type(source_pins) is not dict or
                any(source_pins.get(path) != digest for path, digest in pins.items())):
            raise PawnRoleObservationError("caller_source_seal_missing_or_changed")
        base, pawn = _pointer(module_base), _pointer(pawn_address)
        if base + IMAGE_SIZE - 1 > MAX_ADDRESS or pawn + ROLE_OFFSET > MAX_ADDRESS:
            raise PawnRoleObservationError("invalid_qualified_span")
        if not callable(getattr(session, "read", None)) or not callable(object_identity):
            raise PawnRoleObservationError("controlled_read_and_identity_callbacks_required")

        def image_identity():
            if (getattr(session, "module_sha256", None) != SHIPPING_SHA256
                    or type(getattr(session, "module_size", None)) is not int
                    or session.module_size != IMAGE_SIZE):
                raise PawnRoleObservationError("pinned_image_qualification_required")

        def identity():
            nonlocal identity_calls
            identity_calls += 1
            try:
                row = object_identity(pawn, "Pawn")
            except (ValueError, OSError, TypeError):
                raise PawnRoleObservationError("controlled_identity_callback_refused") from None
            if type(row) is not dict:
                raise PawnRoleObservationError("typed_identity_record_required")
            if "client_sha256" in row and row["client_sha256"] != SHIPPING_SHA256:
                raise PawnRoleObservationError("identity_source_mismatch")
            if type(row.get("serial")) is not int or type(row.get("object_index")) is not int:
                raise PawnRoleObservationError("exact_identity_scalar_types_required")
            value = _identity(row, pawn, "Pawn")
            if value[2] == 0:
                raise PawnRoleObservationError("pawn_weak_identity_uninitialized")
            if "weak_identity_initialized" in row and row["weak_identity_initialized"] is not True:
                raise PawnRoleObservationError("weak_identity_flag_mismatch")
            if "key" in row and row["key"] != struct.pack("<iI", value[1], value[2]).hex():
                raise PawnRoleObservationError("weak_identity_key_mismatch")
            return value

        def read_role():
            nonlocal reads
            reads += 1
            try:
                raw = session.read(pawn + ROLE_OFFSET, ROLE_BYTES)
            except (ValueError, OSError, TypeError):
                raise PawnRoleObservationError("controlled_read_callback_refused") from None
            if type(raw) is not bytes or len(raw) != ROLE_BYTES:
                raise PawnRoleObservationError("incomplete_fixed_role_read")
            return raw

        image_identity()
        before = identity()
        first, second = read_role(), read_role()
        after = identity()
        image_identity()
        if qualified_source_pins(root) != pins:
            raise PawnRoleObservationError("source_seal_changed_during_observation")
        if before != after:
            raise PawnRoleObservationError("pawn_identity_changed")
        if first != second:
            raise PawnRoleObservationError("pawn_role_bytes_changed")
        result = {"status": "observed", "role_raw": first[0],
                  "selected_pawn_weak_identity_initialized": True,
                  "identity_and_role_bytes_rechecked": True,
                  "source_and_image_rechecked": True, "selection": "caller_selected_current_typed_pawn"}
    except (ValueError, OSError, TypeError) as error:
        reason = str(error) if isinstance(error, ConnectionBindingObservationError) else "controlled_observation_refused"
        result = {"status": "refused", "refusal_reason": reason}
    result.update(kind="source_qualified_existing_typed_pawn_role_observation",
        source_profile_sha256=SOURCE_SHA256, source_offset=ROLE_OFFSET, source_bytes=ROLE_BYTES,
        field_storage="raw_uint8", read_calls=reads, read_bytes=reads * ROLE_BYTES,
        identity_callbacks=identity_calls, native_getter_invoked=False, memory_written=False,
        new_process_opened=False, object_references_followed=False, snapshot_is_atomic=False,
        native_serial_continuity_proved=False, role_enum_mapping_inferred=False,
        autonomous_role_inferred=False, pawn_position_verified=False,
        cause_of_missing_input_inferred=False, playable_map_verified=False)
    return result
