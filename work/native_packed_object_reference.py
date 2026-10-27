"""Pure source-qualified direct subset of the native packed object reference.

This is not an encoded callback decoder. Native consumers extract payload48,
normalize odd modes to 1, and decode only active nonzero payloads in modes 1/2.
Mode 0 and inactive mode 2 therefore permit direct payload extraction. The
consumer may subsequently rewrite its field; we never reproduce those writes.
The caller owns process/image/type/weak-identity and original-storage rechecks.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath

SOURCE_PATH = "work/evidence/map-entry-next-20261007/packed-object-reference-direct-subset-profile.json"
SOURCE_SHA256 = "31399aea7254dc0e46f57bc2f706e54f4f5a752bdff8fb6027b7b56fb8b00215"
MODULE_PATH = "work/native_packed_object_reference.py"
ROOT_SOURCE_PATH = 'work/evidence/current-box-position-research-20261020-v1/native-generic-actor-root-scene-world-origin.json'
ROOT_SOURCE_SHA256 = 'a7f63db3678f20760efbba45139e28d3a2b6c9e2f18b74c3d149aba7324162de'
SHIPPING_SHA256 = "4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0"
IMAGE_SIZE = 536408064
MAX_ADDRESS = 0x7fffffffffff
SAFE_REFUSALS = frozenset(("packed_source_changed", "packed_source_schema_changed",
    "packed_source_qualification_refused", "packed_source_seal_missing_or_changed",
    "packed_reference_not_u64", "packed_runtime_callback_required",
    "packed_direct_pointer_invalid"))
SOURCE_FILE_PINS = {
    "work/evidence/map-entry-next-20261007/actor-get-root-component-full.e36ab0.code": "808444686d58288d3592e97ce86cd63d4cd4e630e2f5ac4d6fcae074ac77513b",
    "work/evidence/map-entry-next-20261007/actor-get-root-component-full.e36ab0.asm.txt": "863830fe0f38ec6c0b9868a9f360987b0a18a301b2ef0e70d122f228785fd54f",
    "work/evidence/map-entry-next-20261007/pc-view-target-getter.12d46020.code": "ed352859d10a48faee46dd59ebf4ac253e308f4de1d1fad977c357bbc9cbdba9",
    "work/evidence/map-entry-next-20261007/pc-view-target-getter.12d46020.asm.txt": "b38b1916efea0db2eec040e32f11798b29ae3b2ebc1a3c84967691cb08fc6a8a",
}


class PackedReferenceError(ValueError):
    pass


def _source(root, relative):
    if (type(relative) is not str or not relative or ":" in relative or "\\" in relative or
            "\0" in relative or PurePosixPath(relative).is_absolute() or
            any(part in ("", ".", "..") for part in relative.split("/"))):
        raise PackedReferenceError("packed_source_qualification_refused")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise PackedReferenceError("packed_source_qualification_refused")
    before = path.stat()
    if not 0 < before.st_size <= 32768:
        raise PackedReferenceError("packed_source_qualification_refused")
    raw = path.read_bytes()
    after = path.stat()
    if (len(raw) != before.st_size or
            (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise PackedReferenceError("packed_source_changed")
    return raw


def qualified_source_pins(root):
    try:
        root = Path(root).resolve(strict=True)
        raw = _source(root, SOURCE_PATH)
        if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
            raise PackedReferenceError("packed_source_changed")
        profile = json.loads(raw)
        if (profile.get("kind") != "source_qualified_packed_object_reference_direct_subset" or
                profile.get("client_sha256") != SHIPPING_SHA256 or
                type(profile.get("image_size")) is not int or profile["image_size"] != IMAGE_SIZE or
                profile.get("direct_subsets") != ["payload_zero", "normalized_mode_zero", "normalized_mode_two_active_zero"] or
                profile.get("contract", {}).get("runtime_callback_followed") is not False or
                profile.get("contract", {}).get("original_field_written") is not False):
            raise PackedReferenceError("packed_source_schema_changed")
        rows = profile.get("source_files")
        if type(rows) is not list or len(rows) != 4:
            raise PackedReferenceError("packed_source_schema_changed")
        pins = {SOURCE_PATH: SOURCE_SHA256}
        for row in rows:
            relative = row["relative_path"]
            contents = _source(root, relative)
            if (relative in pins or type(row["bytes"]) is not int or len(contents) != row["bytes"] or
                    hashlib.sha256(contents).hexdigest() != row["sha256"]):
                raise PackedReferenceError("packed_source_changed")
            pins[relative] = row["sha256"]
        if {relative: digest for relative, digest in pins.items() if relative != SOURCE_PATH} != SOURCE_FILE_PINS:
            raise PackedReferenceError("packed_source_schema_changed")
        contents = _source(root, MODULE_PATH)
        if contents != Path(__file__).read_bytes():
            raise PackedReferenceError("packed_source_changed")
        pins[MODULE_PATH] = hashlib.sha256(contents).hexdigest()
        return pins
    except (OSError, KeyError, TypeError, AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        raise PackedReferenceError("packed_source_qualification_refused") from None


def _seal(source_pins):
    # A collector preflight supplies the full pinned source map. During decode,
    # check this immutable profile plus executing module without file traversal.
    # The newer pdata-bounded Actor getter has the identical e36ab0 code hash.
    # Its caller qualifies the sealed document and native image/cache first.
    if (type(source_pins) is dict and source_pins.get(ROOT_SOURCE_PATH) == ROOT_SOURCE_SHA256
            and source_pins.get(MODULE_PATH) == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        return
    if (type(source_pins) is not dict or source_pins.get(SOURCE_PATH) != SOURCE_SHA256 or
            any(source_pins.get(relative) != digest for relative, digest in SOURCE_FILE_PINS.items()) or
            source_pins.get(MODULE_PATH) != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
        raise PackedReferenceError("packed_source_seal_missing_or_changed")


def safe_reference_header(raw, *, source_pins):
    """Small metadata facts only; contains neither payload, pointer nor key id."""
    _seal(source_pins)
    if type(raw) is not int or not 0 <= raw <= 0xffffffffffffffff:
        raise PackedReferenceError("packed_reference_not_u64")
    stored_mode = (raw >> 48) & 3
    mode = 1 if stored_mode & 1 else stored_mode
    active = True if mode == 1 else bool(raw >> 63)
    payload_nonzero = bool(raw & 0xffffffffffff)
    direct = not payload_nonzero or mode == 0 or mode == 2 and not active
    return {"stored_mode": stored_mode, "normalized_mode": mode, "active": active,
            "payload_nonzero": payload_nonzero, "direct_subset_supported": direct,
            "runtime_callback_required": not direct}


def decode_direct_reference(raw, *, source_pins):
    """Return an INTERNAL pointer only for a source-proven direct representation.

    Never publish this return value as a safe observation. The caller must first
    validate/recheck the returned object and original raw field. Null payload
    skips decode in all native modes; callback modes with a payload refuse.
    """
    header = safe_reference_header(raw, source_pins=source_pins)
    if not header["direct_subset_supported"]:
        raise PackedReferenceError("packed_runtime_callback_required")
    payload = raw & 0xffffffffffff
    # Native active normalization sign-extends bit47. Such references cannot be
    # accepted user objects. Inactive bit47 references are also outside user VA.
    if payload and (payload < 0x10000 or payload > MAX_ADDRESS or payload & 7):
        raise PackedReferenceError("packed_direct_pointer_invalid")
    return payload
