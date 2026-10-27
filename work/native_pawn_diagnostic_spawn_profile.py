"""Load a sealed diagnostic point by recomputing policy from qualified samples.

No source coordinates or steps are embedded here. CONFIG_SHA256 pins the
reviewed current diagnostic samples and context. A same lexical World or
SubWorld name does not prove that an observed Origin applies to a Pawn Root.
The packet producer still owns ActorOpen version, references and lifecycle.
"""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sys

import local_spawn_coordinate_policy as policy

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = "work/evidence/map-entry-next-20261007/pawn-diagnostic-spawn-profile.json"
CONFIG_SHA256 = "1081ba1473507a43f55576a097fc9307ea218d0bf189381343ed34c39860fbc6"
MODULE_PATH = "work/native_pawn_diagnostic_spawn_profile.py"
CLIENT_SHA256 = policy.source_bundle.source_io.SHIPPING_SHA256
ORIGIN_PROFILE_SHA256 = "0d3e82a12dd820abf1ae505ef4b59043bbfffaa5b6d1e4abff85173e47b4f570"
POSITION_PROFILE_SHA256 = "5e9573ac68725496291a884dd29ac0a62379af7b4acdb3c7b055fa77195db7f2"
DEFAULT_PROFILE_SHA256 = policy.source_bundle.source_io.SOURCE_SHA256
MAX_FILE_BYTES, MAX_TOTAL_BYTES = 256 * 1024, 2 * 1024 * 1024
MAX_CONTEXT_SOURCES = 32
SHA = re.compile(r"[0-9a-f]{64}")
sys.path.insert(0, str(ROOT / "outputs/df-local-server"))
from dfserver.legacy_ds_quantized_vector import QuantizedVector10
import dfserver.legacy_ds_quantized_vector as vector_codec


class PawnSpawnProfileError(ValueError):
    pass


def _fail(reason):
    raise PawnSpawnProfileError(reason)


def _relative(value):
    if (type(value) is not str or not value or ":" in value or "\\" in value or "\0" in value or
            PurePosixPath(value).is_absolute() or
            any(p in ("", ".", "..") for p in value.split("/"))):
        _fail("spawn_profile_relative_path_required")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: _fail("spawn_profile_duplicate_json_key")
        result[key] = value
    return result


def _json(raw):
    def constant(value): _fail("spawn_profile_nonfinite_json_number")
    def floating(value):
        number = float(value)
        if not math.isfinite(number): _fail("spawn_profile_nonfinite_json_number")
        return number
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant, parse_float=floating)
    except PawnSpawnProfileError: raise
    except Exception: _fail("spawn_profile_json_refused")
    if type(value) is not dict: _fail("spawn_profile_json_object_required")
    return value


class _Files:
    def __init__(self, root, pins):
        self.root, self.pins, self.total, self.paths = root, dict(pins), 0, set()

    def read(self, relative, expected):
        relative = _relative(relative)
        if type(expected) is not str or SHA.fullmatch(expected) is None:
            _fail("spawn_profile_sha256_required")
        path = (self.root / relative).resolve(strict=True)
        if not path.is_relative_to(self.root) or not path.is_file():
            _fail("spawn_profile_path_escaped_root")
        normalized = os.path.normcase(str(path))
        if relative in self.pins or normalized in self.paths:
            _fail("spawn_profile_duplicate_source_path")
        before = path.stat()
        if not 0 < before.st_size <= MAX_FILE_BYTES:
            _fail("spawn_profile_file_byte_bound")
        raw = path.read_bytes()
        after = path.stat()
        self.total += len(raw)
        if (self.total > MAX_TOTAL_BYTES or len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            _fail("spawn_profile_source_changed_or_byte_bound")
        if hashlib.sha256(raw).hexdigest() != expected:
            _fail("spawn_profile_source_sha256_changed")
        self.paths.add(normalized); self.pins[relative] = expected
        return raw

    def row(self, reference):
        if type(reference) is not dict or set(reference) != {"relative_path", "sha256"}:
            _fail("spawn_profile_reference_schema_required")
        return _json(self.read(reference["relative_path"], reference["sha256"]))


def _samples(summary, label, origin_selection):
    if (summary.get("status") != "metadata_export_complete" or summary.get("stage_label") != label or
            summary.get("required_observations_available") is not True or
            summary.get("first_player_state_status") != "observed"):
        _fail("spawn_profile_completed_current_sample_required")
    restart = summary.get("restart_local_state_observation", {})
    if (type(restart) is not dict or restart.get("status") != "observed" or
            restart.get("source_client_sha256") != CLIENT_SHA256 or
            any(restart.get(k) is not True for k in ("pc_pawn_relation_matches",
                "selected_pc_weak_identity_initialized", "selected_pawn_weak_identity_initialized",
                "identity_and_fields_rechecked", "selected_weak_identity_rechecked_before_and_after"))):
        _fail("spawn_profile_current_pc_pawn_not_qualified")
    bundle = summary.get("extended_playable_state_observation", {})
    if type(bundle) is not dict or bundle.get("status") != "completed_observations":
        _fail("spawn_profile_extended_current_sample_required")
    position = bundle.get("pawn_world_position_observation", {})
    defaults = bundle.get("spawn_default_state_observation", {})
    origin = summary.get("pawn_world_origin_state_observation" if origin_selection == "pawn_owning_world_origin_observed"
                         else "world_origin_state_observation", {})
    if (type(position) is not dict or position.get("status") != "observed" or
            position.get("source_profile_sha256") != POSITION_PROFILE_SHA256 or
            position.get("coordinate_meaning") != "root_component_world_translation_in_client_coordinate_space" or
            any(position.get(k) is not True for k in ("selected_pawn_weak_identity_initialized",
                "root_scene_weak_identity_initialized", "translation_plain_tag_ffff",
                "identities_and_raw_fields_rechecked", "source_and_image_rechecked"))):
        _fail("spawn_profile_current_root_position_not_qualified")
    if (type(defaults) is not dict or defaults.get("status") != "observed" or
            defaults.get("source_profile_sha256") != DEFAULT_PROFILE_SHA256 or
            defaults.get("image_source_and_bytes_rechecked") is not True):
        _fail("spawn_profile_current_spawn_defaults_not_qualified")
    if (type(origin) is not dict or origin.get("status") != "observed" or
            origin.get("source_profile_sha256") != ORIGIN_PROFILE_SHA256 or
            origin.get("selected_world_weak_identity_initialized") is not True or
            origin.get("identity_and_origin_bytes_rechecked") is not True):
        _fail("spawn_profile_applicable_current_world_origin_not_qualified")
    return position["world_position_xyz"], origin["origin_xyz"], defaults["feature_gate"], defaults["default_origin_xyz"]


def _context(context, config):
    if (context.get("kind") != "source_qualified_pawn_spawn_context" or
            context.get("client_sha256") != CLIENT_SHA256 or context.get("diagnostic_only") is not True or
            context.get("official_summary_sha256") != config["official_summary"]["sha256"] or
            context.get("local_summary_sha256") != config["local_summary"]["sha256"]):
        _fail("spawn_profile_context_identity_refused")
    for field in ("current_samples_source_qualified", "shipping_and_map_asset_sources_qualified",
            "same_requested_subworld_and_asset_diagnostic_context_verified",
            "current_pawn_root_world_relationship_verified"):
        if context.get(field) is not True: _fail("spawn_profile_verified_context_required")
    # Ordered request logs and identical assets qualify a diagnostic frame;
    # they do not prove which native loading-cache entry became active.
    if context.get("actual_native_loading_context_selection") != "unknown":
        _fail("spawn_profile_loading_selection_claim_not_qualified")
    applicable, basis = context.get("origin_applies_to_current_pawn_root_verified"), context.get("origin_relationship_basis")
    equal = context.get("pc_and_pawn_world_identity_observed_equal", {})
    if type(applicable) is not dict or type(basis) is not dict or set(applicable) != {"official", "local"} or set(basis) != {"official", "local"}:
        _fail("spawn_profile_explicit_origin_relationship_required")
    for sample in ("official", "local"):
        if applicable[sample] is not True: _fail("spawn_profile_origin_application_not_verified")
        if basis[sample] == "observed_same_world_identity":
            if type(equal) is not dict or equal.get(sample) is not True:
                _fail("spawn_profile_named_world_is_not_identity_proof")
        elif basis[sample] != "pawn_owning_world_origin_observed":
            _fail("spawn_profile_origin_relationship_basis_unsupported")
    selected = context.get("selected_map")
    if (type(selected) is not dict or set(selected) != {"map_id", "subworld_name"} or
            type(selected.get("map_id")) is not int or not 0 < selected["map_id"] < 1 << 31 or
            type(selected.get("subworld_name")) is not str or
            re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", selected["subworld_name"]) is None):
        _fail("spawn_profile_selected_map_context_required")
    return basis, selected


def _resolve(root):
    root = Path(root).resolve(strict=True)
    pins = policy.qualified_local_spawn_policy_sources(root)
    files = _Files(root, pins)
    config = _json(files.read(CONFIG_PATH, CONFIG_SHA256))
    if (set(config) != {"kind", "version", "diagnostic_only", "client_sha256", "official_summary",
            "local_summary", "context_record", "maximum_position_error_world_units", "policy_result"} or
            config.get("kind") != "source_qualified_pawn_diagnostic_spawn_profile" or
            type(config.get("version")) is not int or config["version"] != 1 or
            config.get("diagnostic_only") is not True or config.get("client_sha256") != CLIENT_SHA256):
        _fail("spawn_profile_config_schema_refused")
    official, local, context = (files.row(config[name]) for name in ("official_summary", "local_summary", "context_record"))
    basis, selected = _context(context, config)
    sources = context.get("source_files")
    if type(sources) is not list or not 1 <= len(sources) <= MAX_CONTEXT_SOURCES:
        _fail("spawn_profile_map_source_seal_required")
    for source in sources:
        if type(source) is not dict or set(source) != {"relative_path", "sha256"}:
            _fail("spawn_profile_context_source_schema_refused")
        files.read(source["relative_path"], source["sha256"])
    imported = Path(__file__).read_bytes()
    files.read(MODULE_PATH, hashlib.sha256(imported).hexdigest())
    codec_relative = "outputs/df-local-server/dfserver/legacy_ds_quantized_vector.py"
    codec = (root / codec_relative).read_bytes()
    if (hashlib.sha256(codec).hexdigest() != pins.get(codec_relative) or
            codec != Path(vector_codec.__file__).read_bytes()):
        _fail("spawn_profile_imported_quantized_codec_changed")
    return files.pins, config, context, official, local, basis, selected


def qualified_pawn_spawn_profile_sources(root):
    """Seals sources/data; a missing or unpinned optional config refuses."""
    try: return _resolve(root)[0]
    except PawnSpawnProfileError: raise
    except Exception: _fail("spawn_profile_source_qualification_refused")


def load_pawn_diagnostic_spawn_location(root, source_pins):
    """Return QuantizedVector10 plus safe qualification facts, never a packet.

    Config policy_result is checked against a fresh pure computation; supplied
    steps are never accepted directly. Unknown origin application fails closed.
    """
    try:
        pins, config, context, official, local, basis, selected = _resolve(root)
        if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
            _fail("spawn_profile_caller_source_seal_changed")
        point, origin, gate, default = _samples(official, "official-born", basis["official"])
        _, local_origin, local_gate, local_default = _samples(local, "local-white-fog", basis["local"])
        budget = config["maximum_position_error_world_units"]
        if type(budget) not in (int, float) or not math.isfinite(budget) or not 0 < budget <= 1:
            _fail("spawn_profile_distance_budget_refused")
        result = policy.select_current_sample_spawn_steps(observed_client_xyz=point,
            observed_world_origin=origin, observed_feature_gate=gate, observed_default_origin=default,
            local_world_origin=local_origin, local_feature_gate=local_gate, local_default_origin=local_default,
            current_samples_source_qualified=True, same_map_content_and_subworld_verified=True,
            current_pawn_root_world_relationship_verified=True,
            maximum_position_error_world_units=budget, source_pins=pins)
        if result.get("status") != "diagnostic_steps_selected":
            _fail("spawn_profile_coordinate_policy_refused")
        def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if canonical(result) != canonical(config["policy_result"]):
            _fail("spawn_profile_stored_policy_result_mismatch")
        vector = QuantizedVector10(tuple(result["steps"]))
        if qualified_pawn_spawn_profile_sources(root) != pins:
            _fail("spawn_profile_sources_changed_during_policy")
        if any(source_pins.get(p) != h for p, h in pins.items()):
            _fail("spawn_profile_caller_source_seal_changed")
        safe = {"status": "source_qualified_diagnostic_spawn_location", "diagnostic_only": True,
            "config_sha256": CONFIG_SHA256, "policy_profile_sha256": policy.SOURCE_SHA256,
            "selected_map_id": selected["map_id"], "subworld_name": selected["subworld_name"],
            "origin_input_selection": dict(basis),
            "map_context_basis": "same_requested_subworld_and_asset_diagnostic_context",
            "actual_native_loading_context_selection": "unknown",
            "source_pins_rechecked": True, "coordinate_unit": "native_world_units",
            "maximum_position_error_world_units": budget,
            "position_error_bound_approx": result["position_error_bound_approx"],
            "current_point_is_historical_birth_point": False, "native_writer_rounding_reproduced": False,
            "final_spawned_pawn_root_position_verified": False, "playable_map_verified": False,
            "process_accessed": False, "native_methods_invoked": False, "memory_written": False,
            "packet_produced_or_sent": False}
        return vector, safe
    except PawnSpawnProfileError: raise
    except Exception: _fail("spawn_profile_location_load_refused")
