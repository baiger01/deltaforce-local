"""Default-off offline fixed PlayerState content factory; no send or ID mapping.

The captured typed class metadata qualifies field definitions, not current ID
values, ownership, channel selection, notify execution, or an applied model.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver import legacy_ds_player_state_human_appearance_content as codec
from dfserver import legacy_ds_int64_value as signed_codec
from dfserver import legacy_ds_scalar_serializers as scalar_codec
from dfserver import legacy_ds_bit_archive as bit_archive
from dfserver import legacy_ds_actor_content as actor_content
import native_game_state_start_profile as scope_qualification

PREFIX = 'work/evidence/map-entry-next-20261007/'
PROFILE = PREFIX + 'player-state-human-appearance-content-source-profile.json'
PROFILE_SHA = '9255baae0b45d2538daad820bf3f1bdafdf70f890eba11314dd0d16fc55421c7'
CAPTURE = 'work/playable-state-observations/1791434154859701200/snapshot/result.json'
CAPTURE_SHA = '0e02cb9cfe63e810d24f298d9c3ff5e254f8334e5b1d719c25307c4aa5fe3ce7'
MODULE_PATH = 'work/native_player_state_human_appearance_content.py'
CLASS = 'BP_SOLPlayerState_C'
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'
FIELDS = (
    ('HeroID', 'HeroId', 0x9f8, 221, 71, 140, 2, 0x15a86560, 'FInt64Property'),
    ('CurrSameTeamAvatarId', 'CurrSameTeamAvatarId', 0xa08, 223, 73, 142, 20, 0x1ab60db0, 'FUInt64Property'),
    ('CurrDiffTeamAvatarId', 'CurrDiffTeamAvatarId', 0xa10, 224, 74, 143, 20, 0x1ab60db0, 'FUInt64Property'))
MAX_SOURCE_BYTES, MAX_TOTAL_BYTES = 2 * 1024 * 1024, 8 * 1024 * 1024


class PlayerStateContentError(ValueError):
    pass


def _read(root, relative):
    if (type(relative) is not str or ':' in relative or '\\' in relative or '\0' in relative
            or PurePosixPath(relative).is_absolute() or any(p in ('', '.', '..') for p in relative.split('/'))):
        raise PlayerStateContentError('ps_content_source_path_refused')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise PlayerStateContentError('ps_content_source_path_refused')
    before = path.stat()
    if not 0 < before.st_size <= MAX_SOURCE_BYTES:
        raise PlayerStateContentError('ps_content_source_byte_bound')
    with path.open('rb') as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    after = path.stat()
    if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise PlayerStateContentError('ps_content_source_changed_during_read')
    return raw


def _derive(capture):
    """Qualify the exact old typed class/complete layout; export no addresses."""
    try:
        first = capture['first_player_state_observation']; ps = first['pc_player_state_reference']
        if (capture.get('status') != 'metadata_export_complete' or capture.get('client_sha256') != codec.SHIPPING_SHA256
                or first.get('status') != 'observed' or first.get('identity_and_fields_rechecked') is not True
                or ps.get('status') != 'typed_existing_reference' or ps.get('required_base_class') != 'PlayerState'
                or type(ps.get('serial')) is not int or ps['serial'] <= 0
                or type(ps.get('class_address')) is not int or ps['class_address'] <= 0
                or ps.get('class_ancestry', [None])[0] != CLASS or 'DFMPlayerState' not in ps['class_ancestry']):
            raise PlayerStateContentError('captured_typed_ps_class_required')
        rows = [row for row in capture['driver_class_exports'] if type(row) is dict
            and row.get('class_name') == CLASS and row.get('class_address') == ps['class_address']]
        if len(rows) != 1:
            raise PlayerStateContentError('captured_unique_ps_export_required')
        export = rows[0]; layout = export['layout']; commands, parents = layout['commands'], layout['parents']
        key = export.get('class_key')
        if (export.get('layout_status') != 'exported_existing' or export.get('native_getter_invoked') is not False
                or type(key) is not str or re.fullmatch('[0-9a-f]{16}', key) is None
                or struct.unpack('<iI', bytes.fromhex(key))[0] < 0
                or struct.unpack('<iI', bytes.fromhex(key))[1] == 0
                or type(commands) is not list or len(commands) != 688 or type(parents) is not list or len(parents) != 115
                or layout.get('command_count') != 688 or layout.get('parent_count') != 115
                or any(type(c) is not dict or type(c.get('command_index')) is not int or c['command_index'] != i
                       for i, c in enumerate(commands))
                or any(type(p) is not dict or type(p.get('parent_index')) is not int or p['parent_index'] != i
                       for i, p in enumerate(parents))):
            raise PlayerStateContentError('captured_complete_ps_layout_required')
        bindings = []
        for _, metadata_name, offset, ci, pi, handle, opcode, table, _ in FIELDS:
            cmd, parent = commands[ci], parents[pi]
            expected = {'command_index': ci, 'parent_index': pi, 'data_offset': offset,
                'relative_handle': handle, 'dispatch_opcode': opcode, 'dispatch_gate_byte': opcode}
            if (any(type(cmd.get(k)) is not int or cmd[k] != v for k, v in expected.items())
                    or cmd.get('descriptor_name') != metadata_name or parent.get('descriptor_name') != metadata_name
                    or type(parent.get('parent_index')) is not int or parent['parent_index'] != pi
                    or type(parent.get('descriptor_address')) is not int or parent['descriptor_address'] <= 0
                    or parent['descriptor_address'] != cmd.get('descriptor_address')
                    or type(parent.get('record_i32_at_0x28')) is not int or parent['record_i32_at_0x28'] != -1
                    or any(type(row.get('record_sha256')) is not str or
                        re.fullmatch('[0-9a-f]{64}', row['record_sha256']) is None for row in (cmd, parent))):
                raise PlayerStateContentError('captured_exact_top_level_ps_fields_required')
            for label, slot, target in (('property_scalar_leaf_hook', 0x88, 0x286c000),
                    ('property_serializer_hook', 0x90, 0x10e5ce20)):
                hook = cmd.get(label)
                if (type(hook) is not dict or hook.get('status') != 'observed_pinned_image_method'
                        or any(type(hook.get(k)) is not int or hook[k] != v for k, v in
                            (('slot', slot), ('target_rva', target), ('vtable_rva', table)))
                        or hook.get('target_module_sha256') != codec.SHIPPING_SHA256
                        or hook.get('inside_pinned_image') is not True or hook.get('identity_rechecked') is not True):
                    raise PlayerStateContentError('captured_exact_typed_ps_hooks_required')
            prefix = [dict(index=c['command_index'], dispatch_opcode=c['dispatch_opcode'],
                relative_handle=c['relative_handle'], descriptor_name=c.get('descriptor_name')) for c in commands[:ci + 1]]
            if scope_qualification.qualify_outer_handle(prefix, dict(name=metadata_name,
                    dispatch_opcode=opcode, ordinary_handle=handle, command_index=ci)) != handle:
                raise PlayerStateContentError('captured_outer_ps_handle_required')
            bindings.append(scalar_codec.NativeScalarBinding(codec.SHIPPING_SHA256, 0x10e5ce20, 0x286c000, table))
        return tuple(bindings)
    except PlayerStateContentError:
        raise
    except Exception:
        raise PlayerStateContentError('captured_ps_content_schema_refused') from None


def qualified_source_pins(root):
    try:
        root = Path(root).resolve(strict=True); raw = _read(root, PROFILE)
        if hashlib.sha256(raw).hexdigest() != PROFILE_SHA:
            raise PlayerStateContentError('ps_content_profile_changed')
        profile = json.loads(raw)
        if (profile.get('kind') != 'source_qualified_fixed_human_player_state_field_content_profile'
                or profile.get('client_sha256') != codec.SHIPPING_SHA256 or profile.get('class_path') != CLASS_PATH
                or profile.get('payload_bits') != codec.PAYLOAD_BITS or profile.get('handles') != list(codec.HANDLES)
                or profile.get('values_selected') is not False or profile.get('wire_native_acceptance_verified') is not False
                or type(profile.get('source_files')) is not dict):
            raise PlayerStateContentError('ps_content_profile_schema_changed')
        pins, total = {PROFILE: PROFILE_SHA}, len(raw)
        for path, digest in profile['source_files'].items():
            raw = _read(root, path); total += len(raw)
            if total > MAX_TOTAL_BYTES or hashlib.sha256(raw).hexdigest() != digest:
                raise PlayerStateContentError('ps_content_source_changed')
            pins[path] = digest
        if pins.get(CAPTURE) != CAPTURE_SHA:
            raise PlayerStateContentError('ps_content_captured_metadata_pin_required')
        _derive(json.loads(_read(root, CAPTURE)))
        for path, module in ((MODULE_PATH, Path(__file__)),
                ('outputs/df-local-server/dfserver/legacy_ds_player_state_human_appearance_content.py', Path(codec.__file__)),
                ('outputs/df-local-server/dfserver/legacy_ds_int64_value.py', Path(signed_codec.__file__)),
                ('outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py', Path(scalar_codec.__file__)),
                ('outputs/df-local-server/dfserver/legacy_ds_bit_archive.py', Path(bit_archive.__file__)),
                ('outputs/df-local-server/dfserver/legacy_ds_actor_content.py', Path(actor_content.__file__)),
                ('work/native_game_state_start_profile.py', Path(scope_qualification.__file__))):
            raw = _read(root, path); total += len(raw)
            if total > MAX_TOTAL_BYTES or raw != module.read_bytes():
                raise PlayerStateContentError('ps_content_imported_module_changed')
            pins[path] = hashlib.sha256(raw).hexdigest()
        return pins
    except PlayerStateContentError:
        raise
    except Exception:
        raise PlayerStateContentError('ps_content_source_qualification_refused') from None


def prepare_player_state_human_appearance_content(root, *, enabled=False, source_pins=None,
        current_local_player_state_class_path=None, hero_id=None, same_team_avatar_id=None,
        diff_team_avatar_id=None, no_byteswap=False, normal_actor_receive_contract=False):
    """Return content plus public grammar facts; no ID values are selected here."""
    if type(enabled) is not bool:
        raise PlayerStateContentError('ps_content_explicit_boolean_required')
    if not enabled:
        return None, {'status': 'disabled', 'diagnostic_only': True, 'packet_produced_or_sent': False}
    if (normal_actor_receive_contract is not True or no_byteswap is not True
            or type(current_local_player_state_class_path) is not str
            or current_local_player_state_class_path != CLASS_PATH):
        raise PlayerStateContentError('ps_content_explicit_same_class_normal_no_byteswap_contract_required')
    root = Path(root).resolve(strict=True); pins = qualified_source_pins(root)
    if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in pins.items()):
        raise PlayerStateContentError('ps_content_caller_source_seal_required')
    bindings = _derive(json.loads(_read(root, CAPTURE)))
    block = codec.build_player_state_human_appearance_content(hero_id=hero_id,
        same_team_avatar_id=same_team_avatar_id, diff_team_avatar_id=diff_team_avatar_id,
        bindings=bindings, no_byteswap=True, normal_actor_receive_contract=True)
    if qualified_source_pins(root) != pins:
        raise PlayerStateContentError('ps_content_sources_changed_during_preparation')
    return block, {'status': 'prepared', 'kind': 'fixed_source_qualified_human_player_state_field_content',
        'diagnostic_only': True, 'class_name': CLASS, 'field_names': [field[0] for field in FIELDS],
        'ordinary_handles': list(codec.HANDLES), 'payload_bits': codec.PAYLOAD_BITS,
        'source_profile_sha256': PROFILE_SHA, 'payload_sha256': hashlib.sha256(block.payload).hexdigest(),
        'value_origin': 'explicit_caller_inputs', 'current_live_values_observed': False,
        'archive_no_byteswap_declared': True, 'actual_archive_mode_verified': False,
        'hero_or_avatar_mapping_selected': False, 'wire_encoding_verified': False,
        'native_field_acceptance_verified': False, 'repnotify_execution_verified': False,
        'model_configuration_applied': False, 'channel_or_peer_selected': False,
        'queued_for_send': False, 'packet_produced_or_sent': False,
        'process_accessed': False, 'native_methods_invoked': False, 'process_memory_written': False,
        'account_or_saved_config_modified': False, 'raw_addresses_or_identity_values_exported': False}
