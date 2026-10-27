"""One default-off offline official-trial value profile; no sender or ID mapping."""
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys

PROFILE = 'work/evidence/map-entry-next-20261007/official-human-player-state-trial-profile-20261008.json'
PROFILE_SHA256 = '1d1430958136b40054561ffb27b8f1b382cda4edc3716e4c6a7341c09eb12415'
MODULE_PATH = 'work/native_player_state_human_trial_profile.py'
CLIENT_SHA256 = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CLASS_NAME = 'BP_SOLPlayerState_C'
CLASS_PATH = '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C'
VALUE_SOURCE_PROFILE_SHA256 = 'd75d8081bae1e7156d7b42f8d85608c2b38c6b0509d8eb37fad9cb9e2df7a371'
OFFICIAL_TRIAL = '1791453933656875500'
OFFICIAL_SUMMARY = f'work/playable-state-observations/{OFFICIAL_TRIAL}/summary.json'
OFFICIAL_SNAPSHOT = f'work/playable-state-observations/{OFFICIAL_TRIAL}/snapshot/result.json'
LOCAL_SUMMARY = 'work/playable-state-observations/1791443825780353100/summary.json'
SOURCES = (OFFICIAL_SUMMARY, OFFICIAL_SNAPSHOT, LOCAL_SUMMARY)
CODEC_PATHS = tuple('outputs/df-local-server/dfserver/' + name + '.py' for name in (
    'legacy_ds_player_state_human_appearance_content', 'legacy_ds_int64_value',
    'legacy_ds_scalar_serializers', 'legacy_ds_bit_archive', 'legacy_ds_actor_content'))
FIELD_SPECS = (
    ('HeroID', 'FInt64Property', True, 0x9f8, 221, 71, 140, 'OnRep_HeroIDChanged', 0x15a86560),
    ('CurrSameTeamAvatarId', 'FUInt64Property', False, 0xa08, 223, 73, 142, 'OnRep_CurrAvatarId', 0x1ab60db0),
    ('CurrDiffTeamAvatarId', 'FUInt64Property', False, 0xa10, 224, 74, 143, 'OnRep_CurrAvatarId', 0x1ab60db0))
FIELD_NAMES = [row[0] for row in FIELD_SPECS]
VALUES = (88000000025,) * 3
PAYLOAD_BITS = 249
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_PROFILE_BYTES = 128 * 1024
FALSE_FLAGS = ('wire_native_acceptance_verified', 'repnotify_execution_verified',
    'model_configuration_applied', 'general_operator_mapping_verified', 'Uin_mapping_inferred',
    'current_live_values_observed', 'channel_or_peer_selected', 'queued_for_send',
    'packet_produced_or_sent', 'process_accessed', 'native_methods_invoked',
    'process_memory_written', 'account_data_exported', 'raw_identity_or_addresses_exported')
SAFE_REASONS = frozenset(('trial_explicit_boolean_required', 'trial_source_path_refused',
    'trial_source_size_or_change_refused', 'trial_observed_relations_required',
    'trial_exact_typed_fields_required', 'trial_source_values_required',
    'trial_same_official_values_required', 'trial_current_class_source_required',
    'trial_source_changed_during_seal', 'trial_profile_changed', 'trial_profile_schema_refused',
    'trial_codec_source_changed', 'trial_imported_source_changed', 'trial_payload_refused',
    'trial_profile_already_exists_different', 'trial_source_preparation_refused', 'trial_load_refused'))


class TrialProfileError(ValueError):
    pass


def _reason(error, fallback):
    if (type(error) is TrialProfileError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in SAFE_REASONS):
        return error.args[0]
    return fallback


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(root, relative, maximum=MAX_SOURCE_BYTES):
    if (type(relative) is not str or ':' in relative or '\\' in relative or '\0' in relative
            or any(p in ('', '.', '..') for p in relative.split('/'))):
        raise TrialProfileError('trial_source_path_refused')
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise TrialProfileError('trial_source_path_refused')
    before = path.stat()
    if not 0 < before.st_size <= maximum:
        raise TrialProfileError('trial_source_size_or_change_refused')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    after = path.stat()
    if (len(raw) != before.st_size or len(raw) > maximum
            or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise TrialProfileError('trial_source_size_or_change_refused')
    return raw


def _field_rows(values):
    return {name: dict(value_decimal=str(value), native_type=kind, signed=signed,
        source_offset=offset, storage_bytes=8, command_index=ci, parent_index=pi,
        ordinary_handle=handle, declared_repnotify=notify)
        for value, (name, kind, signed, offset, ci, pi, handle, notify, _) in zip(values, FIELD_SPECS)}


def _exact(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(_exact(actual[k], v) for k, v in expected.items())
    if type(expected) in (list, tuple):
        return len(actual) == len(expected) and all(_exact(a, e) for a, e in zip(actual, expected))
    return actual == expected


def _observed_values(document, *, snapshot=False):
    observation = document.get('player_state_human_appearance_values_observation')
    if (document.get('status') != 'metadata_export_complete' or type(observation) is not dict
            or observation.get('status') != 'observed'
            or observation.get('kind') != 'source_qualified_current_player_state_human_appearance_values'
            or observation.get('source_profile_sha256') != VALUE_SOURCE_PROFILE_SHA256
            or any(observation.get(key) is not True for key in ('property_value_reads',
                'pawn_player_state_is_current_player_state',
                'current_identities_relations_selected_records_slots_values_and_sources_rechecked',
                'late_original_observation_rechecked'))
            or not _exact(observation.get('pawn_private'), dict(status='same_current_pawn',
                source_offset=0x3f8, native_type='FObjectProperty', wire_handle_qualified=False))
            or any(observation.get(key) is not False for key in ('account_data_exported',
                'raw_addresses_or_identity_values_exported', 'repnotify_execution_verified',
                'selected_hero_or_avatar_mapping_inferred', 'model_configuration_applied',
                'wire_values_chosen', 'wire_encoding_verified', 'process_memory_written',
                'process_opened_by_module', 'native_methods_invoked', 'snapshot_atomic'))):
        raise TrialProfileError('trial_observed_relations_required')
    if snapshot:
        if (document.get('client_sha256') != CLIENT_SHA256
                or observation.get('complete_layout_recheck_owned_by_caller') is not True
                or observation.get('property_value_scope') != 'three_declared_human_player_state_ids_and_pawn_private_relationship'
                or observation.get('selection') != 'caller_rechecked_same_session_current_primary_human_pc_pawn_and_player_state'):
            raise TrialProfileError('trial_observed_relations_required')
    elif document.get('required_observations_available') is not True:
        raise TrialProfileError('trial_observed_relations_required')
    fields = observation.get('fields')
    if type(fields) is not dict or set(fields) != set(FIELD_NAMES):
        raise TrialProfileError('trial_exact_typed_fields_required')
    values = []
    for name, _, signed, *_ in FIELD_SPECS:
        row = fields[name]
        text = row.get('value_decimal') if type(row) is dict else None
        if type(text) is not str or re.fullmatch(r'0|-?[1-9][0-9]{0,19}', text) is None:
            raise TrialProfileError('trial_exact_typed_fields_required')
        value = int(text)
        if not (-(1 << 63) <= value < (1 << 63) if signed else 0 <= value < (1 << 64)):
            raise TrialProfileError('trial_exact_typed_fields_required')
        values.append(value)
    if not _exact(fields, _field_rows(values)):
        raise TrialProfileError('trial_exact_typed_fields_required')
    return tuple(values)


def _import_codecs(root):
    sys.path.insert(0, str(root / 'outputs/df-local-server'))
    return tuple(importlib.import_module('dfserver.' + Path(p).stem) for p in CODEC_PATHS)


def _build_profile(root, documents, source_hashes):
    """Generation only: freeze qualified source observations, never copy identities."""
    import native_player_state_human_appearance_content as factory
    official, snapshot, local = documents
    values = _observed_values(official)
    if _observed_values(snapshot, snapshot=True) != values:
        raise TrialProfileError('trial_same_official_values_required')
    local_values = _observed_values(local)
    if values != VALUES or local_values != (0, 0, 0):
        raise TrialProfileError('trial_source_values_required')
    bindings = factory._derive(snapshot)
    ps = snapshot['first_player_state_observation']['pc_player_state_reference']
    classes = [r for r in snapshot['roots']['classes']
        if r.get('name') == CLASS_NAME and r.get('address') == ps['class_address']]
    if (len(classes) != 1 or classes[0].get('asset_path') != CLASS_PATH
            or factory.CLASS_PATH != CLASS_PATH or factory.codec.SHIPPING_SHA256 != CLIENT_SHA256):
        raise TrialProfileError('trial_current_class_source_required')
    pins = factory.qualified_source_pins(root)
    block, _ = factory.prepare_player_state_human_appearance_content(root, enabled=True,
        source_pins=pins, current_local_player_state_class_path=CLASS_PATH,
        hero_id=values[0], same_team_avatar_id=values[1], diff_team_avatar_id=values[2],
        no_byteswap=True, normal_actor_receive_contract=True)
    if bindings != factory._derive(json.loads(factory._read(root, factory.CAPTURE))):
        raise TrialProfileError('trial_current_class_source_required')
    if (type(block) is not factory.actor_content.ActorContentBlock or block.has_rep_layout is not True
            or type(block.payload) is not bytes or len(block.payload) != 32
            or type(block.payload_bit_count) is not int or block.payload_bit_count != PAYLOAD_BITS
            or factory.qualified_source_pins(root) != pins):
        raise TrialProfileError('trial_payload_refused')
    codec_files = {p: pins[p] for p in CODEC_PATHS}
    return dict(kind='fixed_official_single_trial_human_player_state_content_profile',
        client_sha256=CLIENT_SHA256, class_name=CLASS_NAME, class_path=CLASS_PATH,
        official_trial=OFFICIAL_TRIAL, source_files=dict(source_hashes),
        observed_value_source_profile_sha256=VALUE_SOURCE_PROFILE_SHA256,
        source_relations_typed_fields_and_late_recheck_qualified=True,
        selected_fields=_field_rows(values), local_comparison_fields=_field_rows(local_values),
        ordinary_handles=[140, 142, 143], payload_bits=block.payload_bit_count,
        payload_hex=block.payload.hex(), payload_sha256=_sha(block.payload),
        archive_no_byteswap_declared=True, normal_actor_receive_contract_declared=True,
        codec_source_files=codec_files, generation_factory_source_pins=pins,
        value_origin='one_qualified_official_trial_not_a_general_operator_mapping',
        **{key: False for key in FALSE_FLAGS})


def seal_official_trial_profile(root):
    """Explicit offline generation, limited to the three fixed supplied sources."""
    try:
        root = Path(root).resolve(strict=True)
        raw = [_read(root, p) for p in SOURCES]
        hashes = {p: _sha(data) for p, data in zip(SOURCES, raw)}
        profile = _build_profile(root, [json.loads(data) for data in raw], hashes)
        if any(_sha(_read(root, p)) != hashes[p] for p in SOURCES):
            raise TrialProfileError('trial_source_changed_during_seal')
        payload = (json.dumps(profile, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode('utf-8')
        path = root / PROFILE
        if path.exists() and path.read_bytes() != payload:
            raise TrialProfileError('trial_profile_already_exists_different')
        path.write_bytes(payload)
        return profile, _sha(payload)
    except Exception as error:
        raise TrialProfileError(_reason(error, 'trial_source_preparation_refused')) from None


def _validate_profile(profile):
    expected = dict(kind='fixed_official_single_trial_human_player_state_content_profile',
        client_sha256=CLIENT_SHA256, class_name=CLASS_NAME, class_path=CLASS_PATH,
        official_trial=OFFICIAL_TRIAL, observed_value_source_profile_sha256=VALUE_SOURCE_PROFILE_SHA256,
        source_relations_typed_fields_and_late_recheck_qualified=True,
        selected_fields=_field_rows(VALUES), local_comparison_fields=_field_rows((0, 0, 0)),
        ordinary_handles=[140, 142, 143], payload_bits=PAYLOAD_BITS,
        archive_no_byteswap_declared=True, normal_actor_receive_contract_declared=True,
        value_origin='one_qualified_official_trial_not_a_general_operator_mapping',
        **{key: False for key in FALSE_FLAGS})
    flexible = {'source_files', 'codec_source_files', 'generation_factory_source_pins', 'payload_hex', 'payload_sha256'}
    if (type(profile) is not dict or set(profile) != set(expected) | flexible
            or any(not _exact(profile[key], value) for key, value in expected.items())):
        raise TrialProfileError('trial_profile_schema_refused')
    for label, paths in (('source_files', SOURCES), ('codec_source_files', CODEC_PATHS)):
        values = profile[label]
        if (type(values) is not dict or set(values) != set(paths)
                or any(type(v) is not str or re.fullmatch('[0-9a-f]{64}', v) is None for v in values.values())):
            raise TrialProfileError('trial_profile_schema_refused')
    pins = profile['generation_factory_source_pins']
    if (type(pins) is not dict or not pins or any(type(k) is not str or type(v) is not str
            or re.fullmatch('[0-9a-f]{64}', v) is None for k, v in pins.items())
            or any(pins.get(p) != profile['codec_source_files'][p] for p in CODEC_PATHS)
            or type(profile['payload_hex']) is not str or re.fullmatch('[0-9a-f]{64}', profile['payload_hex']) is None
            or type(profile['payload_sha256']) is not str or re.fullmatch('[0-9a-f]{64}', profile['payload_sha256']) is None):
        raise TrialProfileError('trial_profile_schema_refused')


def load_trial_content(root, enabled=False):
    """Return isolated ActorContentBlock and deterministic safe source facts."""
    if type(enabled) is not bool:
        raise TrialProfileError('trial_explicit_boolean_required')
    if not enabled:
        return None, {'status': 'disabled', 'diagnostic_only': True, 'field_names': FIELD_NAMES.copy(),
                      'packet_produced_or_sent': False, 'source_pins': {}}
    try:
        root = Path(root).resolve(strict=True)
        raw = _read(root, PROFILE, MAX_PROFILE_BYTES)
        if _sha(raw) != PROFILE_SHA256:
            raise TrialProfileError('trial_profile_changed')
        profile = json.loads(raw); _validate_profile(profile)
        pins = {PROFILE: PROFILE_SHA256}
        module = _read(root, MODULE_PATH)
        if module != Path(__file__).read_bytes():
            raise TrialProfileError('trial_imported_source_changed')
        pins[MODULE_PATH] = _sha(module)
        for path, expected in profile['codec_source_files'].items():
            if _sha(_read(root, path)) != expected:
                raise TrialProfileError('trial_codec_source_changed')
            pins[path] = expected
        modules = _import_codecs(root)
        for path, imported in zip(CODEC_PATHS, modules):
            if _sha(Path(imported.__file__).read_bytes()) != pins[path]:
                raise TrialProfileError('trial_imported_source_changed')
        codec, _, scalar, _, actor = modules
        bindings = tuple(scalar.NativeScalarBinding(CLIENT_SHA256, 0x10e5ce20, 0x286c000, row[-1])
                         for row in FIELD_SPECS)
        block = codec.build_player_state_human_appearance_content(hero_id=VALUES[0],
            same_team_avatar_id=VALUES[1], diff_team_avatar_id=VALUES[2], bindings=bindings,
            no_byteswap=True, normal_actor_receive_contract=True)
        if (type(block) is not actor.ActorContentBlock or block.has_rep_layout is not True
                or type(block.payload) is not bytes or type(block.payload_bit_count) is not int
                or block.payload_bit_count != PAYLOAD_BITS or block.payload.hex() != profile['payload_hex']
                or _sha(block.payload) != profile['payload_sha256']):
            raise TrialProfileError('trial_payload_refused')
        if any(_sha(_read(root, path, MAX_PROFILE_BYTES if path == PROFILE else MAX_SOURCE_BYTES)) != digest
               for path, digest in pins.items()):
            raise TrialProfileError('trial_codec_source_changed')
        return block, dict(status='prepared', kind='fixed_official_single_trial_human_player_state_content',
            diagnostic_only=True, class_name=CLASS_NAME, class_path=CLASS_PATH,
            field_names=FIELD_NAMES.copy(), ordinary_handles=[140, 142, 143], payload_bits=PAYLOAD_BITS,
            payload_sha256=profile['payload_sha256'], source_profile_sha256=PROFILE_SHA256,
            source_pins=pins, official_trial=OFFICIAL_TRIAL,
            value_origin='one_qualified_official_trial_not_a_general_operator_mapping',
            archive_no_byteswap_declared=True, normal_actor_receive_contract_declared=True,
            **{key: False for key in FALSE_FLAGS})
    except Exception as error:
        raise TrialProfileError(_reason(error, 'trial_load_refused')) from None


if __name__ == '__main__':
    profile, digest = seal_official_trial_profile(Path(__file__).resolve().parent.parent)
    print(json.dumps({'profile': PROFILE, 'sha256': digest, 'payload_bits': profile['payload_bits'],
                      'payload_sha256': profile['payload_sha256']}, indent=2))
