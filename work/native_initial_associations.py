"""Source-sealed, opt-in PC/Pawn ordinary-reference experiment.

No process access, native function calls, or game-memory writes. This adds
two protocol content blocks on the local server's existing Actor channels.
Consumer-derived byte qualification does not prove a live PackageMap mode,
native Actor resolution, OnRep execution, possession, or playable gameplay.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_actor_manifest import ActorManifest, CLIENT_SHA256
from dfserver.legacy_ds_rep_layout_refs import ObjectReference, build_object_reference_content


SPEC_PATH = 'work/evidence/map-entry-next-20261005/ordinary-rep-layout-object-stream-spec.json'
SPEC_SHA256 = '8779db1b4f76e69267a9c9a956e3110c1f6c14fc62bd5f627d40759a9cb546b5'
RECEIVER_PATH = 'work/evidence/map-entry-next-20261005/game-package-map-object-reference-override.json'
RECEIVER_SHA256 = '9540e7572bf1fbd3bf720da203bd3e1f0e45d10dc4ac1c3daf670740f46f61d3'
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
PROFILE_FIELDS = (('BP_DFMPlayerController_C', 'Pawn'), ('BP_DFMCharacter_C', 'Controller'))
ROLE_TRIAL_PATH = 'outputs/df-local-server/protocol/local_pawn_role_diagnostic.json'
PAWN_DIAGNOSTIC_SPAWN_PATH = 'work/evidence/map-entry-next-20261007/pawn-diagnostic-spawn-profile.json'


def optional_pawn_diagnostic_spawn_sources(root):
    """No configuration preserves the old path; any existing config must qualify."""
    root = Path(root).resolve()
    if not (root / PAWN_DIAGNOSTIC_SPAWN_PATH).exists():
        return {}
    from native_pawn_diagnostic_spawn_profile import CONFIG_PATH, qualified_pawn_spawn_profile_sources
    if CONFIG_PATH != PAWN_DIAGNOSTIC_SPAWN_PATH:
        raise ValueError('Pawn diagnostic spawn configuration path changed')
    return qualified_pawn_spawn_profile_sources(root)


def load_optional_pawn_diagnostic_spawn_location(root, source_pins):
    """Only a sealed explicit config supplies a Pawn location; no fallback value."""
    root = Path(root).resolve()
    present = (root / PAWN_DIAGNOSTIC_SPAWN_PATH).exists()
    sealed = type(source_pins) is dict and PAWN_DIAGNOSTIC_SPAWN_PATH in source_pins
    if not present:
        if sealed:
            raise ValueError('Sealed Pawn diagnostic spawn configuration disappeared')
        return None, None
    required = optional_pawn_diagnostic_spawn_sources(root)
    if type(source_pins) is not dict or any(source_pins.get(p) != h for p, h in required.items()):
        raise ValueError('Pawn diagnostic spawn sources are outside the sealed association set')
    from native_pawn_diagnostic_spawn_profile import load_pawn_diagnostic_spawn_location
    location, safe = load_pawn_diagnostic_spawn_location(root, source_pins)
    if (type(safe) is not dict or safe.get('origin_input_selection') != {
            'official': 'pawn_owning_world_origin_observed', 'local': 'pawn_owning_world_origin_observed'}):
        raise ValueError('Pawn location trial requires each sampled Pawn own World Origin')
    return location, safe


def _optional_role_trial(root):
    """Explicit, source-backed diagnostic opt-in; never a default Role value."""
    if not (Path(root) / ROLE_TRIAL_PATH).is_file():
        return False
    from native_pawn_initial_role_profile import SUMMARY_PATH, SUMMARY_SHA256
    raw, _ = _read(root, ROLE_TRIAL_PATH)
    config = json.loads(raw)
    if (type(config) is not dict or config.get('kind') != 'source_qualified_local_pawn_role_trial'
            or config.get('client_sha256') != CLIENT_SHA256
            or config.get('diagnostic_only') is not True
            or config.get('normal_actor_receive_contract') is not True
            or config.get('source_summary_relative_path') != SUMMARY_PATH
            or config.get('source_summary_sha256') != SUMMARY_SHA256
            or set(config) != {'kind', 'client_sha256', 'diagnostic_only',
                'normal_actor_receive_contract', 'source_summary_relative_path', 'source_summary_sha256'}):
        raise ValueError('Pawn Role trial requires its exact source-qualified summary and explicit receive contract')
    return True


def _relative_path(root, relative):
    if (type(relative) is not str or not relative or '\\' in relative or ':' in relative
            or PurePosixPath(relative).is_absolute()
            or any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ValueError('Association evidence requires a plain project-relative path')
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('Association evidence is missing or outside the project')
    return path


def _read(root, relative, expected=None):
    try:
        path = _relative_path(root, relative)
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError('Association evidence exceeds local bound')
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError('Association evidence could not be read') from error
    digest = hashlib.sha256(raw).hexdigest()
    if expected is not None and (not re.fullmatch('[0-9a-f]{64}', str(expected)) or digest != expected):
        raise ValueError('Association evidence SHA256 mismatch')
    return raw, digest


def _spec(raw):
    try:
        spec = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError('Association specification is not valid JSON') from error
    if (type(spec) is not dict or spec.get('kind') != 'ordinary_replayout_object_reference_consumer_inverse_spec'
            or spec.get('client_sha256') != CLIENT_SHA256
            or spec.get('qualification', {}).get('consumer_grammar_source_confirmed') is not True
            or spec.get('qualification', {}).get('base_guid_reference_reader_and_writer_recovered') is not True):
        raise ValueError('Association consumer qualification does not match the client')
    profiles = spec.get('property_profiles')
    if type(profiles) is not list or len(profiles) != 2:
        raise ValueError('The sealed specification must contain exactly two qualified fields')
    for item, (class_name, field_name) in zip(profiles, PROFILE_FIELDS):
        hook = item.get('serializer_hook', {})
        prefix = item.get('prefix_commands')
        index, handle = item.get('command_index'), item.get('wire_handle_derived_from_consumer_counter')
        if (item.get('class_name') != class_name or item.get('field_name') != field_name
                or type(index) is not int or index < 0 or type(handle) is not int
                or handle != index + 1 or not 1 <= handle <= 65535
                or item.get('prefix_has_no_array_opcode_zero') is not True
                or type(prefix) is not list or len(prefix) != index + 1
                or any(command.get('index') != i or command.get('dispatch_opcode') == 0
                       for i, command in enumerate(prefix))
                or prefix[-1].get('descriptor_name') != field_name
                or prefix[-1].get('dispatch_opcode') != 8
                or hook.get('slot') != 0x90 or hook.get('target_rva') != '0x10e8ed20'
                or hook.get('target_module_sha256') != CLIENT_SHA256
                or hook.get('identity_rechecked') is not True):
            raise ValueError('Association field does not have a sealed ordinary scalar handle')
    return spec


def qualified_initial_association_source_pins(root):
    """Validate the fixed ledger and its code/report inputs before staging."""
    root = Path(root).resolve()
    raw, digest = _read(root, SPEC_PATH, SPEC_SHA256)
    spec = _spec(raw)
    pins, total = {SPEC_PATH: digest}, len(raw)
    listed = spec.get('source_pins', [])
    roots = spec.get('exact_native_code_roots', [])
    if type(listed) is not list or type(roots) is not list or not 1 <= len(listed) + len(roots) <= 96:
        raise ValueError('Association source ledger exceeds local bound')
    sources = [(item['relative_path'], item['sha256']) for item in listed]
    for item in roots:
        sources.extend(((item['code_relative_path'], item['file_sha256']),
                        (item['asm_relative_path'], item['asm_sha256'])))
    receiver_raw, receiver_digest = _read(root, RECEIVER_PATH, RECEIVER_SHA256)
    receiver = json.loads(receiver_raw)
    if (receiver.get('kind') != 'same_build_game_package_map_ordinary_reference_override_and_mode_sources'
            or receiver.get('client_sha256') != CLIENT_SHA256
            or receiver.get('complete_override', {}).get('rva') != '0x49cd3b0'):
        raise ValueError('Game reference receiver source does not match the client')
    pins[RECEIVER_PATH] = receiver_digest
    total += len(receiver_raw)
    sources.extend((item['relative_path'], item['sha256']) for item in receiver['additional_source_pins'])
    for item in receiver['source_files']:
        sources.extend(((item['relative_path'], item['sha256']),
                        (item['asm_relative_path'], item['asm_sha256'])))
    sources.extend((
        ('work/evidence/map-entry-next-20261005/game-package-map-object-reference-override.49cd3b0.dfcode',
         '4bebf6bf10d51417f51249d569ecf9f599cb6daeb43f748f1f4937926218e152'),
        ('work/evidence/map-entry-next-20261005/game-package-map-object-reference-override.49cd3b0.asm.txt',
         '1220a156cf8ee9bf7f0e154424a6936da9431ac6bce121e86ae986673b0cfa29')))
    for relative, expected in sources:
        if relative in pins:
            if pins[relative] != expected:
                raise ValueError('Conflicting association source seal')
            continue
        contents, actual = _read(root, relative, expected)
        total += len(contents)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('Association source set exceeds local byte bound')
        pins[relative] = actual
    for relative in ('work/native_initial_associations.py',
                     'work/native_reference_conditions.py',
                     'outputs/df-local-server/dfserver/legacy_ds_rep_layout_refs.py'):
        contents, actual = _read(root, relative)
        total += len(contents)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('Association source set exceeds local byte bound')
        pins[relative] = actual
    # Reject importing a helper from a different checkout than the sealed root.
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != pins['work/native_initial_associations.py']:
        raise ValueError('Imported association helper differs from the sealed root')
    from native_game_state_initialization import qualified_game_state_initialization_source_pins
    for relative, actual in qualified_game_state_initialization_source_pins(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting GameState and association source seal')
        pins[relative] = actual
    from native_player_state_initialization import qualified_player_state_source_pins
    for relative, actual in qualified_player_state_source_pins(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting PlayerState and association source seal')
        pins[relative] = actual
    from native_gp_first_player_state import qualified_first_player_source_pins
    for relative, actual in qualified_first_player_source_pins(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting first-player and association source seal')
        pins[relative] = actual
    from native_additional_initial_roles import qualified_additional_initial_role_sources, SPEC_PATH as additional_spec
    if (root / additional_spec).is_file():
        for relative, actual in qualified_additional_initial_role_sources(root).items():
            if relative in pins and pins[relative] != actual:
                raise ValueError('Conflicting additional Actor and association source seal')
            pins[relative] = actual
    from native_pc_ping_profile import qualified_pc_ping_sources
    for relative, actual in qualified_pc_ping_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting PC Ping and association source seal')
        pins[relative] = actual
    from native_pc_startup_profile import qualified_pc_startup_sources
    for relative, actual in qualified_pc_startup_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting PC startup and association source seal')
        pins[relative] = actual
    from native_game_state_start_profile import qualified_game_state_start_sources
    for relative, actual in qualified_game_state_start_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting GameState BeginPlay and association source seal')
        pins[relative] = actual
    from native_pc_restart_trial import qualified_pc_restart_trial_sources
    for relative, actual in qualified_pc_restart_trial_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting PC restart and association source seal')
        pins[relative] = actual
    from native_pc_view_target_profile import qualified_pc_view_target_sources
    for relative, actual in qualified_pc_view_target_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting PC view target and association source seal')
        pins[relative] = actual
    if _optional_role_trial(root):
        from native_pawn_initial_role_profile import qualified_source_pins as role_trial_pins
        for relative, actual in role_trial_pins(root).items():
            if relative in pins and pins[relative] != actual:
                raise ValueError('Conflicting Pawn Role diagnostic source seal')
            pins[relative] = actual
        _, pins[ROLE_TRIAL_PATH] = _read(root, ROLE_TRIAL_PATH)
    for relative, actual in optional_pawn_diagnostic_spawn_sources(root).items():
        if relative in pins and pins[relative] != actual:
            raise ValueError('Conflicting Pawn diagnostic spawn source seal')
        pins[relative] = actual
    return pins


def build_initial_actor_associations(root, manifests, source_pins):
    """Select only exact sealed PC.Pawn and Pawn.Controller profiles.

    The caller owns dynamic GUID allocation and delivery. Neither a transport
    ACK nor this byte construction certifies that the client resolved a GUID.
    """
    root = Path(root).resolve()
    if qualified_initial_association_source_pins(root) != source_pins:
        raise ValueError('Association source identity changed before preparation')
    if (type(manifests) is not tuple or not 2 <= len(manifests) <= 5
            or any(not isinstance(item, ActorManifest) for item in manifests)):
        raise ValueError('The experiment requires an explicit initial Actor manifest set')
    if (any(item.client_sha256 != CLIENT_SHA256 for item in manifests)
            or len({item.actor_guid for item in manifests}) != len(manifests)
            or len({item.channel_index for item in manifests}) != len(manifests)
            or len({item.level_path for item in manifests}) != 1
            or len({(item.connection_network_version, item.archive_network_version) for item in manifests}) != 1):
        raise ValueError('Associations require distinct Actors in one sealed map/connection profile')
    raw, _ = _read(root, SPEC_PATH, SPEC_SHA256)
    profiles = _spec(raw)['property_profiles']
    selected = []
    for profile in profiles:
        matches = [item for item in manifests if item.class_path == profile['asset_path']]
        if len(matches) != 1:
            raise ValueError('Each qualified association class must have exactly one initial Actor')
        selected.append(matches[0])
    plans, fields = [], []
    role_trial = _optional_role_trial(root)
    role_initialization = None
    player_state_updates = {}
    if len(manifests) > 3:
        from native_player_state_initialization import build_player_state_references
        player_state_updates, player_state_fields = build_player_state_references(root, manifests, source_pins)
        fields.extend(player_state_fields)
    for profile, actor, target in ((profiles[0], selected[0], selected[1]),
                                   (profiles[1], selected[1], selected[0])):
        references = [ObjectReference(profile['wire_handle_derived_from_consumer_counter'], target.actor_guid)]
        if actor.actor_guid in player_state_updates:
            references.append(player_state_updates[actor.actor_guid])
        references = tuple(sorted(references, key=lambda row: row.handle))
        if role_trial and profile['class_name'] == 'BP_DFMCharacter_C':
            from native_pawn_initial_role_profile import build_pawn_initial_role_reference_content
            block, role_initialization = build_pawn_initial_role_reference_content(root,
                references=references, source_pins=source_pins, normal_actor_receive_contract=True)
        else:
            block = build_object_reference_content(references)
        plans.append(dict(channel_index=actor.channel_index, actor_guid=actor.actor_guid,
                          content_blocks=(block,)))
        fields.append(dict(class_path=actor.class_path, field_name=profile['field_name'],
            ordinary_handle=profile['wire_handle_derived_from_consumer_counter'],
            actor_guid=actor.actor_guid, referenced_actor_guid=target.actor_guid,
            channel_index=actor.channel_index, payload_bits=block.payload_bit_count,
            payload_sha256=hashlib.sha256(block.payload).hexdigest()))
    if qualified_initial_association_source_pins(root) != source_pins:
        raise ValueError('Association source identity changed during preparation')
    game_state_initialization = None
    if len(manifests) >= 3:
        from native_game_state_initialization import (
            qualified_game_state_initialization_source_pins, build_initial_game_state_update)
        game_state_pins = qualified_game_state_initialization_source_pins(root)
        if any(source_pins.get(relative) != digest for relative, digest in game_state_pins.items()):
            raise ValueError('GameState initialization is outside the sealed association sources')
        selected_classes = {profile['asset_path'] for profile in profiles}
        from native_game_state_initialization import GAME_STATE_CLASS
        selected_classes.add(GAME_STATE_CLASS)
        state_subset = tuple(item for item in manifests if item.class_path in selected_classes)
        plan, game_state_initialization = build_initial_game_state_update(root, state_subset, game_state_pins)
        plans.append(plan)
    summary = dict(kind='source_sealed_post_open_pc_pawn_association_experiment',
        status='prepared_for_transport_ack_gated_send', diagnostic_only=True,
        source_relative_path=SPEC_PATH, source_sha256=SPEC_SHA256, fields=fields,
        byte_grammar_source='ordinary_native_consumer_inverse',
        actual_connection_package_map_mode_verified=False, native_guid_resolution_verified=False,
        native_reference_assignment_verified=False, possession_verified=False,
        connection_binding_replaced=False, playable_map_verified=False,
        game_state_initialization=game_state_initialization)
    if role_initialization is not None:
        summary['pawn_role_initialization'] = role_initialization
    return tuple(plans), summary
