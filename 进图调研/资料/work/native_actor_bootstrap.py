"""Pure, fail-closed initial Actor factories from an exact metadata JSON report.

No files, processes, sockets or native functions are accessed here. The report
bytes are SHA-checked; a source pin does not authenticate who produced a report.
Template flags, Level-source contents, network profile, native resolution,
Actor creation and possession remain unverified. GUIDs are explicit local-server
choices, not native object addresses or automatically allocated values.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
from types import MappingProxyType

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'outputs/df-local-server'))
from dfserver.legacy_ds_actor_manifest import (  # noqa: E402
    ActorManifest, ActorManifestPreflight, CLIENT_SHA256, GuidPathBinding,
    preflight_actor_manifest,
)
from dfserver.legacy_ds_guid_exports import GuidExportNode  # noqa: E402
from dfserver.legacy_ds_game_spawn_flags import (  # noqa: E402
    GameSpawnFlags, SOURCE_EVIDENCE_RELATIVE_PATH, SOURCE_EVIDENCE_SHA256,
    SOURCE_WRITER_RVA, calculate_game_spawn_flags,
)

PAWN_CLASS = 'BP_DFMCharacter_C'
GAME_STATE_CLASS = 'BP_GameState_PVPVE_C'
PLAYER_CONTROLLER_CLASS = 'BP_DFMPlayerController_C'
ROLE_CLASSES = MappingProxyType({'Pawn': PAWN_CLASS, 'GameState': GAME_STATE_CLASS,
                                'PlayerController': PLAYER_CONTROLLER_CLASS})
PC_OPEN_HOOK_SLOT = 0x3d8
PC_BASE_OPEN_HOOK_RVA = 0x12d4ddb0
MAX_METADATA_REPORT_BYTES = 32 * 1024 * 1024  # Factory policy, not an engine limit.


@dataclass(frozen=True)
class SourcePin:
    relative_path: str
    sha256: str
    contents_sha_verified: bool


@dataclass(frozen=True)
class QualifiedPCTailProfile:
    """Caller's explicit base-hook source qualification; never executes code.

    Source contents are not supplied to this pure factory. Its caller must seal
    them separately. The factory still requires the exact proven base RVA and
    matching, rechecked hook metadata on the selected template candidate.
    """
    client_sha256: str
    source_relative_path: str
    source_sha256: str
    hook_target_rva: int


@dataclass(frozen=True)
class QualifiedGameSpawnProfile:
    """Exact interface report plus caller-supplied server state/relations.

    Interface metadata proves the selected native writer's qualification. It
    does not supply any of these six facts about the server's Actor/connection.
    No field has a business default and no CDO state is read by this factory.
    """
    interface_report: bytes
    source_relative_path: str
    source_sha256: str
    original_state_u8: int
    actor_byte93_mask20: bool
    owner_connection_match: bool
    connection_present: bool
    actor_is_connection_actor: bool
    actor_in_connection_actor_array: bool


@dataclass(frozen=True)
class PawnActorBootstrap:
    manifest: ActorManifest
    preflight: ActorManifestPreflight
    metadata_source: SourcePin
    level_source: SourcePin
    channel_sequence: int
    max_packet_bytes: int
    network_profile_verified: bool = field(default=False, init=False)
    native_acceptance: bool = field(default=False, init=False)
    player_spawn_verified: bool = field(default=False, init=False)
    possession_verified: bool = field(default=False, init=False)
    game_spawn_source: SourcePin | None = field(default=None, kw_only=True)
    game_spawn_facts: MappingProxyType | None = field(default=None, kw_only=True)
    game_spawn_result: GameSpawnFlags | None = field(default=None, kw_only=True)

    def summary(self):
        """A small JSON-compatible record; no native pointers or full report."""
        role = getattr(self, 'role', 'Pawn')
        result = {
            'kind': 'pure_metadata_pawn_actor_bootstrap' if role == 'Pawn' else 'pure_metadata_initial_actor_bootstrap',
            'role': role,
            'status': 'property_free_manifest_preflighted',
            'client_sha256': self.manifest.client_sha256,
            'metadata_source': dict(relative_path=self.metadata_source.relative_path,
                sha256=self.metadata_source.sha256, contents_sha_verified=True),
            'level_source': dict(relative_path=self.level_source.relative_path,
                sha256=self.level_source.sha256, contents_sha_verified=False),
            'class_path': self.manifest.class_path,
            'archetype_path': self.manifest.archetype_path,
            'archetype_qualification': self.manifest.archetype_qualification,
            'level_path': self.manifest.level_path,
            'connection_network_version': self.manifest.connection_network_version,
            'archive_network_version': self.manifest.archive_network_version,
            'max_packet_bytes': self.max_packet_bytes,
            'channel_sequence': self.channel_sequence,
            'conservative_packet_bytes': self.preflight.conservative_packet_bytes,
            'content_blocks': 0, 'local_player_index': self.manifest.local_player_index,
            'network_profile_verified': False, 'native_acceptance': False,
            'player_spawn_verified': False, 'possession_verified': False,
        }
        profile_source = getattr(self, 'pc_tail_profile_source', None)
        if profile_source is not None:
            result['pc_tail_profile_source'] = dict(relative_path=profile_source.relative_path,
                sha256=profile_source.sha256, contents_sha_verified=False)
            result['pc_tail_hook_target_rva'] = getattr(self, 'pc_tail_hook_target_rva')
            result['pc_tail_profile_matches_observed_base_hook'] = True
            result['derived_hook_semantics_assumed'] = False
        if self.game_spawn_source is not None:
            flags = self.game_spawn_result
            result['game_spawn_profile'] = {
                'interface_report_source': dict(relative_path=self.game_spawn_source.relative_path,
                    sha256=self.game_spawn_source.sha256, contents_sha_verified=True),
                'native_interface_gate_observed': True,
                'facts': dict(self.game_spawn_facts),
                'facts_origin': 'explicit_caller_server_model',
                'server_owned_facts_verified': False,
                'effective_state_u8': flags.effective_state_u8,
                'flags_u8': flags.flags_u8,
                'state_downgraded': flags.state_downgraded,
                'downgrade_reason': flags.downgrade_reason,
                'native_acceptance': False,
            }
        return result


@dataclass(frozen=True)
class InitialActorBootstrap(PawnActorBootstrap):
    role: str = 'Pawn'
    pc_tail_profile_source: SourcePin | None = None
    pc_tail_hook_target_rva: int | None = None


def _source_pin(relative_path, sha256, *, verified):
    if (type(relative_path) is not str or not relative_path or
            '\\' in relative_path or ':' in relative_path or
            PurePosixPath(relative_path).is_absolute() or
            any(part in ('', '.', '..') for part in relative_path.split('/'))):
        raise ValueError('Source pins require a plain project-relative path')
    if type(sha256) is not str or not re.fullmatch('[0-9a-f]{64}', sha256):
        raise ValueError('Source pins require an explicit lowercase SHA256')
    return SourcePin(relative_path, sha256, verified)


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate metadata JSON key')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Non-finite metadata JSON constant: ' + value)


def _report(raw, source_sha256, *, return_document=False):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_METADATA_REPORT_BYTES:
        raise ValueError('Exact bounded metadata JSON bytes are required')
    if hashlib.sha256(raw).hexdigest() != source_sha256:
        raise ValueError('Metadata JSON bytes disagree with their source SHA256')
    try:
        result = json.loads(raw, object_pairs_hook=_json_object,
                            parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('Metadata JSON is malformed or ambiguous') from error
    if type(result) is not dict:
        raise ValueError('A complete metadata report object is required')
    if (result.get('kind') != 'existing_native_replication_metadata_export' or
            result.get('status') != 'metadata_export_complete' or
            result.get('client_sha256') != CLIENT_SHA256):
        raise ValueError('A complete report for the pinned Shipping build is required')
    roots = result.get('roots')
    if type(roots) is not dict or roots.get('selected_roots_rechecked') is not True:
        raise ValueError('Selected metadata roots must have been rechecked')
    return result if return_document else roots


def _address(value):
    if type(value) is not int or not 0x10000 <= value < (1 << 47):
        raise ValueError('An explicit metadata object address is required')
    return value


def _identity(row):
    _address(row.get('address'))
    index, serial = row.get('object_index'), row.get('serial')
    if (type(index) is not int or not 0 <= index < (1 << 31) or
            type(serial) is not int or not 0 <= serial < (1 << 32)):
        raise ValueError('Complete metadata registry identity is required')
    key = struct.pack('<iI', index, serial).hex() if serial else None
    if 'key' not in row or row['key'] != key:
        raise ValueError('Metadata weak-key bytes disagree with registry identity')


def _rows(roots, name):
    rows = roots.get(name)
    if type(rows) is not list or len(rows) > 32 or any(type(row) is not dict for row in rows):
        raise ValueError('A bounded complete metadata list is required: ' + name)
    return rows


def _metadata_actor(roots, role):
    class_name = ROLE_CLASSES[role]
    classes = [row for row in _rows(roots, 'classes') if row.get('name') == class_name]
    if len(classes) != 1:
        raise ValueError('Exactly one selected ' + role + ' Class metadata record is required')
    klass = classes[0]
    _identity(klass)
    candidates = [row for row in _rows(roots, 'named_template_candidates')
        if row.get('class_name') == class_name or row.get('class_address') == klass['address']]
    if len(candidates) != 1:
        raise ValueError('Exactly one named ' + role + ' template candidate is required')
    candidate = candidates[0]
    _identity(candidate)
    if (candidate['address'] == klass['address'] or
            candidate.get('class_address') != klass['address'] or
            candidate.get('class_name') != class_name or
            candidate.get('name') != 'Default__' + class_name or
            candidate.get('selection_kind') != 'name_class_outer_metadata_candidate' or
            candidate.get('class_default_object_flags_verified') is not False or
            candidate.get('package_map_resolution_verified') is not False):
        raise ValueError(role + ' template name, Class binding or qualification disagrees')
    class_outer = _address(candidate.get('class_outer_address'))
    outer = _address(candidate.get('outer_address'))
    if class_outer in (klass['address'], candidate['address']):
        raise ValueError(role + ' Class Outer cannot be the Class or template itself')
    package_path = candidate.get('class_outer_path')
    if (type(package_path) is not str or not package_path.startswith('/') or
            '.' in package_path or ':' in package_path):
        raise ValueError('An observed direct Package Outer path is required')
    class_path = klass.get('asset_path')
    if class_path != package_path + '.' + class_name:
        raise ValueError(role + ' Class path disagrees with its observed Package Outer')
    relation = candidate.get('outer_relation')
    if relation == 'same_outer_as_class':
        if outer != class_outer or candidate.get('outer_path') != package_path:
            raise ValueError(role + ' template Package Outer binding disagrees')
        separator, template_outer_is_class = '.', False
        expected = package_path + '.' + candidate['name']
    elif relation == 'class':
        if outer != klass['address'] or candidate.get('outer_path') != class_path:
            raise ValueError(role + ' template Class Outer binding disagrees')
        separator, template_outer_is_class = ':', True
        expected = class_path + ':' + candidate['name']
    else:
        raise ValueError('An observed ' + role + ' template Outer relation is required')
    if candidate.get('asset_path') != expected:
        raise ValueError(role + ' template path disagrees with its observed Outer')
    return package_path, class_path, expected, separator, template_outer_is_class, candidate


def _pc_tail(candidate, local_player_index, profile):
    if type(local_player_index) is not int or local_player_index != 0:
        raise ValueError('PlayerController requires an explicit primary local-player index 0')
    if type(profile) is not QualifiedPCTailProfile:
        raise ValueError('PlayerController requires an explicit qualified base-hook tail profile')
    pin = _source_pin(profile.source_relative_path, profile.source_sha256, verified=False)
    if (profile.client_sha256 != CLIENT_SHA256 or type(profile.hook_target_rva) is not int or
            profile.hook_target_rva != PC_BASE_OPEN_HOOK_RVA):
        raise ValueError('PlayerController tail profile does not identify the proven base hook')
    hook = candidate.get('actor_channel_open_hook')
    if (type(hook) is not dict or type(hook.get('slot')) is not int or
            hook['slot'] != PC_OPEN_HOOK_SLOT or
            type(hook.get('target_rva')) is not int or hook['target_rva'] != PC_BASE_OPEN_HOOK_RVA or
            hook.get('target_module_sha256') != CLIENT_SHA256 or
            hook.get('inside_pinned_image') is not True or hook.get('identity_rechecked') is not True or
            hook.get('status') != 'observed_pinned_image_method'):
        raise ValueError('PlayerController template has no rechecked matching proven base open hook')
    _address(hook.get('vtable_address'))
    _address(hook.get('target_address'))
    return pin


def _game_spawn_profile(profile, class_path, template_path):
    """Qualify one observed Pawn writer; never import state from the report."""
    if type(profile) is not QualifiedGameSpawnProfile:
        raise ValueError('Pawn game spawn requires an exact QualifiedGameSpawnProfile')
    pin = _source_pin(profile.source_relative_path, profile.source_sha256, verified=True)
    document = _report(profile.interface_report, profile.source_sha256, return_document=True)
    roots = document['roots']
    _, observed_class_path, observed_template_path, _, _, candidate = _metadata_actor(roots, 'Pawn')
    if observed_class_path != class_path or observed_template_path != template_path:
        raise ValueError('Pawn interface report Class/template paths disagree with this bootstrap')
    observations = [row for row in _rows(document, 'actor_interface_observations')
        if row.get('class_path') == observed_class_path or
           row.get('candidate_path') == observed_template_path]
    if len(observations) != 1:
        raise ValueError('Exactly one matching observed Pawn native interface is required')
    observed = observations[0]
    binding = observed.get('binding')
    klass = next(row for row in _rows(roots, 'classes') if row['name'] == PAWN_CLASS)
    ancestry = klass.get('class_ancestry')
    if (type(ancestry) is not list or len(ancestry) > 64 or
            any(type(row) is not dict for row in ancestry)):
        raise ValueError('A bounded observed Pawn Class ancestry is required')
    declaring = [row for row in ancestry if row.get('name') == 'CharacterBase']
    if len(declaring) != 1:
        raise ValueError('One observed declaring CharacterBase identity is required')
    _identity(declaring[0])
    if (type(binding) is not dict or
            observed.get('status') != 'observed_source_qualified_native_interface' or
            observed.get('interface_name') != 'NetRepActorInterface' or
            observed.get('shipping_sha256') != CLIENT_SHA256 or
            observed.get('native_interface_gate_observed') is not True or
            observed.get('identity_rechecked') is not True or
            observed.get('class_path') != observed_class_path or
            observed.get('candidate_path') != observed_template_path or
            observed.get('candidate_address') != candidate['address'] or
            observed.get('class_address') != candidate['class_address'] or
            binding.get('declaring_class') != 'CharacterBase' or
            binding.get('declaring_class_address') != declaring[0]['address'] or
            binding.get('interface_name') != 'NetRepActorInterface' or
            binding.get('interface_address') != observed.get('interface_address') or
            type(binding.get('adjustment')) is not int or binding['adjustment'] != 0xa60 or
            type(binding.get('entry_index')) is not int or binding['entry_index'] != 0):
        raise ValueError('Pawn native interface gate/identity/declaring binding is not qualified')
    _address(observed.get('interface_address'))
    exact_integers = {'main_vtable_rva': 0x1a67a320, 'secondary_vtable_rva': 0x1a67c2e8,
                      'method_slot': 0x10, 'method_target_rva': SOURCE_WRITER_RVA,
                      'method_code_prefix_bytes': 32}
    if any(type(observed.get(name)) is not int or observed[name] != expected
           for name, expected in exact_integers.items()):
        raise ValueError('Pawn native interface table/method does not match the qualified writer')
    prefix = '4d85c00f847001000048897c242041564883ec4048895c2450498bf848897424'
    if (observed.get('method_code_prefix_hex') != prefix or
            observed.get('method_code_prefix_sha256') != hashlib.sha256(bytes.fromhex(prefix)).hexdigest()):
        raise ValueError('Pawn native interface writer prefix seal does not match')
    hook = candidate.get('actor_channel_open_hook')
    if (type(hook) is not dict or hook.get('identity_rechecked') is not True or
            hook.get('inside_pinned_image') is not True or
            hook.get('target_module_sha256') != CLIENT_SHA256 or
            type(hook.get('vtable_rva')) is not int or
            hook['vtable_rva'] != observed['main_vtable_rva']):
        raise ValueError('Pawn interface main table is not bound to its rechecked template')
    pins = observed.get('source_pins')
    expected_pins = {
        'interface_array': ('work/evidence/native-interface-class-array-branch.json',
            '90d0abd7b529c2dfca619406dc61852cb53586d1c89da5e52821ac5de9fbae77'),
        'data_accessor': ('work/evidence/native-interface-array-data-accessor-prefix.json',
            '0933231b202151ddb3838fe1649af01681ac2beb5304a25ad674de552d7a834f'),
        'pawn_writer': (SOURCE_EVIDENCE_RELATIVE_PATH, SOURCE_EVIDENCE_SHA256),
    }
    if type(pins) is not dict or any(type(pins.get(name)) is not dict or
            pins[name].get('relative_path') != path or pins[name].get('sha256') != sha
            for name, (path, sha) in expected_pins.items()):
        raise ValueError('Pawn interface observation source pins do not match')
    facts = {name: getattr(profile, name) for name in (
        'original_state_u8', 'actor_byte93_mask20', 'owner_connection_match',
        'connection_present', 'actor_is_connection_actor', 'actor_in_connection_actor_array')}
    result = calculate_game_spawn_flags(source_build_sha256=CLIENT_SHA256, **facts)
    return pin, MappingProxyType(facts), result


def _level_path(path):
    if type(path) is not str:
        raise ValueError('An explicit observed complete Level path is required')
    if path.count('.') != 1 or path.count(':') != 1:
        raise ValueError('Level path must explicitly describe Package.World:Level')
    package, remainder = path.split('.')
    world, level = remainder.split(':')
    if (not package.startswith('/') or not world or not level or
            any(c in world + level for c in '/\\')):
        raise ValueError('Level path must explicitly describe Package.World:Level')
    # Preserve each observed name. A null Outer is a package export, so the
    # complete World path cannot be substituted for that package node.
    return package, world, package + '.' + world, level


def build_initial_actor_bootstrap(metadata_report, *, role, source_relative_path, source_sha256,
        level_path, level_source_relative_path, level_source_sha256,
        package_guid, class_guid, archetype_guid, level_package_guid, level_outer_guid, level_guid,
        actor_guid, channel_index, channel_sequence, connection_network_version,
        archive_network_version, max_packet_bytes, references_resolvable,
        location=None, scale=None, velocity=None, local_player_index=None, pc_tail_profile=None,
        game_spawn_profile=None):
    """Preflight one metadata-selected, property-free initial Actor.

    The metadata source is verified against exact supplied bytes. Level contents
    are not provided here: its pin and complete path remain caller provenance.
    Its explicit Package.World:Level path supplies all three graph nodes without
    inventing names. references_resolvable is an explicit caller contract,
    not a consequence of metadata collection or this preflight.
    Only PlayerController may carry the explicit primary-player byte, and only
    when its observed v3d8 target matches the qualified proven base handler.
    Pawn's optional game_spawn_profile separately verifies an exact interface
    report and uses only its six explicit server-model facts to compute the raw
    byte. The returned effective state is not committed to a server model here.
    """
    if type(role) is not str or role not in ROLE_CLASSES:
        raise ValueError('Only Pawn, GameState or PlayerController roles are supported')
    if game_spawn_profile is not None and role != 'Pawn':
        raise ValueError('The qualified game spawn profile is supported only for Pawn')
    metadata_source = _source_pin(source_relative_path, source_sha256, verified=True)
    level_source = _source_pin(level_source_relative_path, level_source_sha256, verified=False)
    roots = _report(metadata_report, source_sha256)
    package_path, class_path, template_path, separator, class_outer, candidate = _metadata_actor(roots, role)
    pc_source = None
    if role == 'PlayerController':
        pc_source = _pc_tail(candidate, local_player_index, pc_tail_profile)
    elif local_player_index is not None or pc_tail_profile is not None:
        raise ValueError('A PlayerController tail is not supported for this Actor role')
    game_source = game_facts = game_result = None
    if game_spawn_profile is not None:
        game_source, game_facts, game_result = _game_spawn_profile(
            game_spawn_profile, class_path, template_path)
    level_package_path, world_leaf, level_outer_path, level_leaf = _level_path(level_path)
    package = GuidExportNode(package_guid, package_path)
    class_name = ROLE_CLASSES[role]
    klass = GuidExportNode(class_guid, class_name, package)
    template = GuidExportNode(archetype_guid, 'Default__'+class_name,
                              klass if class_outer else package)
    level_package = GuidExportNode(level_package_guid, level_package_path)
    level_outer = GuidExportNode(level_outer_guid, world_leaf, level_package)
    level = GuidExportNode(level_guid, level_leaf, level_outer)
    manifest = ActorManifest(client_sha256=CLIENT_SHA256,
        source_relative_path=metadata_source.relative_path, source_sha256=metadata_source.sha256,
        class_guid=class_guid, class_path=class_path, archetype_guid=archetype_guid,
        archetype_path=template_path, archetype_qualification='named_default_object_candidate',
        level_guid=level_guid, level_path=level_path,
        path_bindings=(GuidPathBinding(package_guid, package_path),
            GuidPathBinding(class_guid, class_path, '.'),
            GuidPathBinding(archetype_guid, template_path, separator),
            GuidPathBinding(level_package_guid, level_package_path),
            GuidPathBinding(level_outer_guid, level_outer_path, '.'),
            GuidPathBinding(level_guid, level_path, ':')),
        exports=(klass, template, level), actor_guid=actor_guid,
        connection_network_version=connection_network_version,
        archive_network_version=archive_network_version,
        references_resolvable=references_resolvable, channel_index=channel_index,
        location=location, scale=scale, velocity=velocity, local_player_index=local_player_index,
        game_replication_flags=game_result.flags_u8 if game_result is not None else None)
    preflight = preflight_actor_manifest(manifest, channel_sequence=channel_sequence,
                                          max_packet_bytes=max_packet_bytes)
    return InitialActorBootstrap(manifest, preflight, metadata_source, level_source,
        channel_sequence, max_packet_bytes, role, pc_source,
        PC_BASE_OPEN_HOOK_RVA if pc_source is not None else None,
        game_spawn_source=game_source, game_spawn_facts=game_facts, game_spawn_result=game_result)


def build_pawn_actor_bootstrap(metadata_report, *, source_relative_path, source_sha256,
        level_path, level_source_relative_path, level_source_sha256,
        package_guid, class_guid, archetype_guid, level_package_guid, level_outer_guid, level_guid,
        actor_guid, channel_index, channel_sequence, connection_network_version,
        archive_network_version, max_packet_bytes, references_resolvable,
        location=None, scale=None, velocity=None, game_spawn_profile=None):
    """Compatibility API for one property-free Pawn without a PC tail."""
    result = build_initial_actor_bootstrap(metadata_report, role='Pawn',
        source_relative_path=source_relative_path, source_sha256=source_sha256,
        level_path=level_path, level_source_relative_path=level_source_relative_path,
        level_source_sha256=level_source_sha256, package_guid=package_guid,
        class_guid=class_guid, archetype_guid=archetype_guid, level_package_guid=level_package_guid,
        level_outer_guid=level_outer_guid,
        level_guid=level_guid, actor_guid=actor_guid, channel_index=channel_index,
        channel_sequence=channel_sequence, connection_network_version=connection_network_version,
        archive_network_version=archive_network_version, max_packet_bytes=max_packet_bytes,
        references_resolvable=references_resolvable, location=location, scale=scale, velocity=velocity,
        game_spawn_profile=game_spawn_profile)
    return PawnActorBootstrap(result.manifest, result.preflight, result.metadata_source,
        result.level_source, result.channel_sequence, result.max_packet_bytes,
        game_spawn_source=result.game_spawn_source, game_spawn_facts=result.game_spawn_facts,
        game_spawn_result=result.game_spawn_result)
