"""Default-off BASE hookup. A missing same-capture local Join proof refuses.

This module does no process access, native calls, socket creation or sending.
Only the existing GameServerProbe send hook may send a prepared proposal.
The even Name/Outer export branch is deliberately unsupported here.
"""
from dataclasses import dataclass, field, replace
import dataclasses
from copy import deepcopy
import hashlib
import json
import math
import secrets
import reprlib
import sys
import time
from types import CodeType
from pathlib import Path

from dfserver.replication.legacy_ds_actor_content import ResolvedStableSubobjectProfile
from dfserver.replication.legacy_ds_actor_manifest import ActorManifest
from dfserver.replication.legacy_ds_fashion_subobject_outbox import CurrentFashionPropertyRequest, CurrentFashionSubobjectOutbox, CurrentPawnChannelLease, QualifiedLocalFashionReference, SOURCE_PINS
from native_fashion_hero_content import (SourceJson, SourcePin, OwnedFashionContext,
    OwnedHeroIdBinding, SHIPPING_SHA256)
from native_local_trial_appearance_observer import (reader_flags, safe_fashion_contract_summary)

MAX_JSON = 32 * 1024 * 1024
FIXED_SHADOW_PATH = 'D:/个人工作区/DeltaForce-local-client'
FIXED_BASE_PATH = 'C:/Users/24335/Documents/Codex/2026-09-26/d-wegameapps-rail-apps-deltaforce-2001918'
FIXED_REPOSITORY_PATH = 'D:/个人工作区/deltaforce-local-map-research-publish'
FIXED_CLIENT_RELATIVE = 'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
ORIGINAL_SDK_SHA = '9d39a0f5af96d56f465060a582e21faf5c11d5cfdd4e221891d81c58cd7f1723'
ACTIVE_PROVIDER_SHA = 'ce81132089fa3487d827da94c650ae798d4e6a286acee57d9dec373e9c7e57e4'
PROVIDER_SOURCE_SHA = 'fa21dc8cf311ed9ca5d547563ccc673410ae50e683294cc10806d2d9ec86f0f2'
HERO_CATALOG_SHA = '697e4a3ce2f6f43c0b28477796afd0cfa782daec38cfa3d1acae5ebbf036e64f'
SELECTED_HERO_EVIDENCE = 'work/evidence/map-entry-next-20261007/hero-avatar-selected-catalog-key-evidence.json'
SELECTED_HERO_EVIDENCE_SHA = 'c8e06388f2be03a733fdc57e254bf438cc0f6cd3e651f81194acc9be8bb1dc9a'
RUNTIME_MODULES = {
    'dfserver.legacy_ds_fashion_async_bridge':'outputs/df-local-server/dfserver/legacy_ds_fashion_async_bridge.py',
    'dfserver.legacy_ds_fashion_async_permit':'outputs/df-local-server/dfserver/legacy_ds_fashion_async_permit.py',
    'dfserver.legacy_ds_fashion_retained_protocol':'outputs/df-local-server/dfserver/legacy_ds_fashion_retained_protocol.py',
    'dfserver.legacy_ds_fashion_owned_phase':'outputs/df-local-server/dfserver/legacy_ds_fashion_owned_phase.py',
    'dfserver.legacy_ds_even_component_guid_exports':'outputs/df-local-server/dfserver/legacy_ds_even_component_guid_exports.py',
    'dfserver.legacy_ds_fashion_retained_trial':'outputs/df-local-server/dfserver/legacy_ds_fashion_retained_trial.py',
    'native_fashion_declaration_body':'work/native_fashion_declaration_body.py',
    'dfserver.legacy_ds_control_connection':'outputs/df-local-server/dfserver/legacy_ds_control_connection.py',
    'dfserver.game_server_probe':'outputs/df-local-server/dfserver/game_server_probe.py',
    'dfserver.legacy_ds_handshake_probe':'outputs/df-local-server/dfserver/legacy_ds_handshake_probe.py',
    'dfserver.legacy_ds_fashion_runtime':'outputs/df-local-server/dfserver/legacy_ds_fashion_runtime.py',
    'dfserver.legacy_ds_fashion_subobject_outbox':'outputs/df-local-server/dfserver/legacy_ds_fashion_subobject_outbox.py',
    'dfserver.legacy_ds_actor_content':'outputs/df-local-server/dfserver/legacy_ds_actor_content.py',
    'dfserver.legacy_ds_wire_codec':'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py',
    'dfserver.legacy_ds_bit_archive':'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py',
    'dfserver.legacy_ds_scalar_serializers':'outputs/df-local-server/dfserver/legacy_ds_scalar_serializers.py',
    'native_fashion_hero_content':'work/native_fashion_hero_content.py',
    'native_game_state_start_profile':'work/native_game_state_start_profile.py',
    'native_local_trial_appearance_observer':'work/native_local_trial_appearance_observer.py',
}
READER_REQUIRED_SOURCE_PATHS = (
    'work/read_playable_state_snapshot.py','work/native_fashion_current_class_metadata.py',
    'work/native_current_fashion_guid_references.py','work/native_current_fashion_name_stability.py',
    'work/staging-ds-receipt-fix-20261009/fashion-top-level-scalar-handle/profile.json',
    'work/evidence/map-entry-next-20261007/fashion-existing-guid-exact-key-20261009/sources.json',
    'work/staging-ds-receipt-fix-20261010/fashion-name-stability-direct-subset-v2/profile.json',
)
_COMPILED_SOURCE_CACHE = {}


def hex_hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def namespace(items):
    return tuple((channel, item.actor_guid, item.bunch) for channel, item in sorted(items.items()))


def namespace_digest(items):
    # Bytes and all immutable WireBunch fields are part of the signature.
    return digest(repr(items).encode('utf-8'))


@dataclass(frozen=True)
class RuntimeSourceSeal:
    """Reviewed frozen map plus recheck; hashes actual executing module files."""
    sealed_sources: dict = field(repr=False)
    recheck: object = field(repr=False)
    reader_closure_recheck: object = field(default=None, repr=False)

    def verify(self):
        require(type(self.sealed_sources) is dict and len(self.sealed_sources) <= 512 and
            callable(self.recheck), 'runtime_source_seal_required')
        frozen = dict(self.sealed_sources)
        require(all(frozen.get(p) == h for p,h in SOURCE_PINS.items()), 'frozen_dependencies_changed')
        for module_name, relative in RUNTIME_MODULES.items():
            module = sys.modules.get(module_name)
            require(module is not None and type(getattr(module, '__file__', None)) is str and
                relative in frozen, 'executing_module_source_pin_required')
            actual = Path(module.__file__).resolve()
            raw = actual.read_bytes()
            require(digest(raw) == frozen[relative], 'executing_module_source_changed')
            # A module __file__ relabel must not qualify a function from elsewhere.
            cache_key = (str(actual),frozen[relative],sys.flags.optimize)
            expected = _COMPILED_SOURCE_CACHE.get(cache_key)
            if expected is None:
                expected = {}
                def collect(code):
                    expected[code.co_qualname] = code
                    for child in code.co_consts:
                        if type(child) is CodeType:
                            collect(child)
                collect(compile(raw,str(actual),'exec',dont_inherit=True,optimize=sys.flags.optimize))
                require(len(_COMPILED_SOURCE_CACHE) < 64, 'bounded_compiled_source_cache_required')
                _COMPILED_SOURCE_CACHE[cache_key] = expected
            def verify_symbol(symbol, generated=False, owned_class_member=False):
                code = getattr(symbol, '__code__', None)
                if code is not None and (owned_class_member or getattr(symbol, '__module__', None) == module_name):
                    # Generated dataclass __init__/repr/eq have no source code.
                    if generated and code.co_filename == '<string>':
                        return
                    wrapped = getattr(symbol,'__wrapped__',None)
                    wrapped_code = getattr(wrapped,'__code__',None)
                    if (generated and wrapped_code is not None and wrapped_code.co_filename == '<string>' and
                            Path(code.co_filename).resolve() in (Path(dataclasses.__file__).resolve(),
                                Path(reprlib.__file__).resolve())):
                        return
                    require(Path(code.co_filename).resolve() == actual, 'executing_code_path_changed')
                    canonical = code.replace(co_filename=str(actual))
                    require(code.co_qualname in expected and canonical ==
                        expected[code.co_qualname], 'executing_code_differs_from_sealed_source')
            for symbol in vars(module).values():
                verify_symbol(symbol)
                if type(symbol) is type and getattr(symbol,'__module__',None) == module_name:
                    for member_name,member in vars(symbol).items():
                        if (dataclasses.is_dataclass(symbol) and member_name == '__replace__' and
                                member is getattr(dataclasses,'_replace',None)):
                            continue
                        generated = dataclasses.is_dataclass(symbol) and member_name in (
                            '__init__','__repr__','__eq__','__hash__','__setattr__','__delattr__',
                            '__lt__','__le__','__gt__','__ge__')
                        if type(member) in (staticmethod,classmethod):
                            member = member.__func__
                        if type(member) is property:
                            for accessor in (member.fget,member.fset,member.fdel):
                                if accessor is not None:
                                    verify_symbol(accessor,owned_class_member=True)
                        else:
                            verify_symbol(member,generated=generated,owned_class_member=True)
        require(self.recheck() == frozen and self.sealed_sources == frozen, 'current_source_seal_changed')
        return frozen


@dataclass(frozen=True, eq=False)
class JoinedFashionOwnerContract:
    probe: object = field(repr=False)
    connection: object = field(repr=False)
    configured: object = field(repr=False)
    registration: object = field(repr=False)
    ticket: object = field(repr=False)
    generation: object = field(repr=False)
    transport: object = field(repr=False)
    actor_fields: tuple = field(repr=False)
    actor_namespace: tuple = field(repr=False)
    content_namespace: tuple = field(repr=False)
    export_namespace: tuple = field(repr=False)
    manifests: tuple = field(repr=False)
    reserved_guids: tuple
    pawn_channel: int
    pawn_guid: int
    nonce: str = field(repr=False)
    owner_digest: str = field(repr=False)
    created_at_monotonic: float


@dataclass(frozen=True)
class LocalCaptureRecheck:
    """Current independent observer facts, never manufactured from stage_label."""
    pid: int
    created_at: float
    shadow_path: str
    original_sdk_sha256: str
    active_sdk_sha256: str
    trigger_nonce: str
    request_sha256: str
    snapshot_sha256: str
    summary_sha256: str
    correlation_sha256: str
    projection_sha256: str
    policy_sha256: str


@dataclass(frozen=True)
class CurrentLocalFashionProof:
    request: SourceJson = field(repr=False)
    snapshot: SourceJson = field(repr=False)
    summary: SourceJson = field(repr=False)
    correlation: SourceJson = field(repr=False)
    current: LocalCaptureRecheck = field(repr=False)
    projection: SourceJson = field(repr=False)
    reader_policy: SourceJson = field(repr=False)


def source_json(source, seal):
    require(type(source) is SourceJson and type(source.pin) is SourcePin and
        type(source.raw_bytes) is bytes and 0 < len(source.raw_bytes) <= MAX_JSON and
        seal.get(source.pin.relative_path) == source.pin.sha256 and
        digest(source.raw_bytes) == source.pin.sha256, 'sealed_raw_source_required')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate_source_key')
            result[key] = value
        return result
    result = json.loads(source.raw_bytes, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_source')))
    require(type(result) is dict, 'source_object_required')
    return result


def _current(probe, contract, state=None):
    if type(contract) is not JoinedFashionOwnerContract or contract.probe is not probe:
        return False
    c, ticket, r = contract.connection, contract.ticket, contract.registration
    peer = c.ticket_peers.get(ticket.cookie)
    current = c.control_peers.get(peer)
    state = current if state is None else state
    return bool(probe.listening and not probe._stop.is_set() and probe._handshake is not None and
        probe._handshake.packet_ack_probe is c and
        probe._initial_actor_profiles.get(ticket.map_id) is contract.configured and
        tuple(contract.configured['manifests']) == contract.manifests and
        probe._registered_bootstraps.get(ticket.cookie) is r and
        sum(x['ticket'].map_id == ticket.map_id for x in probe._registered_bootstraps.values()) == 1 and
        r['ticket'] is ticket and r['status'] == 'queued' and r['actor_fields'] == contract.actor_fields and
        r['peer'] == peer and r['generation'] is contract.generation and
        probe._handshake.pending.get(peer) is contract.generation and
        contract.generation.echoed is True and contract.generation.verified_at is not None and
        probe._handshake.current_peer_for_generation(contract.generation, ticket) == peer and
        c.peers.get(peer) is contract.transport and current is not None and state is not None and
        current.ticket is ticket and state.ticket is ticket and state.client_join_observed and
        current.pc_restart_pawn_channel == state.pc_restart_pawn_channel == contract.pawn_channel and
        current.pc_restart_pawn_guid == state.pc_restart_pawn_guid == contract.pawn_guid and
        not state.client_closed and c._current_joined_receipt_owner(peer, current, contract.transport) and
        namespace(state.actor_opens) == contract.actor_namespace and
        namespace(state.actor_contents) == contract.content_namespace and
        tuple(sorted(state.actor_exports.items())) == contract.export_namespace and
        not any(item is not None and item.bunch.channel_index == contract.pawn_channel for item in (
            state.pc_ready_ack, state.game_state_start, state.game_state_all_ready, state.game_state_abseil,
            state.game_state_match_info, state.pc_restart, state.pc_view_target,
            state.late_player_state_human_appearance)) and
        type(peer) is tuple and len(peer) == 2 and peer[0] == '127.0.0.1' and
        type(peer[1]) is int and 1 <= peer[1] <= 65535)


def make_join_owner_contract(probe, map_id, *, source_seal):
    require(type(source_seal) is RuntimeSourceSeal, 'runtime_source_seal_required')
    sealed = source_seal.verify()
    require(probe._handshake is not None and probe._admissions is not None and probe.listening,
        'active_local_owner_required')
    c = probe._handshake.packet_ack_probe
    records = [r for r in probe._registered_bootstraps.values() if r['ticket'].map_id == map_id]
    require(len(records) == 1, 'one_current_registered_owner_required')
    r = records[0]; ticket = r['ticket']; peer = r['peer']
    state, t = c.control_peers.get(peer), c.peers.get(peer)
    configured = probe._initial_actor_profiles.get(map_id)
    require(configured is not None and state is not None and t is not None, 'current_profile_and_transport_required')
    fields = deepcopy(tuple(r['actor_fields']))
    actor_guids = tuple(sorted(f['actor_guid'] for f in fields))
    require(len(actor_guids) == len(set(actor_guids)) and
        set(state.actor_opens) == {f['channel_index'] for f in fields}, 'complete_actor_namespace_required')
    pawn_channels = [f['channel_index'] for f in fields
        if f.get('actor_guid') == state.pc_restart_pawn_guid]
    require(len(pawn_channels) == 1 and pawn_channels[0] == state.pc_restart_pawn_channel and
        pawn_channels[0] in state.actor_contents, 'exact_owned_pawn_association_required')
    pawn_manifests = [m for m in configured['manifests'] if type(m) is ActorManifest and
        m.actor_guid == state.pc_restart_pawn_guid and m.channel_index == pawn_channels[0]]
    require(len(pawn_manifests) == 1 and pawn_manifests[0].client_sha256 == SHIPPING_SHA256 and
        pawn_manifests[0].class_path == '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C' and
        pawn_manifests[0].references_resolvable is True and
        sealed.get(pawn_manifests[0].source_relative_path) == pawn_manifests[0].source_sha256,
        'source_qualified_typed_current_pawn_manifest_required')
    reserved = set(actor_guids)
    for f in fields:
        for root in f['exports']:
            node = root; depth = 0
            while node is not None:
                depth += 1
                require(depth <= 32, 'bounded_complete_export_namespace_required')
                reserved.add(node.guid); node = node.outer
    # Actor.exports is the BASE's additional owner namespace; never just inspect
    # the Pawn's references or an old profile subset.
    reserved.update(state.actor_exports)
    nonce = secrets.token_hex(32)
    binding = digest((nonce + ticket.cookie + repr((actor_guids, state.pc_restart_pawn_guid))).encode())
    contract = JoinedFashionOwnerContract(probe, c, configured, r, ticket, r['generation'], t, fields,
        namespace(state.actor_opens), namespace(state.actor_contents),
        deepcopy(tuple(sorted(state.actor_exports.items()))), deepcopy(tuple(configured['manifests'])), tuple(sorted(reserved)),
        pawn_channels[0], state.pc_restart_pawn_guid, nonce, binding, time.monotonic())
    require(_current(probe, contract), 'current_joined_owner_required')
    return contract


def _win_path(value):
    return value.replace('\\','/').casefold() if type(value) is str else None


def _qualify_local(probe, contract, proof, seal, recheck, reader_closure_recheck):
    require(type(proof) is CurrentLocalFashionProof and type(proof.current) is LocalCaptureRecheck and
        callable(recheck), 'same_capture_local_join_proof_missing')
    current = proof.current
    require(recheck(proof) == current, 'current_shadow_capture_changed')
    req, snap, summary, link = (source_json(x, seal) for x in
        (proof.request, proof.snapshot, proof.summary, proof.correlation))
    policy, projection = (source_json(x,seal) for x in (proof.reader_policy,proof.projection))
    flags = reader_flags(include_current_fashion_contracts=True)
    bridge_path = _win_path(policy.get('bridge_path'))
    repository_path = _win_path(FIXED_REPOSITORY_PATH)
    require(_win_path(policy.get('repository_root')) == repository_path and type(bridge_path) is str and
        bridge_path.startswith(repository_path+'/work/') and
        not any(part in ('','..','.') for part in bridge_path[len(repository_path)+1:].split('/')),
        'confined_current_bridge_source_required')
    # Recover the actual case-preserving relative path used in the approved map.
    bridge_relative = policy['bridge_path'].replace('\\','/')[len(FIXED_REPOSITORY_PATH)+1:]
    require(proof.reader_policy.pin.relative_path == 'work/native-appearance-observer-config.json' and
        policy.get('kind') == 'sealed_local_trial_appearance_observer_config_v1' and
        policy.get('enabled') is True and policy.get('shadow_only') is True and
        policy.get('include_current_fashion_contracts') is True and
        _win_path(policy.get('game_root')) == _win_path(FIXED_SHADOW_PATH) and
        _win_path(policy.get('base_root')) == _win_path(FIXED_BASE_PATH) and
        policy.get('client_sha256') == SHIPPING_SHA256 and
        type(policy.get('reader_flags')) is dict and set(policy['reader_flags']) == set(flags) and
        all(policy['reader_flags'][key] is True for key in flags) and
        all(req.get(key) is True for key in flags) and
        policy.get('source_pins') == req.get('source_pins') and
        callable(reader_closure_recheck) and reader_closure_recheck() == policy['source_pins'] and
        type(policy.get('reader_sha256')) is str and len(policy['reader_sha256']) == 64 and
        type(policy.get('bridge_sha256')) is str and len(policy['bridge_sha256']) == 64 and
        type(policy.get('source_pins')) is dict and 1 <= len(policy['source_pins']) <= 512 and
        all(type(path) is str and hex_hash(value) and seal.get(path) == value
            for path,value in policy['source_pins'].items()) and
        all(path in policy['source_pins'] for path in READER_REQUIRED_SOURCE_PATHS) and
        hex_hash(policy['reader_sha256']) and hex_hash(policy['bridge_sha256']) and
        policy.get('reader_sha256') == seal.get('work/read_playable_state_snapshot.py') and
        policy.get('bridge_sha256') == seal.get(bridge_relative),
        'exact_reviewed_nine_flag_reader_closure_required')
    require(type(current.pid) is int and current.pid > 0 and type(req.get('pid')) is int and
        type(current.created_at) in (int,float) and math.isfinite(current.created_at) and current.created_at > 0 and
        type(req.get('created_at')) in (int,float) and
        req.get('pid') == current.pid and req.get('created_at') == current.created_at and
        _win_path(req.get('game_root')) == _win_path(current.shadow_path) == _win_path(FIXED_SHADOW_PATH) and
        req.get('stage_label') == 'local-white-fog' and
        current.original_sdk_sha256 == ORIGINAL_SDK_SHA and
        req.get('existing_sdk_sha256') == current.active_sdk_sha256 == ACTIVE_PROVIDER_SHA and
        snap.get('client_relative_to_game_root') == FIXED_CLIENT_RELATIVE and
        snap.get('requested_pid') == current.pid and type(snap.get('requested_pid')) is int,
        'exact_original_sdk_shadow_process_required')
    identity = snap.get('collection_process_identity', {})
    require(type(identity.get('pid')) is int and type(identity.get('created_at')) in (int,float) and
        identity.get('pid') == current.pid and identity.get('created_at') == current.created_at and
        identity.get('client_sha256') == SHIPPING_SHA256 and
        identity.get('executable_and_creation_time_rechecked') is True and
        identity.get('loaded_module_rechecked') is True, 'original_process_identity_required')
    require((current.request_sha256, current.snapshot_sha256, current.summary_sha256, current.correlation_sha256,
        current.projection_sha256,current.policy_sha256) == tuple(x.pin.sha256 for x in
            (proof.request, proof.snapshot, proof.summary, proof.correlation,proof.projection,proof.reader_policy)),
        'same_capture_source_hashes_required')
    # The existing automatic observer does not emit this cross-domain Join
    # correlation yet. A safe projection or stage label never substitutes for it.
    echo = {'kind':'current_join_capture_v1','trigger_nonce':contract.nonce,
        'owner_binding_digest':contract.owner_digest,'pid':current.pid,'created_at':current.created_at,
        'pawn_guid':contract.pawn_guid,'pawn_channel':contract.pawn_channel,
        'complete_reserved_guids':list(contract.reserved_guids)}
    require(req.get('current_join_capture') == echo and link.get('current_join_capture') == echo and
        type(req['current_join_capture'].get('pid')) is int and
        type(req['current_join_capture'].get('created_at')) in (int,float) and
        type(req['current_join_capture'].get('pawn_guid')) is int and
        type(req['current_join_capture'].get('pawn_channel')) is int,
        'raw_request_current_join_capture_echo_required')
    times = tuple(link.get(key) for key in ('capture_started_at_monotonic',
        'capture_completed_at_monotonic','current_capture_rechecked_at_monotonic'))
    require(all(type(value) in (int,float) and math.isfinite(value) for value in times) and
        contract.created_at_monotonic <= times[0] <= times[1] <= times[2] <= time.monotonic()+1.0 and
        times[1]-times[0] <= 240,
        'current_owner_capture_timestamp_bracket_required')
    require(link.get('kind') == 'same_local_shadow_current_join_correlation_v1' and
        link.get('trigger_nonce') == current.trigger_nonce == contract.nonce and
        link.get('owner_binding_digest') == contract.owner_digest and
        link.get('request_sha256') == proof.request.pin.sha256 and
        link.get('snapshot_sha256') == proof.snapshot.pin.sha256 and
        link.get('summary_sha256') == proof.summary.pin.sha256 and
        link.get('projection_sha256') == proof.projection.pin.sha256 and
        link.get('reader_policy_sha256') == proof.reader_policy.pin.sha256 and
        type(link.get('pid')) is int and type(link.get('created_at')) in (int,float) and
        link.get('pid') == current.pid and link.get('created_at') == current.created_at and
        link.get('shadow_path') == current.shadow_path and
        link.get('original_sdk_sha256') == current.original_sdk_sha256 and
        link.get('active_sdk_sha256') == current.active_sdk_sha256 and
        link.get('provider_source_sha256') == PROVIDER_SOURCE_SHA and
        link.get('original_sdk_metadata_preflight_rechecked') is True and
        link.get('current_provider_bytes_and_source_preflight_rechecked') is True and
        link.get('source_seals') == req.get('source_pins') and
        type(req.get('source_pins')) is dict and bool(req['source_pins']) and
        all(seal.get(p) == h for p,h in req['source_pins'].items()) and
        tuple(link.get('complete_reserved_guids', ())) == contract.reserved_guids,
        'native_capture_to_current_join_correlation_unproved')
    receiver = snap.get('appearance_receiver_state_observation', {})
    metadata = receiver.get('formal_field_metadata', {})
    private = metadata.get('_private_current_Fashion_identity_facts', {})
    require(private.get('kind') == 'same_session_current_typed_Fashion_private_identity_facts' and
        private.get('source_profile_sha256') == metadata.get('source_profile_sha256') and
        all(private.get(k) is True for k in ('decoded_owner_equals_receiver_equals_current_pawn',
            'immediate_identity_relations_and_sources_rechecked',
            'original_late_identity_relations_and_sources_rechecked')) and
        private.get('native_methods_invoked') is False and private.get('process_memory_written') is False and
        all(metadata.get(k) is True for k in ('component_outer_equals_current_pawn',
            'component_name_and_outer_identity_rechecked','late_original_observation_rechecked')),
        'original_late_typed_name_outer_required')
    component, pawn, component_class = (private.get(k,{}) for k in ('component','pawn','component_class'))
    def native_pointer(value):
        return type(value) is int and 0x10000 <= value < 1 << 47 and value % 8 == 0
    require(all(type(row) is dict and native_pointer(row.get('address')) and
        native_pointer(row.get('class_address')) and type(row.get('object_index')) is int and
        0 < row['object_index'] <= 0x7fffffff and type(row.get('serial')) is int and
        0 < row['serial'] <= 0xffffffff for row in (component,pawn,component_class)) and
        native_pointer(component.get('outer_address')) and
        len({row['address'] for row in (component,pawn,component_class)}) == 3 and
        component['class_address'] != pawn['class_address'],
        'initialized_exact_private_native_identity_scalars_required')
    require(type(component.get('name')) is str and component['name'] and
        component.get('outer_address') == pawn.get('address') and type(pawn.get('address')) is int and
        component.get('class_address') == component_class.get('address') and
        component_class.get('name') == 'DFMCharacterFashionComponent', 'same_original_typed_fashion_required')
    guids = snap.get('appearance_existing_guid_references_observation', {})
    name = snap.get('appearance_name_stability_direct_observation', {})
    require(projection.get('kind') == 'automatic_local_trial_appearance_observation_v1' and
        projection.get('status') == 'complete' and all(projection.get(key) ==
            safe_fashion_contract_summary(key,value) and projection[key].get('status') == 'observed'
            for key,value in (('fashion_class_metadata',metadata),('fashion_existing_guids',guids),
                ('fashion_name_stability',name))), 'same_capture_safe_fashion_projection_required')
    summary_receiver = summary.get('appearance_receiver_state_observation',{})
    require(type(summary_receiver) is dict and all(safe_fashion_contract_summary(key,raw_value) ==
        safe_fashion_contract_summary(key,public_value) for key,raw_value,public_value in (
            ('fashion_class_metadata',metadata,summary_receiver.get('formal_field_metadata')),
            ('fashion_existing_guids',guids,summary.get('appearance_existing_guid_references_observation')),
            ('fashion_name_stability',name,summary.get('appearance_name_stability_direct_observation')))) and
        guids.get('status') == name.get('status') == 'observed' and
        all(guids.get(k) is True for k in ('late_original_observation_rechecked','same_owner_relations_rechecked',
            'identities_names_outers_and_storage_rechecked')) and
        guids.get('native_functions_invoked') is False and guids.get('process_memory_written') is False and
        all(name.get(k) is True for k in ('late_original_observation_rechecked','same_original_typed_fashion_rechecked',
            'same_current_pc_pawn_primary_route_rechecked','actual_virtual_targets_and_direct_members_rechecked')) and
        name.get('name_stability_predicate_value') is True and
        name.get('direct_branch') in ('net_addressable_mask_true','object_flags_mask_and_byte_comparison_true') and
        name.get('native_methods_invoked') is False and name.get('process_memory_written') is False,
        'current_original_guid_and_direct_name_stability_required')
    targets = guids.get('targets', [])
    require(type(targets) is list and len(targets) == 2, 'exact_two_guid_targets_required')
    result = {}
    for target in targets:
        require(type(target) is dict and target.get('target_label') in ('current_fashion','current_pawn') and
            target['target_label'] not in result, 'exact_guid_identity_required')
        require(target.get('status') == 'existing_guid_observed' and
            target.get('reverse_and_forward_exact_key_match') is True and
            type(target.get('existing_guid_u32')) is int and 2 <= target['existing_guid_u32'] <= 0xffffffff,
            'unresolved_component_or_export_delivery_branch_unsupported')
        result[target['target_label']] = target['existing_guid_u32']
    require(result['current_pawn'] == contract.pawn_guid, 'native_pawn_guid_differs_from_own_manifest')
    component_guid = result['current_fashion']
    require(component_guid not in contract.reserved_guids, 'component_guid_collides_with_complete_local_namespace')
    require(_current(probe, contract) and recheck(proof) == current, 'owner_or_capture_changed_during_qualification')
    return component_guid


def queue_current_fashion(probe, map_id, *, contract, local_proof, request,
        native_hero_configuration, source_seal, current_capture_recheck):
    require(type(source_seal) is RuntimeSourceSeal, 'runtime_source_seal_required')
    sealed = source_seal.verify()
    require(type(contract) is JoinedFashionOwnerContract and contract.ticket.map_id == map_id and
        _current(probe, contract), 'exact_current_join_contract_required')
    component_guid = _qualify_local(probe, contract, local_proof, sealed, current_capture_recheck,
        source_seal.reader_closure_recheck)
    require(type(request) is CurrentFashionPropertyRequest and request.metadata_source == local_proof.snapshot,
        'same_original_capture_property_source_required')
    c, ticket, transport, generation = contract.connection, contract.ticket, contract.transport, contract.generation
    peer = c.ticket_peers[ticket.cookie]; original = c.control_peers[peer]
    require(original.fashion_subobject_outbox is None and
        getattr(original,'fashion_async_binding',None) is None, 'one_shot_fashion_already_reserved')
    opened, association = original.actor_opens[contract.pawn_channel], original.actor_contents[contract.pawn_channel]
    def receipt(item):
        return c._actor_own_full_send_positive_receipt(original, item,
            ticket=ticket, transport=transport, generation=generation)
    require(receipt(opened) and receipt(association), 'each_pawn_prerequisite_own_full_send_positive_receipt_required')
    config = source_json(native_hero_configuration, sealed)
    hero = ticket.selected_hero_id
    require(type(hero) is int and 0 < hero < 1 << 63 and
        native_hero_configuration.pin.relative_path == 'outputs/df-local-server/protocol/hero_customization_catalog.json' and
        native_hero_configuration.pin.sha256 == HERO_CATALOG_SHA and
        sealed.get(SELECTED_HERO_EVIDENCE) == SELECTED_HERO_EVIDENCE_SHA and
        type(config.get('fashions')) is list and any(type(row) is dict and row.get('hero_id') == hero and
            row.get('default_equip') is True for row in config['fashions']), 'current_ticket_native_hero_configuration_required')
    owner_pin = local_proof.correlation.pin
    # Generation number is scoped to the random Join contract. Native pointers
    # never select a channel or GUID; channel/GUID come only from BASE manifests.
    generation_number = int(contract.nonce[:16], 16) or 1
    owner = OwnedFashionContext(generation_number, contract.pawn_channel, contract.owner_digest, owner_pin,
        'BP_DFMCharacter_C','DFMCharacterFashionComponent','current_owned_pawn_fashion_component',
        True, True, True, True, False, True)
    hero_binding = OwnedHeroIdBinding(generation_number, contract.pawn_channel, contract.owner_digest,
        native_hero_configuration.pin, hero, hero, 'FInt64Property','native_hero_configuration_id',True,True,True)
    reference = QualifiedLocalFashionReference(component_guid, contract.pawn_guid, contract.pawn_channel,
        generation_number, contract.owner_digest, local_proof.snapshot.pin, True,True,True,True)
    actor_guids = tuple(row[1] for row in contract.actor_namespace)
    envelope = ResolvedStableSubobjectProfile(contract.pawn_guid, actor_guids, (component_guid,),
        'normal_client',True,True,True)
    rebuilt = replace(request, current_owner=owner, hero_binding=hero_binding,
        reference=reference, envelope_profile=envelope)
    lease = CurrentPawnChannelLease(c, ticket, transport, generation, generation_number,
        contract.pawn_channel, contract.pawn_guid, association.bunch, contract.owner_digest,
        namespace_digest(contract.actor_namespace), namespace_digest(contract.content_namespace),
        owner_pin,True,True,True,True)
    def current_owner(_lease):
        if not _current(probe, contract):
            return False
        state = c.control_peers[c.ticket_peers[ticket.cookie]]
        return bool(ticket.selected_hero_id == hero and
            all(c._actor_own_full_send_positive_receipt(state, item, ticket=ticket,
                transport=transport, generation=generation) for item in (opened,association)) and
            _qualify_local(probe, contract, local_proof, sealed, current_capture_recheck,
                source_seal.reader_closure_recheck) == component_guid)
    outbox = CurrentFashionSubobjectOutbox(enabled=True, lease=lease, sealed_sources=sealed,
        source_recheck=source_seal.verify, current_owner_check=current_owner,
        max_packet_bytes=c.max_packet_bytes, retry_interval=c.retry_interval,
        max_transmissions=c.max_transmissions, shared_reply_limit=c.max_replies,
        allow_qualified_forward_gap_receipts=c.qualified_receipt_forward_gaps)
    require(outbox.queue(rebuilt), 'fashion_queue_refused')
    source_seal.verify()
    require(_current(probe, contract), 'owner_changed_before_fashion_commit')
    state = c._clone(original)
    state.fashion_subobject_outbox = outbox
    c.control_peers[peer] = state
    return 'queued'
