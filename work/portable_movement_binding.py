"""Read this admission's existing movement metadata; allocate no new component.

The current vitals producer already emits CharMoveComp Name/Outer metadata.
This module connects that exact local GUID allocation to the observed native
class cache and UHT RPC declaration. It does not claim a live PackageMap GUID,
send metadata, infer a delivery ACK, authenticate a connection or advance position.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from dfserver.legacy_ds_actor_manifest import ActorManifest, CLIENT_SHA256
from dfserver.legacy_ds_static_actor_manifest import StaticActorManifest
from dfserver.legacy_ds_actor_fields import NormalClassFieldProfile
from dfserver.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.legacy_ds_ability_component_creation import (
    AbilityComponentCreation, CLASS_PATH as ABILITY_CLASS_PATH, write_creation as write_ability_creation,
)
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.legacy_ds_dynamic_object_creation import DynamicObjectCreation
from dfserver.legacy_ds_dynamic_object_update import DynamicObjectUpdate
from dfserver.legacy_ds_owned_actor_transport import plain_unreliable_actor
from dfserver.legacy_ds_skill_template import SkillTemplateUpdate, write_followup as write_skill_template


ROOT = Path(__file__).resolve().parent.parent
VITALS = 'outputs/df-local-server/protocol/portable-map-spawn/vitals-metadata-probe-schema.json'
OBSERVED = 'work/native-client-tests/1792460999986794500/owned-vitals-metadata.json'
BASE = 'work/evidence/map-system-audit-20261018/'
UHT = BASE+'ai-runtime-research-20261020-world-movement-owner-functions-v1.json'
VITALS_SHA256 = 'acec9f0b1f31346933d48e410ab8c866efd9cbab0c0da144933eafae94b904aa'
PINS = {
    VITALS: VITALS_SHA256,
    OBSERVED: '36f87df56c20a6f1dcdf25190fedc199415be07b0285028c246c9d1b5c0d695d',
    UHT: 'ecb70137ed2b71bb1aa128c3f368ea0ae1a3c1b2a8e7339b875c4b22a7ed6dc9',
    BASE+'ai-runtime-research-20261020-movement-normal-field-header-v1.json':
        '97fb8d2408fdb0f803c06a64583b624e4903f11d82ae74cc5ffc0ef87ae56d10',
    BASE+'native-owned-weapon-rpc-layout-and-directional-content-header-v1.json':
        '87c30714d14d61c187fd47de93d03aaaa6bb9ee00d62481acd860cfd6fe507d4',
    'work/portable_map_vitals_probe.py':
        '3075ab375f16528113512eead014f641595f8fef18f4e102a934346bb0258e84',
    'outputs/df-local-server/dfserver/replication/legacy_ds_class_net_cache.py':
        '6484470b738b7200f3635636d62f7c7e4c41432afa9e8a6c899263fe3960d55c',
    'outputs/df-local-server/dfserver/replication/legacy_ds_default_subobject.py':
        # Export/body separation preserves the checked combined wire vectors.
        '2eb858e147db841b060d7c10da4872517855c259bdad9e9e62d35dd967f07b47',
    'outputs/df-local-server/dfserver/transport/native/legacy_ds_owned_actor_transport.py':
        '70c323bb6c438b8c9dd69d644e580c735bc61c8f071e2503403d137f35d5f338',
    'outputs/df-local-server/dfserver/replication/legacy_ds_ability_component_creation.py':
        '8ff4476f49b2e3b20cc46ad8d8853cf933dce2eadb2bbe29791677ab3d4d9094',
    'outputs/df-local-server/dfserver/replication/legacy_ds_actor_content.py':
        'c61ce7fe0ba2ba6456d0a9e6575933b64669180964ca709e9c21a321f390e575',
}
IMPLEMENTATIONS = ('outputs/df-local-server/dfserver/legacy_ds_skill_template.py',
                   'work/skill_template_replication.py')


def _read(relative, digest):
    raw = (ROOT/relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('The source-qualified movement binding changed: '+relative)
    return raw


@lru_cache(maxsize=1)
def _contract():
    documents = {name: _read(name, expected) for name, expected in PINS.items()}
    schema, observed, uht = (json.loads(documents[n]) for n in (VITALS, OBSERVED, UHT))
    component = [c for c in schema['components'] if c['name'] == 'CharMoveComp']
    current = [c for c in observed['objects'] if c['identity']['name'] == 'CharMoveComp']
    if (len(component) != 1 or len(current) != 1 or
            schema['client_sha256'] != CLIENT_SHA256 or observed['client_sha256'] != CLIENT_SHA256 or
            component[0]['class_path'] != current[0]['class_path'] or
            current[0]['object_metadata']['default_subobject_flag_present'] is not True):
        raise ValueError('The cooked and observed movement component declarations differ')
    pawn = next(c for c in observed['objects'] if c['scope'] == 'current_pawn')
    if current[0]['object_metadata']['outer']['identity'] != pawn['identity']:
        raise ValueError('The observed movement Outer is not the selected Pawn')
    cache = current[0]['existing_driver_class']
    fields = [f for node in cache['cache_nodes'] for f in node['fields']]
    move = [f for f in fields if f['descriptor_name'] == 'NewServerMove']
    declaration = [f for c in uht['classes'] for f in c['net_function_declarations']
        if f['name'] == 'NewServerMove']
    if len(move) != 1 or len(declaration) != 1 or move[0]['incompatible'] is not False:
        raise ValueError('One compatible actual movement RPC field is required')
    indices = tuple(sorted(f['rep_index'] for f in fields))
    # Native12864fe4..fff uses ClassNetCache+0 plus +28 plus one. The
    # extra representable value has no declared field and must not be dispatched.
    maximum = cache['exclusive_index_maximum']
    if indices != tuple(range(len(fields))) or maximum != len(fields)+1:
        raise ValueError('The observed native class-cache interval/extra slot changed')
    flags = int(declaration[0]['function_flags'], 16)
    if (not flags & 0x40 or not flags & 0x200000 or flags & 0x80 or
            move[0]['rep_index'] != 6 or maximum != 10 or
            declaration[0]['property_count'] != 1 or declaration[0]['native_param_bytes'] != 248):
        raise ValueError('The actual unreliable server movement declaration changed')
    source_pins = dict(PINS)
    for name, digest in schema['sources'].items():
        _read(name, digest)
        source_pins[name] = digest
    for source in schema['cooked_sources']:
        _read(source['relative_path'], source['sha256'])
        source_pins[source['relative_path']] = source['sha256']
    return (schema['pawn_class_path'], component[0]['class_path'], component[0]['name'],
        move[0]['rep_index'], maximum, indices, flags, tuple(sorted(source_pins.items())))


def source_pins():
    pins = dict(_contract()[-1])
    # Trial/profile owners freeze these current implementation versions at setup.
    for relative in (*IMPLEMENTATIONS, 'work/portable_movement_binding.py'):
        pins[relative] = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    return pins


@dataclass(frozen=True)
class AdmittedMovementConfig:
    pawn_guid: int
    pawn_channel: int
    movement_guid: int
    component_name: str
    component_class: str
    rpc_index: int
    field_profile: NormalClassFieldProfile
    cache_field_indices: tuple
    function_flags: int
    metadata_update: DefaultSubobjectUpdate
    metadata_stage: int
    new_server_move_reliable: bool = False
    client_to_server_stable_name_bit: bool = False
    native_guid_observed: bool = False


def _updates(row):
    if 'default_subobject' in row:
        yield 0, row['default_subobject']
    for update in row.get('default_subobjects', ()):
        yield 0, update
    for ordinal, group in enumerate(row.get('continuations', ()), 1):
        if type(group) is not tuple:
            raise ValueError('The complete admitted default-component groups are required')
        for update in group:
            yield ordinal, update


def from_admitted_plans(manifests, plans):
    """Extract an existing exact allocation; never allocate or guess a GUID.

    Root still proves this metadata stage's own full-send ACK, active admission,
    Pawn channel, peer/transport generation and current source guard at dispatch.
    Plans alone do not certify the game's current PackageMap binding.
    """
    pawn_class, component_class, name, index, maximum, indices, flags, _ = _contract()
    if (type(manifests) is not tuple or not manifests or
            any(type(m) not in (ActorManifest, StaticActorManifest) or m.client_sha256 != CLIENT_SHA256
                for m in manifests) or
            type(plans) is not tuple or not plans):
        raise ValueError('The complete source-qualified admitted Actor manifests/plans are required')
    pawns = [m for m in manifests if type(m) is ActorManifest and m.class_path == pawn_class]
    if len(pawns) != 1:
        raise ValueError('Exactly one admitted native owning Pawn is required')
    pawn = pawns[0]
    reserved = set()
    for manifest in manifests:
        reserved.add(manifest.actor_guid)
        if type(manifest) is ActorManifest:
            reserved.update((manifest.class_guid, manifest.archetype_guid))
        reserved.update(p.guid for p in manifest.path_bindings)
        if manifest.level_guid is not None:
            reserved.add(manifest.level_guid)
    actor_by_guid = {m.actor_guid: m for m in manifests}
    owners, candidates, created_abilities = {}, [], {}
    for row in plans:
        if (type(row) is not dict or row.get('actor_guid') not in actor_by_guid or
                row.get('channel_index') != actor_by_guid[row['actor_guid']].channel_index):
            raise ValueError('The admitted content owner/channel differs from its actual manifest')
        for stage, update in _updates(row):
            if type(update) is ActorContentBlock:
                # Actor-selector continuations add no subobject namespace entry.
                write_actor_content_blocks(BitWriter(), (update,))
                continue
            if type(update) is SkillTemplateUpdate:
                created = created_abilities.get(update.guid) if type(update.guid) is int else None
                if (created is None or stage <= created[0] or update.actor_guid != row['actor_guid'] or
                        (update.guid, update.actor_guid, update.class_guid, update.class_path) != created[1]):
                    raise ValueError('GS template values require their exact preceding component creation binding')
                write_skill_template(BitWriter(), update,
                    actor_guids=tuple(guid for guid in actor_by_guid if not guid & 1),
                    object_bindings=(created[1],))
                continue
            if type(update) not in (DefaultSubobjectUpdate, DynamicObjectCreation, DynamicObjectUpdate,
                                    AbilityComponentCreation):
                raise ValueError('Unsupported admitted component namespace type: '+type(update).__name__)
            if (update.actor_guid != row['actor_guid'] or
                    update.guid in reserved):
                raise ValueError('A default-component GUID aliases its parent or existing Actor/path namespace')
            if type(update) is DefaultSubobjectUpdate:
                update.__post_init__()
            elif type(update) is AbilityComponentCreation:
                if stage < 1 or update.guid in owners:
                    raise ValueError('One fresh GS ability creation continuation is required')
                write_ability_creation(BitWriter(), update, actor_guids=tuple(actor_by_guid),
                    exported_class_guids=tuple(binding.guid
                        for binding in actor_by_guid[update.actor_guid].path_bindings
                        if binding.full_path == ABILITY_CLASS_PATH))
                created_abilities[update.guid] = (stage,
                    (update.guid, update.actor_guid, update.class_guid, ABILITY_CLASS_PATH))
            elif (type(update.guid) is not int or not 2 <= update.guid <= 0xffffffff or update.guid & 1 or
                    type(update.class_guid) is not int or not 3 <= update.class_guid <= 0xffffffff or
                    not update.class_guid & 1 or type(update.class_path) is not str):
                raise ValueError('The admitted dynamic object has an invalid namespace binding')
            owner = (update.actor_guid, 'default', update.name) if type(update) is DefaultSubobjectUpdate else (
                update.actor_guid, 'dynamic', ABILITY_CLASS_PATH
                    if type(update) is AbilityComponentCreation else update.class_path)
            if owners.get(update.guid, owner) != owner:
                raise ValueError('A default-component GUID has conflicting Name/Outer owners')
            owners[update.guid] = owner
            if (type(update) is DefaultSubobjectUpdate and update.name == name and
                    update.actor_guid == pawn.actor_guid):
                if (update.source_sha256 != VITALS_SHA256 or update.payload != b'\x00\x00' or
                        update.payload_bit_count != 9 or update.has_rep_layout is not True):
                    raise ValueError('The actual movement metadata kickoff is not its source-qualified empty update')
                candidates.append((stage, update))
    if len(candidates) != 1:
        raise ValueError('Exactly one existing admitted CharMoveComp metadata update is required')
    stage, update = candidates[0]
    return AdmittedMovementConfig(pawn.actor_guid, pawn.channel_index, update.guid, name,
        component_class, index, NormalClassFieldProfile(maximum, False), indices, flags, update, stage)


def qualify_unreliable_header(config, bunch):
    """Require this component RPC's normal unreliable Actor-channel header.

    Content is still C->S has-layout/Actor-selector/packed-GUID/packed-bit-length,
    followed by normal class fields with this config's actual upper bound. The
    caller isolates component GUID and field6 before calling the parameter codec.
    """
    if (type(config) is not AdmittedMovementConfig or config.new_server_move_reliable is not False or
            config.function_flags != _contract()[6] or config.client_to_server_stable_name_bit is not False or
            config.field_profile != NormalClassFieldProfile(_contract()[4], False)):
        raise ValueError('The exact source-qualified unreliable movement config is required')
    plain_unreliable_actor(bunch, channel_index=config.pawn_channel)
