"""Bounded native control admission and explicit initial Actor-open transport.

The recovered wire codec carries Hello0, Challenge3, Login5, Welcome1, Netspeed4
and Join9. Login admission uses only our local lobby-issued match ticket.
Welcome selects a separately evidenced persistent map, never a safehouse
fallback. Join9 is an observed client map-load notification, not a spawned Pawn.
An explicit local producer may queue a restricted Actor-open after Join. Its
packet ACK proves delivery only, not native object resolution or possession.
"""
from dataclasses import dataclass, field, replace
import hashlib
import math
import time

from dfserver.transport.native.legacy_ds_control_fields import ControlMessage, decode_messages, encode_message
from dfserver.transport.native.legacy_ds_control_probe import LegacyDSControlProbe, CONTROL_NAME
from dfserver.replication.legacy_ds_actor_bunch import build_initial_actor_bunch
from dfserver.replication.legacy_ds_actor_content import ActorContentBlock, write_actor_content_blocks
from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
from dfserver.transport.native.legacy_ds_login_fields import decode_single_login5
from dfserver.transport.native.legacy_ds_packet_ack_probe import MASK
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch, WirePacket, decode_observed_application, encode_observed_application

RELIABLE_RETRY_WINDOW = 128  # Local bound below half of the 10-bit sequence space.
MAX_INITIAL_ACTOR_CHANNELS = 16  # Local one-open-per-channel/session bound.
MAX_PC_STARTUP_RECEIPT_REPLIES = 4096  # Local bound separate from control retransmissions.
MAX_ACTUAL_APPLICATION_SENDS = 128  # Metadata only, per current connection owner.
MAX_TRANSPORT_KEEPALIVES = 4096
KNOWN_RECEIPT_SEQUENCE_HALF_RANGE = (MASK + 1) // 2
LOCAL_STAGE_DEADLINE_SECONDS = 120.0
MAX_LOCAL_STAGE_PREPARATIONS = 512
MAX_CONTENT_CONTINUATIONS = 64
MAX_POST_OPEN_CONTENT_BUNCHES = 96
MAX_POST_OPEN_WIRE_BUNCHES = 256
MAX_ADMITTED_RECEIPT_JOURNAL_ENTRIES = 256
MAX_ADMITTED_RECEIPT_JOURNAL_BYTES = 262144
_RECEIPT_LEDGER_REJECTION_REASONS = frozenset((
    'unsupported_or_malformed_bunch', 'nonconsecutive_sequence', 'conflicting_reliable_digest',
    'assembly_limit', 'partial_initial_conflict', 'partial_nonfinal_not_byte_aligned',
    'partial_without_initial', 'unfinished_partial_conflict', 'owning_pawn_binding_not_current',
    'opaque_journal_body_limit', 'reliable_queue_limit'))
ADMITTED_RECEIPT_REJECTION_CODES = frozenset((
    'owner_lease_not_current', 'pc_restart_binding_invalid', 'initial_delivery_proof_missing',
    'opaque_journal_body_limit', 'pawn_binding_invalid', 'actor_channel_outside_owned_namespace',
    'control_framing_unsupported', 'control_sequence_conflict', 'control_decode_unsupported',
    'control_notification_empty', 'control_actor_failure_outside_static_subset',
    'control_semantics_unsupported', 'pc_source_or_owner_binding_invalid', 'pc_delivery_binding_invalid',
    'pc_unreliable_receiver_missing', 'pc_unreliable_rpc_unsupported', 'pc_channel_outside_namespace',
    'pc_startup_marker_missing', 'pc_ledger_seed_untrusted', 'pc_receipt_or_rpc_missing',
    'validation_rejected', *(prefix + reason for prefix in ('pc_ledger_', 'pawn_ledger_', 'owned_ledger_')
        for reason in _RECEIPT_LEDGER_REJECTION_REASONS)))


class _AdmittedActorReceiptRejection(ValueError):
    """A closed diagnostic code; exception text never enters a report."""
    def __init__(self, reason_code):
        self.reason_code = (reason_code if reason_code in ADMITTED_RECEIPT_REJECTION_CODES
                            else 'validation_rejected')
        super().__init__(self.reason_code)


def _ledger_rejection(prefix, reason):
    return _AdmittedActorReceiptRejection(prefix + reason
        if reason in _RECEIPT_LEDGER_REJECTION_REASONS else 'validation_rejected')


@dataclass
class ReliableControl:
    message_id: int
    payload: bytes = field(repr=False)
    channel_sequence: int
    sent_packets: tuple = ()
    last_sent_at: float = 0.0
    transmissions: int = 0


@dataclass
class ActorOpenDelivery:
    bunch: WireBunch = field(repr=False)
    actor_guid: int
    sent_packets: tuple = ()
    last_sent_at: float = 0.0
    transmissions: int = 0
    delivered: bool = False
    local_stage_first_prepared_at: float | None = None
    local_stage_deadline: float | None = None
    local_stage_ticket: object = field(default=None, repr=False)
    local_stage_generation: object = field(default=None, repr=False)
    local_stage_transport: object = field(default=None, repr=False)
    local_stage_full_sends: int = 0
    local_stage_expired: bool = False
    content_dependencies: tuple = ()
    continuations: tuple = field(default=(), repr=False)
    open_fields: object = field(default=None, repr=False)
    component_bindings: tuple = field(default=(), repr=False)
    content_stage_dependencies: tuple = ()
    content_stage_policy: tuple | None = field(default=None, repr=False)
    fragments: tuple = field(default=(), repr=False)


def _content_items(state):
    return tuple(item for head in state.actor_contents.values() for item in (head, *head.continuations))


def _wire_items(item):
    return item.fragments or (item,)


def _content_wire_items(state):
    return tuple(piece for item in _content_items(state) for piece in _wire_items(item))


def _refresh_fragment_delivery(item):
    if item.fragments:
        item.delivered = all(piece.delivered for piece in item.fragments)
        item.transmissions = max(piece.transmissions for piece in item.fragments)
        item.last_sent_at = max(piece.last_sent_at for piece in item.fragments)
        item.sent_packets = tuple(dict.fromkeys(sequence for piece in item.fragments
                                               for sequence in piece.sent_packets))
        item.local_stage_expired = any(piece.local_stage_expired for piece in item.fragments)


def _prepare_content_delivery(bunch, actor_guid, max_packet_bytes, *, parts=None, fragment=True):
    from dfserver.transport.native.legacy_ds_reliable_fragmentation import (
        fragment_content_bunch, packet_fits)
    try:
        packet_fits(bunch, max_packet_bytes)
        return ActorOpenDelivery(bunch, actor_guid)
    except ValueError:
        if not fragment:
            raise
    if parts is not None:
        exports, body = parts
        export_bunch = replace(bunch, payload=exports[0], payload_bits=exports[1])
        packet_fits(export_bunch, max_packet_bytes)  # Never split GUID export grammar.
        body_bunch = replace(bunch, payload=body[0], payload_bits=body[1],
            package_exports=False, channel_sequence=(bunch.channel_sequence+1)&1023)
        pieces = (export_bunch, *fragment_content_bunch(body_bunch, max_packet_bytes=max_packet_bytes))
    else:
        pieces = fragment_content_bunch(bunch, max_packet_bytes=max_packet_bytes)
    # The logical marker reserves the final wire sequence. It is never emitted;
    # subsequent logical stages/RPCs allocate after it, including sequence wrap.
    return ActorOpenDelivery(replace(bunch, channel_sequence=pieces[-1].channel_sequence), actor_guid,
        fragments=tuple(ActorOpenDelivery(piece, actor_guid) for piece in pieces))


def _content_namespace(state):
    return tuple(_content_stage_signature(channel, ordinal, item)
        for channel in sorted(state.actor_contents)
        for ordinal, item in enumerate((state.actor_contents[channel], *state.actor_contents[channel].continuations)))


def _content_stage_signature(channel, ordinal, item):
    value = (channel, ordinal, item.actor_guid, item.bunch, item.content_dependencies,
        item.content_stage_dependencies, item.component_bindings, len(item.continuations))
    return value + (tuple((piece.actor_guid, piece.bunch, len(piece.fragments), len(piece.continuations))
        for piece in item.fragments),) if item.fragments else value


def _content_policies_current(contents):
    return all(item.content_stage_policy == _content_stage_signature(channel, ordinal, item)
        if item.content_stage_policy is not None else not item.content_stage_dependencies
        for channel, head in contents.items() for ordinal, item in enumerate((head, *head.continuations)))


def _content_stage_dependencies(value, channel, legacy_dependencies):
    if (type(value) is not tuple or len(value) > MAX_INITIAL_ACTOR_CHANNELS or any(
            type(target) is not tuple or len(target) != 2 or
            type(target[0]) is not int or not 1 <= target[0] <= 0xffffffff or
            target[0] == channel or target[0] in legacy_dependencies or
            type(target[1]) is not int or not 0 <= target[1] <= MAX_CONTENT_CONTINUATIONS
            for target in value)):
        raise ValueError('Stage prerequisites require bounded distinct other channel/ordinal pairs')
    if len({target[0] for target in value}) != len(value):
        raise ValueError('Stage prerequisites cannot alias the same target channel')
    return value


def _validate_content_stage_graph(contents):
    nodes = {(channel, ordinal): item for channel, head in contents.items()
        for ordinal, item in enumerate((head, *head.continuations))}
    edges = {}
    for (channel, ordinal), item in nodes.items():
        targets = set(item.content_stage_dependencies)
        if ordinal:
            targets.add((channel, ordinal-1))
        for target in item.content_dependencies:
            if target not in contents:
                raise ValueError('Post-open prerequisite content channel is missing')
            targets.add((target, len(contents[target].continuations)))
        if not targets <= nodes.keys():
            raise ValueError('Post-open prerequisite content stage is missing')
        edges[channel, ordinal] = targets
    pending, completed = set(nodes), set()
    while pending:
        ready = {node for node in pending if edges[node] <= completed}
        if not ready:
            raise ValueError('Post-open prerequisite content stages are cyclic')
        completed.update(ready)
        pending.difference_update(ready)


def _clone_content(item):
    return replace(item, fragments=tuple(replace(piece) for piece in item.fragments),
        continuations=tuple(replace(child, fragments=tuple(replace(piece) for piece in child.fragments))
                            for child in item.continuations))


def _last_actor_content(state, channel, opened):
    head = state.actor_contents.get(channel)
    return (head.continuations[-1] if head.continuations else head) if head is not None else opened


def _component_namespace(state):
    bindings = {}
    for item in _content_items(state):
        for guid, actor_guid, name in item.component_bindings:
            binding = (actor_guid, name)
            if (guid in bindings and bindings[guid] != binding or
                    any(value == binding and previous != guid for previous, value in bindings.items())):
                raise ValueError('Queued component GUID/name bindings conflict')
            bindings[guid] = binding
    return bindings


def preflight_actor_content_plans(initial_actor_fields, plans, *, initial_channel_sequence,
                                  max_packet_bytes):
    """Build one explicit followup per existing Actor channel, without mutation.

    Head is stage 0, continuation ordinals start at 1. after_content_stages
    applies only to the head; continuation_after_content_stages is an equally
    sized tuple of per-tail prerequisites. Old after_content still requires
    each target channel's complete content series before any dependent stage.
    Actor-selector framing is source-qualified by the existing content codec.
    Property bodies remain opaque caller inputs; delivery does not prove object
    resolution, reference assignment or possession. A source-declared default
    subobject may add its Name/Outer export to this same reliable followup.
    """
    if (type(plans) is not tuple or len(plans) > MAX_INITIAL_ACTOR_CHANNELS or
            type(initial_channel_sequence) is not int or
            not 0 <= initial_channel_sequence < 1024 or
            type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1492):
        raise ValueError('An explicit bounded post-open Actor content profile is required')
    if (type(initial_actor_fields) is not tuple or
            not 1 <= len(initial_actor_fields) <= MAX_INITIAL_ACTOR_CHANNELS):
        raise ValueError('Post-open content requires an explicit initial Actor set')
    actors, static_actors = {}, set()
    for fields in initial_actor_fields:
        if (type(fields) is not dict or type(fields.get('channel_index')) is not int or
                type(fields.get('actor_guid')) is not int or
                not 1 <= fields['channel_index'] <= 0xffffffff or
                not 2 <= fields['actor_guid'] <= 0xffffffff or
                fields['channel_index'] in actors or fields['actor_guid'] in actors.values()):
            raise ValueError('Post-open content requires distinct existing Actor channels')
        actors[fields['channel_index']] = fields['actor_guid']
        kind = fields.get('actor_kind', 'dynamic')
        if kind not in ('dynamic', 'static'):
            raise ValueError('Post-open content requires an explicit supported Actor kind')
        if kind == 'static':
            if (not fields['actor_guid'] & 1 or fields['actor_guid'] < 3 or
                    fields.get('references_resolvable') is not True or
                    fields.get('actor_open_hook_has_no_extra_fields') is not True):
                raise ValueError('Existing level Actor content requires its qualified static open')
            static_actors.add(fields['actor_guid'])
        elif fields['actor_guid'] & 1:
            raise ValueError('An odd Actor reference requires an explicit static open')
    staged, namespace, component_bindings = {}, set(actors.values()), {}
    ability_class_exports = set()
    ability_game_state_actors = set()
    fsm_pawn_actors, fsm_class_exports = set(), set()
    created_dynamic_objects = {}
    created_ability_objects = {}
    from dfserver.replication.legacy_ds_dynamic_object_creation import DynamicObjectCreation, qualified_class_exports
    has_fsm_creation = any(type(value) is DynamicObjectCreation
        for plan in plans if type(plan) is dict and type(plan.get('continuations', ())) is tuple
        for group in plan.get('continuations', ()) if type(group) is tuple for value in group)
    from dfserver.replication.legacy_ds_guid_exports import GuidExportNode, DEFAULT_LIMITS as export_limits
    for fields in initial_actor_fields:
        exports = fields.get('exports', ())
        if type(exports) is not tuple or len(exports) > export_limits.max_exports:
            raise ValueError('A bounded initial export namespace is required')
        if has_fsm_creation:
            fsm_class_exports.update(qualified_class_exports(exports))
        nodes, exported = 0, set()
        for root in exports:
            node, depth = root, 0
            while node is not None:
                nodes += 1
                if (type(node) is not GuidExportNode or depth > export_limits.max_depth or
                        nodes > export_limits.max_nodes):
                    raise ValueError('Initial export namespace depth or node bound exceeded')
                namespace.add(node.guid)
                exported.add(node.guid)
                if (node.path == 'DFMAbilityGameStateComponent' and node.outer is not None and
                        node.outer.path == '/Script/DFMAbility' and node.outer.outer is None):
                    ability_class_exports.add(node.guid)
                if (node.guid == fields.get('archetype_guid') and
                        node.path == 'Default__BP_GameState_PVPVE_C' and node.outer is not None and
                        node.outer.path == '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE' and
                        node.outer.outer is None):
                    ability_game_state_actors.add(fields['actor_guid'])
                if (node.guid == fields.get('archetype_guid') and
                        node.path == 'Default__BP_DFMCharacter_C' and node.outer is not None and
                        node.outer.path == '/Game/BluePrints/Characters/BP_DFMCharacter' and
                        node.outer.outer is None):
                    fsm_pawn_actors.add(fields['actor_guid'])
                node, depth = node.outer, depth + 1
        if fields['actor_guid'] in static_actors and fields['actor_guid'] not in exported:
            raise ValueError('The existing level Actor must occur in its static export graph')
    for plan in plans:
        keys = set(plan) if type(plan) is dict else set()
        required = {'channel_index', 'actor_guid', 'content_blocks'}
        if (type(plan) is not dict or not required <= keys or
                not keys <= required | {'default_subobject', 'default_subobjects', 'after_content', 'continuations',
                                        'after_content_stages', 'continuation_after_content_stages',
                                        'static_content_source_sha256'} or
                {'default_subobject', 'default_subobjects'} <= keys or
                type(plan['channel_index']) is not int or type(plan['actor_guid']) is not int or
                plan['channel_index'] not in actors or
                plan['actor_guid'] != actors[plan['channel_index']] or
                plan['actor_guid'] & 1 and plan['actor_guid'] not in static_actors or
                plan['channel_index'] in staged or type(plan['content_blocks']) is not tuple or
                not plan['content_blocks'] or
                any(type(block) is not ActorContentBlock for block in plan['content_blocks'])):
            raise ValueError('Post-open content must bind one exact existing Actor per channel')
        static_source = plan.get('static_content_source_sha256')
        if plan['actor_guid'] in static_actors:
            if (type(static_source) is not str or len(static_source) != 64 or
                    any(c not in '0123456789abcdef' for c in static_source)):
                raise ValueError('Existing level Actor content requires an explicit qualified source SHA256')
        elif static_source is not None:
            raise ValueError('Static content source qualification cannot change a dynamic Actor kind')
        dependencies = plan.get('after_content', ())
        if (type(dependencies) is not tuple or len(dependencies) > MAX_INITIAL_ACTOR_CHANNELS or
                any(type(c) is not int or c not in actors or c == plan['channel_index'] for c in dependencies) or
                len(set(dependencies)) != len(dependencies)):
            raise ValueError('Post-open prerequisites must name distinct other Actor channels')
        stage_dependencies = _content_stage_dependencies(plan.get('after_content_stages', ()),
            plan['channel_index'], dependencies)
        from dfserver.transport.native.legacy_ds_reliable_fragmentation import MAX_ASSEMBLED_CONTENT_BITS
        writer = BitWriter(maximum_bits=MAX_ASSEMBLED_CONTENT_BITS)
        has_components = 'default_subobject' in plan or 'default_subobjects' in plan
        head_bindings = ()
        head_parts = None
        if has_components:
            from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate, default_subobject_followup_parts
            updates = (plan['default_subobject'],) if 'default_subobject' in plan else plan['default_subobjects']
            if (type(updates) is not tuple or not 1 <= len(updates) <= 8 or
                    any(type(u) is not DefaultSubobjectUpdate or u.actor_guid != plan['actor_guid'] or
                        u.guid in namespace for u in updates)):
                raise ValueError('Default subobject conflicts with the prepared Actor/export namespace')
            head_parts = default_subobject_followup_parts(updates, plan['content_blocks'], tuple(actors.values()))
            for part in head_parts:
                writer.write_payload(*part)
            namespace.update(u.guid for u in updates)
            component_bindings.update((u.guid, (u.actor_guid, u.name)) for u in updates)
            head_bindings = tuple((u.guid, u.actor_guid, u.name) for u in updates)
        else:
            write_actor_content_blocks(writer, plan['content_blocks'])
        bunch = WireBunch(plan['channel_index'], writer.to_bytes(), writer.bit_count,
            reliable=True, channel_sequence=(initial_channel_sequence + 1) & 1023,
            channel_name=ChannelName(hardcoded_index=102), package_exports=has_components)
        head = _prepare_content_delivery(bunch, plan['actor_guid'], max_packet_bytes, parts=head_parts)
        next_sequence = (head.bunch.channel_sequence+1)&1023
        continuation_groups = plan.get('continuations', ())
        actor_fields = next(f for f in initial_actor_fields if f['channel_index'] == plan['channel_index'])
        if (type(continuation_groups) is not tuple or len(continuation_groups) > MAX_CONTENT_CONTINUATIONS or
                continuation_groups and actor_fields.get('local_player_index') is not None):
            raise ValueError('A bounded non-controller Actor or component content series is required')
        continuation_dependencies = plan.get('continuation_after_content_stages',
            ((),)*len(continuation_groups))
        if type(continuation_dependencies) is not tuple or len(continuation_dependencies) != len(continuation_groups):
            raise ValueError('Each continuation must have one explicit stage prerequisite tuple')
        continuation_dependencies = tuple(_content_stage_dependencies(value, plan['channel_index'], dependencies)
            for value in continuation_dependencies)
        tails = []
        for index, group in enumerate(continuation_groups, 2):
            from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate, default_subobject_followup_parts
            from dfserver.replication.legacy_ds_ability_component_creation import AbilityComponentCreation, CLASS_PATH, write_creation
            from dfserver.replication.legacy_ds_dynamic_object_creation import DynamicObjectCreation, write_creation as write_object_creation
            from dfserver.replication.legacy_ds_dynamic_object_update import DynamicObjectUpdate, write_update as write_object_update
            from dfserver.replication.legacy_ds_skill_template import SkillTemplateUpdate, write_followup as write_skill_template
            if type(group) is not tuple or not 1 <= len(group) <= 8:
                raise ValueError('Each continuation requires a bounded homogeneous content tuple')
            actor_tail = all(type(value) is ActorContentBlock for value in group)
            dynamic_tail = all(type(value) is AbilityComponentCreation for value in group)
            object_tail = all(type(value) is DynamicObjectCreation for value in group)
            object_update_tail = all(type(value) is DynamicObjectUpdate for value in group)
            skill_template_tail = all(type(value) is SkillTemplateUpdate for value in group)
            components = () if actor_tail or dynamic_tail or object_tail or object_update_tail or skill_template_tail else group
            if any(type(u) is not DefaultSubobjectUpdate or u.actor_guid != plan['actor_guid']
                   for u in components):
                raise ValueError('Each continuation must target this Actor or its explicit components')
            for update in components:
                binding = (update.actor_guid, update.name)
                if (update.guid in namespace and component_bindings.get(update.guid) != binding or
                        any(value == binding and guid != update.guid for guid, value in component_bindings.items())):
                    raise ValueError('A continuation changes an existing component GUID/name binding')
                namespace.add(update.guid)
                component_bindings[update.guid] = binding
            tail_writer = BitWriter(maximum_bits=MAX_ASSEMBLED_CONTENT_BITS
                if actor_tail or components else max_packet_bytes*8)
            tail_parts = None
            if actor_tail:
                write_actor_content_blocks(tail_writer, group)
            elif dynamic_tail:
                if plan['actor_guid'] not in ability_game_state_actors:
                    raise ValueError('Dynamic ability creation requires the source-qualified GameState archetype')
                for update in group:
                    binding = (update.actor_guid, CLASS_PATH)
                    if (update.actor_guid != plan['actor_guid'] or update.guid in namespace or
                            binding in component_bindings.values()):
                        raise ValueError('Dynamic ability creation requires its exact fresh GS component binding')
                    write_creation(tail_writer, update, actor_guids=tuple(actors.values()),
                                   exported_class_guids=tuple(sorted(ability_class_exports)))
                    namespace.add(update.guid)
                    component_bindings[update.guid] = binding
                    created_ability_objects[update.guid] = (update.guid, update.actor_guid,
                        update.class_guid, CLASS_PATH)
            elif object_tail:
                if plan['actor_guid'] not in fsm_pawn_actors:
                    raise ValueError('Dynamic FSM creation requires the qualified owning Pawn archetype')
                for update in group:
                    binding = (update.actor_guid, update.class_path)
                    if update.actor_guid != plan['actor_guid'] or binding in component_bindings.values():
                        raise ValueError('Dynamic FSM creation requires one exact fresh Pawn object binding')
                    write_object_creation(tail_writer, update, actor_guids=tuple(actors.values()),
                        exported_class_bindings=tuple(sorted(fsm_class_exports)),
                        allocated_guids=tuple(sorted(namespace)))
                    namespace.add(update.guid)
                    component_bindings[update.guid] = binding
                    created_dynamic_objects[update.guid] = (
                        update.guid, update.actor_guid, update.class_guid, update.class_path)
            elif object_update_tail:
                if plan['actor_guid'] not in fsm_pawn_actors:
                    raise ValueError('Dynamic FSM followup requires the exact owning Pawn archetype')
                for update in group:
                    if update.actor_guid != plan['actor_guid']:
                        raise ValueError('A dynamic FSM followup cannot change its owning Actor')
                    write_object_update(tail_writer, update, actor_guids=tuple(actors.values()),
                        object_bindings=tuple(created_dynamic_objects.values()))
            elif skill_template_tail:
                if plan['actor_guid'] not in ability_game_state_actors:
                    raise ValueError('Skill templates require the exact source-qualified GameState')
                for update in group:
                    if update.actor_guid != plan['actor_guid']:
                        raise ValueError('Skill template values cannot change their owning GameState')
                    write_skill_template(tail_writer, update,
                        actor_guids=tuple(guid for guid in actors.values() if not guid & 1),
                        object_bindings=tuple(created_ability_objects.values()))
            else:
                tail_parts = default_subobject_followup_parts(components, (), tuple(actors.values()))
                for part in tail_parts:
                    tail_writer.write_payload(*part)
            tail_bunch = WireBunch(plan['channel_index'], tail_writer.to_bytes(), tail_writer.bit_count,
                reliable=True, channel_sequence=next_sequence,
                channel_name=ChannelName(hardcoded_index=102),
                package_exports=not (actor_tail or dynamic_tail or object_tail or object_update_tail or skill_template_tail))
            tail = _prepare_content_delivery(tail_bunch, plan['actor_guid'], max_packet_bytes,
                parts=tail_parts, fragment=actor_tail or bool(components))
            next_sequence = (tail.bunch.channel_sequence+1)&1023
            tail.content_dependencies = dependencies
            tail.content_stage_dependencies = continuation_dependencies[index-2]
            tail.component_bindings = (tuple((u.guid, u.actor_guid, CLASS_PATH) for u in group) if dynamic_tail
                    else tuple((u.guid, u.actor_guid, u.class_path) for u in group)
                        if object_tail or object_update_tail or skill_template_tail
                    else tuple((u.guid, u.actor_guid, u.name) for u in components))
            tails.append(tail)
        head.content_dependencies, head.content_stage_dependencies = dependencies, stage_dependencies
        head.continuations, head.component_bindings = tuple(tails), head_bindings
        staged[bunch.channel_index] = head
        if sum(1+len(head.continuations) for head in staged.values()) > MAX_POST_OPEN_CONTENT_BUNCHES:
            raise ValueError('Post-open content exceeds its total admission bunch budget')
        if sum(len(_wire_items(item)) for head in staged.values()
                for item in (head, *head.continuations)) > MAX_POST_OPEN_WIRE_BUNCHES:
            raise ValueError('Post-open content exceeds its total admission wire-fragment budget')
    _validate_content_stage_graph(staged)
    for channel, head in staged.items():
        for ordinal, item in enumerate((head, *head.continuations)):
            item.content_stage_policy = _content_stage_signature(channel, ordinal, item)
    return staged


@dataclass(frozen=True)
class _QualifiedKnownDeliveryReceipt:
    """Private evidence for one completed receive call, never a body ACK."""
    peer: tuple = field(repr=False)
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    packet_sequence: int
    received_at: float


@dataclass(frozen=True)
class _ActualApplicationSend:
    sequence: int
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    bunches: tuple = field(default=(), repr=False)


@dataclass(frozen=True)
class _ActualActorReceipt:
    """Persistent own-full-send + positive-bit proof for one initial bunch."""
    actor_guid: int
    bunch: WireBunch = field(repr=False)
    sequence: int
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)


@dataclass(frozen=True)
class _AdmittedActorReceiptLease:
    peer: tuple = field(repr=False)
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    initial_sequence: int
    channels: tuple
    actor_namespace: tuple = field(repr=False)
    content_namespace: tuple = field(repr=False)


@dataclass(frozen=True)
class _OpaqueActorTransportReceipt:
    channel_index: int
    channel_sequence: int
    payload_bit_count: int
    payload_sha256: str
    partial: bool
    retained_bytes: int
    bunch: WireBunch = field(repr=False)
    ready: tuple = field(repr=False)
    gameplay_handled: bool = False


@dataclass(frozen=True)
class _InventoryRefreshLease:
    peer: tuple = field(repr=False)
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    generation: object = field(repr=False)
    profile: object = field(repr=False)
    actor_namespace: tuple = field(repr=False)
    content_namespace: tuple = field(repr=False)


@dataclass(frozen=True)
class _PostAdmissionChannelTail:
    actor_guid: int
    bunch: WireBunch = field(repr=False)
    receipt: object = field(default=None, repr=False)


@dataclass(frozen=True)
class _WorldBoxBatch:
    projection: object = field(repr=False)
    base_cursor: object = field(repr=False)
    previous_sequence: int
    deliveries: tuple = field(repr=False)
    receipts: tuple = field(repr=False)


@dataclass
class ControlConnection:
    hello_sequence: int
    expected_client_sequence: int
    next_server_sequence: int
    challenge_payload: bytes = field(repr=False)
    hello_received: bool = False
    ticket: object = field(default=None, repr=False)
    welcome_payload: bytes | None = field(default=None, repr=False)
    welcome_sequence: int | None = None
    pending: ReliableControl | None = field(default=None, repr=False)
    consumed: dict = field(default_factory=dict, repr=False)
    netspeed: int | None = None
    client_join_observed: bool = False
    initial_actor_sequence: int | None = None
    actor_opens: dict = field(default_factory=dict, repr=False)
    actor_exports: dict = field(default_factory=dict, repr=False)
    actor_contents: dict = field(default_factory=dict, repr=False)
    client_closed: bool = False
    client_close_sequence: int | None = None
    client_close_reason: int | None = None
    pc_ping_profile: object = field(default=None, repr=False)
    pc_ping_channel: int | None = None
    pc_ping_actor_guid: int | None = None
    joined_at: float | None = None
    last_received_at: float | None = None
    pc_ping_last_reply_at: float | None = None
    pc_ping_reply_count: int = 0
    pc_startup_profile: object = field(default=None, repr=False)
    pc_startup_channel: int | None = None
    pc_startup_actor_guid: int | None = None
    pc_startup_expected_sequence: int | None = None
    pc_startup_consumed: dict = field(default_factory=dict, repr=False)
    pc_startup_request_count: int = 0
    pc_startup_receipt_reply_count: int = 0
    pc_short_timeout_observed: bool = False
    pc_client_world_time: float | None = field(default=None, repr=False)
    pc_client_field_of_view: float | None = field(default=None, repr=False)
    pc_ready_notification_received: bool = False
    pc_seamless_enter_requested: bool | None = None
    pc_ready_ack: ActorOpenDelivery | None = field(default=None, repr=False)
    game_state_start_profile: object = field(default=None, repr=False)
    game_state_start_channel: int | None = None
    game_state_start_actor_guid: int | None = None
    game_state_start: ActorOpenDelivery | None = field(default=None, repr=False)
    local_start_play_requested: bool = False
    game_state_all_ready: ActorOpenDelivery | None = field(default=None, repr=False)
    local_all_player_ready_requested: bool = False
    game_state_abseil: ActorOpenDelivery | None = field(default=None, repr=False)
    game_state_real_start: ActorOpenDelivery | None = field(default=None, repr=False)
    game_state_match_info: ActorOpenDelivery | None = field(default=None, repr=False)
    pc_restart_profile: object = field(default=None, repr=False)
    pc_restart_channel: int | None = None
    pc_restart_actor_guid: int | None = None
    pc_restart_pawn_channel: int | None = None
    pc_restart_pawn_guid: int | None = None
    pc_restart_ticket: object = field(default=None, repr=False)
    pc_restart_actor_namespace: tuple = field(default=(), repr=False)
    pc_restart_content_namespace: tuple = field(default=(), repr=False)
    pc_restart_requested: bool = False
    pc_restart: ActorOpenDelivery | None = field(default=None, repr=False)
    pc_restart_receipt: _ActualActorReceipt | None = field(default=None, repr=False)
    pc_rotation_profile: object = field(default=None, repr=False)
    pc_rotation_value: object = field(default=None, repr=False)
    pc_rotation: ActorOpenDelivery | None = field(default=None, repr=False)
    pc_hud_profile: object = field(default=None, repr=False)
    pc_hud_class_guid: int | None = None
    pc_hud: ActorOpenDelivery | None = field(default=None, repr=False)
    pc_possession_ack_received: bool = False
    pc_possession_ack_count: int = 0
    pc_reliable_receipt: object = field(default=None, repr=False)
    pc_reliable_receipt_seed: int | None = None
    pc_startup_semantic_whole: dict = field(default_factory=dict, repr=False)
    pc_possession_ack_sequences: set = field(default_factory=set, repr=False)
    pc_opaque_receipt_count: int = 0
    pc_view_target_profile: object = field(default=None, repr=False)
    pc_view_target_requested: bool = False
    pc_verify_view_target_count: int = 0
    pc_verify_view_target_sequences: set = field(default_factory=set, repr=False)
    pc_view_target: ActorOpenDelivery | None = field(default=None, repr=False)
    late_player_state_human_appearance: ActorOpenDelivery | None = field(default=None, repr=False)
    late_player_state_human_appearance_profile: object = field(default=None, repr=False)
    late_player_state_human_appearance_owner_check: object = field(default=None, repr=False)
    early_player_state_human_appearance: object = field(default=None, repr=False)
    actual_application_sends: tuple = field(default=(), repr=False)
    actual_actor_receipts: tuple = field(default=(), repr=False)
    fashion_subobject_outbox: object = field(default=None, repr=False)
    fashion_async_binding: object = field(default=None, repr=False)
    fashion_phase_lease: object = field(default=None, repr=False)
    last_successful_application_send_at: float | None = None
    last_keepalive_prepared_at: float | None = None
    keepalive_prepared_count: int = 0
    local_stage_preparations: int = 0
    admitted_actor_reliable_receipts: bool = False
    admitted_actor_receipt_lease: object = field(default=None, repr=False)
    admitted_pawn_receipt: object = field(default=None, repr=False)
    admitted_actor_receipt_ledgers: dict = field(default_factory=dict, repr=False)
    admitted_actor_opaque_journal: tuple = field(default=(), repr=False)
    admitted_actor_opaque_journal_bytes: int = 0
    admitted_actor_receipt_packet_count: int = 0
    admitted_actor_rejection_counts: dict = field(default_factory=dict, repr=False)
    admitted_actor_last_rejection: tuple | None = field(default=None, repr=False)
    client_failed_actor_channels: dict = field(default_factory=dict, repr=False)
    client_begin_play_notified: bool = False
    client_begin_play_notification_count: int = 0
    inventory_refresh_profile: object = field(default=None, repr=False)
    inventory_refresh_lease: object = field(default=None, repr=False)
    inventory_refresh_ready: object = field(default=None, repr=False)
    inventory_refresh: ActorOpenDelivery | None = field(default=None, repr=False)
    inventory_refresh_update: object = field(default=None, repr=False)
    inventory_refresh_revision: int | None = None
    inventory_refresh_committed: bool = False
    inventory_refresh_receipt: object = field(default=None, repr=False)
    inventory_runtime_items: tuple | None = field(default=None, repr=False)
    inventory_runtime_delivery: ActorOpenDelivery | None = field(default=None, repr=False)
    inventory_runtime_update: object = field(default=None, repr=False)
    inventory_runtime_next_items: tuple | None = field(default=None, repr=False)
    inventory_runtime_next_key: int | None = None
    inventory_runtime_previous_sequence: int | None = None
    inventory_runtime_receipt: object = field(default=None, repr=False)
    inventory_refresh_previous_sequence: int | None = None
    post_admission_channel_tails: dict = field(default_factory=dict, repr=False)
    world_delivery_profile: object = field(default=None, repr=False)
    world_delivery_lease: tuple | None = field(default=None, repr=False)
    world_box_batches: dict = field(default_factory=dict, repr=False)
    world_box_cursors: dict = field(default_factory=dict, repr=False)
    world_result_command: object = field(default=None, repr=False)
    world_result_update: object = field(default=None, repr=False)
    world_result_delivery: ActorOpenDelivery | None = field(default=None, repr=False)
    world_result_previous_sequence: int | None = None
    world_result_receipt: object = field(default=None, repr=False)
    world_result_journal: dict = field(default_factory=dict, repr=False)
    owner_switch_profile: object = field(default=None, repr=False)
    owner_switch_lease: object = field(default=None, repr=False)
    owner_switch_state: object = field(default=None, repr=False)
    owner_switch_pending: tuple = field(default=(), repr=False)
    owner_switch_delivery: ActorOpenDelivery | None = field(default=None, repr=False)
    owner_switch_update: object = field(default=None, repr=False)
    owner_switch_previous_sequence: int | None = None
    owner_switch_accepted: int = 0
    owner_switch_result_acks: int = 0
    # Diagnostic only: disposition/error counts for every owning reliable body.
    owner_switch_dispositions: dict = field(default_factory=dict, repr=False)
    owner_switch_rejected_frames: tuple = ()
    owner_switch_trace: tuple = ()
    movement_profile: object = field(default=None, repr=False)
    movement_lease: object = field(default=None, repr=False)
    movement_state: object = field(default=None, repr=False)
    movement_accepted: int = 0
    movement_rejected: int = 0
    movement_last_disposition: str = ''
    movement_last_reason: str = ''
    movement_rejection_counts: dict = field(default_factory=dict, repr=False)
    pc_level_visibility_profile: object = field(default=None, repr=False)
    pc_level_visibility: object = field(default=None, repr=False)
    pc_level_visibility_reports: int = 0


class LegacyDSControlConnection(LegacyDSControlProbe):
    """Opt-in, ticket-authorized control steps for an explicit local map profile."""

    def __init__(self, *, admissions, welcome_maps, expected_net_version,
                 max_packet_bytes=1024, max_replies=128,
                 retry_interval=0.5, max_transmissions=16, transport_keepalive=False,
                 qualified_receipt_forward_gaps=False):
        super().__init__(expected_net_version=expected_net_version,
                         max_packet_bytes=max_packet_bytes, max_replies=max_replies)
        if not callable(getattr(admissions, 'authorize_login_url', None)):
            raise ValueError('An owner-controlled match admission store is required')
        if type(transport_keepalive) is not bool:
            raise ValueError('Transport keepalive requires an explicit boolean')
        if type(qualified_receipt_forward_gaps) is not bool:
            raise ValueError('Qualified receipt forward gaps require an explicit boolean')
        if (isinstance(retry_interval, bool) or not isinstance(retry_interval, (int, float))
                or not math.isfinite(retry_interval) or not 0.1 <= retry_interval <= 5
                or type(max_transmissions) is not int or not 1 <= max_transmissions <= 64):
            raise ValueError('Invalid bounded control retransmission policy')
        if not isinstance(welcome_maps, dict) or not 1 <= len(welcome_maps) <= 64:
            raise ValueError('An explicit evidenced Welcome map profile is required')
        # Challenge always contains a 32-character ASCII random hex string.
        # It can exceed a short Welcome, so both must fit before serving UDP.
        self._validate_packet_budget(encode_message(3, '0' * 32))
        self.welcome_payloads = {}
        for map_id, spec in welcome_maps.items():
            if (type(map_id) is not int or not 0 < map_id <= 0xffffffff
                    or not isinstance(spec, dict) or not isinstance(spec.get('level'), str)
                    or not spec['level'] or len(spec['level']) > 256
                    or any(char in spec['level'] for char in '?\0\r\n')):
                raise ValueError('Invalid persistent map Welcome entry')
            for key in ('game', 'redirect'):
                value = spec.get(key, '')
                if (not isinstance(value, str) or len(value) > 256
                        or any(char in value for char in '\0\r\n')):
                    raise ValueError('Invalid bounded Welcome string')
            payload = encode_message(1, spec['level'], spec.get('game', ''),
                                     spec.get('redirect', ''))
            # Reserve the complete native packet/bunch envelope, including
            # maximal sequence/name fields, rather than just its payload size.
            self._validate_packet_budget(payload)
            self.welcome_payloads[map_id] = payload
        self.admissions = admissions
        self.retry_interval, self.max_transmissions = retry_interval, max_transmissions
        self.ticket_peers = {}
        self.joined_count = 0
        self._qualified_known_delivery_receipt = None
        self.transport_keepalive = transport_keepalive
        self.qualified_receipt_forward_gaps = qualified_receipt_forward_gaps
        self._local_stage_generation_for_peer = None

    def configure_local_stage_retries(self, generation_for_peer):
        """Explicit local-profile policy; ordinary probes keep their old bounds."""
        from dfserver.match.legacy_ds_match_admission import LocalMatchAdmissions
        if (self.control_peers or self._local_stage_generation_for_peer is not None or
                type(self.admissions) is not LocalMatchAdmissions or not self.welcome_payloads or
                not callable(generation_for_peer)):
            raise ValueError('Local stages require fresh explicit admissions and generation resolver')
        self._local_stage_generation_for_peer = generation_for_peer

    def _local_stage_owner(self, peer, state, transport):
        if (self._local_stage_generation_for_peer is None or
                not self._current_joined_receipt_owner(peer, state, transport)):
            return None
        try:
            return self._local_stage_generation_for_peer(peer, state, transport)
        except (ValueError, KeyError, AttributeError):
            return None

    def _stage_budget_exhausted(self, state, transport):
        if self._local_stage_generation_for_peer is None:
            return transport.replies >= self.max_replies
        return state.local_stage_preparations >= MAX_LOCAL_STAGE_PREPARATIONS

    def _stage_can_prepare(self, peer, state, transport, item, now):
        if item.bunch.channel_index in state.client_failed_actor_channels:
            return False
        if self._local_stage_generation_for_peer is None:
            return not (item.delivered or transport.replies >= self.max_replies or
                item.transmissions >= self.max_transmissions or
                item.transmissions and now - item.last_sent_at < self.retry_interval)
        generation = self._local_stage_owner(peer, state, transport)
        if item.delivered or generation is None or self._stage_budget_exhausted(state, transport):
            return False
        if item.local_stage_first_prepared_at is not None:
            if now >= item.local_stage_deadline:
                item.local_stage_expired = True
                return False
            if (item.local_stage_ticket is not state.ticket or
                    item.local_stage_generation is not generation or
                    item.local_stage_transport is not transport):
                return False
        elif len(self._inflight_stage_bunches(state, state.ticket, transport, generation, now)) >= MAX_ACTUAL_APPLICATION_SENDS - 1:
            # A reservation starts at preparation, before any socket success.
            # Keep one shared slot for Control/ACK/keepalive send evidence.
            return False
        delay = min(4.0, .5 * (2 ** min(max(item.transmissions - 1, 0), 3)))
        return not item.transmissions or now - item.last_sent_at >= delay

    def _stage_note_prepared(self, peer, state, transport, item, now):
        if self._local_stage_generation_for_peer is None:
            item.sent_packets = (*item.sent_packets, transport.out_sequence)[-64:]
            transport.replies += 1
        else:
            generation = self._local_stage_owner(peer, state, transport)
            if generation is None:
                raise ValueError('Local stage owner changed during preparation')
            if item.local_stage_first_prepared_at is None:
                item.local_stage_first_prepared_at = now
                item.local_stage_deadline = now + LOCAL_STAGE_DEADLINE_SECONDS
                item.local_stage_ticket = state.ticket
                item.local_stage_generation = generation
                item.local_stage_transport = transport
            state.local_stage_preparations += 1
            # sent_packets is populated only by the full-send journal below.
            # Preparing a packet consumes this separate finite budget, not ACK
            # eligibility or the legacy Control reply allowance.
        item.last_sent_at, item.transmissions = now, item.transmissions + 1
        transport.out_sequence = (transport.out_sequence + 1) & MASK

    def _stage_retries_exhausted(self, state, item):
        if self._local_stage_generation_for_peer is None:
            return item.transmissions >= self.max_transmissions
        return item.local_stage_expired or state.local_stage_preparations >= MAX_LOCAL_STAGE_PREPARATIONS

    @staticmethod
    def _stage_items(state):
        return (*state.actor_opens.values(), *_content_wire_items(state),
            state.pc_ready_ack, state.game_state_match_info, state.game_state_start,
            state.game_state_all_ready, state.game_state_abseil, state.game_state_real_start,
            state.pc_restart, state.pc_rotation, state.pc_hud, state.pc_view_target,
            state.inventory_refresh, state.inventory_runtime_delivery, state.world_result_delivery,
            state.owner_switch_delivery,
            *(item for batch in state.world_box_batches.values() for item in batch.deliveries))

    @staticmethod
    def _inflight_stage_bunches(state, ticket, transport, generation, now):
        return frozenset(item.bunch for item in LegacyDSControlConnection._stage_items(state)
            if item is not None and not item.delivered and not item.local_stage_expired and
               item.local_stage_first_prepared_at is not None and item.local_stage_deadline is not None and
               now < item.local_stage_deadline and item.local_stage_ticket is ticket and
               item.local_stage_transport is transport and item.local_stage_generation is generation)

    @staticmethod
    def _retain_actual_stage_sends(state, sends, ticket, transport, generation, now):
        # Retrying a bunch needs no additional reservation. Protect its newest
        # actual send; old retry receipts may be forgotten but never fabricated.
        pending = set(LegacyDSControlConnection._inflight_stage_bunches(
            state, ticket, transport, generation, now))
        retained = set()
        for index in range(len(sends) - 1, -1, -1):
            matched = pending.intersection(sends[index].bunches)
            if matched:
                retained.add(index)
                pending.difference_update(matched)
        for index in range(len(sends) - 1, -1, -1):
            if len(retained) >= MAX_ACTUAL_APPLICATION_SENDS:
                break
            retained.add(index)
        return tuple(sent for index, sent in enumerate(sends) if index in retained)

    def _stage_delivery_matches(self, original, item, packet, transport, generation, legacy_match):
        if (self._local_stage_generation_for_peer is None or
                type(item) is not ActorOpenDelivery or item.local_stage_first_prepared_at is None):
            return legacy_match(item, packet)
        return (item.local_stage_ticket is original.ticket and
            item.local_stage_generation is generation and item.local_stage_transport is transport and
            self._local_stage_owner(self.ticket_peers.get(original.ticket.cookie), original, transport) is generation and
            legacy_match(item, packet) and any(
                sent.ticket is original.ticket and sent.transport is transport and sent.generation is generation and
                item.bunch in sent.bunches and sent.sequence in item.sent_packets and
                distance < len(packet.history) * 32 and
                bool((packet.history[distance // 32] >> (distance % 32)) & 1)
                for sent in original.actual_application_sends
                for distance in ((packet.acknowledged_sequence - sent.sequence) & MASK,)))

    def _validate_packet_budget(self, payload):
        encode_observed_application(WirePacket(
            MASK, MASK, (0xffffffff,), False, 0, None, (WireBunch(
                0, payload, len(payload) * 8, reliable=True,
                channel_sequence=1023, channel_name=CONTROL_NAME),), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)

    def register_verified_echo(self, peer, cookie):
        super().register_verified_echo(peer, cookie)
        state = self.control_peers[peer]
        if not isinstance(state, ControlConnection):
            transport = self.peers[peer]
            self.control_peers[peer] = ControlConnection(
                state.hello_sequence, state.hello_sequence,
                (transport.out_sequence + 1) & 1023, state.challenge_payload,
                initial_actor_sequence=(transport.out_sequence + 1) & 1023)

    def forget_peer(self, peer):
        state = self.control_peers.get(peer)
        if state and state.ticket and self.ticket_peers.get(state.ticket.cookie) == peer:
            del self.ticket_peers[state.ticket.cookie]
        super().forget_peer(peer)

    def rebind_verified_peer(self, old_peer, new_peer):
        """Preserve every reliable/control/Actor object while changing its key."""
        state = self.control_peers.get(old_peer)
        try:
            active = (isinstance(state, ControlConnection) and state.ticket is not None and
                      self.admissions.is_active(state.ticket))
        except Exception:
            active = False
        if (not isinstance(state, ControlConnection) or state.ticket is None or
                state.client_closed or not active or
                self.ticket_peers.get(state.ticket.cookie) != old_peer or
                new_peer in self.ticket_peers.values() or
                sum(owner == old_peer for owner in self.ticket_peers.values()) != 1):
            raise ValueError('Only a live admitted connection can change its peer')
        migrated_lease = migrated_pawn_binding = migrated_inventory_lease = None
        if state.admitted_actor_reliable_receipts:
            from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
            from dfserver.transport.native.legacy_ds_owned_pawn_receipt import OwnedPawnReceiptAdapter
            transport = self.peers.get(old_peer)
            lease = state.admitted_actor_receipt_lease
            generation = self._local_stage_owner(old_peer, state, transport)
            if (type(lease) is not _AdmittedActorReceiptLease or lease.peer != old_peer or
                    lease.ticket is not state.ticket or lease.transport is not transport or
                    type(generation) is not PendingChallenge or generation.echoed is not True or
                    generation.verified_at is None or lease.generation is not generation or
                    lease.initial_sequence != state.hello_sequence or
                    tuple((channel, item.actor_guid, item.bunch)
                        for channel, item in sorted(state.actor_opens.items())) != lease.actor_namespace or
                    _content_namespace(state) != lease.content_namespace):
                raise ValueError('Only the current admitted receipt lease may follow its verified peer')
            self._pc_restart_binding(state, old_peer)
            if state.admitted_pawn_receipt is not None:
                if type(state.admitted_pawn_receipt) is not OwnedPawnReceiptAdapter:
                    raise ValueError('The current admitted Pawn receipt adapter is required')
                binding = self._admitted_actor_receipt_binding(
                    state, state, old_peer, transport, generation)
                state.admitted_pawn_receipt._current_owner(state, binding)
                migrated_pawn_binding = replace(binding, peer=new_peer)
            migrated_lease = replace(lease, peer=new_peer)
            inventory = state.inventory_refresh_lease
            if inventory is not None:
                if (type(inventory) is not _InventoryRefreshLease or inventory.peer != old_peer or
                        inventory.ticket is not state.ticket or inventory.transport is not transport or
                        inventory.generation is not generation or inventory.profile is not state.inventory_refresh_profile or
                        inventory.actor_namespace != lease.actor_namespace or inventory.content_namespace != lease.content_namespace or
                        inventory.profile.sources_current() is not True):
                    raise ValueError('Only the exact inventory owner may follow its verified peer')
                migrated_inventory_lease = replace(inventory, peer=new_peer)
        # All owner validation and replacement construction precede the base
        # dictionary-only migration. Reliable ledgers and actual proof owners
        # retain their identities; the authenticated handshake moves afterward.
        super().rebind_verified_peer(old_peer, new_peer)
        self.ticket_peers[state.ticket.cookie] = new_peer
        if migrated_lease is not None:
            state.admitted_actor_receipt_lease = migrated_lease
            if migrated_inventory_lease is not None:
                state.inventory_refresh_lease = migrated_inventory_lease
            if migrated_pawn_binding is not None:
                state.admitted_pawn_receipt._binding = migrated_pawn_binding

    @staticmethod
    def _now(value):
        value = time.monotonic() if value is None else value
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0):
            raise ValueError('A finite monotonic control timestamp is required')
        return value

    @staticmethod
    def _delivered(pending, packet):
        # The acknowledged sequence is a cursor, not proof of delivery. Only
        # the corresponding recorded history bit can clear a reliable outbox.
        return any(
            distance < len(packet.history) * 32 and
            bool((packet.history[distance // 32] >> (distance % 32)) & 1)
            for sequence in pending.sent_packets
            for distance in ((packet.acknowledged_sequence - sequence) & MASK,)
        )

    @staticmethod
    def _clone(state):
        return replace(state, consumed=dict(state.consumed),
                       pending=replace(state.pending) if state.pending else None,
                       actor_opens={index: replace(item)
                                    for index, item in state.actor_opens.items()},
                       actor_exports=dict(state.actor_exports),
                       actor_contents={index: _clone_content(item)
                                       for index, item in state.actor_contents.items()},
                       pc_startup_consumed=dict(state.pc_startup_consumed),
                       pc_startup_semantic_whole=dict(state.pc_startup_semantic_whole),
                       pc_possession_ack_sequences=set(state.pc_possession_ack_sequences),
                       pc_verify_view_target_sequences=set(state.pc_verify_view_target_sequences),
                       pc_reliable_receipt=(state.pc_reliable_receipt.clone()
                           if state.pc_reliable_receipt is not None else None),
                       admitted_pawn_receipt=(state.admitted_pawn_receipt.clone()
                           if state.admitted_pawn_receipt is not None else None),
                       admitted_actor_receipt_ledgers={channel: ledger.clone()
                           for channel, ledger in state.admitted_actor_receipt_ledgers.items()},
                       admitted_actor_rejection_counts=dict(state.admitted_actor_rejection_counts),
                       owner_switch_dispositions=dict(state.owner_switch_dispositions),
                       movement_rejection_counts=dict(state.movement_rejection_counts),
                       client_failed_actor_channels=dict(state.client_failed_actor_channels),
                       pc_ready_ack=replace(state.pc_ready_ack) if state.pc_ready_ack else None,
                       game_state_start=replace(state.game_state_start) if state.game_state_start else None,
                       game_state_all_ready=replace(state.game_state_all_ready) if state.game_state_all_ready else None,
                       game_state_abseil=replace(state.game_state_abseil) if state.game_state_abseil else None,
                       game_state_real_start=replace(state.game_state_real_start) if state.game_state_real_start else None,
                       game_state_match_info=replace(state.game_state_match_info) if state.game_state_match_info else None,
                       pc_restart=replace(state.pc_restart) if state.pc_restart else None,
                       pc_rotation=replace(state.pc_rotation) if state.pc_rotation else None,
                       pc_hud=replace(state.pc_hud) if state.pc_hud else None,
                       pc_view_target=replace(state.pc_view_target) if state.pc_view_target else None,
                       inventory_refresh=replace(state.inventory_refresh) if state.inventory_refresh else None,
                       inventory_runtime_delivery=(replace(state.inventory_runtime_delivery)
                           if state.inventory_runtime_delivery else None),
                       post_admission_channel_tails=dict(state.post_admission_channel_tails),
                       world_box_batches={path: replace(batch, deliveries=tuple(replace(item) for item in batch.deliveries))
                           for path, batch in state.world_box_batches.items()},
                       world_box_cursors=dict(state.world_box_cursors),
                       world_result_delivery=replace(state.world_result_delivery) if state.world_result_delivery else None,
                       world_result_journal=dict(state.world_result_journal),
                       owner_switch_delivery=(replace(state.owner_switch_delivery)
                           if state.owner_switch_delivery else None),
                       late_player_state_human_appearance=(replace(state.late_player_state_human_appearance)
                           if state.late_player_state_human_appearance else None),
                       fashion_subobject_outbox=(state.fashion_subobject_outbox.clone()
                           if state.fashion_subobject_outbox is not None and state.fashion_async_binding is None
                           else state.fashion_subobject_outbox))

    def _early_player_state_human_appearance_current(self, state, peer):
        policy = state.early_player_state_human_appearance
        if policy is None:
            return True
        if (state.ticket is None or not self.admissions.is_active(state.ticket) or
                self.ticket_peers.get(state.ticket.cookie) != peer or peer not in self.peers):
            raise ValueError('Early PlayerState trial has no active owned transport')
        return policy.check(state, peer)

    def _late_player_state_human_appearance_ready(self, state, peer):
        profile = state.late_player_state_human_appearance_profile
        if (not callable(state.late_player_state_human_appearance_owner_check) or
                state.late_player_state_human_appearance_owner_check(state, peer) is not True or
                not profile.sources_current()):
            raise ValueError('PlayerState trial owner or sources changed')
        self._pc_restart_binding(state, peer)
        ready = (not self._pc_restart_waiting(state, peer) and state.pc_restart_requested and
            self._actual_actor_delivery(state.pc_restart) and state.pc_possession_ack_received is True and
            state.pc_possession_ack_count > 0 and bool(state.pc_possession_ack_sequences))
        item = state.late_player_state_human_appearance
        if item is not None:
            from dfserver.replication.legacy_ds_late_player_state_human_appearance import build_late_player_state_human_appearance_bunch
            opened = state.actor_opens[item.bunch.channel_index]
            expected = build_late_player_state_human_appearance_bunch(profile, item.bunch.channel_index,
                (opened.bunch.channel_sequence + 1) & 1023, self.max_packet_bytes * 8)
            if item.actor_guid != opened.actor_guid or item.bunch != expected:
                raise ValueError('PlayerState trial outbox or sequence changed')
        return bool(ready)

    def _queue_late_player_state_human_appearance(self, peer, *, profile, channel, actor_guid, owner_check):
        from dfserver.replication.legacy_ds_late_player_state_human_appearance import LatePlayerStateHumanAppearanceDiagnostic, build_late_player_state_human_appearance_bunch
        if (type(profile) is not LatePlayerStateHumanAppearanceDiagnostic or
                type(channel) is not int or type(actor_guid) is not int):
            raise ValueError('PlayerState trial requires exact profile and channel types')
        profile.__post_init__()
        original = self.control_peers.get(peer)
        if original is None or not callable(owner_check):
            raise ValueError('PlayerState trial requires a current registered owner')
        state = self._clone(original)
        if state.late_player_state_human_appearance is None:
            state.late_player_state_human_appearance_profile = profile
            state.late_player_state_human_appearance_owner_check = owner_check
        elif state.late_player_state_human_appearance_profile != profile:
            raise ValueError('PlayerState trial cannot replace its existing outbox')
        opened = state.actor_opens.get(channel)
        if (type(channel) is not int or type(actor_guid) is not int or opened is None or
                opened.actor_guid != actor_guid or channel in state.actor_contents or
                opened.bunch.reliable is not True or type(opened.bunch.channel_sequence) is not int or
                not 0 <= opened.bunch.channel_sequence < 1024 or
                any(item is not None and item.bunch.channel_index == channel for item in (
                    state.pc_ready_ack, state.game_state_start, state.game_state_all_ready,
                    state.game_state_abseil, state.game_state_real_start, state.game_state_match_info,
                    state.pc_restart, state.pc_rotation, state.pc_hud, state.pc_view_target))):
            raise ValueError('PlayerState trial has no exclusive initial Actor sequence')
        if not self._late_player_state_human_appearance_ready(state, peer):
            return 'pending'
        if state.late_player_state_human_appearance is not None:
            item = state.late_player_state_human_appearance
            if (item.bunch.channel_index, item.actor_guid) != (channel, actor_guid):
                raise ValueError('PlayerState trial target changed')
            return 'already_queued'
        bunch = build_late_player_state_human_appearance_bunch(profile, channel,
            (opened.bunch.channel_sequence + 1) & 1023, self.max_packet_bytes * 8)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        state.late_player_state_human_appearance = ActorOpenDelivery(bunch, actor_guid)
        self.control_peers[peer] = state
        self.control_events['actor_content_player_state_human_appearance_diagnostic_queued'] += 1
        return 'queued'

    def queue_actor_open(self, peer, **actor_fields):
        """Queue one caller-described initial Actor on an admitted, joined peer.

        The producer must supply the complete explicit export/reference profile
        accepted by build_actor_bunch. Native class/path resolution remains its
        unverified precondition. No default Actor is manufactured. This method
        owns the initial reliable channel sequence and complete packet budget;
        producers cannot substitute the current control-channel sequence.
        """
        state, transport = self.control_peers.get(peer), self.peers.get(peer)
        if (transport is None or not isinstance(state, ControlConnection) or
                state.ticket is None or not state.client_join_observed or state.client_closed):
            raise ValueError('Initial Actor transport requires an admitted joined peer')
        if len(state.actor_opens) >= MAX_INITIAL_ACTOR_CHANNELS:
            raise ValueError('Initial Actor channel limit reached')
        if any(item.transmissions for item in _content_items(state)):
            raise ValueError('The initial Actor set has already advanced to post-open content')
        if 'channel_sequence' in actor_fields or 'max_packet_bytes' in actor_fields:
            raise ValueError('The connection owns Actor sequence and packet budget')
        bunch = build_initial_actor_bunch(channel_sequence=state.initial_actor_sequence,
                                 max_packet_bytes=self.max_packet_bytes, **actor_fields)
        if bunch.channel_index in state.actor_opens:
            raise ValueError('An initial Actor channel cannot be opened twice')
        actor_guid = actor_fields['actor_guid']
        if actor_guid in _component_namespace(state):
            raise ValueError('An Actor GUID conflicts with a queued component binding')
        if any(item.actor_guid == actor_guid for item in state.actor_opens.values()):
            raise ValueError('An Actor GUID cannot be opened on two channels')
        definitions = {}
        # build_actor_bunch has already bounded and validated these graphs.
        for root in actor_fields['exports']:
            node = root
            while node is not None:
                definition = (node.path, node.outer.guid if node.outer is not None else 0,
                              node.checksum)
                previous = state.actor_exports.get(node.guid)
                if previous is not None and previous != definition:
                    raise ValueError('A queued export conflicts with this connection GUID graph')
                definitions[node.guid] = definition
                node = node.outer
        # Reserve worst-case packet and ACK fields before any queue mutation.
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,),
            False, 0, None, (bunch,), 0), max_packet_bytes=self.max_packet_bytes,
            received_by_server=False)
        state.actor_exports.update(definitions)
        state.actor_opens[bunch.channel_index] = ActorOpenDelivery(bunch, actor_guid,
            open_fields=tuple(actor_fields.items()))
        self.control_events['actor_open_queued'] += 1

    def queue_actor_opens(self, peer, actor_fields, *, post_open_actor_contents=(),
                          early_player_state_human_appearance=None):
        """Stage one complete bootstrap set and commit it without partial queues.

        This provides the same explicit-reference contract as queue_actor_open.
        Callers serialize access to this connection. No fields or native objects
        are inferred here; reliable transport delivery is still not a spawn.
        """
        if (type(actor_fields) is not tuple or not 1 <= len(actor_fields) <= MAX_INITIAL_ACTOR_CHANNELS or
                any(type(fields) is not dict for fields in actor_fields)):
            raise ValueError('An explicit bounded tuple of Actor field dictionaries is required')
        original = self.control_peers.get(peer)
        if not isinstance(original, ControlConnection):
            raise ValueError('No admitted Actor connection for the bootstrap set')
        if not _content_policies_current(original.actor_contents):
            raise ValueError('Queued Actor content stage policy changed')
        previous_events = self.control_events.copy()
        self.control_peers[peer] = self._clone(original)
        try:
            for fields in actor_fields:
                self.queue_actor_open(peer, **fields)
            state = self.control_peers[peer]
            prepared_fields = []
            for item in state.actor_opens.values():
                if (item.open_fields is None or build_initial_actor_bunch(
                        channel_sequence=state.initial_actor_sequence, max_packet_bytes=self.max_packet_bytes,
                        **dict(item.open_fields)) != item.bunch):
                    raise ValueError('Queued Actor source fields differ from its prepared open')
                prepared_fields.append(dict(item.open_fields))
            contents = preflight_actor_content_plans(tuple(prepared_fields), post_open_actor_contents,
                initial_channel_sequence=state.initial_actor_sequence,
                max_packet_bytes=self.max_packet_bytes)
            if set(contents) & set(state.actor_contents):
                raise ValueError('An Actor post-open content plan cannot be queued twice')
            reserved = _component_namespace(state)
            bound_pc_channels = {state.pc_ping_channel, state.pc_startup_channel, state.pc_restart_channel} - {None}
            for head in contents.values():
                if head.continuations and head.bunch.channel_index in bound_pc_channels:
                    raise ValueError('A bound controller channel cannot receive a component content series')
                for item in (head, *head.continuations):
                    for guid, actor_guid, name in item.component_bindings:
                        binding = (actor_guid, name)
                        if (guid in reserved and reserved[guid] != binding or
                                any(value == binding and previous != guid for previous, value in reserved.items())):
                            raise ValueError('A new content plan changes a queued component GUID/name binding')
                        reserved[guid] = binding
            if (len(_content_items(state)) + sum(1 + len(head.continuations) for head in contents.values()) >
                    MAX_POST_OPEN_CONTENT_BUNCHES):
                raise ValueError('Post-open content exceeds its total admission bunch budget')
            if (len(_content_wire_items(state)) + sum(len(_wire_items(item))
                    for head in contents.values() for item in (head, *head.continuations)) >
                    MAX_POST_OPEN_WIRE_BUNCHES):
                raise ValueError('Post-open content exceeds its total admission wire-fragment budget')
            state.actor_contents.update(contents)
            if early_player_state_human_appearance is not None:
                if any(item.continuations for item in contents.values()):
                    raise ValueError('The retained early appearance diagnostic does not support content series')
                from dfserver.replication.legacy_ds_early_player_state_human_appearance import EarlyPlayerStateHumanAppearanceGate, namespace
                from dfserver.replication.legacy_ds_late_player_state_human_appearance import LatePlayerStateHumanAppearanceDiagnostic, build_late_player_state_human_appearance_bunch
                policy = early_player_state_human_appearance
                if (type(policy) is not tuple or len(policy) != 4 or
                        type(policy[0]) is not int or type(policy[1]) is not int or
                        type(policy[2]) is not LatePlayerStateHumanAppearanceDiagnostic or not callable(policy[3]) or
                        state.early_player_state_human_appearance is not None or
                        state.late_player_state_human_appearance is not None or
                        state.late_player_state_human_appearance_profile is not None):
                    raise ValueError('Early PlayerState trial requires one explicit fresh policy')
                channel, guid, profile, owner_check = policy
                opened, item = state.actor_opens.get(channel), contents.get(channel)
                if opened is None or item is None or opened.actor_guid != guid or item.actor_guid != guid:
                    raise ValueError('Early PlayerState trial has no exact new PlayerState content')
                profile.__post_init__()
                expected = build_late_player_state_human_appearance_bunch(profile, channel,
                    (opened.bunch.channel_sequence + 1) & 1023, self.max_packet_bytes * 8)
                if replace(item.bunch, channel_sequence=expected.channel_sequence) != expected:
                    raise ValueError('Early PlayerState content differs from its sealed fields')
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None,
                    (expected,), 0), max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item.bunch = expected
                state.early_player_state_human_appearance = EarlyPlayerStateHumanAppearanceGate(
                    channel, guid, profile, owner_check, namespace(state.actor_opens), namespace(state.actor_contents))
                self._early_player_state_human_appearance_current(state, peer)
            if contents:
                self.control_events['actor_content_queued'] += len(contents)
        except BaseException:
            self.control_peers[peer] = original
            self.control_events.clear()
            self.control_events.update(previous_events)
            raise

    def _queue(self, state, message_id, payload):
        pending = ReliableControl(message_id, payload, state.next_server_sequence)
        state.next_server_sequence = (state.next_server_sequence + 1) & 1023
        state.pending = pending
        return pending

    def set_pc_ping_profile(self, peer, channel_index, actor_guid, profile):
        from dfserver.transport.native.legacy_ds_pc_ping_receiver import PCPingProfile
        state = self.control_peers.get(peer)
        if (not isinstance(state, ControlConnection) or state.client_closed or
                state.ticket is None or not state.client_join_observed or
                type(profile) is not PCPingProfile or
                type(channel_index) is not int or type(actor_guid) is not int or
                channel_index not in state.actor_opens or
                state.actor_opens[channel_index].actor_guid != actor_guid or
                channel_index in state.actor_contents and state.actor_contents[channel_index].continuations or
                state.pc_ping_profile is not None):
            raise ValueError('PC Ping requires an exact admitted queued Actor channel')
        profile.__post_init__()
        state.pc_ping_profile, state.pc_ping_channel, state.pc_ping_actor_guid = profile, channel_index, actor_guid

    def _consume_pc_ping(self, state, packet, peer, now):
        from dfserver.transport.native.legacy_ds_pc_ping_receiver import decode_pc_ping_bunches, build_pc_ping_reply
        profile = state.pc_ping_profile
        opened = state.actor_opens.get(state.pc_ping_channel)
        if (profile is None or state.ticket is None or state.client_closed or
                not state.client_join_observed or not self.admissions.is_active(state.ticket) or
                self.ticket_peers.get(state.ticket.cookie) != peer or state.joined_at is None or
                opened is None or opened.actor_guid != state.pc_ping_actor_guid or not opened.delivered or
                not all(item.delivered for item in state.actor_opens.values()) or
                not all(item.delivered for item in _content_items(state))):
            raise ValueError('PC Ping requires current admitted Actor delivery')
        params = decode_pc_ping_bunches(packet.bunches, channel_index=state.pc_ping_channel, profile=profile)
        delta = 0.0 if state.last_received_at is None else now - state.last_received_at
        if now < state.joined_at or delta < 0:
            raise ValueError('PC Ping clock moved backwards')
        if state.pc_ping_reply_count >= profile.maximum_replies:
            raise ValueError('PC Ping reply budget exhausted')
        if (delta > 2 or state.pc_ping_last_reply_at is not None and
                now - state.pc_ping_last_reply_at < profile.minimum_reply_interval):
            return (), 'pc_ping_rpc_consumed_without_reply'
        # One response to the final TC1 in a bounded packet avoids amplification.
        reply = build_pc_ping_reply(params[-1], channel_index=state.pc_ping_channel,
            profile=profile, world_seconds=now - state.joined_at, delta_seconds=delta)
        state.pc_ping_last_reply_at = now
        state.pc_ping_reply_count += 1
        return (reply,), 'pc_ping_rpc_reply_prepared'

    def set_pc_startup_profile(self, peer, channel_index, actor_guid, profile):
        from dfserver.transport.native.legacy_ds_pc_startup_rpc import PCStartupProfile
        state = self.control_peers.get(peer)
        if (not isinstance(state, ControlConnection) or state.client_closed or
                state.ticket is None or not state.client_join_observed or
                type(profile) is not PCStartupProfile or
                type(channel_index) is not int or type(actor_guid) is not int or
                channel_index not in state.actor_opens or
                state.actor_opens[channel_index].actor_guid != actor_guid or
                channel_index in state.actor_contents and state.actor_contents[channel_index].continuations or
                state.pc_startup_profile is not None):
            raise ValueError('PC startup requires an exact admitted queued Actor channel')
        profile.__post_init__()
        state.pc_startup_profile = profile
        state.pc_startup_channel, state.pc_startup_actor_guid = channel_index, actor_guid

    def _pc_restart_binding(self, state, peer):
        """Recheck the exact current ticket, PC/Pawn channels and prerequisite profiles."""
        from dfserver.transport.native.legacy_ds_pc_restart_rpc import PCRestartProfile
        if getattr(state, 'early_player_state_human_appearance', None) is not None:
            self._early_player_state_human_appearance_current(state, peer)
        if (not isinstance(state, ControlConnection) or state.client_closed or
                state.ticket is None or not state.client_join_observed or
                not self.admissions.is_active(state.ticket) or
                self.ticket_peers.get(state.ticket.cookie) != peer or peer not in self.peers or
                state.pc_restart_ticket is not state.ticket or type(state.pc_restart_profile) is not PCRestartProfile or
                state.pc_startup_profile is None or state.game_state_start_profile is None or
                state.pc_startup_channel != state.pc_restart_channel or
                state.pc_startup_actor_guid != state.pc_restart_actor_guid or
                state.pc_startup_profile.class_path != state.pc_restart_profile.class_path or
                state.game_state_start_profile.all_ready_handle is None or
                state.game_state_start_profile.abseil_handle is None):
            raise ValueError('Restart requires the same active admitted PC/Pawn binding and Ready profiles')
        state.pc_restart_profile.__post_init__()
        pc = state.actor_opens.get(state.pc_restart_channel)
        pawn = state.actor_opens.get(state.pc_restart_pawn_channel)
        gs = state.actor_opens.get(state.game_state_start_channel)
        if (pc is None or pc.actor_guid != state.pc_restart_actor_guid or
                pawn is None or pawn.actor_guid != state.pc_restart_pawn_guid or
                gs is None or gs.actor_guid != state.game_state_start_actor_guid or
                len({state.pc_restart_channel, state.pc_restart_pawn_channel,
                     state.game_state_start_channel}) != 3 or
                len({pc.actor_guid, pawn.actor_guid, gs.actor_guid}) != 3 or
                tuple((channel, item.actor_guid, item.bunch) for channel, item in sorted(state.actor_opens.items())) !=
                state.pc_restart_actor_namespace or
                _content_namespace(state) !=
                state.pc_restart_content_namespace or
                any(channel in state.actor_contents and
                    state.actor_contents[channel].actor_guid != item.actor_guid
                    for channel, item in state.actor_opens.items())):
            raise ValueError('Restart PC/Pawn/GameState identities differ from the queued Actor set')

    @staticmethod
    def _actual_actor_delivery(item):
        if item is not None and item.fragments:
            return all(LegacyDSControlConnection._actual_actor_delivery(piece) for piece in item.fragments)
        return item is not None and item.delivered and item.transmissions > 0 and bool(item.sent_packets)

    def _content_stage_receipted(self, peer, state, transport, item):
        if item is not None and item.fragments:
            return all(self._content_stage_receipted(peer, state, transport, piece) for piece in item.fragments)
        if not self._actual_actor_delivery(item):
            return False
        if self._local_stage_generation_for_peer is None:
            return True
        generation = self._local_stage_owner(peer, state, transport)
        return (generation is not None and item.local_stage_ticket is state.ticket and
            item.local_stage_transport is transport and item.local_stage_generation is generation and
            self._actor_own_full_send_positive_receipt(state, item,
                ticket=state.ticket, transport=transport, generation=generation))

    def _content_stage_waiting(self, peer, state, transport, channel, ordinal, item):
        targets = {(channel, previous) for previous in range(ordinal)}
        for dependency in item.content_dependencies:
            head = state.actor_contents.get(dependency)
            if head is None:
                return True
            targets.update((dependency, stage) for stage in range(1+len(head.continuations)))
        targets.update(item.content_stage_dependencies)
        for dependency, stage in targets:
            head = state.actor_contents.get(dependency)
            if head is None or not 0 <= stage <= len(head.continuations):
                return True
            target = (head, *head.continuations)[stage]
            if not self._content_stage_receipted(peer, state, transport, target):
                return True
        return False

    def _pc_restart_waiting(self, state, peer):
        self._pc_restart_binding(state, peer)
        waiting = []
        if not all(self._actual_actor_delivery(item) for item in state.actor_opens.values()):
            waiting.append('actor_open_delivery')
        if (state.pc_restart_channel not in state.actor_contents or
                state.pc_restart_pawn_channel not in state.actor_contents or
                not all(self._actual_actor_delivery(item) for item in _content_items(state))):
            waiting.append('association_content_delivery')
        if not state.pc_ready_notification_received or state.pc_startup_expected_sequence is None:
            waiting.append('native_ready_request')
        required = [('pc_ready_ack_delivery', state.pc_ready_ack, state.pc_restart_actor_guid),
                    ('begin_play_delivery', state.game_state_start, state.game_state_start_actor_guid),
                    ('all_ready_delivery', state.game_state_all_ready, state.game_state_start_actor_guid),
                    ('abseil_delivery', state.game_state_abseil, state.game_state_start_actor_guid)]
        if state.game_state_start_profile.map_id_handle is not None:
            required.append(('match_info_delivery', state.game_state_match_info, state.game_state_start_actor_guid))
        for name, item, guid in required:
            if item is None or item.actor_guid != guid or not self._actual_actor_delivery(item):
                waiting.append(name)
        return waiting

    def _room_real_start_ready(self, state, peer):
        if (not state.pc_restart_requested or not state.pc_possession_ack_received or
                self._pc_restart_waiting(state, peer) or not self._actual_actor_delivery(state.pc_restart) or
                (state.pc_rotation_profile is not None and not self._actual_actor_delivery(state.pc_rotation)) or
                (state.pc_hud_profile is not None and not self._actual_actor_delivery(state.pc_hud))):
            return False
        roster = self.admissions.active_room_tickets(state.ticket)
        for ticket in roster:
            member_peer = self.ticket_peers.get(ticket.cookie)
            member = self.control_peers.get(member_peer)
            if (member is None or member.ticket is not ticket or
                    not member.pc_restart_requested or not member.pc_possession_ack_received or
                    self._pc_restart_waiting(member, member_peer) or
                    not self._actual_actor_delivery(member.pc_restart) or
                    (member.pc_rotation_profile is not None and not self._actual_actor_delivery(member.pc_rotation)) or
                    (member.pc_hud_profile is not None and not self._actual_actor_delivery(member.pc_hud))):
                return False
        return bool(roster)

    def set_pc_restart_profile(self, peer, channel_index, pc_guid, pawn_guid, profile):
        """Bind a source-qualified restart to this joined ticket; this sends nothing."""
        from dfserver.transport.native.legacy_ds_pc_restart_rpc import PCRestartProfile, build_pc_restart
        original = self.control_peers.get(peer)
        if (not isinstance(original, ControlConnection) or original.pc_restart_profile is not None or
                type(profile) is not PCRestartProfile or type(channel_index) is not int or
                type(pc_guid) is not int or type(pawn_guid) is not int or
                not 2 <= pc_guid <= 0xffffffff or pc_guid & 1 or
                not 2 <= pawn_guid <= 0xffffffff or pawn_guid & 1 or pc_guid == pawn_guid):
            raise ValueError('Restart requires distinct explicit dynamic PC/Pawn identities')
        pawn_channels = [channel for channel, item in original.actor_opens.items() if item.actor_guid == pawn_guid]
        if len(pawn_channels) != 1:
            raise ValueError('Restart requires exactly one queued Pawn channel')
        state = self._clone(original)
        state.pc_restart_profile, state.pc_restart_channel = profile, channel_index
        state.pc_restart_actor_guid, state.pc_restart_pawn_guid = pc_guid, pawn_guid
        state.pc_restart_pawn_channel, state.pc_restart_ticket = pawn_channels[0], state.ticket
        if channel_index not in state.actor_contents or pawn_channels[0] not in state.actor_contents:
            raise ValueError('Restart requires explicit PC and Pawn association content plans')
        state.pc_restart_actor_namespace = tuple((channel, item.actor_guid, item.bunch)
                                                 for channel, item in sorted(state.actor_opens.items()))
        state.pc_restart_content_namespace = _content_namespace(state)
        self._pc_restart_binding(state, peer)
        # Budget the complete message before allowing the owner to request it.
        bunch = build_pc_restart(channel_index=channel_index, channel_sequence=1023,
            profile=profile, pawn_guid=pawn_guid, reference_resolved=True, exports_acknowledged=True)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        self.control_peers[peer] = state

    def set_inventory_refresh_profile(self, peer, profile):
        """Bind one frozen inventory append stream before its normal delivery."""
        from dfserver.replication.legacy_ds_inventory_refresh import InventoryRefreshProfile
        original, transport = self.control_peers.get(peer), self.peers.get(peer)
        if (type(profile) is not InventoryRefreshProfile or original is None or
                original.inventory_refresh_profile is not None or
                not original.admitted_actor_reliable_receipts or transport is None):
            raise ValueError('Inventory refresh requires a fresh admitted owner receipt namespace')
        profile.__post_init__()
        self._pc_restart_binding(original, peer)
        generation = self._local_stage_owner(peer, original, transport)
        if (generation is None or original.pc_startup_channel != profile.pc_channel or
                original.pc_startup_actor_guid != profile.pc_guid or
                original.pc_restart_pawn_channel != profile.pawn_channel or
                original.pc_restart_pawn_guid != profile.pawn_guid or
                original.pc_startup_profile.exclusive_index_maximum != profile.exclusive_index_maximum or
                _component_namespace(original).get(profile.component_guid) != (profile.pawn_guid, 'InventoryManager') or
                profile.sources_current() is not True):
            raise ValueError('Inventory refresh source or actual PC/Pawn/component binding differs')
        head = original.actor_contents[profile.pawn_channel]
        stages = (head, *head.continuations)
        for ordinal, payload, bits in profile.initial_payloads:
            if (ordinal >= len(stages) or stages[ordinal].actor_guid != profile.pawn_guid or
                    (stages[ordinal].bunch.payload, stages[ordinal].bunch.payload_bits) != (payload, bits)):
                raise ValueError('The original inventory stage differs from its frozen append projection')
        state = self._clone(original)
        state.inventory_refresh_profile = profile
        state.inventory_refresh_revision = profile.initial_array_key
        state.inventory_refresh_lease = _InventoryRefreshLease(peer, state.ticket, transport, generation, profile,
            tuple((channel, item.actor_guid, item.bunch) for channel, item in sorted(state.actor_opens.items())),
            _content_namespace(state))
        self.control_peers[peer] = state

    def _inventory_refresh_binding(self, state, peer):
        original, transport = self.control_peers.get(peer), self.peers.get(peer)
        lease, profile = state.inventory_refresh_lease, state.inventory_refresh_profile
        if (type(lease) is not _InventoryRefreshLease or lease.peer != peer or
                original is None or lease.ticket is not state.ticket or original.ticket is not state.ticket or
                lease.transport is not transport or lease.profile is not profile or
                tuple((channel, item.actor_guid, item.bunch) for channel, item in sorted(state.actor_opens.items())) !=
                lease.actor_namespace or _content_namespace(state) != lease.content_namespace or
                profile.sources_current() is not True):
            raise ValueError('The inventory refresh owner, transport or source namespace changed')
        self._admitted_actor_receipt_binding(state, original, peer, transport, lease.generation)
        if state.inventory_refresh is not None:
            update, bunch = self._inventory_refresh_expected_bunch(state)
            if (state.inventory_refresh_update != update or state.inventory_refresh.bunch != bunch or
                    state.inventory_refresh.actor_guid != profile.pawn_guid):
                raise ValueError('The exact pending inventory refresh delivery changed')
        if state.inventory_runtime_delivery is not None:
            expected = self._inventory_runtime_bunch(state)
            if (state.inventory_runtime_delivery.bunch != expected or
                    state.inventory_runtime_delivery.actor_guid != profile.pawn_guid):
                raise ValueError('The exact subsequent inventory delivery changed')
        return lease

    def _inventory_refresh_expected_bunch(self, state):
        from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate, write_default_subobjects_followup
        profile = state.inventory_refresh_profile
        update = profile.project_refresh(state.inventory_refresh_ready)
        if (type(update) is not DefaultSubobjectUpdate or
                (update.actor_guid, update.guid, update.name) !=
                (profile.pawn_guid, profile.component_guid, 'InventoryManager')):
            raise ValueError('Inventory refresh changed the owning component')
        writer = BitWriter(maximum_bits=self.max_packet_bytes*8)
        write_default_subobjects_followup(writer, (update,), (),
            tuple(item.actor_guid for item in state.actor_opens.values()))
        previous = state.inventory_refresh_previous_sequence
        if type(previous) is not int or not 0 <= previous <= 1023:
            raise ValueError('First inventory refresh requires its reserved shared Pawn sequence')
        bunch = WireBunch(profile.pawn_channel, writer.to_bytes(), writer.bit_count,
            reliable=True, channel_sequence=(previous+1)&1023,
            channel_name=ChannelName(hardcoded_index=102), package_exports=True)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        return update, bunch

    def inventory_refresh_revision_state(self, peer):
        """Expose an ACK-committed baseline; subsequent inventory writers must serialize after it."""
        state = self.control_peers.get(peer)
        if state is None or not state.inventory_refresh_committed:
            raise ValueError('The native-ready inventory refresh has not been acknowledged')
        if state.inventory_runtime_delivery is not None and not state.inventory_runtime_delivery.delivered:
            raise ValueError('An authoritative inventory update is awaiting its exact delivery ACK')
        lease = self._inventory_refresh_binding(state, peer)
        profile = state.inventory_refresh_profile
        self._post_admission_previous_sequence(state, profile.pawn_channel, profile.pawn_guid)
        previous = state.inventory_runtime_delivery or state.inventory_refresh
        receipt = state.inventory_runtime_receipt if state.inventory_runtime_delivery is not None else state.inventory_refresh_receipt
        if (type(receipt) is not _ActualActorReceipt or previous is None or not previous.delivered or
                receipt.ticket is not lease.ticket or receipt.transport is not lease.transport or
                receipt.generation is not lease.generation or receipt.actor_guid != profile.pawn_guid or
                receipt.bunch != previous.bunch or receipt.sequence not in previous.sent_packets):
            raise ValueError('The exact full-send and positive inventory receipt is required for a baseline')
        return dict(ticket=lease.ticket, generation=lease.generation, transport=lease.transport,
            pawn_guid=profile.pawn_guid, pawn_channel=profile.pawn_channel,
            component_guid=profile.component_guid, array_key=state.inventory_refresh_revision,
            original_items=state.inventory_runtime_items or profile.original_items,
            previous_delivery=previous)

    def _inventory_runtime_bunch(self, state):
        from dfserver.replication.legacy_ds_default_subobject import write_default_subobjects_followup
        update, profile = state.inventory_runtime_update, state.inventory_refresh_profile
        if (update is None or (update.actor_guid, update.guid, update.name) !=
                (profile.pawn_guid, profile.component_guid, 'InventoryManager') or
                type(state.inventory_runtime_previous_sequence) is not int):
            raise ValueError('A subsequent inventory update requires the exact owning component and previous sequence')
        writer = BitWriter(maximum_bits=self.max_packet_bytes*8)
        write_default_subobjects_followup(writer, (update,), (),
            tuple(item.actor_guid for item in state.actor_opens.values()))
        return WireBunch(profile.pawn_channel, writer.to_bytes(), writer.bit_count, reliable=True,
            channel_sequence=(state.inventory_runtime_previous_sequence+1)&1023,
            channel_name=ChannelName(hardcoded_index=102), package_exports=True)

    def queue_inventory_update(self, peer, *, expected_array_key, update, authoritative_items):
        """Serialize one authority-produced item delta after the actual acknowledged baseline."""
        from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate
        baseline = self.inventory_refresh_revision_state(peer)
        if type(expected_array_key) is not int or expected_array_key != baseline['array_key'] or type(update) is not DefaultSubobjectUpdate:
            raise ValueError('An inventory writer must use the exact current acknowledged array key')
        original = self.control_peers[peer]
        key, items = original.inventory_refresh_profile.apply_update(update, baseline['original_items'],
            expected_array_key, authoritative_items)
        state = self._clone(original)
        state.inventory_runtime_update, state.inventory_runtime_next_key = update, key
        state.inventory_runtime_next_items = items
        state.inventory_runtime_receipt = None
        state.inventory_runtime_previous_sequence = self._post_admission_previous_sequence(
            state, baseline['pawn_channel'], baseline['pawn_guid'])
        bunch = self._inventory_runtime_bunch(state)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        state.inventory_runtime_delivery = ActorOpenDelivery(bunch, state.inventory_refresh_profile.pawn_guid)
        self._post_admission_reserve(state, bunch, state.inventory_refresh_profile.pawn_guid)
        self.control_peers[peer] = state
        return state.inventory_runtime_delivery

    def _inventory_refresh_before_socket(self, peer, payload):
        state = self.control_peers.get(peer)
        if state is None or state.inventory_refresh is None:
            return False
        try:
            self._inventory_refresh_binding(state, peer)
            item = state.inventory_runtime_delivery if state.inventory_refresh_committed else state.inventory_refresh
            if item is None or item.delivered:
                return False
            packet = decode_observed_application(payload, max_packet_bytes=self.max_packet_bytes,
                received_by_server=False)
            return len(packet.bunches) == 1 and replace(packet.bunches[0],
                header_start_bit=None, payload_start_bit=None) == item.bunch
        except (ValueError, OSError, KeyError):
            return False

    def _acknowledge_inventory_refresh(self, original, state, packet, peer, transport, generation):
        item = state.inventory_runtime_delivery if state.inventory_refresh_committed else state.inventory_refresh
        if item is None or item.delivered or state.client_closed:
            return
        try:
            lease = self._inventory_refresh_binding(state, peer)
        except (ValueError, OSError, KeyError):
            return
        if generation is not lease.generation:
            return
        matched = next((sent for sent in original.actual_application_sends
                for distance in ((packet.acknowledged_sequence-sent.sequence) & MASK,)
                if sent.ticket is state.ticket and sent.transport is transport and
                sent.generation is generation and item.bunch in sent.bunches and
                sent.sequence in item.sent_packets and distance < len(packet.history)*32 and
                bool((packet.history[distance//32] >> (distance % 32)) & 1)), None)
        if matched is None:
            return
        receipt = _ActualActorReceipt(item.actor_guid, item.bunch, matched.sequence,
            state.ticket, transport, generation)
        self._post_admission_commit(state, item, receipt)
        item.delivered = True
        if state.inventory_refresh_committed:
            state.inventory_runtime_receipt = receipt
            state.inventory_refresh_revision = state.inventory_runtime_next_key
            state.inventory_runtime_items = state.inventory_runtime_next_items
        else:
            state.inventory_refresh_receipt = receipt
            state.inventory_refresh_revision = state.inventory_refresh_profile.initial_array_key + 1
            state.inventory_refresh_committed = True

    def _post_admission_previous_sequence(self, state, channel, actor_guid):
        tail = state.post_admission_channel_tails.get(channel)
        if tail is not None:
            lease, receipt = state.admitted_actor_receipt_lease, tail.receipt
            if (type(tail) is not _PostAdmissionChannelTail or tail.actor_guid != actor_guid or
                    type(receipt) is not _ActualActorReceipt or receipt.bunch != tail.bunch or
                    receipt.actor_guid != actor_guid or receipt.ticket is not state.ticket or
                    receipt.transport is not lease.transport or receipt.generation is not lease.generation):
                raise ValueError('The shared Actor channel still awaits its exact post-admission receipt')
            return tail.bunch.channel_sequence
        opened = state.actor_opens.get(channel)
        if opened is None or opened.actor_guid != actor_guid:
            raise ValueError('The exact initial Actor channel is required for post-admission content')
        return _last_actor_content(state, channel, opened).bunch.channel_sequence

    def _post_admission_reserve(self, state, bunch, actor_guid):
        self._post_admission_reserve_series(state, (bunch,), actor_guid)

    def _post_admission_reserve_series(self, state, bunches, actor_guid):
        bunch = bunches[0]
        previous = self._post_admission_previous_sequence(state, bunch.channel_index, actor_guid)
        if any(item.channel_index != bunch.channel_index or item.channel_sequence != (previous+index+1)&1023
                for index, item in enumerate(bunches)):
            raise ValueError('A post-admission writer must use the next shared Actor reliable sequence')
        state.post_admission_channel_tails[bunch.channel_index] = _PostAdmissionChannelTail(actor_guid, bunches[-1])

    @staticmethod
    def _post_admission_commit(state, item, receipt):
        tail = state.post_admission_channel_tails.get(item.bunch.channel_index)
        if (type(tail) is not _PostAdmissionChannelTail or tail.actor_guid != item.actor_guid or
                tail.bunch != item.bunch or receipt.bunch != item.bunch):
            raise ValueError('The acknowledged delivery differs from the shared Actor channel reservation')
        state.post_admission_channel_tails[item.bunch.channel_index] = replace(tail, receipt=receipt)

    def set_world_delivery_profile(self, peer, profile):
        """Bind exact configured static boxes; this does not assert live-world readiness."""
        from dfserver.replication.legacy_ds_world_delivery import WorldDeliveryProfile
        original = self.control_peers.get(peer)
        if (type(profile) is not WorldDeliveryProfile or original is None or
                original.world_delivery_profile is not None or original.inventory_refresh_lease is None or
                profile.recipient_scope[1] != original.ticket.player_id):
            raise ValueError('One actual admitted inventory owner and finite world profile are required')
        profile.__post_init__()
        if profile.sources_current() is not True:
            raise ValueError('The qualified world delivery sources changed')
        for receiver in profile.receivers:
            opened = original.actor_opens.get(receiver.channel_index)
            fields = dict(opened.open_fields or ()) if opened is not None else {}
            exports = fields.get('exports', ())
            if (opened is None or opened.actor_guid != receiver.actor_guid or fields.get('actor_kind') != 'static' or
                    len(exports) != 1):
                raise ValueError('The source box must have its exact queued static Actor open')
            actor = exports[0]
            level = actor.outer
            world = level.outer if level is not None else None
            package = world.outer if world is not None else None
            if (package is None or package.outer is not None or actor.guid != receiver.actor_guid or
                    package.path+'.'+world.path+':'+level.path+'.'+actor.path != receiver.object_path):
                raise ValueError('The configured world box differs from the exact queued export path')
        state = self._clone(original)
        lease = state.inventory_refresh_lease
        state.world_delivery_profile = profile
        state.world_delivery_lease = (profile, state.ticket, lease.transport, lease.generation)
        self.control_peers[peer] = state

    def _world_delivery_binding(self, state, peer, object_path):
        lease = self._inventory_refresh_binding(state, peer)
        profile, bound = state.world_delivery_profile, state.world_delivery_lease
        if (profile is None or type(bound) is not tuple or len(bound) != 4 or
                bound[0] is not profile or bound[1] is not state.ticket or
                bound[2] is not lease.transport or bound[3] is not lease.generation or
                profile.recipient_scope[1] != state.ticket.player_id or profile.sources_current() is not True):
            raise ValueError('The exact current finite world delivery owner is required')
        receivers = [row for row in profile.receivers if row.object_path == object_path]
        if len(receivers) != 1:
            raise ValueError('The box is outside this admitted source-qualified world subset')
        receiver = receivers[0]
        opened = state.actor_opens.get(receiver.channel_index)
        if (opened is None or opened.actor_guid != receiver.actor_guid or
                receiver.channel_index in state.client_failed_actor_channels or
                profile.live_world_current(object_path) is not True):
            raise ValueError('A current independently verified live-world box binding is required')
        return lease, receiver

    def _world_box_bunches(self, state, receiver, projection, previous_sequence):
        from dfserver.replication.legacy_ds_world_delivery import WorldBoxProjection
        if (type(projection) is not WorldBoxProjection or projection.object_path != receiver.object_path or
                type(projection.stages) is not tuple or not 1 <= len(projection.stages) <= 66 or
                any(type(block) is not ActorContentBlock for block in projection.stages)):
            raise ValueError('One bounded source-produced box projection is required')
        bunches = []
        for index, block in enumerate(projection.stages):
            writer = BitWriter(maximum_bits=self.max_packet_bytes*8)
            write_actor_content_blocks(writer, (block,))
            bunch = WireBunch(receiver.channel_index, writer.to_bytes(), writer.bit_count, reliable=True,
                channel_sequence=(previous_sequence+index+1)&1023, channel_name=ChannelName(hardcoded_index=102))
            encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            bunches.append(bunch)
        return tuple(bunches)

    def _world_box_batch_current(self, state, peer, object_path):
        lease, receiver = self._world_delivery_binding(state, peer, object_path)
        batch = state.world_box_batches.get(object_path)
        if type(batch) is not _WorldBoxBatch:
            raise ValueError('An actual source-produced box delivery batch is required')
        expected = self._world_box_bunches(state, receiver, batch.projection, batch.previous_sequence)
        if (len(batch.deliveries) != len(expected) or len(batch.receipts) != len(expected) or
                any(item.actor_guid != receiver.actor_guid or item.bunch != bunch
                    for item, bunch in zip(batch.deliveries, expected))):
            raise ValueError('The pending box delivery bytes or sequence changed')
        for item, receipt in zip(batch.deliveries, batch.receipts):
            if receipt is not None and (type(receipt) is not _ActualActorReceipt or
                    receipt.ticket is not state.ticket or receipt.transport is not lease.transport or
                    receipt.generation is not lease.generation or receipt.actor_guid != receiver.actor_guid or
                    receipt.bunch != item.bunch or receipt.sequence not in item.sent_packets):
                raise ValueError('A box stage has no exact current full-send positive receipt')
        return lease, receiver, batch

    def world_box_cursor(self, peer, object_path):
        state = self.control_peers.get(peer)
        self._world_delivery_binding(state, peer, object_path)
        if object_path in state.world_box_batches:
            _, _, batch = self._world_box_batch_current(state, peer, object_path)
            if not all(receipt is not None for receipt in batch.receipts):
                raise ValueError('The source box projection still awaits actual stage ACKs')
        return state.world_box_cursors.get(object_path)

    def queue_world_box_snapshot(self, peer, *, object_path, snapshot):
        """Project one authority snapshot; preserve its cursor until every stage is acknowledged."""
        original = self.control_peers.get(peer)
        _, receiver = self._world_delivery_binding(original, peer, object_path)
        if original.world_result_delivery is not None and original.world_result_receipt is None:
            raise ValueError('The current move-result reply must finish before another box snapshot')
        cursor = original.world_box_cursors.get(object_path)
        projection = original.world_delivery_profile.project_box(object_path, snapshot, cursor)
        previous = original.world_box_batches.get(object_path)
        if previous is not None and not all(receipt is not None for receipt in previous.receipts):
            self._world_box_batch_current(original, peer, object_path)
            if projection != previous.projection:
                raise ValueError('An in-flight box projection cannot be replaced before all its ACKs')
            return previous
        if not projection.stages:
            if cursor is None or projection.cursor_after_ack != cursor:
                raise ValueError('An empty box projection cannot manufacture a committed cursor')
            return previous
        state = self._clone(original)
        sequence = self._post_admission_previous_sequence(state, receiver.channel_index, receiver.actor_guid)
        bunches = self._world_box_bunches(state, receiver, projection, sequence)
        self._post_admission_reserve_series(state, bunches, receiver.actor_guid)
        batch = _WorldBoxBatch(projection, cursor, sequence,
            tuple(ActorOpenDelivery(bunch, receiver.actor_guid) for bunch in bunches), (None,)*len(bunches))
        state.world_box_batches[object_path] = batch
        self.control_peers[peer] = state
        return batch

    def _world_result_bunch(self, state):
        from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate, write_default_subobjects_followup
        update, profile = state.world_result_update, state.inventory_refresh_profile
        if (type(update) is not DefaultSubobjectUpdate or
                (update.actor_guid, update.guid, update.name) != (profile.pawn_guid, profile.component_guid, 'InventoryManager') or
                type(state.world_result_previous_sequence) is not int):
            raise ValueError('The native move result must target the exact current owning InventoryManager')
        writer = BitWriter(maximum_bits=self.max_packet_bytes*8)
        write_default_subobjects_followup(writer, (update,), (), tuple(item.actor_guid for item in state.actor_opens.values()))
        return WireBunch(profile.pawn_channel, writer.to_bytes(), writer.bit_count, reliable=True,
            channel_sequence=(state.world_result_previous_sequence+1)&1023,
            channel_name=ChannelName(hardcoded_index=102), package_exports=True)

    def queue_world_move_success(self, peer, transfer_receipt):
        """Build only the qualified RPC22 after both exact source/destination data receipts."""
        original = self.control_peers.get(peer)
        path = getattr(transfer_receipt, 'source_path', None)
        self._world_delivery_binding(original, peer, path)
        command = transfer_receipt.cmd_gid
        known = original.world_result_journal.get(command)
        if known is not None:
            if known[0] != transfer_receipt:
                raise ValueError('The completed move command aliases another authoritative transfer')
            return known[1]
        _, _, batch = self._world_box_batch_current(original, peer, path)
        if not all(receipt is not None for receipt in batch.receipts) or batch.base_cursor is None:
            raise ValueError('The source deletion must have its actual complete box delta ACKs')
        if (batch.projection.authority_revision < transfer_receipt.source_revision or
                not any(element.element_id == transfer_receipt.source_deleted_element_id and
                    element.item.item_gid == transfer_receipt.item_gid for element in batch.base_cursor.known_items)):
            raise ValueError('The acknowledged source batch did not remove this exact original item')
        cursor = original.world_box_cursors.get(path)
        if cursor != batch.projection.cursor_after_ack:
            raise ValueError('The source box cursor has not committed this exact received projection')
        if original.world_result_delivery is not None and original.world_result_receipt is None:
            if original.world_result_command != transfer_receipt:
                raise ValueError('The shared Pawn channel still has another move result pending')
            return original.world_result_delivery
        if len(original.world_result_journal) >= 4096:
            raise ValueError('The finite move-result journal is exhausted')
        baseline = self.inventory_refresh_revision_state(peer)
        update = original.world_delivery_profile.success_update(transfer_receipt, cursor, baseline['original_items'],
            baseline['pawn_guid'], baseline['component_guid'])
        state = self._clone(original)
        state.world_result_command, state.world_result_update, state.world_result_receipt = transfer_receipt, update, None
        state.world_result_previous_sequence = self._post_admission_previous_sequence(state,
            baseline['pawn_channel'], baseline['pawn_guid'])
        bunch = self._world_result_bunch(state)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        self._post_admission_reserve(state, bunch, baseline['pawn_guid'])
        state.world_result_delivery = ActorOpenDelivery(bunch, baseline['pawn_guid'])
        self.control_peers[peer] = state
        return state.world_result_delivery

    @staticmethod
    def _exact_post_admission_ack(original, item, packet, lease):
        sent = next((sent for sent in original.actual_application_sends
            for distance in ((packet.acknowledged_sequence-sent.sequence) & MASK,)
            if sent.ticket is lease.ticket and sent.transport is lease.transport and sent.generation is lease.generation and
                item.bunch in sent.bunches and sent.sequence in item.sent_packets and distance < len(packet.history)*32 and
                bool((packet.history[distance//32] >> (distance % 32)) & 1)), None)
        return None if sent is None else _ActualActorReceipt(item.actor_guid, item.bunch, sent.sequence,
            lease.ticket, lease.transport, lease.generation)

    def _acknowledge_world_deliveries(self, original, state, packet, peer, generation):
        if state.world_delivery_profile is None or state.client_closed:
            return
        for path in tuple(state.world_box_batches):
            try:
                lease, _, batch = self._world_box_batch_current(state, peer, path)
            except (ValueError, OSError, KeyError):
                continue
            if lease.generation is not generation:
                continue
            receipts = list(batch.receipts)
            for index, item in enumerate(batch.deliveries):
                if receipts[index] is not None:
                    continue
                receipts[index] = self._exact_post_admission_ack(original, item, packet, lease)
                if receipts[index] is not None:
                    item.delivered = True
            if tuple(receipts) == batch.receipts:
                continue
            state.world_box_batches[path] = replace(batch, receipts=tuple(receipts))
            if all(receipt is not None for receipt in receipts):
                self._post_admission_commit(state, batch.deliveries[-1], receipts[-1])
                state.world_box_cursors[path] = batch.projection.cursor_after_ack
        item = state.world_result_delivery
        if item is None or state.world_result_receipt is not None:
            return
        try:
            lease, _, _ = self._world_box_batch_current(state, peer, state.world_result_command.source_path)
            if item.bunch != self._world_result_bunch(state) or generation is not lease.generation:
                return
            receipt = self._exact_post_admission_ack(original, item, packet, lease)
            if receipt is not None:
                self._post_admission_commit(state, item, receipt)
                item.delivered = True
                state.world_result_receipt = receipt
                state.world_result_journal[state.world_result_command.cmd_gid] = (state.world_result_command, receipt)
        except (ValueError, OSError, KeyError):
            return

    def _world_delivery_before_socket(self, peer, payload):
        state = self.control_peers.get(peer)
        if state is None or state.world_delivery_profile is None:
            return False
        try:
            packet = decode_observed_application(payload, max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            if len(packet.bunches) != 1:
                return False
            bunch = replace(packet.bunches[0], header_start_bit=None, payload_start_bit=None)
            item = state.world_result_delivery
            if item is not None and state.world_result_receipt is None and bunch == item.bunch:
                self._world_box_batch_current(state, peer, state.world_result_command.source_path)
                return bunch == self._world_result_bunch(state)
            for path in state.world_box_batches:
                _, _, batch = self._world_box_batch_current(state, peer, path)
                for index, item in enumerate(batch.deliveries):
                    if item.bunch == bunch and batch.receipts[index] is None:
                        return all(receipt is not None for receipt in batch.receipts[:index])
        except (ValueError, OSError, KeyError):
            return False
        return False

    def enable_admitted_actor_receipts(self, peer, *, owned_actor_channels=()):
        """Bind explicit queued dynamic owner channels; this prepares no ACK.

        The producer qualifies additional PlayerState/owned-weapon channels.
        The configured PC and Pawn are implicit. Delivery may still be pending;
        each receive separately requires actual full sends and positive ACKs.
        """
        from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
        state, transport = self.control_peers.get(peer), self.peers.get(peer)
        self._pc_restart_binding(state, peer)
        if (state.admitted_actor_reliable_receipts or
                type(owned_actor_channels) is not tuple or
                len(owned_actor_channels) > MAX_INITIAL_ACTOR_CHANNELS - 2 or
                any(type(channel) is not int or not 1 <= channel <= 0xffffffff
                    for channel in owned_actor_channels) or
                len(set(owned_actor_channels)) != len(owned_actor_channels) or
                type(state.hello_sequence) is not int or not 0 <= state.hello_sequence < 1024):
            raise ValueError('One explicit bounded admitted Actor receipt namespace is required')
        implicit = (state.pc_restart_channel, state.pc_restart_pawn_channel)
        if set(owned_actor_channels) & {*implicit, state.game_state_start_channel}:
            raise ValueError('Additional owned channels cannot alias the PC, Pawn or GameState')
        channels = (*implicit, *owned_actor_channels)
        for channel in channels:
            opened = state.actor_opens.get(channel)
            if (type(opened) is not ActorOpenDelivery or
                    type(opened.actor_guid) is not int or not 2 <= opened.actor_guid <= 0xffffffff or
                    opened.actor_guid & 1 or not opened.bunch.open or
                    opened.bunch.channel_index != channel):
                raise ValueError('Receipt requires an exact queued dynamic owned Actor')
        generation = self._local_stage_owner(peer, state, transport)
        if (type(generation) is not PendingChallenge or generation.echoed is not True or
                generation.verified_at is None or
                state.pc_reliable_receipt is not None and
                state.pc_reliable_receipt_seed != state.hello_sequence):
            raise ValueError('Receipt requires the current verified generation and trusted Hello seed')
        candidate = self._clone(state)
        candidate.admitted_actor_receipt_lease = _AdmittedActorReceiptLease(peer, state.ticket,
            transport, generation, state.hello_sequence, channels,
            tuple((channel, item.actor_guid, item.bunch)
                for channel, item in sorted(state.actor_opens.items())), _content_namespace(state))
        candidate.admitted_actor_reliable_receipts = True
        self.control_peers[peer] = candidate

    def _admitted_actor_receipt_binding(self, state, original, peer, transport, generation):
        from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
        from dfserver.transport.native.legacy_ds_owned_pawn_receipt import OwnedPawnReceiptBinding
        lease = state.admitted_actor_receipt_lease
        if (type(lease) is not _AdmittedActorReceiptLease or
                not self._current_joined_receipt_owner(peer, original, transport) or
                lease.peer != peer or lease.ticket is not state.ticket or
                lease.ticket is not original.ticket or lease.transport is not transport or
                type(generation) is not PendingChallenge or generation.echoed is not True or
                generation.verified_at is None or generation is not lease.generation or
                self._local_stage_owner(peer, original, transport) is not generation or
                state.hello_sequence != lease.initial_sequence or
                tuple((channel, item.actor_guid, item.bunch)
                    for channel, item in sorted(state.actor_opens.items())) != lease.actor_namespace or
                _content_namespace(state) != lease.content_namespace):
            raise _AdmittedActorReceiptRejection('owner_lease_not_current')
        try:
            self._pc_restart_binding(state, peer)
        except ValueError:
            raise _AdmittedActorReceiptRejection('pc_restart_binding_invalid') from None
        # Prepared packets, cursor-only ACKs and manually set delivered flags do
        # not qualify an incoming Actor body. Every prerequisite has its own proof.
        required = (*state.actor_opens.values(), *_content_items(state))
        receipts = {(r.actor_guid, r.bunch) for r in state.actual_actor_receipts
            if r.ticket is lease.ticket and r.transport is transport and r.generation is generation}
        if (not required or not _content_policies_current(state.actor_contents) or
                any(not self._actual_actor_delivery(item) or
                    any((piece.actor_guid, piece.bunch) not in receipts for piece in _wire_items(item))
                    for item in required)):
            raise _AdmittedActorReceiptRejection('initial_delivery_proof_missing')
        return OwnedPawnReceiptBinding(peer, lease.ticket, generation, transport,
            admission_active=True, configured_owner_current=True,
            pawn_open_full_send_acknowledged=True, all_initial_content_acknowledged=True)

    @staticmethod
    def _journal_admitted_actor_receipt(state, bunch, ready, duplicate):
        if duplicate:
            return
        retained = len(bunch.payload) + sum(len(body.payload) for body in ready if body != bunch)
        if retained > MAX_ADMITTED_RECEIPT_JOURNAL_BYTES:
            raise _AdmittedActorReceiptRejection('opaque_journal_body_limit')
        entry = _OpaqueActorTransportReceipt(bunch.channel_index, bunch.channel_sequence,
            bunch.payload_bits, hashlib.sha256(bunch.payload).hexdigest(), bunch.partial,
            retained, bunch, ready)
        journal = (*state.admitted_actor_opaque_journal, entry)
        total = state.admitted_actor_opaque_journal_bytes + retained
        while len(journal) > MAX_ADMITTED_RECEIPT_JOURNAL_ENTRIES or total > MAX_ADMITTED_RECEIPT_JOURNAL_BYTES:
            total -= journal[0].retained_bytes
            journal = journal[1:]
        state.admitted_actor_opaque_journal = journal
        state.admitted_actor_opaque_journal_bytes = total

    def set_owner_switch_profile(self, peer, profile):
        from dfserver.transport.native.legacy_ds_owner_switch import set_profile
        set_profile(self, peer, profile)

    def _owner_switch_before_socket(self, peer, payload):
        from dfserver.transport.native.legacy_ds_owner_switch import before_socket
        return before_socket(self, peer, payload)

    def set_movement_profile(self, peer, profile):
        from dfserver.transport.native.legacy_ds_movement import set_profile
        set_profile(self, peer, profile)

    def accepted_movement_position(self, peer):
        from dfserver.transport.native.legacy_ds_movement import accepted_position
        return accepted_position(self, peer)

    def set_level_visibility_profile(self, peer, profile):
        from dfserver.transport.native.legacy_ds_level_visibility import LevelVisibilityProfile
        from dfserver.transport.native.legacy_ds_level_visibility_state import LevelVisibilityState
        original = self.control_peers.get(peer)
        if (original is None or type(profile) is not LevelVisibilityProfile or
                original.pc_level_visibility_profile is not None or not original.admitted_actor_reliable_receipts or
                original.pc_startup_profile is None or
                original.pc_startup_profile.class_path != profile.class_path or
                original.pc_startup_profile.exclusive_index_maximum != profile.exclusive_index_maximum):
            raise ValueError('The exact admitted PlayerController visibility profile is required')
        profile.__post_init__()
        state = self._clone(original)
        state.pc_level_visibility_profile = profile
        state.pc_level_visibility = LevelVisibilityState()
        self.control_peers[peer] = state

    def _consume_admitted_actor_packet(self, state, original, packet, peer, now,
                                      transport, generation):
        """Trial all bunches on cloned state; any unsupported piece rejects all."""
        from dfserver.transport.native.legacy_ds_owned_pawn_receipt import OwnedPawnReceiptAdapter
        from dfserver.transport.native.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger
        binding = self._admitted_actor_receipt_binding(state, original, peer, transport, generation)
        replies = ()
        pawn_bodies = ()
        for bunch in packet.bunches:
            if bunch.channel_index == 0:
                self._consume_admitted_control_bunch(state, bunch)
            elif bunch.channel_index == state.pc_startup_channel:
                try:
                    state, pending, _, _ = self._consume_pc_startup_packet(state,
                        replace(packet, bunches=(bunch,)), peer, now, transport_receipt=True)
                except _AdmittedActorReceiptRejection:
                    raise
                except ValueError:
                    raise _AdmittedActorReceiptRejection('pc_source_or_owner_binding_invalid') from None
                replies += pending
            elif bunch.channel_index == state.pc_restart_pawn_channel:
                if state.admitted_pawn_receipt is None:
                    try:
                        state.admitted_pawn_receipt = OwnedPawnReceiptAdapter(state, binding=binding,
                            ordinary_transport=True)
                    except ValueError:
                        raise _AdmittedActorReceiptRejection('pawn_binding_invalid') from None
                received = state.admitted_pawn_receipt.receive(bunch,
                    control_connection=state, binding=binding)
                if not received.received:
                    raise _ledger_rejection('pawn_ledger_', received.reason)
                self._journal_admitted_actor_receipt(state, bunch, received.ready, received.duplicate)
                pawn_bodies += received.ready
                if state.owner_switch_profile is not None:
                    from dfserver.transport.native.legacy_ds_owner_switch import consume
                    for ready in received.ready:
                        consume(self, state, peer, ready, received, now)
            elif bunch.channel_index in state.admitted_actor_receipt_lease.channels:
                ledger = state.admitted_actor_receipt_ledgers.get(bunch.channel_index)
                if ledger is None:
                    ledger = OwnedActorReceiptLedger(bunch.channel_index, state.hello_sequence)
                    state.admitted_actor_receipt_ledgers[bunch.channel_index] = ledger
                received = ledger.receive(bunch)
                if not received.received:
                    raise _ledger_rejection('owned_ledger_', received.reason)
                self._journal_admitted_actor_receipt(state, bunch, received.ready, received.duplicate)
            else:
                raise _AdmittedActorReceiptRejection('actor_channel_outside_owned_namespace')
        if state.movement_profile is not None:
            from dfserver.transport.native.legacy_ds_movement import consume as consume_movement
            consume_movement(self, state, peer, pawn_bodies, now)
        self._admitted_actor_receipt_binding(state, original, peer, transport, generation)
        state.admitted_actor_receipt_packet_count += 1
        return state, replies, 'admitted_actor_reliable_packet_received'

    def _consume_admitted_control_bunch(self, state, bunch):
        """Receive only pinned post-Join notifications and exact Control retries.

        ID16's native ReceivedBunch branch (12866c04..12866f85) validates an
        Actor channel then reports its failure to the owning controller; failure
        of its own PC closes the native connection. This local subset accepts
        only another queued static Actor, records its failure and stops retries.
        Its historical positive transport proof remains distinct from resolution.

        ID20 subtype0 reaches GP/DFMGameInstance vslot308 -> 49b7fa0, complete
        677-byte SHA256 96bab0b213ac9f9d5c3520a36124ea57a9b422409fe471ec9e53fe63afc97084.
        The subtype0 branch clears native connection+21f4 and logs the immutable
        literal 15e74b60 'ClientBeginPlay: %s'. Only the captured empty-string
        notification is represented locally; no readiness/GameState is forced.
        Source build/cache pins are in legacy_ds_control_fields.py.
        """
        if not self._plain_control(bunch):
            raise _AdmittedActorReceiptRejection('control_framing_unsupported')
        digest = hashlib.sha256(bunch.payload).digest()
        if bunch.channel_sequence != state.expected_client_sequence:
            if state.consumed.get(bunch.channel_sequence) != digest:
                raise _AdmittedActorReceiptRejection('control_sequence_conflict')
            return
        try:
            messages = decode_messages(bunch.payload, payload_bits=bunch.payload_bits)
        except ValueError:
            raise _AdmittedActorReceiptRejection('control_decode_unsupported') from None
        if not messages:
            raise _AdmittedActorReceiptRejection('control_notification_empty')
        for message in messages:
            if message.message_id == 16:
                channel, = message.fields
                opened = state.actor_opens.get(channel)
                if (type(opened) is not ActorOpenDelivery or not opened.actor_guid & 1 or
                        not opened.bunch.open or opened.bunch.channel_index != channel or
                        channel in state.admitted_actor_receipt_lease.channels):
                    raise _AdmittedActorReceiptRejection('control_actor_failure_outside_static_subset')
                state.client_failed_actor_channels[channel] = opened.actor_guid
            elif message.message_id == 20 and message.fields == (0, ''):
                state.client_begin_play_notified = True
                state.client_begin_play_notification_count += 1
            else:
                raise _AdmittedActorReceiptRejection('control_semantics_unsupported')
        state.consumed.pop(bunch.channel_sequence, None)
        state.consumed[bunch.channel_sequence] = digest
        while len(state.consumed) > RELIABLE_RETRY_WINDOW:
            state.consumed.pop(next(iter(state.consumed)))
        state.expected_client_sequence = (state.expected_client_sequence + 1) & 1023

    def request_pc_restart(self, peer):
        """Owner-only post-travel gate; poll decides readiness and owns the outbox."""
        state = self.control_peers.get(peer)
        waiting = self._pc_restart_waiting(state, peer)
        state.pc_restart_requested = True
        status = ('acknowledged' if state.pc_possession_ack_received else
                  'delivered' if state.pc_restart is not None and state.pc_restart.delivered else
                  'queued' if state.pc_restart is not None else 'pending')
        return {'status': status, 'requested': True, 'waiting_for': waiting,
                'native_possession_verified': False, 'playable_map_verified': False}

    def _pc_view_target_binding(self, state, peer):
        from dfserver.transport.native.legacy_ds_pc_view_target_rpc import PCViewTargetProfile
        self._pc_restart_binding(state, peer)
        if (type(state.pc_view_target_profile) is not PCViewTargetProfile or
                state.pc_view_target_profile.class_path != state.pc_restart_profile.class_path or
                state.pc_view_target_profile.exclusive_index_maximum !=
                    state.pc_restart_profile.exclusive_index_maximum or
                state.pc_view_target_profile.object_binding != state.pc_restart_profile.object_binding):
            raise ValueError('View target requires the same source-qualified PC and object codec')
        state.pc_view_target_profile.__post_init__()

    def _pc_rotation_binding(self, state, peer):
        from dfserver.transport.native.legacy_ds_pc_rotation_rpc import PCRotationProfile
        from dfserver.replication.legacy_ds_rotator import CompressedRotator16
        self._pc_restart_binding(state, peer)
        if (type(state.pc_rotation_profile) is not PCRotationProfile or
                state.pc_rotation_profile.class_path != state.pc_restart_profile.class_path or
                state.pc_rotation_profile.exclusive_index_maximum != state.pc_restart_profile.exclusive_index_maximum or
                type(state.pc_rotation_value) is not CompressedRotator16):
            raise ValueError('Rotation requires the same admitted PC and its explicit spawn rotation')
        state.pc_rotation_profile.__post_init__()
        state.pc_rotation_value.__post_init__()

    def set_pc_rotation_profile(self, peer, profile, rotation):
        from dfserver.transport.native.legacy_ds_pc_rotation_rpc import PCRotationProfile, build_pc_rotation
        original = self.control_peers.get(peer)
        if (not isinstance(original, ControlConnection) or original.pc_rotation_profile is not None or
                original.pc_restart is not None or original.pc_view_target is not None or
                type(profile) is not PCRotationProfile):
            raise ValueError('One pre-restart rotation binding is required')
        state = self._clone(original)
        state.pc_rotation_profile, state.pc_rotation_value = profile, rotation
        self._pc_rotation_binding(state, peer)
        bunch = build_pc_rotation(channel_index=state.pc_restart_channel, channel_sequence=1023,
            profile=profile, rotation=rotation, reset_camera=True)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        self.control_peers[peer] = state

    def _pc_hud_binding(self, state, peer):
        from dfserver.transport.native.legacy_ds_pc_hud_rpc import PCHUDProfile
        self._pc_restart_binding(state, peer)
        profile = state.pc_hud_profile
        if (type(profile) is not PCHUDProfile or profile.class_path != state.pc_restart_profile.class_path or
                profile.exclusive_index_maximum != state.pc_restart_profile.exclusive_index_maximum):
            raise ValueError('HUD setup requires the same admitted PlayerController')
        profile.__post_init__()
        leaf = state.actor_exports.get(state.pc_hud_class_guid)
        if leaf is None or leaf[0] != profile.hud_class_path.rsplit('.', 1)[1] or leaf[2] is not None:
            raise ValueError('The exact HUD class must be exported in the owned Actor namespace')
        package = state.actor_exports.get(leaf[1])
        if package != (profile.hud_class_path.rsplit('.', 1)[0], 0, None):
            raise ValueError('The HUD class package differs from the cooked GameMode reference')

    def set_pc_hud_profile(self, peer, profile, class_guid):
        from dfserver.transport.native.legacy_ds_pc_hud_rpc import PCHUDProfile, build_pc_hud
        original = self.control_peers.get(peer)
        if (not isinstance(original, ControlConnection) or original.pc_hud_profile is not None or
                original.pc_restart is not None or type(profile) is not PCHUDProfile):
            raise ValueError('One pre-restart source-qualified HUD setup is required')
        state = self._clone(original)
        state.pc_hud_profile, state.pc_hud_class_guid = profile, class_guid
        self._pc_hud_binding(state, peer)
        bunch = build_pc_hud(channel_index=state.pc_restart_channel, channel_sequence=1023,
            profile=profile, class_guid=class_guid, reference_resolved=True, exports_acknowledged=True)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        self.control_peers[peer] = state

    def set_pc_view_target_profile(self, peer, profile):
        """Use the admitted ticket's owned Pawn as the explicit local camera target."""
        from dfserver.transport.native.legacy_ds_pc_view_target_rpc import PCViewTargetProfile, build_pc_view_target
        original = self.control_peers.get(peer)
        if (not isinstance(original, ControlConnection) or
                original.pc_view_target_profile is not None or type(profile) is not PCViewTargetProfile):
            raise ValueError('One source-qualified view-target profile is required')
        state = self._clone(original)
        state.pc_view_target_profile = profile
        self._pc_view_target_binding(state, peer)
        bunch = build_pc_view_target(channel_index=state.pc_restart_channel, channel_sequence=1023,
            profile=profile, actor_guid=state.pc_restart_pawn_guid,
            reference_resolved=True, exports_acknowledged=True)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self.max_packet_bytes, received_by_server=False)
        self.control_peers[peer] = state

    def _consume_pc_startup_packet(self, state, packet, peer, now, *, transport_receipt=False):
        """Keep native reliable receipt separate from supported game RPC dispatch.

        Every continuous actual fragment is recorded before semantic decode.
        The legacy policy leaves unknown bodies negatively ACKed. The explicit
        admitted transport policy journals them and lets the whole-packet owner
        decide its ACK. Unknown fields never become game handlers.
        """
        from dfserver.transport.native.legacy_ds_pc_startup_rpc import decode_pc_startup_bunch, build_pc_ready_ack
        from dfserver.transport.native.legacy_ds_pc_ping_receiver import decode_pc_ping_bunches
        from dfserver.transport.native.legacy_ds_pc_restart_rpc import decode_pc_possession_ack_bunch
        from dfserver.transport.native.legacy_ds_pc_view_target_rpc import decode_pc_verify_view_target_bunch
        from dfserver.transport.native.legacy_ds_pc_receipt import PCReceiptLedger, bounded_actor_fields
        from dfserver.transport.native.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger, plain_unreliable_actor
        from dfserver.replication.legacy_ds_actor_fields import NormalClassFieldProfile, build_class_field_content
        from dfserver.replication.legacy_ds_actor_content import write_actor_content_blocks
        from dfserver.transport.native.legacy_ds_bit_archive import BitWriter
        if state.early_player_state_human_appearance is not None:
            self._early_player_state_human_appearance_current(state, peer)
        channel = state.pc_startup_channel
        opened = state.actor_opens.get(channel)
        if (state.pc_startup_profile is None or state.ticket is None or state.client_closed or
                not state.client_join_observed or not self.admissions.is_active(state.ticket) or
                self.ticket_peers.get(state.ticket.cookie) != peer or opened is None or
                opened.actor_guid != state.pc_startup_actor_guid or not opened.delivered or
                not all(item.delivered for item in state.actor_opens.values()) or
                not all(item.delivered for item in _content_items(state))):
            raise _AdmittedActorReceiptRejection('pc_delivery_binding_invalid')
        handled, receipt_pieces, whole, pings, possession_acks, view_target_verifications = 0, 0, True, [], 0, 0
        startup_indices = {field.rep_index for field in state.pc_startup_profile.requests}

        def isolated_rpc(bunch, field):
            # Only already sliced, supported parameter bodies reach a codec.
            block = build_class_field_content((field,), profile=NormalClassFieldProfile(
                state.pc_startup_profile.exclusive_index_maximum, False))
            writer = BitWriter(maximum_bits=4096)
            write_actor_content_blocks(writer, (block,))
            return replace(bunch, payload=writer.to_bytes(), payload_bits=writer.bit_count)

        for incoming in packet.bunches:
            try:
                if incoming.channel_index != channel:
                    raise _AdmittedActorReceiptRejection('pc_channel_outside_namespace')
                if not incoming.reliable:
                    if transport_receipt:
                        try:
                            plain_unreliable_actor(incoming, channel_index=channel)
                        except ValueError:
                            raise _ledger_rejection('pc_ledger_', 'unsupported_or_malformed_bunch') from None
                        # The packet owner may acknowledge actual transport
                        # receipt even when this opaque RPC has no game handler.
                        self._journal_admitted_actor_receipt(state, incoming, (incoming,), False)
                        receipt_pieces += 1
                    if state.pc_ping_profile is None:
                        if transport_receipt:
                            whole = False
                            continue
                        raise _AdmittedActorReceiptRejection('pc_unreliable_receiver_missing')
                    try:
                        decode_pc_ping_bunches((incoming,), channel_index=state.pc_ping_channel,
                                             profile=state.pc_ping_profile)
                    except ValueError:
                        if transport_receipt:
                            whole = False
                            continue
                        raise _AdmittedActorReceiptRejection('pc_unreliable_rpc_unsupported') from None
                    pings.append(incoming)
                    handled += 1
                    continue
                if state.pc_reliable_receipt is None:
                    if not transport_receipt:
                        first = decode_pc_startup_bunch(incoming, channel_index=channel,
                                                      profile=state.pc_startup_profile)
                        if not first or first[0].name != 'ServerShortTimeout':
                            raise _AdmittedActorReceiptRejection('pc_startup_marker_missing')
                    seed = state.hello_sequence if transport_receipt else incoming.channel_sequence
                    ledger_type = OwnedActorReceiptLedger if transport_receipt else PCReceiptLedger
                    state.pc_reliable_receipt = ledger_type(channel, seed)
                    state.pc_reliable_receipt_seed = seed
                if transport_receipt and state.pc_reliable_receipt_seed != state.hello_sequence:
                    raise _AdmittedActorReceiptRejection('pc_ledger_seed_untrusted')
                if transport_receipt and not isinstance(state.pc_reliable_receipt, OwnedActorReceiptLedger):
                    state.pc_reliable_receipt = OwnedActorReceiptLedger.from_ledger(state.pc_reliable_receipt)
                received = state.pc_reliable_receipt.receive(incoming)
                if not received.received:
                    raise _ledger_rejection('pc_ledger_', received.reason)
                receipt_pieces += 1
                if transport_receipt:
                    self._journal_admitted_actor_receipt(state, incoming, received.ready, received.duplicate)
                state.pc_startup_expected_sequence = received.expected_sequence
                if not received.ready:
                    # No completed RPC is available; the outer policy decides
                    # whether this actual fragment qualifies for a packet ACK.
                    whole = False
                    continue
                for bunch in received.ready:
                    digest = hashlib.sha256(bunch.payload_bits.to_bytes(4, 'little') + bunch.payload).digest()
                    sequence = bunch.channel_sequence
                    if received.duplicate and state.pc_startup_consumed.get(sequence) == digest:
                        handled += 1
                        whole = whole and state.pc_startup_semantic_whole.get(sequence, False)
                        if sequence in state.pc_possession_ack_sequences:
                            possession_acks += 1
                        if sequence in state.pc_verify_view_target_sequences:
                            view_target_verifications += 1
                        continue
                    body_whole, requests, possession_ack, verify_view_target = True, [], False, 0
                    inventory_ready, inventory_field, inventory_field_count = None, None, 0
                    visibility_fields, visibility_update = [], None
                    try:
                        fields = bounded_actor_fields(bunch,
                            exclusive_index_maximum=state.pc_startup_profile.exclusive_index_maximum)
                    except ValueError:
                        fields, body_whole = (), False
                    for field in fields:
                        try:
                            if field.rep_index in startup_indices:
                                requests.extend(decode_pc_startup_bunch(isolated_rpc(bunch, field),
                                    channel_index=channel, profile=state.pc_startup_profile))
                            elif (state.pc_restart_profile is not None and
                                  field.rep_index == state.pc_restart_profile.acknowledgement_index):
                                if (not state.pc_restart_requested or state.pc_restart is None or
                                        not state.pc_restart.transmissions or not state.pc_restart.sent_packets or
                                        self._pc_restart_waiting(state, peer)):
                                    raise ValueError('Possession acknowledgement requires a transmitted qualified restart')
                                decode_pc_possession_ack_bunch(isolated_rpc(bunch, field),
                                    channel_index=state.pc_restart_channel, profile=state.pc_restart_profile,
                                    expected_pawn_guid=state.pc_restart_pawn_guid)
                                possession_ack = True
                            elif (state.pc_view_target_profile is not None and
                                  field.rep_index == state.pc_view_target_profile.verify_index):
                                self._pc_view_target_binding(state, peer)
                                decode_pc_verify_view_target_bunch(isolated_rpc(bunch, field),
                                    channel_index=channel, profile=state.pc_view_target_profile)
                                verify_view_target += 1
                            elif (state.inventory_refresh_profile is not None and
                                  field.rep_index == state.inventory_refresh_profile.function_index):
                                inventory_field, inventory_field_count = field, inventory_field_count+1
                            elif (transport_receipt and state.pc_level_visibility_profile is not None and
                                  field.rep_index in (state.pc_level_visibility_profile.single_index,
                                                      state.pc_level_visibility_profile.multiple_index)):
                                visibility_fields.append(field)
                            else:
                                body_whole = False
                        except ValueError:
                            body_whole = False
                    if inventory_field is not None:
                        try:
                            self._inventory_refresh_binding(state, peer)
                            if (inventory_field_count != 1 or not (possession_ack or
                                    state.pc_possession_ack_received and state.pc_possession_ack_count > 0 and
                                    state.pc_possession_ack_sequences)):
                                raise ValueError('Inventory readiness requires one field and the current native Pawn acknowledgement')
                            inventory_ready = state.inventory_refresh_profile.accept_ready(inventory_field, sequence)
                        except (ValueError, OSError, KeyError):
                            body_whole = False
                    if visibility_fields:
                        from dfserver.transport.native.legacy_ds_level_visibility_state import apply as apply_visibility
                        try:
                            pending_visibility = state.pc_level_visibility
                            for field in visibility_fields:
                                pending_visibility = apply_visibility(pending_visibility, field,
                                    state.pc_level_visibility_profile)
                            visibility_update = pending_visibility
                        except ValueError:
                            body_whole = False
                    if not fields:
                        body_whole = False
                    if not body_whole and not received.duplicate:
                        state.pc_opaque_receipt_count += 1
                    whole = whole and body_whole
                    if (not requests and not possession_ack and not verify_view_target and
                            inventory_ready is None and visibility_update is None):
                        continue
                    candidate = self._clone(state)
                    if visibility_update is not None:
                        candidate.pc_level_visibility = visibility_update
                        candidate.pc_level_visibility_reports += len(visibility_fields)
                    if inventory_ready is not None and candidate.inventory_refresh_ready is None:
                        candidate.inventory_refresh_ready = inventory_ready
                    if possession_ack and not candidate.pc_possession_ack_received:
                        candidate.pc_possession_ack_received = True
                        candidate.pc_possession_ack_count += 1
                    if verify_view_target:
                        candidate.pc_view_target_requested = True
                        candidate.pc_verify_view_target_count += verify_view_target
                    for request in requests:
                        if request.name == 'ServerShortTimeout':
                            candidate.pc_short_timeout_observed = True
                        elif request.name == 'Server_RcvACWorldTime':
                            candidate.pc_client_world_time = request.value
                        elif request.name == 'ServerFieldOfView':
                            candidate.pc_client_field_of_view = request.value
                        elif request.name == 'NotifySeamlessLoginReady':
                            candidate.pc_ready_notification_received = True
                            candidate.pc_seamless_enter_requested = request.value
                            if candidate.pc_ready_ack is None:
                                previous = _last_actor_content(candidate, channel, opened)
                                ack = build_pc_ready_ack(channel_index=channel,
                                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                                    profile=candidate.pc_startup_profile)
                                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,),
                                    False, 0, None, (ack,), 0), max_packet_bytes=self.max_packet_bytes,
                                    received_by_server=False)
                                candidate.pc_ready_ack = ActorOpenDelivery(ack, candidate.pc_startup_actor_guid)
                    candidate.pc_startup_consumed.pop(sequence, None)
                    candidate.pc_startup_consumed[sequence] = digest
                    candidate.pc_startup_semantic_whole[sequence] = body_whole
                    if possession_ack:
                        candidate.pc_possession_ack_sequences.add(sequence)
                    if verify_view_target:
                        candidate.pc_verify_view_target_sequences.add(sequence)
                    while len(candidate.pc_startup_consumed) > RELIABLE_RETRY_WINDOW:
                        old_sequence = next(iter(candidate.pc_startup_consumed))
                        candidate.pc_startup_consumed.pop(old_sequence)
                        candidate.pc_startup_semantic_whole.pop(old_sequence, None)
                        candidate.pc_possession_ack_sequences.discard(old_sequence)
                        candidate.pc_verify_view_target_sequences.discard(old_sequence)
                    candidate.pc_startup_request_count += len(requests)
                    state = candidate
                    handled += 1
                    possession_acks += int(possession_ack)
                    view_target_verifications += verify_view_target
            except ValueError:
                if transport_receipt:
                    raise
                whole = False
        if not handled and not receipt_pieces:
            raise _AdmittedActorReceiptRejection('pc_receipt_or_rpc_missing')
        replies = ()
        if pings:
            replies, _ = self._consume_pc_ping(state, replace(packet, bunches=tuple(pings)), peer, now)
        event = (('pc_possession_ack_packet_consumed' if whole else 'pc_possession_ack_mixed_packet_consumed')
                 if possession_acks else
                 ('pc_verify_view_target_packet_consumed' if whole else 'pc_verify_view_target_mixed_packet_consumed')
                 if view_target_verifications else
                 ('pc_startup_packet_consumed' if whole else 'pc_startup_mixed_packet_consumed')
                 if handled else 'pc_reliable_receipt_only_consumed')
        return state, replies, event, whole

    def set_game_state_start_profile(self, peer, channel_index, actor_guid, profile):
        from dfserver.replication.legacy_ds_game_state_start import GameStateStartProfile
        state = self.control_peers.get(peer)
        if (not isinstance(state, ControlConnection) or state.client_closed or
                state.ticket is None or not state.client_join_observed or
                type(profile) is not GameStateStartProfile or
                type(channel_index) is not int or type(actor_guid) is not int or
                channel_index not in state.actor_opens or
                state.actor_opens[channel_index].actor_guid != actor_guid or
                state.game_state_start_profile is not None or
                channel_index == state.pc_startup_channel):
            raise ValueError('StartPlay requires an exact admitted GameState Actor channel')
        profile.__post_init__()
        state.game_state_start_profile = profile
        state.game_state_start_channel, state.game_state_start_actor_guid = channel_index, actor_guid

    def _encode_reply(self, transport, state, acknowledged_sequence, history, now,
                      *, include_pending=True, actor_replies=(), count_as_control=True):
        pending = state.pending if include_pending else None
        if pending and pending.transmissions >= self.max_transmissions:
            pending = None
        bunches = (() if pending is None else (WireBunch(
            0, pending.payload, len(pending.payload) * 8, reliable=True,
            channel_sequence=pending.channel_sequence, channel_name=CONTROL_NAME),))
        body = encode_observed_application(WirePacket(
            transport.out_sequence, acknowledged_sequence, (history,), False,
            0, None, bunches + actor_replies, 0), max_packet_bytes=self.max_packet_bytes,
            received_by_server=False)
        if pending:
            pending.sent_packets = (*pending.sent_packets, transport.out_sequence)[-64:]
            pending.last_sent_at = now
            pending.transmissions += 1
        transport.out_sequence = (transport.out_sequence + 1) & MASK
        if count_as_control:
            transport.replies += 1
        return body

    def _consume_new(self, state, bunch, peer):
        if not state.hello_received:
            if (not bunch.open or decode_messages(bunch.payload) !=
                    (ControlMessage(0, (1, self.expected_net_version, '')),)):
                raise ValueError('Unsupported native Hello')
            state.hello_received = True
            self._queue(state, 3, state.challenge_payload)
            return 'control_hello_challenge_prepared'

        if state.ticket is None:
            login = decode_single_login5(bunch.payload, payload_bits=bunch.payload_bits)
            ticket = self.admissions.authorize_login_url(login.url)
            bound = self.ticket_peers.get(ticket.cookie)
            if bound is not None and bound != peer:
                raise ValueError('Local match ticket is already bound to a different peer')
            welcome = self.welcome_payloads.get(ticket.map_id)
            if welcome is None:
                raise ValueError('The selected map has no evidenced Welcome entry')
            state.ticket, state.welcome_payload = ticket, welcome
            # A correctly admitted Login proves the client processed Challenge;
            # it does not manufacture a packet-history delivery ACK.
            state.welcome_sequence = self._queue(state, 1, welcome).channel_sequence
            return 'control_login_welcome_prepared'

        messages = decode_messages(bunch.payload)
        if not messages:
            raise ValueError('Empty reliable native control data')
        for message in messages:
            if message.message_id == 4 and not state.client_join_observed:
                state.netspeed = message.fields[0]
            elif (message.message_id == 9 and state.netspeed is not None
                  and not state.client_join_observed):
                state.client_join_observed = True
            else:
                raise ValueError('Unsupported control order or payload')
        return ('control_join_ack_prepared' if state.client_join_observed
                else 'control_netspeed_ack_prepared')

    def _empty_control_close(self, bunch):
        # A channel close is a bunch flag, not an empty NMT/Login message.
        return (bunch.close and not bunch.open and bunch.payload_bits == 0 and
                bunch.payload == b'' and self._plain_control(replace(bunch, close=False)))

    def _current_joined_receipt_owner(self, peer, original, transport):
        """Qualify only this still-current admitted session's header receipts."""
        if (self.control_peers.get(peer) is not original or
                self.peers.get(peer) is not transport or
                original.ticket is None or not original.client_join_observed or
                original.client_closed or
                self.ticket_peers.get(original.ticket.cookie) != peer):
            return False
        try:
            return bool(self.admissions.is_active(original.ticket))
        except (ValueError, OSError, KeyError):
            return False

    def _note_actual_application_send(self, peer, payload, *, generation, ticket, transport, sent_at):
        """Called only after full sendto success and probe owner rechecks."""
        from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
        current = self.control_peers.get(peer)
        if (type(generation) is not PendingChallenge or not generation.echoed or
                generation.verified_at is None or current is None or current.ticket is not ticket or
                type(sent_at) not in (int, float) or not math.isfinite(sent_at) or sent_at < 0 or
                not self._current_joined_receipt_owner(peer, current, transport)):
            return False
        if (self._local_stage_generation_for_peer is not None and
                self._local_stage_owner(peer, current, transport) is not generation):
            return False
        try:
            packet = decode_observed_application(payload, max_packet_bytes=self.max_packet_bytes,
                                                  received_by_server=False)
        except (ValueError, TypeError):
            return False
        if not 0 < ((transport.out_sequence - packet.sequence) & MASK) < (MASK + 1) // 2:
            return False
        retained = tuple(item for item in current.actual_application_sends
            if item.ticket is ticket and item.transport is transport and item.generation is generation and
               item.sequence != packet.sequence)
        sent = _ActualApplicationSend(packet.sequence, ticket, transport, generation,
            tuple(replace(b, header_start_bit=None, payload_start_bit=None) for b in packet.bunches))
        if self._local_stage_generation_for_peer is None:
            current.actual_application_sends = (*retained[-(MAX_ACTUAL_APPLICATION_SENDS - 1):], sent)
        else:
            current.actual_application_sends = self._retain_actual_stage_sends(
                current, (*retained, sent), ticket, transport, generation, sent_at)
        if self._local_stage_generation_for_peer is not None:
            for item in self._stage_items(current):
                if (item is not None and item.local_stage_first_prepared_at is not None and
                        item.local_stage_ticket is ticket and item.local_stage_generation is generation and
                        item.local_stage_transport is transport and
                        item.bunch in sent.bunches):
                    item.sent_packets = (*item.sent_packets, packet.sequence)[-64:]
                    item.local_stage_full_sends += 1
        for item in _content_items(current):
            _refresh_fragment_delivery(item)
        current.last_successful_application_send_at = sent_at
        outbox = current.fashion_subobject_outbox
        if outbox is not None and current.fashion_async_binding is None:
            proposal = outbox.prepared_for_payload(payload)
            if proposal is not None:
                try:
                    outbox.note_full_send(proposal, application_payload=payload,
                        bytes_sent=len(payload), sent_at=sent_at)
                except (ValueError, OSError, KeyError):
                    outbox.cancel()
        return True

    def _record_actual_actor_receipts(self, original, state, packet, transport, generation):
        """Called before cursor mutation after the header policy accepted it."""
        if generation is None or original.client_closed or any(b.close for b in packet.bunches):
            return
        current = tuple((item.actor_guid, item.bunch) for item in
            (*original.actor_opens.values(), *_content_wire_items(original)))
        retained = list(state.actual_actor_receipts)
        for sent in original.actual_application_sends:
            if (sent.ticket is not original.ticket or sent.transport is not transport or
                    sent.generation is not generation):
                continue
            distance = (packet.acknowledged_sequence - sent.sequence) & MASK
            if (distance >= len(packet.history) * 32 or
                    not ((packet.history[distance // 32] >> (distance % 32)) & 1)):
                continue
            restart = original.pc_restart
            if (restart is not None and original.pc_restart_ticket is original.ticket and
                    restart.actor_guid == original.pc_restart_actor_guid and
                    sent.sequence in restart.sent_packets and restart.bunch in sent.bunches):
                # Keep this exact Restart receipt outside the bounded initial
                # Actor ledger; never evict PC/Pawn prerequisites to retain it.
                state.pc_restart_receipt = _ActualActorReceipt(restart.actor_guid,
                    restart.bunch, sent.sequence, original.ticket, transport, generation)
            for actor_guid, bunch in current:
                if bunch not in sent.bunches:
                    continue
                record = _ActualActorReceipt(actor_guid, bunch, sent.sequence,
                    original.ticket, transport, generation)
                if not any(r.actor_guid == actor_guid and r.bunch == bunch and
                        r.ticket is original.ticket and r.transport is transport and
                        r.generation is generation for r in retained):
                    retained.append(record)
        state.actual_actor_receipts = tuple(retained[-(MAX_INITIAL_ACTOR_CHANNELS+MAX_POST_OPEN_WIRE_BUNCHES):])

    @staticmethod
    def _actor_own_full_send_positive_receipt(state, item, *, ticket, transport, generation):
        if item is not None and item.fragments:
            return all(LegacyDSControlConnection._actor_own_full_send_positive_receipt(state, piece,
                ticket=ticket, transport=transport, generation=generation) for piece in item.fragments)
        return bool(item is not None and any(r.actor_guid == item.actor_guid and r.bunch == item.bunch and
            r.ticket is ticket and r.transport is transport and r.generation is generation
            for r in state.actual_actor_receipts))

    def _fashion_before_socket(self, peer, payload):
        state = self.control_peers.get(peer)
        outbox = state.fashion_subobject_outbox if state is not None else None
        if outbox is None or state.fashion_async_binding is not None:
            return False
        proposal = outbox.prepared_for_payload(payload)
        try:
            return proposal is not None and outbox.validate_before_socket(proposal)
        except (ValueError, OSError, KeyError):
            outbox.cancel()
            return False

    @staticmethod
    def _actual_successful_receipt_matches(original, packet, transport, generation):
        return any(item.ticket is original.ticket and item.transport is transport and
            item.generation is generation and distance < len(packet.history) * 32 and
            bool((packet.history[distance // 32] >> (distance % 32)) & 1)
            for item in original.actual_application_sends
            for distance in ((packet.acknowledged_sequence - item.sequence) & MASK,))

    def _qualified_receipt_forward_gap(self, peer, original, transport, packet, delta, generation):
        """Bounded local receipt-only policy; native receiver validation is pending."""
        if (not self.qualified_receipt_forward_gaps or
                not 32 < delta < KNOWN_RECEIPT_SEQUENCE_HALF_RANGE or
                any(bunch.close for bunch in packet.bunches)):
            return False
        from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
        if (type(generation) is not PendingChallenge or generation.echoed is not True or
                generation.verified_at is None or
                not self._current_joined_receipt_owner(peer, original, transport) or
                not self._actual_successful_receipt_matches(original, packet, transport, generation)):
            return False
        try:
            return self._early_player_state_human_appearance_current(original, peer) is True
        except (ValueError, OSError, KeyError):
            return False

    def handle(self, datagram, peer, now=None, *, verified_generation=None):
        # Clear even before validation: an invalid/replayed call at the same
        # timestamp must never reuse a prior call's liveness evidence.
        self._qualified_known_delivery_receipt = None
        now = self._now(now)
        transport, original = self.peers.get(peer), self.control_peers.get(peer)
        if transport is None or original is None:
            return self._result('application_without_verified_echo')
        receipt_ticket = original.ticket
        if not isinstance(datagram, bytes) or not 18 <= len(datagram) <= 1500:
            return self._result('application_shape_rejected')
        try:
            packet = decode_observed_application(datagram[8:],
                max_packet_bytes=self.max_packet_bytes, received_by_server=True)
        except ValueError:
            return self._result('application_header_rejected')
        delta = (packet.sequence - transport.in_sequence) & MASK
        ack_delta = (packet.acknowledged_sequence - transport.acknowledged_out_sequence) & MASK
        sent_delta = (transport.out_sequence - transport.acknowledged_out_sequence) & MASK
        if ack_delta >= sent_delta:
            return self._result('application_sequence_rejected')
        receipt_only_forward_gap = False
        if not 1 <= delta <= 32:
            receipt_only_forward_gap = self._qualified_receipt_forward_gap(
                peer, original, transport, packet, delta, verified_generation)
            if not receipt_only_forward_gap:
                return self._result('application_sequence_rejected')
        gap_actual_send_ring = original.actual_application_sends if receipt_only_forward_gap else None
        if receipt_only_forward_gap:
            # A known successful receipt does not qualify unrelated prepared,
            # failed or unsent outboxes. Each delivery needs its own positive
            # bit for an actual full send with these exact current owners.
            actual_positive_sequences = frozenset(item.sequence
                for item in gap_actual_send_ring
                if item.ticket is original.ticket and item.transport is transport and
                   item.generation is verified_generation
                for distance in ((packet.acknowledged_sequence - item.sequence) & MASK,)
                if distance < len(packet.history) * 32 and
                   bool((packet.history[distance // 32] >> (distance % 32)) & 1))
            delivery_matches = lambda item, packet: any(
                sequence in actual_positive_sequences for sequence in item.sent_packets)
        else:
            delivery_matches = self._delivered
        legacy_delivery_matches = delivery_matches
        delivery_matches = lambda item, current_packet: self._stage_delivery_matches(
            original, item, current_packet, transport, verified_generation, legacy_delivery_matches)
        closing = any(bunch.close for bunch in packet.bunches)
        if original.client_closed and not closing:
            return self._result('application_after_client_close')
        state = self._clone(original)
        if not closing and self._current_joined_receipt_owner(peer, original, transport):
            self._record_actual_actor_receipts(original, state, packet, transport, verified_generation)
            if state.fashion_subobject_outbox is not None and state.fashion_async_binding is None:
                try:
                    state.fashion_subobject_outbox.acknowledge(packet,
                        receipt_only_forward_gap=receipt_only_forward_gap)
                except (ValueError, OSError, KeyError):
                    state.fashion_subobject_outbox.cancel()
        early_receipts_allowed = True
        if state.early_player_state_human_appearance is not None:
            try:
                self._early_player_state_human_appearance_current(state, peer)
            except (ValueError, OSError, KeyError):
                early_receipts_allowed = False
        if not original.client_closed and state.pending and delivery_matches(state.pending, packet):
            state.pending = None
        for item in (*state.actor_opens.values(), *_content_wire_items(state)):
            if early_receipts_allowed and not original.client_closed and not item.delivered and delivery_matches(item, packet):
                item.delivered = True
        for item in _content_items(state):
            _refresh_fragment_delivery(item)
        if (state.pc_ready_ack is not None and not original.client_closed and
                not state.pc_ready_ack.delivered and delivery_matches(state.pc_ready_ack, packet)):
            state.pc_ready_ack.delivered = True
        if (state.game_state_start is not None and not original.client_closed and
                not state.game_state_start.delivered and delivery_matches(state.game_state_start, packet)):
            state.game_state_start.delivered = True
        if (state.game_state_all_ready is not None and not original.client_closed and
                not state.game_state_all_ready.delivered and delivery_matches(state.game_state_all_ready, packet)):
            state.game_state_all_ready.delivered = True
        if (state.game_state_abseil is not None and not original.client_closed and
                not state.game_state_abseil.delivered and delivery_matches(state.game_state_abseil, packet)):
            state.game_state_abseil.delivered = True
        if (state.game_state_real_start is not None and not original.client_closed and
                not state.game_state_real_start.delivered and delivery_matches(state.game_state_real_start, packet)):
            state.game_state_real_start.delivered = True
        if (state.game_state_match_info is not None and not original.client_closed and
                not state.game_state_match_info.delivered and delivery_matches(state.game_state_match_info, packet)):
            state.game_state_match_info.delivered = True
        if (state.pc_restart is not None and not original.client_closed and
                not state.pc_restart.delivered and delivery_matches(state.pc_restart, packet)):
            state.pc_restart.delivered = True
        if (state.pc_rotation is not None and not original.client_closed and
                not state.pc_rotation.delivered and delivery_matches(state.pc_rotation, packet)):
            state.pc_rotation.delivered = True
        if (state.pc_hud is not None and not original.client_closed and
                not state.pc_hud.delivered and delivery_matches(state.pc_hud, packet)):
            state.pc_hud.delivered = True
        if (state.pc_view_target is not None and not original.client_closed and
                not state.pc_view_target.delivered and delivery_matches(state.pc_view_target, packet)):
            state.pc_view_target.delivered = True
        self._acknowledge_inventory_refresh(original, state, packet, peer, transport, verified_generation)
        self._acknowledge_world_deliveries(original, state, packet, peer, verified_generation)
        from dfserver.transport.native.legacy_ds_owner_switch import acknowledge as acknowledge_owner_switch
        acknowledge_owner_switch(self, original, state, packet, peer, transport, verified_generation)
        accepted, response_needed = not packet.bunches, False
        item = state.late_player_state_human_appearance
        if item is not None and not original.client_closed and not item.delivered and delivery_matches(item, packet):
            try:
                if self._late_player_state_human_appearance_ready(state, peer):
                    item.delivered = True
            except (ValueError, OSError, KeyError):
                pass
        # Header receipts refer to our recorded outbound packet sequences. They
        # are independent of accepting this packet's body. Keep a checkpoint
        # before any dispatcher can mutate reliable-channel/application state.
        receipt_checkpoint = (self._clone(state) if not closing and
            self._current_joined_receipt_owner(peer, original, transport) else None)
        known_delivery_receipt = (receipt_checkpoint is not None and
            early_receipts_allowed and verified_generation is not None and
            self._actual_successful_receipt_matches(original, packet, transport, verified_generation))
        if receipt_only_forward_gap:
            # Only header delivery knowledge advances here. Never dispatch the
            # gap packet's Control/RPC body or consume reliable-channel state.
            if (not known_delivery_receipt or
                    original.actual_application_sends is not gap_actual_send_ring or
                    not self._current_joined_receipt_owner(peer, original, transport)):
                return self._result('application_sequence_rejected')
            try:
                current_sources = self._early_player_state_human_appearance_current(receipt_checkpoint, peer)
            except (ValueError, OSError, KeyError):
                return self._result('application_sequence_rejected')
            if current_sources is not True:
                return self._result('application_sequence_rejected')
            if (original.actual_application_sends is not gap_actual_send_ring or
                    not self._current_joined_receipt_owner(peer, original, transport)):
                return self._result('application_sequence_rejected')
            bridge = getattr(self, '_fashion_async_bridge', None)
            if bridge is not None:
                # Observe this qualified header before committing its cursors;
                # its unknown body remains undispatched and unacknowledged.
                bridge.observe_header_locked(self, peer, packet, verified_generation)
            receipt_checkpoint.last_received_at = now
            transport.in_sequence = packet.sequence
            transport.acknowledged_out_sequence = packet.acknowledged_sequence
            transport.history = 0  # The unknown gap body and missing packets stay unacknowledged.
            self.control_peers[peer] = receipt_checkpoint
            self._qualified_known_delivery_receipt = _QualifiedKnownDeliveryReceipt(
                peer, receipt_ticket, transport, verified_generation, packet.sequence, now)
            return self._result('qualified_receipt_forward_gap_consumed')
        actor_replies = ()
        ping_packet = False
        startup_packet = False
        startup_whole = False
        admitted_packet = False
        event = 'control_ack_only_consumed'
        if packet.bunches:
            accepted = False
            event = 'control_payload_rejected'
            rejection_event = 'control_login_or_order_rejected'
            try:
                if closing:
                    # Keep this observed empty-close branch separate from the
                    # message dispatcher. Mixed closes/data are not admitted.
                    if (len(packet.bunches) != 1 or
                            not self._empty_control_close(packet.bunches[0]) or
                            state.ticket is None or not state.client_join_observed):
                        raise ValueError('Unsupported native Control close')
                    bunch = packet.bunches[0]
                    if state.client_closed:
                        if (bunch.channel_sequence != state.client_close_sequence or
                                bunch.close_reason != state.client_close_reason):
                            raise ValueError('Conflicting native Control close retry')
                        event = 'control_client_close_retry_consumed'
                    else:
                        if bunch.channel_sequence != state.expected_client_sequence:
                            raise ValueError('Unexpected reliable Control close sequence')
                        state.client_closed = True
                        state.client_close_sequence = bunch.channel_sequence
                        state.client_close_reason = bunch.close_reason
                        state.expected_client_sequence = (state.expected_client_sequence + 1) & 1023
                        state.pending = None
                        state.actor_exports.clear()
                        event = 'control_client_close_consumed'
                if not closing and state.admitted_actor_reliable_receipts:
                    admitted_packet = True
                    rejection_event = 'admitted_actor_reliable_packet_rejected'
                    state, actor_replies, event = self._consume_admitted_actor_packet(
                        state, original, packet, peer, now, transport, verified_generation)
                elif (not closing and state.pc_startup_profile is not None and
                        any(bunch.channel_index != 0 for bunch in packet.bunches)):
                    rejection_event = 'application_channel_payload_unsupported'
                    state, actor_replies, event, startup_whole = self._consume_pc_startup_packet(state, packet, peer, now)
                    startup_packet = True
                elif (not closing and state.pc_ping_profile is not None and
                        any(bunch.channel_index != 0 for bunch in packet.bunches)):
                    rejection_event = 'application_channel_payload_unsupported'
                    actor_replies, event = self._consume_pc_ping(state, packet, peer, now)
                    ping_packet = True
                for bunch in (() if closing or ping_packet or startup_packet or admitted_packet else packet.bunches):
                    if not self._plain_control(bunch):
                        # An Actor RPC is not a failed Login. Keep unsupported
                        # application channels unacknowledged, but identify the
                        # missing receiver accurately in the diagnostic ledger.
                        if bunch.channel_index != 0:
                            rejection_event = 'application_channel_payload_unsupported'
                        raise ValueError('Unsupported native channel or partial control')
                    digest = hashlib.sha256(bunch.payload).digest()
                    # The expected sequence is new even after a full wrap;
                    # stale payload digests must never suppress advancement.
                    if bunch.channel_sequence == state.expected_client_sequence:
                        if state.hello_received and not original.hello_received:
                            raise ValueError('Login cannot precede the sent Challenge')
                        if state.ticket is not None and original.ticket is None:
                            raise ValueError('Netspeed or Join cannot precede the sent Welcome')
                        event = self._consume_new(state, bunch, peer)
                        if state.client_join_observed and not original.client_join_observed:
                            state.joined_at = now
                        state.consumed.pop(bunch.channel_sequence, None)
                        state.consumed[bunch.channel_sequence] = digest
                        while len(state.consumed) > RELIABLE_RETRY_WINDOW:
                            state.consumed.pop(next(iter(state.consumed)))
                        state.expected_client_sequence = (state.expected_client_sequence + 1) & 1023
                    elif state.consumed.get(bunch.channel_sequence) == digest:
                        event = 'control_reliable_retry_consumed'
                    else:
                        raise ValueError('Unexpected reliable control sequence')
            except ValueError as error:
                state = self._clone(receipt_checkpoint if receipt_checkpoint is not None else original)
                actor_replies, ping_packet = (), False
                startup_packet, startup_whole = False, False
                event = 'control_close_rejected' if closing else rejection_event
                if admitted_packet and receipt_checkpoint is not None:
                    reason = (error.reason_code if type(error) is _AdmittedActorReceiptRejection
                              else 'validation_rejected')
                    counts = receipt_checkpoint.admitted_actor_rejection_counts
                    counts[reason] = min(counts.get(reason, 0) + 1, 0x7fffffff)
                    receipt_checkpoint.admitted_actor_last_rejection = (packet.sequence, now, reason)
                if not closing and not admitted_packet and state.pc_ping_profile is not None:
                    # A recognized unreliable Ping can receive a response while
                    # this packet's delivery-history bit stays zero. No reliable
                    # Control/RPC sequence or unknown bunch is consumed here.
                    from dfserver.transport.native.legacy_ds_pc_ping_receiver import select_pc_ping_bunches
                    try:
                        pings = select_pc_ping_bunches(packet.bunches,
                            channel_index=state.pc_ping_channel, profile=state.pc_ping_profile)
                        if pings:
                            actor_replies, _ = self._consume_pc_ping(
                                state, replace(packet, bunches=pings), peer, now)
                            ping_packet, response_needed = True, bool(actor_replies)
                            event = ('pc_ping_reply_for_unacknowledged_mixed_packet' if actor_replies
                                     else 'pc_ping_mixed_packet_consumed_without_reply')
                    except ValueError:
                        state = self._clone(receipt_checkpoint if receipt_checkpoint is not None else original)
                        actor_replies, ping_packet, response_needed = (), False, False
            else:
                if startup_packet:
                    accepted = startup_whole
                    response_needed = startup_whole or bool(actor_replies)
                else:
                    accepted, response_needed = True, bool(actor_replies) if ping_packet else True
        if (startup_packet and response_needed and
                state.pc_startup_receipt_reply_count >= MAX_PC_STARTUP_RECEIPT_REPLIES):
            return self._result('pc_startup_reply_limit_reached')
        if accepted and response_needed and not (ping_packet or startup_packet or admitted_packet) and transport.replies >= self.max_replies:
            if state.client_closed:
                # A spent outbound budget cannot keep an already closed peer
                # alive. Commit shutdown without manufacturing an extra reply.
                response_needed = False
            else:
                return self._result('application_reply_limit_reached')
        if accepted and state.client_join_observed and not original.client_join_observed:
            try:
                self.admissions.begin_joined_session(state.ticket)
            except ValueError:
                return self._result('control_join_admission_expired')
        history = ((transport.history << delta) | int(accepted)) & 0xffffffff
        response = None
        if response_needed and (accepted or ping_packet or startup_packet):
            # Construct the complete reply before committing channel/admission
            # state. Reliable retries retain their original channel sequence.
            response = self._encode_reply(transport, state, packet.sequence, history, now,
                include_pending=not (ping_packet or startup_packet or admitted_packet), actor_replies=actor_replies,
                count_as_control=not (ping_packet or startup_packet or admitted_packet))
            if startup_packet:
                state.pc_startup_receipt_reply_count += 1
        bridge = getattr(self, '_fashion_async_bridge', None)
        if bridge is not None and not closing:
            # The accepted header will now commit. Record the immutable own ACK
            # candidate before global cursors advance; never replay this packet.
            bridge.observe_header_locked(self, peer, packet, verified_generation)
        transport.in_sequence = packet.sequence
        transport.acknowledged_out_sequence = packet.acknowledged_sequence
        transport.history = history
        if accepted or ping_packet or startup_packet:
            if state.ticket:
                if state.client_closed:
                    if self.ticket_peers.get(state.ticket.cookie) == peer:
                        del self.ticket_peers[state.ticket.cookie]
                        self.admissions.end_joined_session(state.ticket)
                else:
                    self.ticket_peers[state.ticket.cookie] = peer
            if state.client_join_observed and not original.client_join_observed:
                self.joined_count += 1
            self.control_peers[peer] = state
            state.last_received_at = now
        elif (receipt_checkpoint is not None and
                self._current_joined_receipt_owner(peer, original, transport)):
            # The unsupported body still has a zero receive-history bit and no
            # reply. Commit only the pre-dispatch outbound-delivery checkpoint.
            receipt_checkpoint.last_received_at = now
            self.control_peers[peer] = receipt_checkpoint
        elif (original.ticket is not None and not original.client_closed and
                self.ticket_peers.get(original.ticket.cookie) == peer and
                self.admissions.is_active(original.ticket)):
            # The authenticated header/sequence was received even when its RPC
            # body is unsupported. This server-owned clock update is neither a
            # positive packet ACK nor an application/ready-state mutation.
            original.last_received_at = now
        current = self.control_peers.get(peer)
        if (known_delivery_receipt and current is not None and
                current.ticket is receipt_ticket and
                self._current_joined_receipt_owner(peer, current, transport)):
            try:
                current_sources = self._early_player_state_human_appearance_current(current, peer)
            except (ValueError, OSError, KeyError):
                pass
            else:
                if current_sources:
                    self._qualified_known_delivery_receipt = _QualifiedKnownDeliveryReceipt(
                        peer, current.ticket, transport, verified_generation, packet.sequence, now)
        # Empty ACK-only packets do not trigger another empty ACK. An outbox
        # timer handles lost reliable controls instead of ACK ping-pong.
        return self._result(event, response)

    def poll(self, now=None):
        now = self._now(now)
        responses = []
        for peer, original in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or original.client_closed or original.pending is None
                    or transport.replies >= self.max_replies):
                continue
            pending = original.pending
            if (pending.transmissions >= self.max_transmissions or
                    now - pending.last_sent_at < self.retry_interval):
                continue
            state = self._clone(original)
            body = self._encode_reply(transport, state,
                transport.in_sequence, transport.history, now)
            self.control_peers[peer] = state
            self.control_events['control_timer_retransmit_prepared'] += 1
            responses.append((peer, 'control_timer_retransmit_prepared', body))
        # Actor channels have independent reliable sequences but share the
        # packet sequence/reply budget with channel0. First sends are immediate;
        # retries preserve every bunch bit and never refresh peer activity.
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed):
                continue
            try:
                self._early_player_state_human_appearance_current(state, peer)
            except (ValueError, OSError, KeyError):
                continue
            for item in state.actor_opens.values():
                if self._stage_budget_exhausted(state, transport):
                    break
                if not self._stage_can_prepare(peer, state, transport, item, now):
                    continue
                body = encode_observed_application(WirePacket(
                    transport.out_sequence, transport.in_sequence, (transport.history,),
                    False, 0, None, (item.bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                event = ('actor_open_send_prepared' if not item.transmissions else
                         'actor_open_timer_retransmit_prepared')
                self._stage_note_prepared(peer, state, transport, item, now)
                self.control_events[event] += 1
                responses.append((peer, event, body))
        # This optional phase starts only after exact delivery ACKs for the
        # complete initial Actor set. Followups reuse each channel with its next
        # reliable sequence; retries preserve the identical content bunch.
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed or not state.actor_opens or
                    not all(item.delivered for item in state.actor_opens.values()) or
                    not _content_policies_current(state.actor_contents) or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    not self.admissions.is_active(state.ticket)):
                continue
            try:
                self._early_player_state_human_appearance_current(state, peer)
            except (ValueError, OSError, KeyError):
                continue
            for channel, ordinal, item in ((channel, ordinal, item)
                    for channel, head in state.actor_contents.items()
                    for ordinal, item in enumerate((head, *head.continuations))):
                if item.delivered:
                    continue
                if self._content_stage_waiting(peer, state, transport, channel, ordinal, item):
                    continue
                early = state.early_player_state_human_appearance
                if (early is not None and item.bunch.channel_index != early.channel and
                        not self._actual_actor_delivery(state.actor_contents[early.channel])):
                    continue
                if self._stage_budget_exhausted(state, transport):
                    break
                for piece_index, piece in enumerate(_wire_items(item)):
                    # Export grammar is never fragmented. The subsequent normal
                    # body can be sent only after its separate export receipt.
                    if (item.fragments and piece_index and item.fragments[0].bunch.package_exports and
                            not self._content_stage_receipted(peer, state, transport, item.fragments[0])):
                        break
                    if not self._stage_can_prepare(peer, state, transport, piece, now):
                        continue
                    body = encode_observed_application(WirePacket(
                        transport.out_sequence, transport.in_sequence, (transport.history,),
                        False, 0, None, (piece.bunch,), 0),
                        max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                    event = ('actor_content_send_prepared' if not piece.transmissions else
                             'actor_content_timer_retransmit_prepared')
                    if early is not None and item.bunch.channel_index == early.channel:
                        event = ('actor_content_early_player_state_human_appearance_send_prepared' if not piece.transmissions
                                 else 'actor_content_early_player_state_human_appearance_timer_retransmit_prepared')
                    self._stage_note_prepared(peer, state, transport, piece, now)
                    self.control_events[event] += 1
                    responses.append((peer, event, body))
                _refresh_fragment_delivery(item)
        # The zero-parameter ready acknowledgement uses the PC Actor channel's
        # next reliable sequence. It has its own exact delivery history and is
        # never replaced with a control message or a forced client state flag.
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            item = state.pc_ready_ack
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed or item is None or item.delivered or
                    any(content.fragments and not self._actual_actor_delivery(content)
                        for content in _content_items(state)
                        if content.bunch.channel_index == item.bunch.channel_index) or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    not self.admissions.is_active(state.ticket) or
                    not self._stage_can_prepare(peer, state, transport, item, now)):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'pc_ready_ack_send_prepared' if not item.transmissions else 'pc_ready_ack_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        # MatchInfo identity must reach the same GameState before StartPlay. The
        # values come from this admitted room; no official identity is replayed.
        from dfserver.replication.legacy_ds_game_state_start import build_game_state_match_info
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed or state.game_state_start_profile is None or
                    state.game_state_start_profile.map_id_handle is None or
                    state.pc_ready_ack is None or not state.pc_ready_ack.delivered or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    not self.admissions.is_active(state.ticket) or
                    not all(item.delivered for item in state.actor_opens.values()) or
                    not all(item.delivered for item in _content_items(state)) or
                    self._stage_budget_exhausted(state, transport)):
                continue
            opened = state.actor_opens.get(state.game_state_start_channel)
            if opened is None or opened.actor_guid != state.game_state_start_actor_guid:
                continue
            item = state.game_state_match_info
            if item is None:
                previous = _last_actor_content(state, state.game_state_start_channel, opened)
                item = ActorOpenDelivery(build_game_state_match_info(
                    channel_index=state.game_state_start_channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.game_state_start_profile, map_id=state.ticket.map_id,
                    room_id=state.ticket.room_id), state.game_state_start_actor_guid)
                state.game_state_match_info = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'game_state_match_info_send_prepared' if not item.transmissions else 'game_state_match_info_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        # Server-owned local StartPlay transition, after the same ticket's Ready
        # acknowledgement delivery. This sends one evidenced GameState scalar;
        # all-player readiness, scene/physics completion and possession remain
        # separate unsupported transitions, never inferred from transport ACK.
        from dfserver.replication.legacy_ds_game_state_start import build_game_state_start
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed or state.game_state_start_profile is None or
                    not state.pc_ready_notification_received or state.pc_ready_ack is None or
                    not state.pc_ready_ack.delivered or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    not self.admissions.is_active(state.ticket) or
                    not all(item.delivered for item in state.actor_opens.values()) or
                    not all(item.delivered for item in _content_items(state)) or
                    state.game_state_start_profile.map_id_handle is not None and (
                        state.game_state_match_info is None or not state.game_state_match_info.delivered) or
                    self._stage_budget_exhausted(state, transport)):
                continue
            channel = state.game_state_start_channel
            opened = state.actor_opens.get(channel)
            if opened is None or opened.actor_guid != state.game_state_start_actor_guid:
                continue
            item = state.game_state_start
            if item is None:
                previous = state.game_state_match_info or _last_actor_content(state, channel, opened)
                if (not previous.bunch.reliable or type(previous.bunch.channel_sequence) is not int or
                        not 0 <= previous.bunch.channel_sequence < 1024):
                    continue
                bunch = build_game_state_start(channel_index=channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.game_state_start_profile)
                item = ActorOpenDelivery(bunch, state.game_state_start_actor_guid)
                state.game_state_start = item
                state.local_start_play_requested = True
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'game_state_start_send_prepared' if not item.transmissions else 'game_state_start_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        from dfserver.replication.legacy_ds_game_state_start import build_game_state_all_ready
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    state.game_state_start_profile is None or
                    state.game_state_start_profile.all_ready_handle is None or
                    state.game_state_start is None or not state.game_state_start.delivered or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    self._stage_budget_exhausted(state, transport)):
                continue
            roster = self.admissions.active_room_tickets(state.ticket)
            if not roster:
                continue
            ready = True
            for ticket in roster:
                member_peer = self.ticket_peers.get(ticket.cookie)
                member = self.control_peers.get(member_peer)
                if (member is None or member.ticket is not ticket or member.client_closed or
                        not member.client_join_observed or not member.pc_ready_notification_received or
                        member.pc_ready_ack is None or not member.pc_ready_ack.delivered or
                        member.game_state_start is None or not member.game_state_start.delivered):
                    ready = False
                    break
            if not ready:
                continue
            item = state.game_state_all_ready
            if item is None:
                previous = state.game_state_start
                item = ActorOpenDelivery(build_game_state_all_ready(
                    channel_index=state.game_state_start_channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.game_state_start_profile), state.game_state_start_actor_guid)
                state.game_state_all_ready = item
                state.local_all_player_ready_requested = True
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'game_state_all_ready_send_prepared' if not item.transmissions else 'game_state_all_ready_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        from dfserver.replication.legacy_ds_game_state_start import build_game_state_abseil
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    not state.client_join_observed or state.game_state_start_profile is None or
                    state.game_state_start_profile.abseil_handle is None or
                    state.game_state_all_ready is None or not state.game_state_all_ready.delivered or
                    self.ticket_peers.get(state.ticket.cookie) != peer or
                    self._stage_budget_exhausted(state, transport)):
                continue
            roster = self.admissions.active_room_tickets(state.ticket)
            if not roster or any(
                    (member := self.control_peers.get(self.ticket_peers.get(ticket.cookie))) is None or
                    member.ticket is not ticket or member.client_closed or not member.client_join_observed or
                    member.game_state_all_ready is None or not member.game_state_all_ready.delivered
                    for ticket in roster):
                continue
            item = state.game_state_abseil
            if item is None:
                previous = state.game_state_all_ready
                item = ActorOpenDelivery(build_game_state_abseil(
                    channel_index=state.game_state_start_channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.game_state_start_profile), state.game_state_start_actor_guid)
                state.game_state_abseil = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'game_state_abseil_send_prepared' if not item.transmissions else 'game_state_abseil_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        # The owner supplies the separate post-travel request. Delivery flags
        # alone never request a restart; every ticket/channel/phase is rechecked
        # on each first send and retry, preserving one reliable bunch sequence.
        from dfserver.transport.native.legacy_ds_pc_restart_rpc import build_pc_restart
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if transport is None or not state.pc_restart_requested:
                continue
            try:
                if self._pc_restart_waiting(state, peer):
                    continue
            except ValueError:
                continue
            item = state.pc_restart
            if item is None:
                previous = state.pc_ready_ack
                if (previous is None or not previous.bunch.reliable or
                        type(previous.bunch.channel_sequence) is not int):
                    continue
                bunch = build_pc_restart(channel_index=state.pc_restart_channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.pc_restart_profile, pawn_guid=state.pc_restart_pawn_guid,
                    reference_resolved=True, exports_acknowledged=True)
                # Reserve the whole packet before committing the outbox.
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item = ActorOpenDelivery(bunch, state.pc_restart_actor_guid)
                state.pc_restart = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'pc_restart_send_prepared' if not item.transmissions else 'pc_restart_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        # Source-qualified VerifyViewTarget requests may arrive before travel
        # finishes. Keep them pending until the owner's separate restart gate
        # has completed through its actual transport ACK.
        from dfserver.transport.native.legacy_ds_pc_rotation_rpc import build_pc_rotation
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if transport is None or state.pc_rotation_profile is None:
                continue
            try:
                self._pc_rotation_binding(state, peer)
                if (not state.pc_restart_requested or not state.pc_possession_ack_received or
                        self._pc_restart_waiting(state, peer) or not self._actual_actor_delivery(state.pc_restart)):
                    continue
            except ValueError:
                continue
            item = state.pc_rotation
            if item is None:
                bunch = build_pc_rotation(channel_index=state.pc_restart_channel,
                    channel_sequence=(state.pc_restart.bunch.channel_sequence+1)&1023,
                    profile=state.pc_rotation_profile, rotation=state.pc_rotation_value, reset_camera=True)
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item = ActorOpenDelivery(bunch, state.pc_restart_actor_guid)
                state.pc_rotation = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = ('pc_rotation_send_prepared' if not item.transmissions else
                     'pc_rotation_timer_retransmit_prepared')
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        from dfserver.transport.native.legacy_ds_pc_hud_rpc import build_pc_hud
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if transport is None or state.pc_hud_profile is None:
                continue
            try:
                self._pc_hud_binding(state, peer)
                if (not state.pc_restart_requested or not state.pc_possession_ack_received or
                        self._pc_restart_waiting(state, peer) or not self._actual_actor_delivery(state.pc_restart) or
                        (state.pc_rotation_profile is not None and not self._actual_actor_delivery(state.pc_rotation))):
                    continue
            except ValueError:
                continue
            item = state.pc_hud
            if item is None:
                previous = state.pc_rotation or state.pc_restart
                bunch = build_pc_hud(channel_index=state.pc_restart_channel,
                    channel_sequence=(previous.bunch.channel_sequence+1)&1023,
                    profile=state.pc_hud_profile, class_guid=state.pc_hud_class_guid,
                    reference_resolved=True, exports_acknowledged=True)
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item = ActorOpenDelivery(bunch, state.pc_restart_actor_guid)
                state.pc_hud = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'pc_hud_send_prepared' if not item.transmissions else 'pc_hud_timer_retransmit_prepared'
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        from dfserver.transport.native.legacy_ds_pc_view_target_rpc import build_pc_view_target
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if transport is None or not state.pc_view_target_requested:
                continue
            try:
                self._pc_view_target_binding(state, peer)
                if (not state.pc_restart_requested or self._pc_restart_waiting(state, peer) or
                        not self._actual_actor_delivery(state.pc_restart) or
                        (state.pc_rotation_profile is not None and not self._actual_actor_delivery(state.pc_rotation)) or
                        (state.pc_hud_profile is not None and not self._actual_actor_delivery(state.pc_hud))):
                    continue
            except ValueError:
                continue
            item = state.pc_view_target
            if item is None:
                bunch = build_pc_view_target(channel_index=state.pc_restart_channel,
                    channel_sequence=((state.pc_hud or state.pc_rotation or state.pc_restart).bunch.channel_sequence + 1) & 1023,
                    profile=state.pc_view_target_profile, actor_guid=state.pc_restart_pawn_guid,
                    reference_resolved=True, exports_acknowledged=True)
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item = ActorOpenDelivery(bunch, state.pc_restart_actor_guid)
                state.pc_view_target = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = ('pc_view_target_send_prepared' if not item.transmissions else
                     'pc_view_target_timer_retransmit_prepared')
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        # This local room transition requires each actual participant's native
        # possession acknowledgement as well as the reliable entry deliveries.
        from dfserver.replication.legacy_ds_game_state_start import build_game_state_real_start
        for peer, state in list(self.control_peers.items()):
            transport = self.peers.get(peer)
            if (transport is None or state.client_closed or state.ticket is None or
                    state.game_state_start_profile is None or
                    state.game_state_start_profile.real_start_handle is None or
                    self._stage_budget_exhausted(state, transport)):
                continue
            try:
                if not self._room_real_start_ready(state, peer):
                    continue
            except ValueError:
                continue
            item = state.game_state_real_start
            if item is None:
                previous = state.game_state_abseil
                bunch = build_game_state_real_start(channel_index=state.game_state_start_channel,
                    channel_sequence=(previous.bunch.channel_sequence + 1) & 1023,
                    profile=state.game_state_start_profile)
                encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                item = ActorOpenDelivery(bunch, state.game_state_start_actor_guid)
                state.game_state_real_start = item
            if not self._stage_can_prepare(peer, state, transport, item, now):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = ('game_state_real_start_send_prepared' if not item.transmissions else
                     'game_state_real_start_timer_retransmit_prepared')
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        for peer, state in list(self.control_peers.items()):
            transport, item = self.peers.get(peer), state.late_player_state_human_appearance
            if (transport is None or item is None or item.delivered or transport.replies >= self.max_replies or
                    item.transmissions >= self.max_transmissions or
                    item.transmissions and now - item.last_sent_at < self.retry_interval):
                continue
            try:
                if not self._late_player_state_human_appearance_ready(state, peer):
                    continue
            except (ValueError, OSError, KeyError):
                continue
            body = encode_observed_application(WirePacket(transport.out_sequence,
                transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            event = 'actor_content_player_state_human_appearance_diagnostic_' + (
                'send_prepared' if not item.transmissions else 'timer_retransmit_prepared')
            item.sent_packets = (*item.sent_packets, transport.out_sequence)[-64:]
            item.last_sent_at, item.transmissions = now, item.transmissions + 1
            transport.out_sequence = (transport.out_sequence + 1) & MASK
            transport.replies += 1
            self.control_events[event] += 1
            responses.append((peer, event, body))
        for peer, state in list(self.control_peers.items()):
            if state.inventory_refresh_ready is None or state.inventory_refresh_committed:
                continue
            transport = self.peers.get(peer)
            try:
                self._inventory_refresh_binding(state, peer)
                profile = state.inventory_refresh_profile
                if state.inventory_refresh is None:
                    state.inventory_refresh_previous_sequence = self._post_admission_previous_sequence(
                        state, profile.pawn_channel, profile.pawn_guid)
                update, bunch = self._inventory_refresh_expected_bunch(state)
                if state.inventory_refresh is None:
                    self._post_admission_reserve(state, bunch, profile.pawn_guid)
                    state.inventory_refresh = ActorOpenDelivery(bunch, profile.pawn_guid)
                    state.inventory_refresh_update = update
                elif state.inventory_refresh_update != update:
                    raise ValueError('The pending inventory refresh changed before its ACK')
                item = state.inventory_refresh
                if not self._stage_can_prepare(peer, state, transport, item, now):
                    continue
                body = encode_observed_application(WirePacket(transport.out_sequence,
                    transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            except (ValueError, OSError, KeyError):
                continue
            event = ('actor_content_inventory_ready_refresh_send_prepared' if not item.transmissions else
                'actor_content_inventory_ready_refresh_timer_retransmit_prepared')
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        for peer, state in list(self.control_peers.items()):
            item, transport = state.inventory_runtime_delivery, self.peers.get(peer)
            if item is None or item.delivered:
                continue
            try:
                self._inventory_refresh_binding(state, peer)
                if not self._stage_can_prepare(peer, state, transport, item, now):
                    continue
                body = encode_observed_application(WirePacket(transport.out_sequence,
                    transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
            except (ValueError, OSError, KeyError):
                continue
            event = ('actor_content_inventory_delta_send_prepared' if not item.transmissions else
                'actor_content_inventory_delta_timer_retransmit_prepared')
            self._stage_note_prepared(peer, state, transport, item, now)
            self.control_events[event] += 1
            responses.append((peer, event, body))
        from dfserver.transport.native.legacy_ds_owner_switch import poll as poll_owner_switch
        for peer, state in list(self.control_peers.items()):
            responses.extend(poll_owner_switch(self, peer, state, now))
        for peer, state in list(self.control_peers.items()):
            if state.world_delivery_profile is None:
                continue
            transport = self.peers.get(peer)
            deliveries = []
            for path in tuple(state.world_box_batches):
                try:
                    _, _, batch = self._world_box_batch_current(state, peer, path)
                except (ValueError, OSError, KeyError):
                    continue
                pending = next((item for item, receipt in zip(batch.deliveries, batch.receipts) if receipt is None), None)
                if pending is not None:
                    deliveries.append(('actor_content_world_box_', pending))
            if state.world_result_delivery is not None and state.world_result_receipt is None:
                try:
                    self._world_box_batch_current(state, peer, state.world_result_command.source_path)
                    if state.world_result_delivery.bunch != self._world_result_bunch(state):
                        raise ValueError('The pending native move result changed')
                    deliveries.append(('actor_content_world_move_result_', state.world_result_delivery))
                except (ValueError, OSError, KeyError):
                    pass
            for prefix, item in deliveries:
                if not self._stage_can_prepare(peer, state, transport, item, now):
                    continue
                body = encode_observed_application(WirePacket(transport.out_sequence,
                    transport.in_sequence, (transport.history,), False, 0, None, (item.bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                event = prefix+('send_prepared' if not item.transmissions else 'timer_retransmit_prepared')
                self._stage_note_prepared(peer, state, transport, item, now)
                self.control_events[event] += 1
                responses.append((peer, event, body))
        for peer, original in list(self.control_peers.items()):
            if original.fashion_subobject_outbox is None or original.fashion_async_binding is not None:
                continue
            state = self._clone(original)
            try:
                proposal = state.fashion_subobject_outbox.prepare(now=now)
            except (ValueError, OSError, KeyError):
                state.fashion_subobject_outbox.cancel()
                self.control_peers[peer] = state
                continue
            if proposal is None:
                continue
            transport = self.peers.get(peer)
            # The outbox builds against the stable shared owner transport. Only
            # this coordinator reserves its packet cursor after full preflight.
            transport.out_sequence = (transport.out_sequence + 1) & MASK
            transport.replies += 1
            self.control_peers[peer] = state
            event = 'actor_content_fashion_subobject_send_prepared'
            self.control_events[event] += 1
            responses.append((peer, event, proposal.application_payload))
        if self.transport_keepalive:
            for peer, original in list(self.control_peers.items()):
                transport = self.peers.get(peer)
                if (transport is None or not self._current_joined_receipt_owner(peer, original, transport) or
                        original.joined_at is None or original.keepalive_prepared_count >= MAX_TRANSPORT_KEEPALIVES):
                    continue
                gate = max(value for value in (original.joined_at, original.last_keepalive_prepared_at,
                    original.last_successful_application_send_at) if value is not None)
                if now - gate < 1.0:
                    continue
                state = self._clone(original)
                body = self._encode_reply(transport, state, transport.in_sequence, transport.history, now,
                    include_pending=False, actor_replies=(), count_as_control=False)
                state.last_keepalive_prepared_at = now
                state.keepalive_prepared_count += 1
                self.control_peers[peer] = state
                self.control_events['transport_keepalive_send_prepared'] += 1
                responses.append((peer, 'transport_keepalive_send_prepared', body))
        bridge = getattr(self, '_fashion_async_bridge', None)
        if bridge is not None:
            # Last: all normal producers/keepalive have reserved their cursors.
            # Fashion pending work reserves none, and does no callback/I/O here.
            responses.extend(bridge.poll_locked(self, now))
        return responses

    def summary(self):
        from dfserver.transport.native.legacy_ds_movement import MOVEMENT_REJECTION_CODES
        report = {
            'enabled': True, 'mode': 'local_ticket_login_welcome_and_map_join',
            'wire_codec_implemented': True,
            'supported_control_message_ids': [0, 1, 3, 4, 5, 9],
            'hello_consumed_peers': sum(p.hello_received for p in self.control_peers.values()),
            'login_authorized_peers': sum(p.ticket is not None for p in self.control_peers.values()),
            'pending_reliable_controls': sum(p.pending is not None for p in self.control_peers.values()),
            'client_load_map_join_observed_count': self.joined_count,
            'client_closed_peers': sum(p.client_closed for p in self.control_peers.values()),
            'events': dict(self.control_events),
            'local_match_admissions': self.admissions.summary(),
            'login_implemented': True, 'welcome_implemented': True,
            'unknown_nonempty_payload_ack_enabled': False,
            'pc_ping_receiver_connections': sum(p.pc_ping_profile is not None for p in self.control_peers.values()),
            'pc_ping_rpc_replies': sum(p.pc_ping_reply_count for p in self.control_peers.values()),
            'pc_ping_clock_policy': 'local_join_elapsed_world_time_and_last_authenticated_transport_receipt',
            'pc_startup_receiver_connections': sum(p.pc_startup_profile is not None for p in self.control_peers.values()),
            'pc_startup_requests_consumed': sum(p.pc_startup_request_count for p in self.control_peers.values()),
            'pc_ready_notifications_received': sum(p.pc_ready_notification_received for p in self.control_peers.values()),
            'pc_ready_ack_delivery_acks': sum(p.pc_ready_ack is not None and p.pc_ready_ack.delivered
                                            for p in self.control_peers.values()),
            'pc_ready_ack_transmissions': sum(p.pc_ready_ack.transmissions if p.pc_ready_ack else 0
                                            for p in self.control_peers.values()),
            'local_start_play_requested': sum(p.local_start_play_requested for p in self.control_peers.values()),
            'game_state_start_delivery_acks': sum(p.game_state_start is not None and p.game_state_start.delivered
                                                 for p in self.control_peers.values()),
            'game_state_start_transmissions': sum(p.game_state_start.transmissions if p.game_state_start else 0
                                                 for p in self.control_peers.values()),
            'all_player_ready_implemented': False,
            'all_player_ready_property_sync_implemented': True,
            'local_all_player_ready_requested': sum(p.local_all_player_ready_requested for p in self.control_peers.values()),
            'game_state_all_ready_delivery_acks': sum(p.game_state_all_ready is not None and p.game_state_all_ready.delivered
                                                     for p in self.control_peers.values()),
            'abseil_permission_property_sync_implemented': True,
            'game_state_abseil_delivery_acks': sum(p.game_state_abseil is not None and p.game_state_abseil.delivered
                                                  for p in self.control_peers.values()),
            'game_state_abseil_transmissions': sum(p.game_state_abseil.transmissions if p.game_state_abseil else 0
                                                  for p in self.control_peers.values()),
            'real_match_start_property_sync_implemented': True,
            'game_state_real_start_profile_connections': sum(
                p.game_state_start_profile is not None and
                p.game_state_start_profile.real_start_handle is not None
                for p in self.control_peers.values()),
            'game_state_real_start_transmissions': sum(
                p.game_state_real_start.transmissions if p.game_state_real_start else 0
                for p in self.control_peers.values()),
            'game_state_real_start_delivery_acks': sum(
                p.game_state_real_start is not None and p.game_state_real_start.delivered
                for p in self.control_peers.values()),
            'match_info_identity_sync_implemented': True,
            'game_state_match_info_delivery_acks': sum(p.game_state_match_info is not None and p.game_state_match_info.delivered
                                                      for p in self.control_peers.values()),
            'pc_restart_rpc_implemented': True,
            'pc_restart_profile_connections': sum(p.pc_restart_profile is not None for p in self.control_peers.values()),
            'pc_restart_requests': sum(p.pc_restart_requested for p in self.control_peers.values()),
            'pc_restart_transmissions': sum(p.pc_restart.transmissions if p.pc_restart else 0
                                           for p in self.control_peers.values()),
            'pc_restart_delivery_acks': sum(p.pc_restart is not None and p.pc_restart.delivered
                                           for p in self.control_peers.values()),
            'pc_rotation_profile_connections': sum(p.pc_rotation_profile is not None for p in self.control_peers.values()),
            'pc_rotation_transmissions': sum(p.pc_rotation.transmissions if p.pc_rotation else 0
                                            for p in self.control_peers.values()),
            'pc_rotation_delivery_acks': sum(p.pc_rotation is not None and p.pc_rotation.delivered
                                            for p in self.control_peers.values()),
            'pc_possession_rpc_acknowledgements': sum(p.pc_possession_ack_count for p in self.control_peers.values()),
            'pc_opaque_reliable_bodies_received': sum(p.pc_opaque_receipt_count for p in self.control_peers.values()),
            'pc_opaque_rpc_gameplay_handled': False,
            'admitted_actor_receipt_connections': sum(p.admitted_actor_reliable_receipts
                for p in self.control_peers.values()),
            'admitted_actor_reliable_packets_received': sum(p.admitted_actor_receipt_packet_count
                for p in self.control_peers.values()),
            'admitted_actor_rejection_reasons': {reason: total
                for reason in sorted(ADMITTED_RECEIPT_REJECTION_CODES)
                if (total := sum(p.admitted_actor_rejection_counts.get(reason, 0)
                    for p in self.control_peers.values()))},
            'admitted_actor_opaque_journal_entries': sum(len(p.admitted_actor_opaque_journal)
                for p in self.control_peers.values()),
            'admitted_actor_opaque_journal_bytes': sum(p.admitted_actor_opaque_journal_bytes
                for p in self.control_peers.values()),
            'admitted_actor_rpc_gameplay_handled': any(p.owner_switch_accepted for p in self.control_peers.values()),
            'admitted_movement_accepted': sum(p.movement_accepted for p in self.control_peers.values()),
            'admitted_movement_rejected': sum(p.movement_rejected for p in self.control_peers.values()),
            'admitted_movement_rejection_reasons': {reason: total
                for reason in sorted(MOVEMENT_REJECTION_CODES)
                if (total := sum(p.movement_rejection_counts.get(reason, 0)
                    for p in self.control_peers.values()))},
            'owner_reported_level_visibility': [dict(reports=p.pc_level_visibility_reports,
                revision=p.pc_level_visibility.revision,
                native_world_membership_verified=False,
                levels=[dict(package_name=r.package_name.text, package_number=r.package_name.number,
                    file_name=r.file_name.text, file_number=r.file_name.number,
                    visible=r.is_visible, file_name_omitted=r.file_name_omitted)
                    for r in p.pc_level_visibility.records]) for p in self.control_peers.values()
                if p.pc_level_visibility is not None],
            'owner_switch_requests_accepted': sum(p.owner_switch_accepted for p in self.control_peers.values()),
            'owner_switch_dispositions': [dict(p.owner_switch_dispositions)
                for p in self.control_peers.values() if p.owner_switch_dispositions],
            'owner_switch_rejected_frames': [list(p.owner_switch_rejected_frames)
                for p in self.control_peers.values() if p.owner_switch_rejected_frames],
            'owner_switch_trace': [list(p.owner_switch_trace)
                for p in self.control_peers.values() if p.owner_switch_trace],
            'owner_switch_result_delivery_acks': sum(p.owner_switch_result_acks for p in self.control_peers.values()),
            'admitted_post_join_control_message_ids': [16, 20],
            'admitted_game_specific_control_subtypes': [0],
            'client_actor_channel_failures_received': sum(len(p.client_failed_actor_channels)
                for p in self.control_peers.values()),
            'client_failed_static_actor_channels': [dict(channel_index=channel, actor_guid=guid)
                for p in self.control_peers.values()
                for channel, guid in sorted(p.client_failed_actor_channels.items())],
            'client_begin_play_notifications_received': sum(p.client_begin_play_notification_count
                for p in self.control_peers.values()),
            'client_begin_play_notification_forces_game_state': False,
            'pc_view_target_profile_connections': sum(p.pc_view_target_profile is not None for p in self.control_peers.values()),
            'pc_hud_profile_connections': sum(p.pc_hud_profile is not None for p in self.control_peers.values()),
            'pc_hud_transmissions': sum(p.pc_hud.transmissions if p.pc_hud else 0 for p in self.control_peers.values()),
            'pc_hud_delivery_acks': sum(p.pc_hud is not None and p.pc_hud.delivered for p in self.control_peers.values()),
            'pc_verify_view_target_requests': sum(p.pc_verify_view_target_count for p in self.control_peers.values()),
            'pc_view_target_transmissions': sum(p.pc_view_target.transmissions if p.pc_view_target else 0
                                               for p in self.control_peers.values()),
            'pc_view_target_delivery_acks': sum(p.pc_view_target is not None and p.pc_view_target.delivered
                                               for p in self.control_peers.values()),
            'pc_view_target_policy': 'local_admitted_pc_uses_its_bound_owned_pawn',
            'native_camera_verified': False,
            'native_possession_verified': False,
            'playable_map_verified': False,
            'initial_actor_open_transport_queue_implemented': True,
            'initial_actor_channels_queued': sum(len(p.actor_opens) for p in self.control_peers.values()),
            'initial_actor_delivery_acks': sum(item.delivered for p in self.control_peers.values()
                                             for item in p.actor_opens.values()),
            'initial_actor_channels_pending': sum(not item.delivered and not self._stage_retries_exhausted(p, item)
                                                  for p in self.control_peers.values() if not p.client_closed
                                                  for item in p.actor_opens.values()),
            'initial_actor_retries_exhausted': sum(not item.delivered and self._stage_retries_exhausted(p, item)
                                                  for p in self.control_peers.values() if not p.client_closed
                                                  for item in p.actor_opens.values()),
            'initial_actor_channels_cancelled_by_client_close': sum(not item.delivered
                                                  for p in self.control_peers.values() if p.client_closed
                                                  for item in p.actor_opens.values()),
            'post_open_actor_content_transport_implemented': True,
            'post_open_actor_content_channels_queued': sum(len(p.actor_contents)
                for p in self.control_peers.values()),
            'post_open_actor_content_stage_dependencies_implemented': True,
            'post_open_actor_content_stages_queued': sum(len(_content_items(p))
                for p in self.control_peers.values()),
            'post_open_actor_content_stage_dependency_edges': sum(len(item.content_stage_dependencies)
                for p in self.control_peers.values() for item in _content_items(p)),
            'post_open_actor_content_stage_policy_invalid_connections': sum(
                not _content_policies_current(p.actor_contents) for p in self.control_peers.values()),
            'post_open_actor_content_stages_waiting_on_content': sum(not item.delivered and
                self._content_stage_waiting(peer, state, self.peers[peer], channel, ordinal, item)
                for peer, state in self.control_peers.items() if peer in self.peers and not state.client_closed and
                    _content_policies_current(state.actor_contents)
                for channel, head in state.actor_contents.items()
                for ordinal, item in enumerate((head, *head.continuations))),
            'post_open_actor_content_delivery_acks': sum(item.delivered
                for p in self.control_peers.values() for item in _content_items(p)),
            'post_open_actor_content_channels_pending': sum(not item.delivered and
                not self._stage_retries_exhausted(p, item) for p in self.control_peers.values()
                if not p.client_closed for item in _content_items(p)),
            'post_open_actor_content_retries_exhausted': sum(not item.delivered and
                self._stage_retries_exhausted(p, item) for p in self.control_peers.values()
                if not p.client_closed for item in _content_items(p)),
            'post_open_actor_content_cancelled_by_client_close': sum(not item.delivered
                for p in self.control_peers.values() if p.client_closed
                for item in _content_items(p)),
            'native_actor_resolution_verified': False,
            'native_actor_spawn_verified': False,
            'native_challenge_acceptance_verified': False,
            'native_connection_completed': False,
            'actor_replication_implemented': False,
            'player_spawn_implemented': False, 'gameplay_server_implemented': False,
        }
        items = [p.late_player_state_human_appearance for p in self.control_peers.values()
                 if p.late_player_state_human_appearance is not None]
        if items:
            report['late_player_state_human_appearance_diagnostic'] = {
                'queued_outboxes': len(items), 'transport_delivery_acks': sum(i.delivered for i in items),
                'transmissions_prepared': sum(i.transmissions for i in items),
                'native_field_acceptance_verified': False, 'repnotify_execution_verified': False,
                'model_configuration_applied': False, 'Uin_modified': False}
        early = [p for p in self.control_peers.values() if p.early_player_state_human_appearance is not None]
        if early:
            items = [p.actor_contents[p.early_player_state_human_appearance.channel] for p in early]
            report['early_player_state_human_appearance_diagnostic'] = {
                'queued_ps_contents': len(items), 'transport_delivery_acks': sum(i.delivered for i in items),
                'transmissions_prepared': sum(i.transmissions for i in items),
                'association_content_dependency': 'actual_ps_transport_delivery',
                'native_field_acceptance_verified': False, 'initialization_timing_verified': False,
                'model_configuration_applied': False, 'Uin_modified': False}
        return report
