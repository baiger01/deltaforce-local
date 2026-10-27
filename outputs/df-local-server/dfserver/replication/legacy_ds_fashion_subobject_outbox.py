"""Pure one-shot post-open Fashion outbox; never connected to a socket.

Current owner, local reference/stable-name and prerequisite full-send/positive
receipt proofs are caller contracts. Captured official GUIDs cannot satisfy
those contracts. No GUID allocation/export, source read, native access or
global transport/channel mutation occurs here. The default is disabled.
"""
from dataclasses import dataclass, field, fields
from copy import copy
import math

from dfserver.legacy_ds_actor_content import (ActorContentLimits,
    ResolvedStableSubobjectContentBlock, ResolvedStableSubobjectProfile,
    write_actor_content_blocks)
from dfserver.legacy_ds_bit_archive import BitWriter
from dfserver.legacy_ds_wire_codec import (ChannelName, WireBunch, WirePacket,
    encode_observed_application)
from native_fashion_hero_content import (OwnedFashionContext, OwnedHeroIdBinding,
    SourceJson, SourcePin, prepare_fashion_hero_property_body)

MASK, HALF, MAX_TRANSMISSIONS = 0x3fff, 0x2000, 64
SOURCE_PINS = {
    # Both the archived candidates and the caller-qualified executing destinations
    # are pinned. Current baseline Actor-only codec cannot activate this candidate.
    'work/native_fashion_hero_content.py':
        'fa8ec6b0679285c0e83cf5c89a42a98692984708e95d0d7eae1394701c00d340',
    'outputs/df-local-server/dfserver/legacy_ds_actor_content.py':
        '6137f4ef35233df0eabbb43a29f6c7db87fab4232b310daf38b846b2a7ff49b5',
    'work/staging-ds-receipt-fix-20261009/fashion-hero-property-body/candidate_native_fashion_hero_content.py':
        'fa8ec6b0679285c0e83cf5c89a42a98692984708e95d0d7eae1394701c00d340',
    'work/staging-ds-receipt-fix-20261009/resolved-stable-subobject-content/candidate_legacy_ds_actor_content.py':
        '6137f4ef35233df0eabbb43a29f6c7db87fab4232b310daf38b846b2a7ff49b5',
    'outputs/df-local-server/dfserver/legacy_ds_wire_codec.py':
        '556afbca7ac3e515e575f63535ebbb00d6275030bf459cb609aee97a731eecbf',
    'outputs/df-local-server/dfserver/legacy_ds_bit_archive.py':
        'ab64dd2d3e3853b9c78de25d39d9cc1f4d8df004d8ddde3241365197524ab17e',
}


class FashionOutboxError(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise FashionOutboxError(reason)


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _uint(value, low, high):
    return type(value) is int and low <= value <= high


def _time(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


@dataclass(frozen=True, eq=False)
class CurrentPawnChannelLease:
    """Source-qualified Python owner references, not process/native pointers.

    connection denotes the stable connection coordinator, not its replaceable
    transactional ControlConnection snapshot. current_owner_check must recheck
    exact current logical connection/ticket/transport/
    handshake-generation identities, joined admission, closed state, frozen
    Actor/content namespaces and exclusive Pawn cursor under the caller lock.
    The two receipt facts require each prerequisite's own actual full send and
    positive ACK, not merely the baseline item's delivered/sent_packets flags.
    """
    connection: object = field(repr=False)
    ticket: object = field(repr=False)
    transport: object = field(repr=False)
    handshake_generation: object = field(repr=False)
    generation_number: int
    pawn_channel_index: int
    pawn_actor_guid: int
    association_bunch: WireBunch = field(repr=False)
    owner_binding_digest: str = field(repr=False)
    frozen_actor_namespace_digest: str = field(repr=False)
    frozen_content_namespace_digest: str = field(repr=False)
    source_pin: SourcePin
    current_joined_owner_verified: bool
    pawn_open_own_full_send_positive_receipt_verified: bool
    pawn_association_own_full_send_positive_receipt_verified: bool
    no_competing_pawn_channel_reservation_verified: bool


@dataclass(frozen=True)
class QualifiedLocalFashionReference:
    """Explicit current local PackageMap/stable receiver contract; no parity rule."""
    component_guid: int
    pawn_actor_guid: int
    pawn_channel_index: int
    generation_number: int
    owner_binding_digest: str = field(repr=False)
    source_pin: SourcePin
    local_namespace_current_and_resolved_verified: bool
    required_local_reference_export_full_send_receipt_verified: bool
    current_component_owner_and_non_actor_class_verified: bool
    actual_stable_name_receiver_branch_verified: bool


@dataclass(frozen=True)
class CurrentFashionPropertyRequest:
    metadata_source: SourceJson = field(repr=False)
    field_profile_source: SourceJson = field(repr=False)
    factory_profile_source: SourceJson = field(repr=False)
    observer_source_pin: SourcePin
    current_owner: OwnedFashionContext = field(repr=False)
    hero_binding: OwnedHeroIdBinding = field(repr=False)
    reference: QualifiedLocalFashionReference = field(repr=False)
    envelope_profile: ResolvedStableSubobjectProfile = field(repr=False)


@dataclass(frozen=True, eq=False)
class PreparedFashionPacket:
    """Proposal, not successful send. Caller reserves the shared packet cursor."""
    application_payload: bytes = field(repr=False)
    packet_sequence: int
    bunch: WireBunch = field(repr=False)


@dataclass(frozen=True)
class _PreparedRecord:
    token: PreparedFashionPacket = field(repr=False, compare=False)
    payload: bytes = field(repr=False)
    packet_sequence: int
    prepared_at: float


class CurrentFashionSubobjectOutbox:
    """At most one new reliable bunch on one existing Pawn channel.

    Pure methods are intended to run under the same caller lock as the existing
    send/close path. A caller must reserve transport.out_sequence after prepare
    and call note_full_send only at the existing full socket-send hook. Neither
    preparing nor positive transport receipt proves RepNotify/model execution.
    """
    def __init__(self, *, enabled=False, lease=None, sealed_sources=None,
            source_recheck=None, current_owner_check=None, max_packet_bytes=1492,
            retry_interval=0.5, max_transmissions=16, shared_reply_limit=128,
            allow_qualified_forward_gap_receipts=False):
        _require(type(enabled) is bool and type(allow_qualified_forward_gap_receipts) is bool,
            'explicit_boolean_required')
        self.enabled = enabled
        self._queued = self._delivered = self._cancelled = False
        self._prepared = []
        self._successful = []
        self._last_prepare_at = None
        self._last_reserved = None
        if not enabled:
            return
        _require(type(lease) is CurrentPawnChannelLease and type(sealed_sources) is dict
            and len(sealed_sources) <= 512 and callable(source_recheck) and callable(current_owner_check),
            'qualified_current_lease_and_source_callbacks_required')
        _require(_uint(max_packet_bytes, 1, 1492) and _time(retry_interval) and 0.1 <= retry_interval <= 5
            and _uint(max_transmissions, 1, MAX_TRANSMISSIONS) and _uint(shared_reply_limit, 1, 128),
            'bounded_retry_packet_profile_required')
        self._lease, self._sealed = lease, dict(sealed_sources)
        self._source_recheck, self._owner_check = source_recheck, current_owner_check
        self._maximum, self._interval, self._limit = max_packet_bytes, retry_interval, max_transmissions
        self._reply_limit = shared_reply_limit
        self._gap = allow_qualified_forward_gap_receipts
        self._validate_lease()
        self._lease_fingerprint = self._fingerprint_lease()
        self._check()

    def _pin(self, pin):
        _require(type(pin) is SourcePin and _digest(pin.sha256)
            and self._sealed.get(pin.relative_path) == pin.sha256, 'source_pin_refused')

    def _validate_lease(self):
        lease = self._lease
        _require(all(ref is not None for ref in (lease.connection, lease.ticket, lease.transport,
            lease.handshake_generation)) and _uint(lease.generation_number, 1, (1<<64)-1)
            and _uint(lease.pawn_channel_index, 2, 65535) and _uint(lease.pawn_actor_guid, 2, 0xffffffff)
            and all(_digest(value) for value in (lease.owner_binding_digest,
                lease.frozen_actor_namespace_digest, lease.frozen_content_namespace_digest))
            and all(value is True for value in (lease.current_joined_owner_verified,
                lease.pawn_open_own_full_send_positive_receipt_verified,
                lease.pawn_association_own_full_send_positive_receipt_verified,
                lease.no_competing_pawn_channel_reservation_verified)), 'current_pawn_lease_refused')
        self._pin(lease.source_pin)
        bunch = lease.association_bunch
        _require(type(bunch) is WireBunch and bunch.channel_index == lease.pawn_channel_index
            and bunch.reliable is True and _uint(bunch.channel_sequence, 0, 1023)
            and bunch.open is False and bunch.close is False and bunch.partial is False
            and bunch.package_exports is False and bunch.must_be_mapped is False
            and type(bunch.channel_name) is ChannelName and bunch.channel_name == ChannelName(hardcoded_index=102),
            'exact_existing_pawn_association_channel_required')

    def _fingerprint_lease(self):
        l = self._lease
        # Store primitive values instead of aliasing the externally held bunch.
        bunch = tuple((f.name, getattr(l.association_bunch, f.name)) for f in fields(WireBunch)
            if f.name != 'channel_name') + (('channel_name', tuple(
                getattr(l.association_bunch.channel_name, f.name) for f in fields(ChannelName))),)
        return (id(l.connection), id(l.ticket), id(l.transport), id(l.handshake_generation),
            l.generation_number, l.pawn_channel_index, l.pawn_actor_guid, bunch,
            l.owner_binding_digest, l.frozen_actor_namespace_digest, l.frozen_content_namespace_digest, l.source_pin)

    def _check(self):
        _require(self.enabled and not self._cancelled, 'disabled_or_cancelled')
        _require(all(self._sealed.get(p) == digest for p, digest in SOURCE_PINS.items()), 'executing_dependency_seal_refused')
        fresh = self._source_recheck()
        _require(type(fresh) is dict and fresh == self._sealed, 'source_seal_changed')
        self._validate_lease()
        _require(self._fingerprint_lease() == self._lease_fingerprint, 'original_owner_namespace_changed')
        _require(self._owner_check(self._lease) is True, 'current_owner_closed_or_changed')
        # A callback may mutate its inputs; do not commit based on pre-callback facts.
        fresh = self._source_recheck()
        _require(type(fresh) is dict and fresh == self._sealed
            and self._fingerprint_lease() == self._lease_fingerprint, 'source_or_owner_changed_during_check')
        self._validate_lease()

    def _body_and_bunch(self, request, sequence):
        _require(type(request) is CurrentFashionPropertyRequest
            and type(request.current_owner) is OwnedFashionContext
            and type(request.hero_binding) is OwnedHeroIdBinding
            and type(request.reference) is QualifiedLocalFashionReference
            and type(request.envelope_profile) is ResolvedStableSubobjectProfile,
            'typed_current_fashion_request_required')
        l, r, owner, hero = self._lease, request.reference, request.current_owner, request.hero_binding
        self._pin(r.source_pin)
        _require((r.generation_number, r.pawn_channel_index, r.pawn_actor_guid, r.owner_binding_digest) ==
            (l.generation_number, l.pawn_channel_index, l.pawn_actor_guid, l.owner_binding_digest)
            and _uint(r.generation_number, 1, (1<<64)-1) and _uint(r.pawn_channel_index, 2, 65535)
            and _uint(r.pawn_actor_guid, 2, 0xffffffff)
            and _uint(r.component_guid, 2, 0xffffffff)
            and all(v is True for v in (r.local_namespace_current_and_resolved_verified,
                r.required_local_reference_export_full_send_receipt_verified,
                r.current_component_owner_and_non_actor_class_verified,
                r.actual_stable_name_receiver_branch_verified)), 'qualified_local_component_reference_required')
        _require((owner.generation, owner.channel_index, owner.owner_binding_digest) ==
            (l.generation_number, l.pawn_channel_index, l.owner_binding_digest), 'property_current_pawn_channel_mismatch')
        # The selected native ID mapping is qualified by the factory; this outbox
        # rechecks the current immutable ticket also belongs to that exact binding.
        _require(type(getattr(l.ticket, 'selected_hero_id', None)) is int
            and l.ticket.selected_hero_id == hero.selected_native_hero_id, 'ticket_selected_native_hero_mismatch')
        profile = request.envelope_profile
        profile.__post_init__()
        _require(profile.channel_actor_guid == l.pawn_actor_guid
            and r.component_guid in profile.resolved_non_actor_guids
            and r.component_guid not in profile.known_actor_guids, 'component_actor_namespace_mismatch')
        body, _ = prepare_fashion_hero_property_body(metadata_source=request.metadata_source,
            field_profile_source=request.field_profile_source, factory_profile_source=request.factory_profile_source,
            observer_source_pin=request.observer_source_pin, sealed_sources=self._sealed,
            current_owner=owner, hero_binding=hero, enabled=True)
        writer = BitWriter(maximum_bits=self._maximum*8)
        write_actor_content_blocks(writer, (ResolvedStableSubobjectContentBlock(r.component_guid,
            body.has_rep_layout, body.payload, body.payload_bit_count),),
            limits=ActorContentLimits(1, 97, self._maximum*8), allow_resolved_stable_subobjects=True,
            resolved_stable_subobject_profile=profile)
        return WireBunch(l.pawn_channel_index, writer.to_bytes(), writer.bit_count,
            reliable=True, channel_sequence=sequence, channel_name=ChannelName(hardcoded_index=102))

    def queue(self, request=None):
        if not self.enabled:
            return False
        self._check()
        _require(not self._queued, 'one_shot_channel_reservation_already_used')
        sequence = (self._lease.association_bunch.channel_sequence + 1) & 1023
        bunch = self._body_and_bunch(request, sequence)
        encode_observed_application(WirePacket(MASK, MASK, (0xffffffff,), False, 0, None, (bunch,), 0),
            max_packet_bytes=self._maximum, received_by_server=False)
        self._check()
        _require(self._body_and_bunch(request, sequence) == bunch, 'property_or_reference_changed_during_queue')
        self._request, self._bunch, self._last_reserved, self._queued = request, bunch, sequence, True
        return True

    def _queued_check(self):
        self._check()
        _require(self._queued, 'property_not_queued')
        _require(self._body_and_bunch(self._request, self._last_reserved) == self._bunch,
            'original_property_or_reference_changed')

    def prepare(self, *, now):
        if not self.enabled:
            return None
        self._queued_check()
        _require(_time(now) and (self._last_prepare_at is None or now >= self._last_prepare_at), 'monotonic_time_required')
        if self._delivered or len(self._prepared) >= self._limit or (
                self._last_prepare_at is not None and now-self._last_prepare_at < self._interval):
            return None
        t = self._lease.transport
        _require(all(_uint(getattr(t, name, None), 0, MASK) for name in
            ('out_sequence', 'in_sequence', 'acknowledged_out_sequence'))
            and _uint(getattr(t, 'history', None), 0, 0xffffffff)
            and _uint(getattr(t, 'replies', None), 0, self._reply_limit), 'bounded_shared_transport_header_required')
        if t.replies == self._reply_limit:
            return None
        header_snapshot = (t.out_sequence, t.in_sequence, t.acknowledged_out_sequence, t.history, t.replies)
        _require(all(p.packet_sequence != t.out_sequence for p in self._prepared), 'shared_packet_cursor_not_reserved')
        payload = encode_observed_application(WirePacket(t.out_sequence, t.in_sequence, (t.history,),
            False, 0, None, (self._bunch,), 0), max_packet_bytes=self._maximum, received_by_server=False)
        proposal = PreparedFashionPacket(payload, t.out_sequence, self._bunch)
        self._queued_check()
        _require(header_snapshot == (t.out_sequence, t.in_sequence, t.acknowledged_out_sequence, t.history, t.replies),
            'shared_packet_header_changed_during_prepare')
        self._prepared.append(_PreparedRecord(proposal, payload, proposal.packet_sequence, now))
        self._last_prepare_at = now
        return proposal

    def note_full_send(self, prepared, *, application_payload, bytes_sent, sent_at):
        """Call only at the existing outbound full sendto success hook.

        BASE sends these application bytes directly. bytes_sent is the actual
        sendto return value, which must equal the entire prepared payload length.
        Short/failed/wrong/stale/unsent proposals never add receipt evidence.
        """
        self._queued_check()
        record = next((p for p in self._prepared if p.token is prepared), None)
        _require(type(prepared) is PreparedFashionPacket and record is not None,
            'unknown_prepared_proposal')
        if (prepared.application_payload != record.payload or prepared.packet_sequence != record.packet_sequence
                or prepared.bunch != self._bunch or type(application_payload) is not bytes
                or application_payload != record.payload
                or not _uint(bytes_sent, 0, 1492) or bytes_sent != len(application_payload)
                or not _time(sent_at) or sent_at < record.prepared_at):
            return False
        t = self._lease.transport
        if not _uint(t.out_sequence, 0, MASK) or not 0 < ((t.out_sequence-prepared.packet_sequence)&MASK) < HALF:
            return False
        self._queued_check()
        if not any(p is record for p in self._successful):
            self._successful.append(record)
        return True

    def acknowledge(self, packet, *, receipt_only_forward_gap=False):
        """Observe one accepted header before global cursor mutation; no body/ACK dispatch."""
        self._queued_check()
        _require(type(receipt_only_forward_gap) is bool, 'explicit_receipt_scope_required')
        if type(packet) is not WirePacket or self._delivered:
            return False
        t = self._lease.transport
        if (not all(_uint(getattr(t, k, None), 0, MASK) for k in ('in_sequence', 'out_sequence', 'acknowledged_out_sequence'))
            or not _uint(packet.sequence, 0, MASK) or not _uint(packet.acknowledged_sequence, 0, MASK)
            or type(packet.history) is not tuple or not 1 <= len(packet.history) <= 8
            or any(not _uint(v, 0, 0xffffffff) for v in packet.history)
            or type(packet.bunches) is not tuple or any(type(b) is not WireBunch or b.close is not False for b in packet.bunches)):
            return False
        delta = (packet.sequence-t.in_sequence)&MASK
        sent_delta = (t.out_sequence-t.acknowledged_out_sequence)&MASK
        ack_delta = (packet.acknowledged_sequence-t.acknowledged_out_sequence)&MASK
        if not 0 < sent_delta < HALF or ack_delta >= sent_delta:
            return False
        if receipt_only_forward_gap:
            if not self._gap or not 32 < delta < HALF:
                return False
        elif not 1 <= delta <= 32:
            return False
        matched = any(distance < len(packet.history)*32 and ((packet.history[distance//32] >> (distance%32))&1)
            and 0 < ((t.out_sequence-p.packet_sequence)&MASK) < HALF
            for p in self._successful for distance in ((packet.acknowledged_sequence-p.packet_sequence)&MASK,))
        if not matched:
            return False
        header_snapshot = (t.in_sequence, t.out_sequence, t.acknowledged_out_sequence)
        self._queued_check()
        _require(header_snapshot == (t.in_sequence, t.out_sequence, t.acknowledged_out_sequence),
            'receipt_transport_cursor_changed_during_check')
        self._delivered = True
        return True

    def cancel(self):
        self._cancelled = True

    def clone(self):
        """Transaction copy; tokens keep identity and exact logical owner refs.

        The coordinator/ticket/transport/generation are stable through the
        ControlConnection snapshot replacement and authenticated peer rebind.
        Prepared and successful rings are copied so speculative receipt work
        cannot mutate the original snapshot.
        """
        result = copy(self)
        result._prepared = list(self._prepared)
        result._successful = list(self._successful)
        if self.enabled:
            result._sealed = dict(self._sealed)
        return result

    def prepared_for_payload(self, payload):
        """Return only this outbox's actual proposal token, never a cursor."""
        return next((p.token for p in self._prepared if p.payload == payload), None)

    def validate_before_socket(self, prepared):
        self._queued_check()
        return (type(prepared) is PreparedFashionPacket and
            any(p.token is prepared and p.payload == prepared.application_payload
                for p in self._prepared) and not self._delivered)

    @property
    def last_reserved_reliable_sequence(self):
        return self._last_reserved

    def summary(self):
        return {'status':'disabled' if not self.enabled else 'cancelled' if self._cancelled else
            'transport_receipt_observed' if self._delivered else 'queued' if self._queued else 'unqueued',
            'prepared_count':len(self._prepared), 'actual_full_send_count':len(self._successful),
            'own_positive_transport_receipt_observed':self._delivered,
            'initial_actor_namespace_changed':False, 'global_transport_changed':False,
            'native_methods_invoked':False, 'process_accessed':False, 'socket_send_performed':False,
            'repnotify_execution_verified':False, 'model_initialized':False}
