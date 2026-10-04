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

from .legacy_ds_control_fields import ControlMessage, decode_messages, encode_message
from .legacy_ds_control_probe import LegacyDSControlProbe, CONTROL_NAME
from .legacy_ds_actor_bunch import build_actor_bunch
from .legacy_ds_login_fields import decode_single_login5
from .legacy_ds_packet_ack_probe import MASK
from .legacy_ds_wire_codec import (
    WireBunch, WirePacket, decode_observed_application, encode_observed_application,
)

RELIABLE_RETRY_WINDOW = 128  # Local bound below half of the 10-bit sequence space.
MAX_INITIAL_ACTOR_CHANNELS = 16  # Local one-open-per-channel/session bound.


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
    client_closed: bool = False
    client_close_sequence: int | None = None
    client_close_reason: int | None = None


class LegacyDSControlConnection(LegacyDSControlProbe):
    """Opt-in, ticket-authorized control steps for an explicit local map profile."""

    def __init__(self, *, admissions, welcome_maps, expected_net_version,
                 max_packet_bytes=1024, max_replies=128,
                 retry_interval=0.5, max_transmissions=16):
        super().__init__(expected_net_version=expected_net_version,
                         max_packet_bytes=max_packet_bytes, max_replies=max_replies)
        if not callable(getattr(admissions, 'authorize_login_url', None)):
            raise ValueError('An owner-controlled match admission store is required')
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
        super().rebind_verified_peer(old_peer, new_peer)
        self.ticket_peers[state.ticket.cookie] = new_peer

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
                       actor_exports=dict(state.actor_exports))

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
        if 'channel_sequence' in actor_fields or 'max_packet_bytes' in actor_fields:
            raise ValueError('The connection owns Actor sequence and packet budget')
        bunch = build_actor_bunch(channel_sequence=state.initial_actor_sequence,
                                 max_packet_bytes=self.max_packet_bytes, **actor_fields)
        if bunch.channel_index in state.actor_opens:
            raise ValueError('An initial Actor channel cannot be opened twice')
        actor_guid = actor_fields['actor_guid']
        if any(item.actor_guid == actor_guid for item in state.actor_opens.values()):
            raise ValueError('A dynamic Actor GUID cannot be opened on two channels')
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
        state.actor_opens[bunch.channel_index] = ActorOpenDelivery(bunch, actor_guid)
        self.control_events['actor_open_queued'] += 1

    def queue_actor_opens(self, peer, actor_fields):
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
        previous_events = self.control_events.copy()
        self.control_peers[peer] = self._clone(original)
        try:
            for fields in actor_fields:
                self.queue_actor_open(peer, **fields)
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

    def _encode_reply(self, transport, state, acknowledged_sequence, history, now,
                      *, include_pending=True):
        pending = state.pending if include_pending else None
        if pending and pending.transmissions >= self.max_transmissions:
            pending = None
        bunches = (() if pending is None else (WireBunch(
            0, pending.payload, len(pending.payload) * 8, reliable=True,
            channel_sequence=pending.channel_sequence, channel_name=CONTROL_NAME),))
        body = encode_observed_application(WirePacket(
            transport.out_sequence, acknowledged_sequence, (history,), False,
            0, None, bunches, 0), max_packet_bytes=self.max_packet_bytes,
            received_by_server=False)
        if pending:
            pending.sent_packets = (*pending.sent_packets, transport.out_sequence)[-64:]
            pending.last_sent_at = now
            pending.transmissions += 1
        transport.out_sequence = (transport.out_sequence + 1) & MASK
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

    def handle(self, datagram, peer, now=None):
        now = self._now(now)
        transport, original = self.peers.get(peer), self.control_peers.get(peer)
        if transport is None or original is None:
            return self._result('application_without_verified_echo')
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
        if not 1 <= delta <= 32 or ack_delta >= sent_delta:
            return self._result('application_sequence_rejected')
        closing = any(bunch.close for bunch in packet.bunches)
        if original.client_closed and not closing:
            return self._result('application_after_client_close')
        state = self._clone(original)
        if not original.client_closed and state.pending and self._delivered(state.pending, packet):
            state.pending = None
        for item in state.actor_opens.values():
            if not original.client_closed and not item.delivered and self._delivered(item, packet):
                item.delivered = True
        accepted, response_needed = not packet.bunches, False
        event = 'control_ack_only_consumed'
        if packet.bunches:
            accepted = False
            event = 'control_payload_rejected'
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
                for bunch in (() if closing else packet.bunches):
                    if not self._plain_control(bunch):
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
                        state.consumed.pop(bunch.channel_sequence, None)
                        state.consumed[bunch.channel_sequence] = digest
                        while len(state.consumed) > RELIABLE_RETRY_WINDOW:
                            state.consumed.pop(next(iter(state.consumed)))
                        state.expected_client_sequence = (state.expected_client_sequence + 1) & 1023
                    elif state.consumed.get(bunch.channel_sequence) == digest:
                        event = 'control_reliable_retry_consumed'
                    else:
                        raise ValueError('Unexpected reliable control sequence')
            except ValueError:
                state = self._clone(original)
                event = 'control_close_rejected' if closing else 'control_login_or_order_rejected'
            else:
                accepted, response_needed = True, True
        if accepted and response_needed and transport.replies >= self.max_replies:
            if state.client_closed:
                # A spent outbound budget cannot keep an already closed peer
                # alive. Commit shutdown without manufacturing an extra reply.
                response_needed = False
            else:
                return self._result('application_reply_limit_reached')
        history = ((transport.history << delta) | int(accepted)) & 0xffffffff
        response = None
        if accepted and response_needed:
            # Construct the complete reply before committing channel/admission
            # state. Reliable retries retain their original channel sequence.
            response = self._encode_reply(transport, state, packet.sequence, history, now)
        transport.in_sequence = packet.sequence
        transport.acknowledged_out_sequence = packet.acknowledged_sequence
        transport.history = history
        if accepted:
            if state.ticket:
                if state.client_closed:
                    if self.ticket_peers.get(state.ticket.cookie) == peer:
                        del self.ticket_peers[state.ticket.cookie]
                else:
                    self.ticket_peers[state.ticket.cookie] = peer
            if state.client_join_observed and not original.client_join_observed:
                self.joined_count += 1
            self.control_peers[peer] = state
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
            for item in state.actor_opens.values():
                if transport.replies >= self.max_replies:
                    break
                if (item.delivered or item.transmissions >= self.max_transmissions or
                        (item.transmissions and now - item.last_sent_at < self.retry_interval)):
                    continue
                body = encode_observed_application(WirePacket(
                    transport.out_sequence, transport.in_sequence, (transport.history,),
                    False, 0, None, (item.bunch,), 0),
                    max_packet_bytes=self.max_packet_bytes, received_by_server=False)
                event = ('actor_open_send_prepared' if not item.transmissions else
                         'actor_open_timer_retransmit_prepared')
                item.sent_packets = (*item.sent_packets, transport.out_sequence)[-64:]
                item.last_sent_at = now
                item.transmissions += 1
                transport.out_sequence = (transport.out_sequence + 1) & MASK
                transport.replies += 1
                self.control_events[event] += 1
                responses.append((peer, event, body))
        return responses

    def summary(self):
        return {
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
            'initial_actor_open_transport_queue_implemented': True,
            'initial_actor_channels_queued': sum(len(p.actor_opens) for p in self.control_peers.values()),
            'initial_actor_delivery_acks': sum(item.delivered for p in self.control_peers.values()
                                             for item in p.actor_opens.values()),
            'initial_actor_channels_pending': sum(not item.delivered and item.transmissions < self.max_transmissions
                                                  for p in self.control_peers.values() if not p.client_closed
                                                  for item in p.actor_opens.values()),
            'initial_actor_retries_exhausted': sum(not item.delivered and item.transmissions >= self.max_transmissions
                                                  for p in self.control_peers.values() if not p.client_closed
                                                  for item in p.actor_opens.values()),
            'initial_actor_channels_cancelled_by_client_close': sum(not item.delivered
                                                  for p in self.control_peers.values() if p.client_closed
                                                  for item in p.actor_opens.values()),
            'native_actor_resolution_verified': False,
            'native_actor_spawn_verified': False,
            'native_challenge_acceptance_verified': False,
            'native_connection_completed': False,
            'actor_replication_implemented': False,
            'player_spawn_implemented': False, 'gameplay_server_implemented': False,
        }

