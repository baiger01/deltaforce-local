"""Opt-in local Hello/Challenge exchange using the recovered native wire codec.

This implements one control step, not Login/Welcome, channel replication or a
gameplay server. An exact supported Hello can be marked delivered after it is
consumed. Unknown payloads are never acknowledged as delivered. The observed
eight-byte routing prefix/PacketHandler envelope remain separately qualified.
"""
from collections import Counter
from dataclasses import dataclass
import secrets

from .legacy_ds_control_fields import ControlMessage, decode_messages, encode_message
from .legacy_ds_packet_ack_probe import LegacyDSPacketAckProbe, MASK
from .legacy_ds_wire_codec import (ChannelName, WireBunch, WirePacket,
                                   decode_observed_application, encode_observed_application)

CONTROL_NAME = ChannelName(hardcoded_index=255)


@dataclass
class ControlPeer:
    hello_sequence: int
    challenge_sequence: int
    challenge_payload: bytes
    hello_received: bool = False


class LegacyDSControlProbe(LegacyDSPacketAckProbe):
    def __init__(self, *, expected_net_version, max_packet_bytes=1024, max_replies=128):
        super().__init__(max_replies=max_replies)
        if (type(expected_net_version) is not int or
                not 0 <= expected_net_version <= 0xffffffff or
                type(max_packet_bytes) is not int or not 1 <= max_packet_bytes <= 1492):
            raise ValueError('An explicit local client wire profile is required')
        self.expected_net_version = expected_net_version
        self.max_packet_bytes = max_packet_bytes
        self.control_peers = {}
        self.control_events = Counter()
        self.next_control_ids = Counter()

    def register_verified_echo(self, peer, cookie):
        super().register_verified_echo(peer, cookie)
        if peer not in self.control_peers:
            transport = self.peers[peer]
            # Native InitializeSequence seeds each reliable channel from the
            # corresponding packet seed, then SendBunch increments it.
            self.control_peers[peer] = ControlPeer(
                (transport.in_sequence + 2) & 1023,
                (transport.out_sequence + 1) & 1023,
                encode_message(3, secrets.token_hex(16)))

    def _result(self, event, response=None):
        self.control_events[event] += 1
        return event, response

    def forget_peer(self, peer):
        self.peers.pop(peer, None)
        self.control_peers.pop(peer, None)

    def rebind_verified_peer(self, old_peer, new_peer):
        if old_peer not in self.control_peers or new_peer in self.control_peers:
            raise ValueError('An existing control and unused destination are required')
        super().rebind_verified_peer(old_peer, new_peer)
        self.control_peers[new_peer] = self.control_peers.pop(old_peer)

    @staticmethod
    def _plain_control(bunch):
        return (bunch.channel_index == 0 and bunch.reliable and not bunch.close and
                not bunch.flag4 and not bunch.connection_flag and
                not bunch.package_exports and not bunch.must_be_mapped and
                not bunch.partial and bunch.channel_name == CONTROL_NAME and
                bunch.payload_bits == len(bunch.payload) * 8)

    def handle(self, datagram, peer):
        transport, control = self.peers.get(peer), self.control_peers.get(peer)
        if transport is None or control is None:
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

        event, accepted, send_challenge = 'empty_packet_ack_prepared', not packet.bunches, False
        if packet.bunches:
            event = 'control_payload_unimplemented'
            if len(packet.bunches) == 1:
                bunch = packet.bunches[0]
                if self._plain_control(bunch):
                    try:
                        messages = decode_messages(bunch.payload, payload_bits=bunch.payload_bits)
                    except ValueError:
                        messages = ()
                    hello = (ControlMessage(0, (1, self.expected_net_version, '')),)
                    if (bunch.open and bunch.channel_sequence == control.hello_sequence and
                            messages == hello):
                        event = ('control_hello_retry_challenge_prepared' if control.hello_received
                                 else 'control_hello_challenge_prepared')
                        accepted = send_challenge = True
                    elif (control.hello_received and
                          bunch.channel_sequence == ((control.hello_sequence + 1) & 1023) and
                          bunch.payload):
                        # Record a bounded message ID only; Login's fields
                        # are not decoded, accepted, printed or delivered.
                        message_id = bunch.payload[0]
                        self.next_control_ids[message_id] += 1
                        event = 'control_next_message_unimplemented'

        if accepted and transport.replies >= self.max_replies:
            return self._result('application_reply_limit_reached')

        response = None
        next_history = ((transport.history << delta) | int(accepted)) & 0xffffffff
        if accepted:
            bunches = ()
            if send_challenge:
                bunches = (WireBunch(0, control.challenge_payload,
                    len(control.challenge_payload)*8, reliable=True,
                    channel_sequence=control.challenge_sequence, channel_name=CONTROL_NAME),)
            response_packet = WirePacket(transport.out_sequence, packet.sequence,
                                         (next_history,), False, 0, None, bunches, 0)
            response = encode_observed_application(response_packet,
                max_packet_bytes=self.max_packet_bytes, received_by_server=False)

        # Commit after the complete packet and response have been constructed.
        transport.in_sequence = packet.sequence
        transport.acknowledged_out_sequence = packet.acknowledged_sequence
        transport.history = next_history
        if response is not None:
            transport.out_sequence = (transport.out_sequence + 1) & MASK
            transport.replies += 1
            if send_challenge:
                control.hello_received = True
        return self._result(event, response)

    def summary(self):
        return {'enabled': True, 'mode': 'local_native_hello_challenge_only',
                'wire_codec_implemented': True,
                'supported_control_message_ids': [0, 3],
                'hello_consumed_peers': sum(p.hello_received for p in self.control_peers.values()),
                'next_unimplemented_control_message_ids': dict(self.next_control_ids),
                'events': dict(self.control_events),
                'login_implemented': False, 'welcome_implemented': False,
                'unknown_nonempty_payload_ack_enabled': False,
                'native_challenge_acceptance_verified': False,
                'native_connection_completed': False, 'gameplay_server_implemented': False}
