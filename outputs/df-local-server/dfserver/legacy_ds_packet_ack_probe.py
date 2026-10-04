"""Bounded loopback ACK experiment for the observed post-handshake packet header.

The local captures support a candidate one-bit handler flag, packed 32-bit
header, 14-bit packet sequences and history words. Nine zero remainder bits
and adjacent termination bits are observed shape constraints; their engine
semantics remain unverified. This is not a control channel or DS.
Only empty packets are accepted; unknown control payloads are not acknowledged
as delivered. Client receive acceptance still requires a native trial.
"""
from dataclasses import dataclass

MASK = 0x3fff


@dataclass(frozen=True)
class PacketHeader:
    sequence: int
    acknowledged_sequence: int
    history: tuple[int, ...]
    remainder: int
    remainder_bits: int


def decode_packet(body: bytes) -> PacketHeader:
    if not isinstance(body, bytes) or not 10 <= len(body) <= 1492 or not body[-1]:
        raise ValueError('Unsupported bounded application packet')
    value = int.from_bytes(body, 'little')
    if value & 1:
        raise ValueError('Handshake packet is not an application packet')
    outer_end = value.bit_length() - 1
    inner = value & ((1 << outer_end) - 1)
    inner_end = inner.bit_length() - 1
    if inner_end != outer_end - 1:
        raise ValueError('Expected adjacent native termination bits')
    payload_bits = inner_end - 1
    packed = (value >> 1) & 0xffffffff
    words = (packed & 15) + 1
    header_bits = 32 + words * 32
    if words > 8 or payload_bits < header_bits + 9:
        raise ValueError('Invalid or truncated packet history')
    history = tuple((value >> (33 + i * 32)) & 0xffffffff for i in range(words))
    remaining = payload_bits - header_bits
    remainder = (value >> (1 + header_bits)) & ((1 << remaining) - 1)
    return PacketHeader((packed >> 18) & MASK, (packed >> 4) & MASK,
                        history, remainder, remaining)


def encode_empty_packet(sequence: int, acknowledged_sequence: int, history: int) -> bytes:
    if (type(sequence) is not int or type(acknowledged_sequence) is not int or
            type(history) is not int or not 0 <= sequence <= MASK or
            not 0 <= acknowledged_sequence <= MASK or not 0 <= history <= 0xffffffff):
        raise ValueError('Invalid bounded ACK fields')
    packed = (sequence << 18) | (acknowledged_sequence << 4)
    # One handler bit + header/history + nine zero metadata bits + two terminators.
    return ((packed << 1) | (history << 33) | (1 << 74) | (1 << 75)).to_bytes(10, 'little')


@dataclass
class PeerState:
    in_sequence: int
    out_sequence: int
    acknowledged_out_sequence: int
    history: int = 0
    replies: int = 0


class LegacyDSPacketAckProbe:
    def __init__(self, *, max_replies=128):
        if type(max_replies) is not int or not 1 <= max_replies <= 128:
            raise ValueError('Invalid bounded packet ACK reply limit')
        self.peers = {}
        self.max_replies = max_replies

    def register_verified_echo(self, peer, cookie):
        if (not isinstance(peer, tuple) or len(peer) != 2 or peer[0] != '127.0.0.1' or
                type(peer[1]) is not int or not 1 <= peer[1] <= 65535 or
                not isinstance(cookie, bytes) or len(cookie) != 20):
            raise ValueError('A verified loopback peer and fixed cookie are required')
        if peer not in self.peers:
            server_seed = int.from_bytes(cookie[0:2], 'little') & MASK
            client_seed = int.from_bytes(cookie[2:4], 'little') & MASK
            self.peers[peer] = PeerState((client_seed-1) & MASK, server_seed, (server_seed-1) & MASK)

    def handle(self, datagram, peer):
        state = self.peers.get(peer)
        if state is None:
            return 'application_without_verified_echo', None
        if not isinstance(datagram, bytes) or not 18 <= len(datagram) <= 1500:
            return 'application_shape_rejected', None
        try:
            packet = decode_packet(datagram[8:])
        except ValueError:
            return 'application_header_rejected', None
        delta = (packet.sequence - state.in_sequence) & MASK
        ack_delta = (packet.acknowledged_sequence - state.acknowledged_out_sequence) & MASK
        sent_delta = (state.out_sequence - state.acknowledged_out_sequence) & MASK
        if not 1 <= delta <= 32 or ack_delta >= sent_delta:
            return 'application_sequence_rejected', None
        peer_acked_reply = ack_delta > 0 and any(
            (packet.history[i // 32] >> (i % 32)) & 1
            for i in range(min(ack_delta, len(packet.history)*32)))
        empty = packet.remainder_bits == 9 and packet.remainder == 0
        state.in_sequence = packet.sequence
        state.history = ((state.history << delta) | int(empty)) & 0xffffffff
        state.acknowledged_out_sequence = packet.acknowledged_sequence
        if not empty:
            return 'control_payload_unimplemented', None
        if state.replies >= self.max_replies:
            return 'application_reply_limit_reached', None
        response = encode_empty_packet(state.out_sequence, state.in_sequence, state.history)
        state.out_sequence = (state.out_sequence + 1) & MASK
        state.replies += 1
        return ('empty_packet_ack_and_peer_delivery_observed' if peer_acked_reply
                else 'empty_packet_ack_prepared'), response

    def forget_peer(self, peer):
        self.peers.pop(peer, None)

    def rebind_verified_peer(self, old_peer, new_peer):
        """Move an already authenticated transport; never initialize its seeds.

        The handshake owner must authenticate the old cookie before calling
        this method and serialize access with its other connection operations.
        """
        if (not isinstance(new_peer, tuple) or len(new_peer) != 2 or
                new_peer[0] != '127.0.0.1' or type(new_peer[1]) is not int or
                not 1 <= new_peer[1] <= 65535 or old_peer == new_peer or
                old_peer not in self.peers or new_peer in self.peers):
            raise ValueError('An existing transport and unused loopback destination are required')
        self.peers[new_peer] = self.peers.pop(old_peer)
