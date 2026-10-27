"""Bounded receipt of an already admitted, opened PC Actor channel.

This ledger records actual ten-bit reliable wire sequences. Its initial_sequence
is the first EXPECTED sequence, supplied only after the caller qualifies the
channel. Receipt is separate from RPC dispatch and never grants a packet ACK.

Partial rules follow legacy_ds_decoded_bunch's pinned ReceivedNextBunch source:
non-final ordinary fragments are byte aligned, continuation sequences are
consecutive, and only the final fragment may end within a byte. The 32 KiB
assembly budget, retry window, atomic rejection and absence of a future-sequence
queue are local policies. No unknown RPC is interpreted here.
"""

from collections import OrderedDict
from dataclasses import dataclass, replace
from hashlib import sha256
import struct

from dfserver.replication.legacy_ds_actor_fields import ClassFieldEnvelope
from dfserver.transport.native.legacy_ds_bit_archive import BitReader, UINT32_MAX
from dfserver.transport.native.legacy_ds_wire_codec import ChannelName, WireBunch


MAX_ASSEMBLY_BYTES = 32768
MAX_ASSEMBLY_BITS = MAX_ASSEMBLY_BYTES * 8
RECEIPT_WINDOW = 256
MAX_ENVELOPES = 256
ACTOR_NAME = ChannelName(hardcoded_index=102)


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid ' + label)


class PCReceiptReader(BitReader):
    """A local large-body reader for opaque envelopes, not semantic codecs."""

    def __init__(self, data, *, bit_count=None):
        if not isinstance(data, bytes) or len(data) > MAX_ASSEMBLY_BYTES:
            raise ValueError('Invalid bounded PC receipt archive')
        if bit_count is None:
            bit_count = len(data) * 8
        _integer(bit_count, 0, len(data) * 8, 'PC receipt bit count')
        self._value = int.from_bytes(data, 'little')
        self.bit_count, self.position = bit_count, 0

    def read_bits(self, count):
        _integer(count, 0, MAX_ASSEMBLY_BITS, 'PC receipt read bit count')
        if count > self.remaining:
            raise ValueError('Truncated PC receipt archive')
        result = (self._value >> self.position) & ((1 << count) - 1)
        self.position += count
        return result

    def read_bytes(self, count):
        _integer(count, 0, MAX_ASSEMBLY_BYTES, 'PC receipt read byte count')
        return self.read_bits(count * 8).to_bytes(count, 'little')


def _ordinary_actor_bunch(bunch, *, channel_index=None):
    if not isinstance(bunch, WireBunch):
        raise ValueError('A decoded WireBunch is required')
    _integer(bunch.channel_index, 0, UINT32_MAX, 'PC channel index')
    if channel_index is not None and bunch.channel_index != channel_index:
        raise ValueError('PC channel mismatch')
    for key in ('open', 'close', 'flag4', 'reliable', 'connection_flag',
                'package_exports', 'must_be_mapped', 'partial',
                'partial_initial', 'partial_final'):
        if type(getattr(bunch, key)) is not bool:
            raise ValueError('Explicit bunch booleans are required')
    name = bunch.channel_name
    if (not isinstance(name, ChannelName) or
            type(name.hardcoded_index) is not int or name.hardcoded_index != 102 or
            name.text is not None or type(name.number) is not int or name.number != 0):
        raise ValueError('An explicit Actor channel name is required')
    if (not bunch.reliable or
            bunch.open or bunch.close or bunch.flag4 or bunch.connection_flag or
            bunch.package_exports or bunch.must_be_mapped or
            type(bunch.close_reason) is not int or bunch.close_reason != 0):
        raise ValueError('Unsupported PC receipt bunch profile')
    _integer(bunch.channel_sequence, 0, 1023, 'ten-bit reliable sequence')
    _integer(bunch.payload_bits, 0, MAX_ASSEMBLY_BITS, 'PC receipt payload bits')
    if (not isinstance(bunch.payload, bytes) or
            len(bunch.payload) != (bunch.payload_bits + 7) // 8 or
            int.from_bytes(bunch.payload, 'little') >> bunch.payload_bits):
        raise ValueError('Invalid exact PC receipt payload')
    if not bunch.partial and (bunch.partial_initial or bunch.partial_final):
        raise ValueError('Partial endpoints require a partial bunch')


def _digest(bunch):
    # Cursor positions describe a containing packet, not the reliable content.
    flags = (int(bunch.partial) | (int(bunch.partial_initial) << 1) |
             (int(bunch.partial_final) << 2))
    return sha256(struct.pack('<IHIB', bunch.channel_index, bunch.channel_sequence,
                              bunch.payload_bits, flags) + bunch.payload).digest()


@dataclass(frozen=True)
class PCReceiptResult:
    received: bool
    duplicate: bool
    ready: tuple[WireBunch, ...]
    expected_sequence: int
    reason: str


class PCReceiptLedger:
    def __init__(self, channel_index, initial_sequence, *,
                 window_size=RECEIPT_WINDOW, max_assembly_bytes=MAX_ASSEMBLY_BYTES):
        _integer(channel_index, 0, UINT32_MAX, 'PC channel index')
        _integer(initial_sequence, 0, 1023, 'initial expected sequence')
        # A window shorter than half the wire modulus cannot retain a previous
        # generation of the same sequence when it becomes expected again.
        _integer(window_size, 1, 512, 'PC receipt retry window')
        _integer(max_assembly_bytes, 1, MAX_ASSEMBLY_BYTES, 'PC assembly byte bound')
        self.channel_index = channel_index
        self.expected_sequence = initial_sequence
        self.window_size, self.max_assembly_bytes = window_size, max_assembly_bytes
        self._history = OrderedDict()
        self._pending = None

    def clone(self):
        cloned = PCReceiptLedger(self.channel_index, self.expected_sequence,
                                 window_size=self.window_size,
                                 max_assembly_bytes=self.max_assembly_bytes)
        cloned._history = self._history.copy()
        # WireBunch, its bytes and all stored history tuples are immutable.
        cloned._pending = self._pending
        return cloned

    def _result(self, received, duplicate, ready, reason):
        return PCReceiptResult(received, duplicate, ready, self.expected_sequence, reason)

    def receive(self, bunch):
        try:
            _ordinary_actor_bunch(bunch, channel_index=self.channel_index)
        except ValueError:
            return self._result(False, False, (), 'unsupported_or_malformed_bunch')
        sequence, digest = bunch.channel_sequence, _digest(bunch)
        # Fresh expected input takes precedence over retry lookup at wire wrap.
        if sequence != self.expected_sequence:
            previous = self._history.get(sequence)
            if previous is None:
                return self._result(False, False, (), 'nonconsecutive_sequence')
            if digest != previous[0]:
                return self._result(False, False, (), 'conflicting_reliable_digest')
            # Replaying a fragment cannot rebuild or redispatch an assembly.
            ready = () if previous[1].partial else (previous[1],)
            return self._result(True, True, ready, 'reliable_duplicate')

        pending, ready = self._pending, ()
        if bunch.payload_bits > self.max_assembly_bytes * 8:
            return self._result(False, False, (), 'assembly_limit')
        if bunch.partial:
            if bunch.partial_initial:
                if bunch.partial_final or pending is not None:
                    return self._result(False, False, (), 'partial_initial_conflict')
                if bunch.payload_bits % 8:
                    return self._result(False, False, (), 'partial_nonfinal_not_byte_aligned')
                pending = bunch
            else:
                if pending is None:
                    return self._result(False, False, (), 'partial_without_initial')
                if not bunch.partial_final and bunch.payload_bits % 8:
                    return self._result(False, False, (), 'partial_nonfinal_not_byte_aligned')
                bits = pending.payload_bits + bunch.payload_bits
                if bits > self.max_assembly_bytes * 8:
                    return self._result(False, False, (), 'assembly_limit')
                value = (int.from_bytes(pending.payload, 'little') |
                         (int.from_bytes(bunch.payload, 'little') << pending.payload_bits))
                assembled = replace(pending, payload=value.to_bytes((bits + 7) // 8, 'little'),
                                    payload_bits=bits, channel_sequence=sequence,
                                    header_start_bit=None, payload_start_bit=None)
                if bunch.partial_final:
                    ready = (replace(assembled, partial=False, partial_initial=False,
                                     partial_final=False),)
                    pending = None
                else:
                    pending = assembled
        else:
            if pending is not None:
                return self._result(False, False, (), 'unfinished_partial_conflict')
            ready = (bunch,)

        # All validation and assembly above finish before committing a receipt.
        self._pending = pending
        self._history[sequence] = (digest, bunch)
        while len(self._history) > self.window_size:
            self._history.popitem(last=False)
        self.expected_sequence = (sequence + 1) & 1023
        return self._result(True, False, ready, 'bunch_ready' if ready else 'partial_retained')


def bounded_actor_fields(bunch, *, exclusive_index_maximum=245):
    """Frame all ordinary Actor fields atomically, with their bodies opaque.

    Field grammar is pinned by native-actor-replicator-first-body-envelope.json;
    block grammar by native-actor-content-block-envelope.json. Index maximum
    must be the caller's qualified current ClassNetCache value. Neither the
    returned indices nor a large body's framing certify an RPC signature.
    """
    _ordinary_actor_bunch(bunch)
    if bunch.partial:
        raise ValueError('PC framing requires a completed bunch')
    _integer(exclusive_index_maximum, 1, UINT32_MAX, 'class-cache exclusive maximum')
    reader = PCReceiptReader(bunch.payload, bit_count=bunch.payload_bits)
    fields, blocks = [], 0
    while reader.remaining:
        blocks += 1
        if blocks > MAX_ENVELOPES:
            raise ValueError('PC Actor block limit')
        if reader.read_bool():
            raise ValueError('RepLayout PC blocks remain unsupported')
        if not reader.read_bool():
            raise ValueError('Subobject PC blocks remain unsupported')
        length = reader.read_packed_int()
        body = PCReceiptReader(reader.read_payload(length), bit_count=length)
        while body.remaining:
            if len(fields) >= MAX_ENVELOPES:
                raise ValueError('PC class-field limit')
            index = body.read_bounded_int(exclusive_index_maximum)
            bits = body.read_packed_int()
            fields.append(ClassFieldEnvelope(index, body.read_payload(bits), bits))
    return tuple(fields)
