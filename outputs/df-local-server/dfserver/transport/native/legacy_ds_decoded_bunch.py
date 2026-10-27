"""Receive state for decoded bunches on the ordinary (non-internal-ACK) path.

Derived from version-pinned ReceivedRawBunch / ReceivedNextBunch samples in
work/native-client-tests/1790847786646593300/ds-native-control-code. The memory
flags below are semantic input flags, NOT their order in an on-wire header.
There is no UDP decoder, control-message dispatcher or actor replication here.
The transport probe must keep rejecting unknown payloads until those exist.

Connection-specific special open paths and GUID decoding are outside this
component. An export-bearing input requires the upstream GUID decoder to have
succeeded. The assembly byte limit is our local resource policy, not a claimed
native CVar value. Reliable sequences are signed 32-bit channel sequences,
independent of the candidate 14-bit packet sequences.
Errors in the current input fail-stop this local component. Native RawBunch
does not copy a queued input's IsError or skipACK back to the current packet;
queued native errors are diagnostic notices here. Local resource-limit errors
still stop processing as an explicitly local policy.
"""
from dataclasses import dataclass, replace


OPEN, CLOSE, RELIABLE = 0x01, 0x02, 0x10
PARTIAL, INITIAL, FINAL = 0x20, 0x40, 0x80


def next_sequence(value):
    value = (value + 1) & 0xffffffff
    return value if value < 0x80000000 else value - 0x100000000


@dataclass(frozen=True)
class DecodedBunch:
    sequence: int
    packet_id: int
    flags: int
    payload: bytes
    payload_bits: int
    has_exports: bool = False
    exports_processed: bool = False
    close_reason: int = 0
    extra_flag: bool = False

    def __post_init__(self):
        if (type(self.sequence) is not int or not -(1 << 31) <= self.sequence < 1 << 31 or
                type(self.packet_id) is not int or not -(1 << 31) <= self.packet_id < 1 << 31 or
                type(self.flags) is not int or not 0 <= self.flags <= 255 or
                not isinstance(self.payload, bytes) or type(self.payload_bits) is not int or
                not 0 <= self.payload_bits or len(self.payload) != (self.payload_bits + 7) // 8 or
                type(self.has_exports) is not bool or type(self.exports_processed) is not bool or
                type(self.extra_flag) is not bool or type(self.close_reason) is not int or
                not 0 <= self.close_reason <= 255):
            raise ValueError('Invalid decoded bunch fields')

    @property
    def reliable(self):
        return bool(self.flags & RELIABLE)


@dataclass(frozen=True)
class ReceiveResult:
    event: str
    ready: tuple[DecodedBunch, ...] = ()
    skip_ack: bool = False
    error: bool = False
    closed: bool = False
    notices: tuple[str, ...] = ()


class DecodedBunchReceiver:
    def __init__(self, *, in_reliable=0, opened=False, max_assembly_bytes=8192,
                 max_queued_reliable=256):
        if (type(in_reliable) is not int or not -(1 << 31) <= in_reliable < 1 << 31 or
                type(opened) is not bool or type(max_assembly_bytes) is not int or
                not 1 <= max_assembly_bytes <= 1024 * 1024 or
                type(max_queued_reliable) is not int or not 1 <= max_queued_reliable <= 256):
            raise ValueError('Invalid decoded receiver state or local resource bound')
        self.in_reliable = in_reliable
        self.opened, self.closed, self.failed = opened, False, False
        self.open_packet_range = None
        self.pending_partial = None
        self.queued_reliable = {}
        self.max_assembly_bytes = max_assembly_bytes
        self.max_queued_reliable = max_queued_reliable

    def _error(self, event, *, skip_ack=False):
        self.failed = True
        return ReceiveResult(event, error=True, skip_ack=skip_ack)

    def _append(self, pending, incoming):
        bits = pending.payload_bits + incoming.payload_bits
        if bits > self.max_assembly_bytes * 8:
            return None
        # Native non-final fragments are byte aligned; only the last may end
        # within a byte. Preserve the exact number of valid payload bits.
        value = int.from_bytes(pending.payload, 'little')
        if incoming.payload_bits:
            value |= ((int.from_bytes(incoming.payload, 'little') &
                       ((1 << incoming.payload_bits) - 1)) << pending.payload_bits)
        return replace(pending, payload=value.to_bytes((bits + 7) // 8, 'little'),
                       payload_bits=bits, sequence=incoming.sequence)

    def _next(self, incoming):
        if incoming.reliable:
            # This precedes partial/open validation in the observed native body.
            self.in_reliable = incoming.sequence
        ready = incoming
        if incoming.flags & PARTIAL:
            pending = self.pending_partial
            if incoming.flags & INITIAL:
                if pending and not pending.flags & FINAL and pending.reliable:
                    if incoming.reliable:
                        return self._error('reliable_partial_initial_conflict')
                    return ReceiveResult('unreliable_initial_keeps_reliable_partial', skip_ack=True)
                if incoming.flags & FINAL:
                    return ReceiveResult('initial_and_final_combination_unimplemented', skip_ack=True)
                self.pending_partial = None
                if not incoming.has_exports and incoming.payload_bits % 8:
                    return self._error('partial_initial_not_byte_aligned')
                if incoming.payload_bits > self.max_assembly_bytes * 8:
                    return self._error('local_assembly_limit')
                self.pending_partial = (replace(incoming, payload=b'', payload_bits=0)
                                        if incoming.has_exports else incoming)
                return ReceiveResult('partial_initial_retained')
            valid = bool(pending and not pending.flags & FINAL and
                         pending.reliable == incoming.reliable and
                         incoming.sequence == next_sequence(pending.sequence))
            if (pending and not pending.reliable and not incoming.reliable and
                    not pending.flags & FINAL and incoming.sequence == pending.sequence):
                valid = True
            if not valid:
                if pending and pending.reliable and incoming.reliable:
                    return self._error('reliable_partial_sequence_or_shape_conflict', skip_ack=True)
                if not (pending and pending.reliable):
                    self.pending_partial = None
                return ReceiveResult('partial_continuation_rejected', skip_ack=True)
            if incoming.flags & FINAL and incoming.has_exports:
                return self._error('partial_final_has_exports')
            if (not incoming.flags & FINAL and not incoming.has_exports and
                    incoming.payload_bits % 8):
                return self._error('partial_continuation_not_byte_aligned')
            if incoming.has_exports:
                pending = replace(pending, sequence=incoming.sequence)
            else:
                pending = self._append(pending, incoming)
                if pending is None:
                    return self._error('local_assembly_limit')
            self.pending_partial = pending
            if not incoming.flags & FINAL:
                return ReceiveResult('partial_continuation_retained')
            # Keep initial/open/reliable flags; propagate native final flags,
            # close reason and the extra bit without guessing its enum name.
            pending = replace(pending, flags=(pending.flags & ~0x0e) |
                              (incoming.flags & 0x0e) | FINAL,
                              close_reason=incoming.close_reason, extra_flag=incoming.extra_flag)
            self.pending_partial = pending
            ready = pending
        if ready.flags & OPEN:
            if self.open_packet_range is not None:
                return self._error('channel_open_range_already_recorded')
            self.open_packet_range = (ready.packet_id, incoming.packet_id)
            self.opened = True
        if not self.opened:
            if ready.reliable:
                return self._error('reliable_bunch_before_channel_open')
            return ReceiveResult('unreliable_bunch_before_channel_open', skip_ack=True)
        if ready.flags & CLOSE:
            self.closed = True
        return ReceiveResult('bunch_ready', (ready,), closed=self.closed)

    def receive(self, incoming):
        if not isinstance(incoming, DecodedBunch):
            raise TypeError('An upstream decoder must supply DecodedBunch')
        if self.failed or self.closed:
            return ReceiveResult('channel_unavailable', error=self.failed, closed=self.closed)
        if incoming.has_exports and not incoming.exports_processed:
            return ReceiveResult('guid_exports_unimplemented', skip_ack=True)
        if incoming.payload_bits > self.max_assembly_bytes * 8:
            return self._error('local_assembly_limit')
        if incoming.reliable and incoming.sequence != next_sequence(self.in_reliable):
            if incoming.sequence in self.queued_reliable:
                return ReceiveResult('queued_sequence_duplicate')
            self.queued_reliable[incoming.sequence] = incoming
            if len(self.queued_reliable) >= self.max_queued_reliable:
                return self._error('reliable_queue_limit')
            return ReceiveResult('reliable_bunch_queued')
        result = self._next(incoming)
        ready, notices = list(result.ready), []
        current_skip_ack = result.skip_ack
        while self.queued_reliable and not (result.error or result.closed):
            # Native RawBunch checks the head of its signed-order list. An old
            # sequence that escaped the upstream filter must not be skipped.
            head = min(self.queued_reliable)
            if head != next_sequence(self.in_reliable):
                break
            queued = self.queued_reliable.pop(head)
            result = self._next(queued)
            ready.extend(result.ready)
            if result.error and result.event != 'local_assembly_limit':
                # RawBunch inspects the original input's IsError, not this
                # queued object's flag; avoid falsely rejecting the current
                # packet or stopping its subsequent queue drain.
                notices.append('queued_bunch_error:' + result.event)
                self.failed = False
                result = replace(result, error=False)
            if result.skip_ack:
                # This message was already acknowledged when queued; the caller
                # cannot retroactively NAK that earlier packet. Native RawBunch
                # logs the local warning, without manufacturing a fatal error.
                notices.append('queued_bunch_requested_skip_ack')
                result = replace(result, skip_ack=False)
        return replace(result, ready=tuple(ready), skip_ack=current_skip_ack, notices=tuple(notices))
