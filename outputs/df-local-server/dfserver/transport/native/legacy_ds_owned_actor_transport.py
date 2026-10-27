"""Opaque transport receipt for explicitly admitted, already opened Actors.

Ordinary unreliable bunches do not advance InReliable. Future reliable bunches
are retained until their gap is filled, following ReceivedRawBunch's queue in
protocol/decoded_bunch_receiver_evidence.json (native body SHA256 06c81120e891c6a4
ef02a408fc5bf19271f0419d9521316ebcfaebca2dd00773). Wire sequences use the codec's
ten-bit modulus; the forward window, byte caps and atomic failure are local
policies. No unknown RPC is executed. Export/open/close/partial-unreliable
semantics remain outside this bounded transport subset.
"""
from dfserver.transport.native.legacy_ds_pc_receipt import MAX_ASSEMBLY_BYTES, PCReceiptLedger, _digest, _integer, _ordinary_actor_bunch
from dfserver.transport.native.legacy_ds_wire_codec import WireBunch


def plain_unreliable_actor(bunch, *, channel_index, max_payload_bytes=MAX_ASSEMBLY_BYTES):
    """Validate a complete opaque body on an already qualified Actor channel."""
    if (type(bunch) is not WireBunch or type(bunch.channel_index) is not int or
            bunch.channel_index != channel_index or bunch.channel_name is not None or
            bunch.channel_sequence is not None or type(bunch.close_reason) is not int or
            bunch.close_reason != 0):
        raise ValueError('Invalid ordinary unreliable Actor header')
    for name in ('reliable', 'open', 'close', 'flag4', 'connection_flag',
            'package_exports', 'must_be_mapped', 'partial', 'partial_initial', 'partial_final'):
        if getattr(bunch, name) is not False:
            raise ValueError('Unsupported unreliable Actor flags')
    if (type(bunch.payload_bits) is not int or
            not 0 <= bunch.payload_bits <= max_payload_bytes * 8 or
            type(bunch.payload) is not bytes or
            len(bunch.payload) != (bunch.payload_bits + 7) // 8 or
            int.from_bytes(bunch.payload, 'little') >> bunch.payload_bits):
        raise ValueError('Invalid exact unreliable Actor payload')


class OwnedActorReceiptLedger(PCReceiptLedger):
    def __init__(self, channel_index, initial_sequence, *, window_size=256,
            max_assembly_bytes=MAX_ASSEMBLY_BYTES, max_queued_reliable=256,
            max_queued_bytes=262144):
        super().__init__(channel_index, initial_sequence, window_size=window_size,
            max_assembly_bytes=max_assembly_bytes)
        _integer(max_queued_reliable, 1, 256, 'owned Actor queued bunch limit')
        _integer(max_queued_bytes, 1, 8 * 1024 * 1024, 'owned Actor queued byte limit')
        self.max_queued_reliable, self.max_queued_bytes = max_queued_reliable, max_queued_bytes
        self._future = {}
        self._future_bytes = 0

    @property
    def queued_count(self):
        return len(self._future)

    @classmethod
    def from_ledger(cls, ledger):
        if isinstance(ledger, cls):
            return ledger.clone()
        if type(ledger) is not PCReceiptLedger:
            raise ValueError('An actual trusted startup receipt ledger is required')
        result = cls(ledger.channel_index, ledger.expected_sequence,
            window_size=ledger.window_size, max_assembly_bytes=ledger.max_assembly_bytes)
        result._history, result._pending = ledger._history.copy(), ledger._pending
        return result

    def clone(self):
        result = type(self)(self.channel_index, self.expected_sequence,
            window_size=self.window_size, max_assembly_bytes=self.max_assembly_bytes,
            max_queued_reliable=self.max_queued_reliable, max_queued_bytes=self.max_queued_bytes)
        result._history, result._pending = self._history.copy(), self._pending
        result._future, result._future_bytes = self._future.copy(), self._future_bytes
        return result

    def receive(self, bunch):
        if isinstance(bunch, WireBunch) and not bunch.reliable:
            try:
                plain_unreliable_actor(bunch, channel_index=self.channel_index,
                    max_payload_bytes=self.max_assembly_bytes)
            except ValueError:
                return self._result(False, False, (), 'unsupported_or_malformed_bunch')
            return self._result(True, False, (bunch,), 'unreliable_received')
        try:
            _ordinary_actor_bunch(bunch, channel_index=self.channel_index)
        except ValueError:
            return self._result(False, False, (), 'unsupported_or_malformed_bunch')
        sequence = bunch.channel_sequence
        if sequence != self.expected_sequence:
            if sequence in self._history:
                return super().receive(bunch)
            previous = self._future.get(sequence)
            if previous is not None:
                if _digest(previous) != _digest(bunch):
                    return self._result(False, False, (), 'conflicting_reliable_digest')
                return self._result(True, True, (), 'reliable_queued_duplicate')
            distance = (sequence - self.expected_sequence) & 1023
            if not 0 < distance < 256:
                return self._result(False, False, (), 'nonconsecutive_sequence')
            if (bunch.payload_bits > self.max_assembly_bytes * 8 or
                    self._future_bytes + len(bunch.payload) > self.max_queued_bytes or
                    len(self._future) >= self.max_queued_reliable):
                return self._result(False, False, (), 'reliable_queue_limit')
            if bunch.partial and (bunch.partial_initial and bunch.partial_final or
                    not bunch.partial_final and bunch.payload_bits % 8):
                return self._result(False, False, (), 'unsupported_or_malformed_bunch')
            self._future[sequence] = bunch
            self._future_bytes += len(bunch.payload)
            return self._result(True, False, (), 'reliable_queued')
        candidate = self.clone()
        outcome = PCReceiptLedger.receive(candidate, bunch)
        if not outcome.received:
            return self._result(False, False, (), outcome.reason)
        ready = list(outcome.ready)
        while candidate.expected_sequence in candidate._future:
            pending = candidate._future.pop(candidate.expected_sequence)
            candidate._future_bytes -= len(pending.payload)
            drained = PCReceiptLedger.receive(candidate, pending)
            if not drained.received:
                return self._result(False, False, (), drained.reason)
            ready.extend(drained.ready)
        self._history, self._pending = candidate._history, candidate._pending
        self._future, self._future_bytes = candidate._future, candidate._future_bytes
        self.expected_sequence = candidate.expected_sequence
        return self._result(True, False, tuple(ready), outcome.reason)
