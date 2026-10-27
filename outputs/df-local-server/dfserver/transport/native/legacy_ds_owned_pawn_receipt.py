"""Pure bounded receipt for the current admitted owning-Pawn Actor channel.

This adapter reuses PCReceiptLedger's generic reliable-bunch rules, never its
PC Actor-field framer. Complete and partial unknown bodies remain opaque. A
received result means local transport receipt only; the owning packet handler
must separately decide its packet ACK after every bunch has been received.

The caller supplies current admission/generation and actual delivery gates on
each call. A configured PC/Pawn association is sufficient for pure transport;
PC possession acknowledgement is not required and no gameplay is dispatched.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
from hashlib import sha256

from dfserver.transport.native.legacy_ds_pc_receipt import MAX_ASSEMBLY_BYTES, PCReceiptLedger
from dfserver.transport.native.legacy_ds_wire_codec import WireBunch

MAX_OPAQUE_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_OPAQUE_JOURNAL_ENTRIES = 512


@dataclass(frozen=True)
class OwnedPawnReceiptBinding:
    peer: tuple = field(repr=False)
    ticket: object = field(repr=False)
    generation: object = field(repr=False)
    transport: object = field(repr=False)
    admission_active: bool
    configured_owner_current: bool
    pawn_open_full_send_acknowledged: bool
    all_initial_content_acknowledged: bool


@dataclass(frozen=True)
class OpaquePawnReceipt:
    channel_sequence: int
    payload_bit_count: int
    payload_sha256: str
    partial: bool
    pending: bool
    ready_payload_sha256: str | None
    retained_bytes: int
    bunch: WireBunch = field(repr=False)
    ready: tuple[WireBunch, ...] = field(repr=False)
    gameplay_handled: bool = False


@dataclass(frozen=True)
class OwnedPawnReceiptResult:
    received: bool
    duplicate: bool
    pending: bool
    ready: tuple[WireBunch, ...] = field(repr=False)
    expected_sequence: int
    reason: str
    payload_sha256: str | None = None
    gameplay_handled: bool = False
    packet_ack_granted: bool = False


def _bounded_integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid owning-Pawn ' + label)
    return value


def _qualified_control(control, binding):
    # Import at call time so the control owner may import this pure adapter.
    from dfserver.transport.native.legacy_ds_control_connection import ActorOpenDelivery, ControlConnection
    if type(control) is not ControlConnection or type(binding) is not OwnedPawnReceiptBinding:
        raise ValueError('An actual current ControlConnection and explicit owning-Pawn binding are required')
    if (type(binding.peer) is not tuple or len(binding.peer) != 2 or
            type(binding.peer[0]) is not str or not 1 <= len(binding.peer[0]) <= 253 or
            type(binding.peer[1]) is not int or not 1 <= binding.peer[1] <= 65535 or
            any(value is None for value in (binding.ticket, binding.generation, binding.transport)) or
            not all(value is True for value in (binding.admission_active,
                binding.configured_owner_current, binding.pawn_open_full_send_acknowledged,
                binding.all_initial_content_acknowledged))):
        raise ValueError('The active admission, peer, generation and actual owning-Pawn delivery gates are required')
    if (control.ticket is not binding.ticket or control.pc_restart_ticket is not binding.ticket or
            control.client_closed is not False or control.client_join_observed is not True):
        raise ValueError('The configured owning-Pawn admission is foreign, closed or has not joined')
    sequence = _bounded_integer(control.hello_sequence, 0, 1023, 'trusted initial reliable sequence')
    pawn_channel = _bounded_integer(control.pc_restart_pawn_channel, 1, 0xffffffff, 'configured Pawn channel')
    pawn_guid = _bounded_integer(control.pc_restart_pawn_guid, 2, 0xffffffff, 'configured Pawn GUID')
    pc_channel = _bounded_integer(control.pc_restart_channel, 1, 0xffffffff, 'configured PC channel')
    pc_guid = _bounded_integer(control.pc_restart_actor_guid, 2, 0xffffffff, 'configured PC GUID')
    if pawn_guid & 1 or pc_guid & 1 or pc_guid == pawn_guid or pc_channel == pawn_channel:
        raise ValueError('The configured current PC and dynamic Pawn namespaces must be distinct')
    for channel, guid in ((pawn_channel, pawn_guid), (pc_channel, pc_guid)):
        opened = control.actor_opens.get(channel)
        if (type(opened) is not ActorOpenDelivery or opened.actor_guid != guid or
                opened.bunch.channel_index != channel or opened.delivered is not True):
            raise ValueError('The exact configured owning PC/Pawn Actor open must have a current delivery receipt')
    return sequence, pawn_channel, pawn_guid, pc_channel, pc_guid


class OwnedPawnReceiptAdapter:
    """One current owner lease; clone before tentatively receiving a whole packet."""
    def __init__(self, control_connection, *, binding, max_assembly_bytes=MAX_ASSEMBLY_BYTES,
            max_journal_bytes=262144, max_journal_entries=256, ordinary_transport=False):
        self._namespace = _qualified_control(control_connection, binding)
        self._binding = binding
        _bounded_integer(max_journal_bytes, 1, MAX_OPAQUE_JOURNAL_BYTES, 'opaque journal byte bound')
        _bounded_integer(max_journal_entries, 1, MAX_OPAQUE_JOURNAL_ENTRIES, 'opaque journal entry bound')
        initial_sequence, channel, _, _, _ = self._namespace
        if type(ordinary_transport) is not bool:
            raise ValueError('Explicit ordinary owning-Pawn transport mode is required')
        from dfserver.transport.native.legacy_ds_owned_actor_transport import OwnedActorReceiptLedger
        ledger_type = OwnedActorReceiptLedger if ordinary_transport else PCReceiptLedger
        self._ledger = ledger_type(channel, initial_sequence,
            max_assembly_bytes=max_assembly_bytes, window_size=min(max_journal_entries, 256))
        self.max_journal_bytes = max_journal_bytes
        self.max_journal_entries = max_journal_entries
        self._journal = OrderedDict()
        self._journal_bytes = 0

    @property
    def expected_sequence(self):
        return self._ledger.expected_sequence

    @property
    def channel_index(self):
        return self._namespace[1]

    @property
    def actor_guid(self):
        return self._namespace[2]

    @property
    def journal(self):
        return tuple(self._journal.values())

    @property
    def journal_bytes(self):
        return self._journal_bytes

    def clone(self):
        candidate = object.__new__(type(self))
        candidate._namespace = self._namespace
        candidate._binding = self._binding
        candidate._ledger = self._ledger.clone()
        candidate.max_journal_bytes = self.max_journal_bytes
        candidate.max_journal_entries = self.max_journal_entries
        candidate._journal = self._journal.copy()
        candidate._journal_bytes = self._journal_bytes
        return candidate

    def _current_owner(self, control_connection, binding):
        namespace = _qualified_control(control_connection, binding)
        original = self._binding
        if (namespace != self._namespace or binding.peer != original.peer or
                binding.ticket is not original.ticket or binding.generation is not original.generation or
                binding.transport is not original.transport):
            raise ValueError('The current owning-Pawn transport lease changed')

    def _result(self, received, duplicate, pending, ready, reason, payload_digest=None):
        return OwnedPawnReceiptResult(received, duplicate, pending, ready,
            self.expected_sequence, reason, payload_digest)

    def receive(self, bunch, *, control_connection, binding):
        """Atomically receipt one bounded wire bunch without parsing its body.

        The original adapter is changed only after owner, sequence, fragment and
        journal limits succeed. Repeated bytes can be receipted again but return
        no ready bodies and do not redispatch or create another journal entry.
        """
        try:
            self._current_owner(control_connection, binding)
        except (ValueError, AttributeError, TypeError):
            return self._result(False, False, False, (), 'owning_pawn_binding_not_current')
        candidate = self._ledger.clone()
        outcome = candidate.receive(bunch)
        if not outcome.received:
            return self._result(False, False, False, (), outcome.reason)
        payload_digest = sha256(bunch.payload).hexdigest()
        if outcome.duplicate:
            return self._result(True, True, False, (), outcome.reason, payload_digest)
        ready = outcome.ready
        pending = not ready and (bunch.partial or outcome.reason == 'reliable_queued')
        retained_bytes = len(bunch.payload) + sum(len(value.payload) for value in ready if value != bunch)
        if retained_bytes > self.max_journal_bytes:
            return self._result(False, False, False, (), 'opaque_journal_body_limit')
        entry = OpaquePawnReceipt(bunch.channel_sequence, bunch.payload_bits, payload_digest,
            bunch.partial, bool(pending), sha256(ready[0].payload).hexdigest() if ready else None,
            retained_bytes, bunch, ready)
        journal = self._journal.copy()
        journal_bytes = self._journal_bytes
        previous = journal.pop(bunch.channel_sequence, None)
        if previous is not None:
            journal_bytes -= previous.retained_bytes
        journal[bunch.channel_sequence] = entry
        journal_bytes += retained_bytes
        while len(journal) > self.max_journal_entries or journal_bytes > self.max_journal_bytes:
            _, expired = journal.popitem(last=False)
            journal_bytes -= expired.retained_bytes
        self._ledger, self._journal, self._journal_bytes = candidate, journal, journal_bytes
        return self._result(True, False, bool(pending), ready, outcome.reason, payload_digest)
