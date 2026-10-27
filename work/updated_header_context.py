"""Callback-only observation of two guarded current Actor-header gate bytes.

Only four fixed image spans are read. The caller owns process/image identity
and callback deadlines. Repeated reads detect changes, not an atomic snapshot;
a successful zero gate is not native gameplay or connection qualification.
"""
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
IMAGE_BYTES = 536408064
HEADER_CONTEXT = 'work/research_updated_header_context_79fb7b10_v1.json'
HEADER_CONTEXT_SHA256 = '8cda6a07e1875045f380dbe86a3d854fd6ab4bd19af09f6f1d6f81d3051a2e53'
HEADER_CELLS = 'work/research_updated_header_cells_79fb7b10_v3.json'
HEADER_CELLS_SHA256 = 'b0c98f1a378bca8b1c98a38cdc9a973f4c8318bc5691171133a354890baac2d8'
CELLS = (('global_hook_enable', 0x1de36180), ('alternate_actor_channel', 0x1e322935))
GUARDS = ((0x4e24db6, bytes.fromhex('803dc313011900488bd97423')),
          (0x4977e22, bytes.fromhex('803d0cab9a1900488bd7488bcb740b488b03ff9050030000eb05e8ef96ee0d')))
MAX_READ_CALLS = 12
MAX_READ_BYTES = 135
_MISSING = object()


def _instructions(rows, first, size):
    by_rva = {int(row['rva'], 16): row for row in rows}
    at, parts = first, []
    while at < first + size:
        raw = bytes.fromhex(by_rva[at]['bytes_hex'])
        if not raw or at + len(raw) > first + size:
            raise ValueError('Header source instruction span is incomplete')
        parts.append(raw)
        at += len(raw)
    return b''.join(parts)


def _proof(path, digest, kind):
    source = ROOT / path
    if not 0 < source.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError('Header context proof exceeds its source bound')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Header context proof SHA changed')
    document = json.loads(raw)
    if (document.get('kind') != kind or document.get('client_sha256') != SOURCE_SHA256 or
            document.get('native_engine_function_called') is not False or
            document.get('process_opened') is not False):
        raise ValueError('Header context proof identity or scope changed')
    return document


def source_pins():
    """Validate both sealed proofs and return their pins plus this reader module."""
    if (CELLS != (('global_hook_enable', 0x1de36180), ('alternate_actor_channel', 0x1e322935)) or
            type(GUARDS) is not tuple or len(GUARDS) != 2 or
            tuple((rva, len(raw)) for rva, raw in GUARDS) != ((0x4e24db6, 12), (0x4977e22, 31))):
        raise ValueError('Header context fixed source read spans changed')
    try:
        context = _proof(HEADER_CONTEXT, HEADER_CONTEXT_SHA256, 'current_source_actor_header_dispatch_context')
        cells = _proof(HEADER_CELLS, HEADER_CELLS_SHA256, 'current_pawn_header_mutable_gate_cells_source_inventory')
        gate = context['minimum_additional_runtime_gate']
        expected = [dict(rva=hex(rva), bytes=1, required_value=0) for _, rva in CELLS]
        if (gate['reads'] != expected or gate['pawn_per_hook_state_read_required_when_global_zero'] is not False or
                gate['no_native_calls'] is not True or context['source_derived_header_contract_compiled'] is not True):
            raise ValueError('Header context source gate changed')
        pawn, = [f for f in cells['native_functions'] if f['entry_rva'] == '0x4e24db0']
        channel, = [f for f in context['functions'] if f['name'] == 'game_channel_process_bunch']
        if (pawn['complete_unwind_coverage'] is not True or channel['new_rva'] != '0x4977dc0' or
                channel['full_linear_decode'] is not True or
                channel['all_non_reference_instruction_bytes_identical'] is not True):
            raise ValueError('Header gate complete function qualification changed')
        pawn_rows = [row for part in pawn['fragments'] for row in part['instructions']]
        for rows, (rva, raw) in zip((pawn_rows, channel['decoded_new_instructions']), GUARDS):
            if _instructions(rows, rva, len(raw)) != raw:
                raise ValueError('Header gate source instruction guard changed')
        if (cells['minimum_observation']['code_guards'][0]['bytes_hex'] != GUARDS[0][1][:7].hex() or
                context['alternate_channel_gate']['instruction']['rip_targets'] != ['0x1e322935'] or
                context['alternate_channel_gate']['required_ordinary_value'] != 0):
            raise ValueError('Header gate source cell binding changed')
    except (KeyError, TypeError, StopIteration) as error:
        raise ValueError('Header context proof is incomplete') from error
    module = Path(__file__).resolve()
    if module != ROOT / 'work/updated_header_context.py' or not 0 < module.stat().st_size <= 1024 * 1024:
        raise ValueError('Header context module source path or bound changed')
    return {HEADER_CONTEXT: HEADER_CONTEXT_SHA256, HEADER_CELLS: HEADER_CELLS_SHA256,
            'work/updated_header_context.py': hashlib.sha256(module.read_bytes()).hexdigest()}


class _BackendIdentity:
    """Freeze exposed callback/session/reader identity without reading process data."""
    def __init__(self, callback, base):
        self.attributes, self.methods = [], []
        pending, seen = [callback], set()
        while pending:
            target = pending.pop()
            if id(target) in seen:
                continue
            if len(seen) >= 16:
                raise ValueError('Header callback backend identity chain exceeds bound')
            seen.add(id(target))
            owner, function = getattr(target, '__self__', None), getattr(target, '__func__', None)
            if owner is not None and function is not None:
                self.methods.append((owner, target.__name__, function))
                pending.append(owner)
            for name in ('base', 'module_base', 'backend'):
                value = getattr(target, name, _MISSING)
                if value is not _MISSING:
                    if name == 'backend':
                        if not callable(value):
                            raise ValueError('Header callback backend identity is not callable')
                        pending.append(value)
                    elif type(value) is not int or value != base:
                        raise ValueError('Header callback module base identity disagrees')
                self.attributes.append((target, name, value))
        self.check()

    def check(self):
        for target, name, expected in self.attributes:
            current = getattr(target, name, _MISSING)
            if name != 'backend' and expected is not _MISSING:
                changed = type(current) is not int or current != expected
            else:
                changed = current is not expected
            if changed:
                raise ValueError('Header callback base/backend identity changed')
        for owner, name, function in self.methods:
            current = getattr(owner, name, None)
            if getattr(current, '__self__', None) is not owner or getattr(current, '__func__', None) is not function:
                raise ValueError('Header callback method/backend identity changed')


def read_header_context(read_exact, module_base, *, client_sha256):
    """Observe the two cells with two full recheck passes; never enable a sender.

    Exposed callback/session base and backend identities are rechecked. Opaque
    closure state and the actual process identity remain caller-owned.
    """
    if (type(client_sha256) is not str or client_sha256 != SOURCE_SHA256 or not callable(read_exact) or
            type(module_base) is not int or module_base < 0x10000 or module_base & 0xffff or
            module_base + IMAGE_BYTES > (1 << 47)):
        raise ValueError('An exact current client SHA, callback and aligned bounded module base are required')
    guards, cells = tuple(GUARDS), tuple(CELLS)
    pins_function = source_pins
    pins = pins_function()
    identity = _BackendIdentity(read_exact, module_base)
    allowed = {(module_base + rva, len(raw)) for rva, raw in guards}
    allowed.update((module_base + rva, 1) for _, rva in cells)
    calls = total = 0

    def read(rva, size):
        nonlocal calls, total
        if source_pins is not pins_function:
            raise ValueError('Header context source pin callback changed')
        identity.check()
        address = module_base + rva
        if ((address, size) not in allowed or calls >= MAX_READ_CALLS or total + size > MAX_READ_BYTES):
            raise ValueError('Unqualified header context read or exhausted fixed read bound')
        calls += 1
        total += size
        try:
            raw = read_exact(address, size)
        except Exception as error:
            raise ValueError('Unavailable exact header context callback read') from error
        identity.check()
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('Incomplete or mutable header context callback bytes')
        return raw

    for rva, raw in guards:
        if read(rva, len(raw)) != raw:
            raise ValueError('Current header instruction guard changed')
    values = {name: read(rva, 1)[0] for name, rva in cells}
    for _ in range(2):
        for rva, raw in guards:
            if read(rva, len(raw)) != raw:
                raise ValueError('Current header instruction guard changed during recheck')
        for name, rva in cells:
            if read(rva, 1)[0] != values[name]:
                raise ValueError('Header context mutable byte changed during recheck')
    identity.check()
    if source_pins is not pins_function or pins_function() != pins:
        raise ValueError('Header context source pins changed during observation')
    zero = all(value == 0 for value in values.values())
    return dict(kind='updated_header_context_observation', client_sha256=client_sha256,
        status='observed_zero_gates' if zero else 'observed_nonzero_gate_refused', values=values,
        cells=[dict(name=name, rva=hex(rva), bytes=1, value=values[name]) for name, rva in cells],
        zero_gate_qualified=zero, source_instructions_rechecked=True, backend_identity_rechecked=True,
        source_pins=pins, read_calls=calls, read_bytes=total, atomic_snapshot=False,
        process_identity_verified=False, native_function_called=False, native_gameplay_qualified=False,
        runtime_profile_activated=False)
