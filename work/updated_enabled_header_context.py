"""Observe the sealed enabled Actor route through a caller-owned read callback.

This module opens no process and invokes no engine function. The caller owns
actual process/image verification and read deadlines. An intact source-native
wire route is distinct from delivery timing, Actor creation and gameplay.
"""
import hashlib
import json
from pathlib import Path

from updated_header_context import _BackendIdentity


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'
IMAGE_BYTES = 536408064
PROOF = 'work/evidence/updated-enabled-actor-receiver-79fb7b10-v3.json'
PROOF_SHA256 = '09ca979cf1edcb49540aa89b7a88a4d94c123b4cb1cf6a7abd663f031caf7869'
IDENTITY_HELPER = 'work/updated_header_context.py'
IDENTITY_HELPER_SHA256 = '95d4337e2b46016ce0efc09e75ba7bfe9bbba14c83ed2259005aec45b7fe1fe1'
TOP_CELLS = (('global_hook_enable', 0x1de36180), ('alternate_actor_channel', 0x1e322935))
TOP_GUARDS = ((0x4e24db6, bytes.fromhex('803dc313011900488bd97423')),
              (0x4977e22, bytes.fromhex('803d0cab9a1900488bd7488bcb740b488b03ff9050030000eb05e8ef96ee0d')))
HOOK_RANGES = ((0x1de37012, 10), (0x1de3701e, 2), (0x1de3702f, 2),
    (0x1de37033, 1), (0x1de37035, 1), (0x1de37039, 1), (0x1de3703b, 9),
    (0x1de3704a, 5), (0x1de37059, 1), (0x1de39cf9, 1), (0x1de39d25, 2),
    (0x1de3a61c, 1), (0x1de3a61e, 1))
MAX_READ_CALLS = 309
MAX_READ_BYTES = 1944
_PRODUCERS = {
    'work/research_updated_enabled_header.py': 'd86a556c3ff9792790bd9196a3c48e23439c585f64dc5d562005b6d34a43b7cf',
    'work/research_updated_enabled_header_test.py': '774cc137243d13887a107b5a3c3fe71209c99b225346c899804db4f19688f8f5',
    'work/research_updated_native_registration.py': 'f353be3a12323d7343bf1ab66e956a5136386867db810d7dcdcc8d3627e806aa',
    'work/research_updated_replication_core.py': '3f9938b62167eba78650c869261f9e6e76f2e8582e058134d9f2739ca5af7c83',
}


def _sealed(path, digest):
    source = ROOT / path
    if not 0 < source.stat().st_size <= 32 * 1024 * 1024:
        raise ValueError('Enabled header source exceeds its fixed byte bound')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Enabled header proof/helper source SHA changed')
    return raw


def _sources_and_plan():
    proof = json.loads(_sealed(PROOF, PROOF_SHA256))
    if (proof.get('kind') != 'current_actual_enabled_actor_receiver_source_contract' or
            proof.get('client_sha256') != SOURCE_SHA256 or proof.get('source_pins') != _PRODUCERS or
            any(proof.get(key) is not False for key in ('process_opened', 'native_engine_function_called',
                'process_memory_written', 'profile_activated', 'native_acceptance_verified'))):
        raise ValueError('Enabled header proof identity/scope changed')
    pins = {PROOF: PROOF_SHA256, IDENTITY_HELPER: IDENTITY_HELPER_SHA256, **_PRODUCERS}
    for path, digest in pins.items():
        if path != PROOF:
            _sealed(path, digest)
    scope = proof['hook_gate_scope']
    cells = scope['required_quiet_cells']
    ranges = tuple((int(row['rva'], 16), row['bytes']) for row in scope['exact_read_ranges'])
    hooks = tuple(int(row['rva'], 16) for row in cells)
    expected_hooks = tuple(rva for start, size in ranges for rva in range(start, start + size))
    if (ranges != HOOK_RANGES or len(ranges) != 13 or sum(size for _, size in ranges) != 37 or
            scope['bytes_to_read'] != 37 or len(cells) != 37 or hooks != expected_hooks or
            len(set(hooks)) != 37 or scope['table_rva'] != '0x1de36180' or
            scope['registered_bytes'] != 0x8f56 or scope['registered_group_id'] != 11 or
            TOP_CELLS != (('global_hook_enable', 0x1de36180), ('alternate_actor_channel', 0x1e322935))):
        raise ValueError('Enabled header fixed sparse hook ranges changed')
    wire = proof['wire_shape']
    if (wire['extra_payload_header_fields_in_native_alternate_wrappers'] is not False or
            any(wire[key] is not True for key in ('original_bunch_preserved', 'queued_bytes_deep_copied',
                'bit_position_preserved', 'package_map_versions_and_archive_flags_preserved')) or
            proof['actual_capture']['before_values'] != dict.fromkeys(dict(TOP_CELLS), 1) or
            proof['actual_capture']['after_values'] != dict.fromkeys(dict(TOP_CELLS), 1)):
        raise ValueError('Enabled header intact-bunch route proof changed')

    instructions = {}
    def keep(row):
        rva, raw = int(row['rva'], 16), bytes.fromhex(row['bytes_hex'])
        if rva in instructions and instructions[rva] != raw:
            raise ValueError('Enabled header source instructions conflict')
        instructions[rva] = raw
    for body in proof['functions']:
        if body['full_linear_decode'] is not True or body['all_non_reference_instruction_bytes_identical'] is not True:
            raise ValueError('Enabled header complete function comparison changed')
        for row in body['decoded_new_instructions']:
            keep(row)
    for body in proof['native_current_bodies']:
        if 'fragments' in body:
            if body['complete_unwind_coverage'] is not True or body['function_called'] is not False:
                raise ValueError('Enabled header complete current body proof changed')
            rows = [row for fragment in body['fragments'] for row in fragment['instructions']]
        elif body.get('complete_leaf') in ('padded_direct_tail_thunk', 'padded_straight_line_leaf'):
            rows = body['instructions']
            raw = b''.join(bytes.fromhex(row['bytes_hex']) for row in rows)
            if len(raw) != body['bytes'] or hashlib.sha256(raw).hexdigest() != body['sha256']:
                raise ValueError('Enabled header complete leaf proof changed')
        else:
            raise ValueError('Enabled header current body lacks a complete source boundary')
        for row in rows:
            keep(row)

    guards = {}
    def guard(rva, raw):
        if (type(rva) is not int or type(raw) is not bytes or not 0 < len(raw) <= 31 or
                not 0 < rva < rva + len(raw) <= IMAGE_BYTES):
            raise ValueError('Enabled header instruction guard span exceeds bound')
        at, pieces = rva, []
        while at < rva + len(raw):
            current = instructions.get(at)
            if not current or at + len(current) > rva + len(raw):
                raise ValueError('Enabled header instruction guard lacks complete source bytes')
            pieces.append(current)
            at += len(current)
        if b''.join(pieces) != raw or rva in guards and guards[rva] != raw:
            raise ValueError('Enabled header instruction guard source disagrees')
        guards[rva] = raw
    for cell, rva in zip(cells, hooks):
        if (cell['bytes'] != 1 or cell['required_quiet_value'] != 0 or
                cell['dispatch_key'] != rva - 0x1de36180 or
                not any(row['compared_value'] == 0 for row in cell['guards'])):
            raise ValueError('Enabled header hook byte/dispatch binding changed')
        for row in cell['guards']:
            if row['compared_value'] not in (0, 2) or row['rip_targets'] != [cell['rva']]:
                raise ValueError('Enabled header hook source comparison changed')
            guard(int(row['rva'], 16), bytes.fromhex(row['bytes_hex']))
            zero = row['zero_register_source']
            if zero is not None:
                guard(int(zero['rva'], 16), bytes.fromhex(zero['bytes_hex']))
    for row in proof['exact_instruction_witnesses']:
        guard(int(row['rva'], 16), bytes.fromhex(row['bytes_hex']))
    if tuple((rva, len(raw)) for rva, raw in TOP_GUARDS) != ((0x4e24db6, 12), (0x4977e22, 31)):
        raise ValueError('Enabled header top-level instruction spans changed')
    for rva, raw in TOP_GUARDS:
        guard(rva, raw)
    plan = tuple(sorted(guards.items()))
    if len(plan) != 88 or sum(len(raw) for _, raw in plan) != 609:
        raise ValueError('Enabled header source guard count/byte bound changed')
    module = Path(__file__).resolve()
    if module != ROOT / 'work/updated_enabled_header_context.py' or not 0 < module.stat().st_size <= 1024 * 1024:
        raise ValueError('Enabled header reader module source path/bound changed')
    pins['work/updated_enabled_header_context.py'] = hashlib.sha256(module.read_bytes()).hexdigest()
    return pins, plan, ranges, hooks, tuple(TOP_CELLS)


def source_pins():
    """Exact proof, producer, reused identity helper and this reader's source pins."""
    try:
        return _sources_and_plan()[0]
    except (KeyError, TypeError, StopIteration) as error:
        raise ValueError('Enabled header source proof is incomplete') from error


def read_enabled_header_context(read_exact, module_base, *, client_sha256):
    """Capture actual1/1 top flags and all37 sparse hook states, then recheck twice."""
    if (type(client_sha256) is not str or client_sha256 != SOURCE_SHA256 or not callable(read_exact) or
            type(module_base) is not int or module_base < 0x10000 or module_base & 0xffff or
            module_base + IMAGE_BYTES > (1 << 47)):
        raise ValueError('An exact current SHA, callback and aligned bounded image base are required')
    source_function, plan_function = source_pins, _sources_and_plan
    pins, guards, ranges, hooks, top_cells = plan_function()
    # Complete the fixed read plan before inspecting any callback-owned attributes.
    allowed = {(module_base + rva, len(raw)) for rva, raw in guards}
    allowed.update((module_base + rva, size) for rva, size in ranges)
    allowed.update((module_base + rva, 1) for _, rva in top_cells)
    identity = _BackendIdentity(read_exact, module_base)
    calls = total = 0

    def read(rva, size):
        nonlocal calls, total
        if source_pins is not source_function or _sources_and_plan is not plan_function:
            raise ValueError('Enabled header source callbacks changed')
        identity.check()
        address = module_base + rva
        if (address, size) not in allowed or calls >= MAX_READ_CALLS or total + size > MAX_READ_BYTES:
            raise ValueError('Unqualified enabled header read or fixed read budget exceeded')
        calls += 1
        total += size
        try:
            raw = read_exact(address, size)
        except Exception as error:
            raise ValueError('Unavailable exact enabled header callback read') from error
        identity.check()
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('Incomplete or mutable enabled header callback bytes')
        return raw

    def check_guards():
        for rva, raw in guards:
            if read(rva, len(raw)) != raw:
                raise ValueError('Enabled header instruction guard changed')

    def states():
        top = {name: read(rva, 1)[0] for name, rva in top_cells}
        values = {}
        for rva, size in ranges:
            for index, value in enumerate(read(rva, size)):
                values[hex(rva + index)] = value
        if tuple(int(rva, 16) for rva in values) != hooks:
            raise ValueError('Enabled header sparse state coverage changed')
        return top, values

    check_guards()
    top, values = states()
    for _ in range(2):
        check_guards()
        if states() != (top, values):
            raise ValueError('Enabled header top flags or hook bytes changed during recheck')
    identity.check()
    if (source_pins is not source_function or _sources_and_plan is not plan_function or
            source_function() != pins):
        raise ValueError('Enabled header source pins changed during observation')
    top_match = all(value == 1 for value in top.values())
    quiet = all(value == 0 for value in values.values())
    status = ('observed_top_level_context_refused' if not top_match else
              'observed_nonzero_hook_refused' if not quiet else 'observed_source_native_receiver_route')
    return dict(kind='updated_enabled_header_context_observation', client_sha256=client_sha256, status=status,
        top_level_values=top, hook_values=values, native_receiver_route_qualified=top_match and quiet,
        source_instructions_rechecked=True, backend_identity_rechecked=True, source_pins=pins,
        hook_bytes=37, hook_ranges=13, instruction_guards=len(guards), read_calls=calls, read_bytes=total,
        native_gameplay_qualified=False, native_function_called=False, process_memory_written=False,
        account_data_read=False, process_identity_verified=False, image_hash_verified_by_observer=False,
        atomic_snapshot=False, native_delivery_timing_verified=False, runtime_profile_activated=False)
