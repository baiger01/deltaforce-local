"""Decode the source-backed operation blocker bit array without changing it.

The owning observer must qualify its current Pawn/Blackboard and pointer mode.
This module calls no native function and supplies no gameplay permission.
"""
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parent.parent
SOURCE = 'work/evidence/interaction-operate-bitarray-getter-20261021.json'
SOURCE_SHA = 'c4dc5996f1e6a75146ef82e53f4a1927b6fbb9b3805634638057ce02e3b48631'
NAMES = 'work/evidence/operation-forbid-reasons-20261021.json'
NAMES_SHA = '0e13f51389e9e4d19703f188a7b8421a9c4e24112c14cdcffa143c21beb9cd65'
OFFSET = 0x1018
HEADER_BYTES = 28
INLINE_BYTES = 16
MAX_BITS = 1024


def reason_names():
    raw = (ROOT / NAMES).read_bytes()
    if hashlib.sha256(raw).hexdigest() != NAMES_SHA:
        raise ValueError('The original operation reason names changed')
    data = json.loads(raw)
    rows = data.get('enum_rows', ())
    if (data.get('process_access') is not False or data.get('sentinel_value') != 118 or
            len(rows) != 119 or [row['value'] for row in rows] != list(range(119))):
        raise ValueError('The exact original operation reason enum is required')
    return {row['value']: row['name'] for row in rows if row['value'] < 118}


def source_pins():
    from sprint_transient_input_guard import source_pins as accessor_sources
    raw = (ROOT / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('The original operation blocker getter source changed')
    doc = json.loads(raw)
    if (doc.get('client_sha256') !=
            '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
            or doc.get('process_access') is not False):
        raise ValueError('The pinned offline operation getter is required')
    instructions = {i['rva']: i for f in doc['functions'] for i in f['instructions']}
    anchors = {'0x5c90056': '488d9918100000', '0x5c9005d': '488d4b10',
        '0x5c90067': '448b5318', '0x5c90071': '4c0f45c0',
        '0x5c90090': '41833c9000', '0x5c900b2': '413bca', '0x5c900bf': '0f94c0'}
    if any(instructions.get(at, {}).get('bytes') != value for at, value in anchors.items()):
        raise ValueError('The original operation bit-array read semantics changed')
    reason_names()
    return {**accessor_sources(), SOURCE: SOURCE_SHA, NAMES: NAMES_SHA,
        'work/operate_gate_readonly_scope.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def header(raw):
    if type(raw) is not bytes or len(raw) != HEADER_BYTES:
        raise ValueError('The exact source-qualified operation array header is required')
    pointer, count = struct.unpack_from('<Qi', raw, INLINE_BYTES)
    if not 0 <= count <= MAX_BITS or not pointer and count > INLINE_BYTES * 8:
        raise ValueError('The operation array count exceeds its qualified storage bound')
    size = ((count + 31) // 32) * 4
    return pointer, count, size


def decode(raw, external=None):
    pointer, count, size = header(raw)
    if pointer:
        if type(external) is not bytes or len(external) != size:
            raise ValueError('The exact indirect operation bit-array words are required')
        words = external
    else:
        if external is not None:
            raise ValueError('Inline operation storage cannot consume indirect words')
        words = raw[:size]
    bits = int.from_bytes(words, 'little')
    reasons = tuple(index for index in range(count) if bits & (1 << index))
    names = reason_names()
    return dict(bit_count=count, blocker_reason_indices=reasons,
        blocker_reasons=tuple(dict(index=index, name=names.get(index)) for index in reasons),
        unknown_reason_indices=tuple(index for index in reasons if index not in names),
        can_operate=not reasons, storage='indirect' if pointer else 'inline',
        native_methods_invoked=False, process_memory_written=False,
        initialization_complete_inferred=False, gameplay_permission_inferred=False)


def observe(read, module_base, board, record):
    """Read one already-qualified board, rejecting any changed header/words."""
    source_pins()
    from fsm_readonly_scope import PATHS
    from sprint_transient_input_guard import contract
    accessor = contract()
    if (not callable(read) or type(module_base) is not int or
            type(board) is not int or not 65536 <= board < (1 << 47) - OFFSET - HEADER_BYTES
            or board & 7 or record.get('class_path') != PATHS['blackboard'] or
            'GPBlackboardComponent' not in record.get('identity', {}).get('class_ancestry', [])):
        raise ValueError('The current typed Pawn Blackboard reference is required')
    def bounded(address, size):
        if not 65536 <= address < (1 << 47) - size or not 1 <= size <= MAX_BITS // 8:
            raise ValueError('The operation blocker read exceeds its fixed scope')
        value = read(address, size)
        if type(value) is not bytes or len(value) != size:
            raise ValueError('The operation blocker read was incomplete')
        return value
    cell = module_base + accessor['data_accessor_cell_rva']
    cell_bytes = bounded(cell, 8)
    if struct.unpack('<Q', cell_bytes)[0] != module_base + accessor['data_accessor_native_target_rva']:
        raise ValueError('The original direct bit-array accessor binding changed')
    first = bounded(board + OFFSET, HEADER_BYTES)
    pointer, count, size = header(first)
    external = None
    if pointer and size:
        if pointer < 65536 or pointer & 3:
            raise ValueError('The indirect operation words require an aligned current pointer')
        external = bounded(pointer, size)
    elif pointer:
        external = b''
    result = decode(first, external)
    if pointer and size and bounded(pointer, size) != external:
        raise ValueError('The operation blocker words changed during observation')
    if bounded(board + OFFSET, HEADER_BYTES) != first or bounded(cell, 8) != cell_bytes:
        raise ValueError('The operation blocker header changed during observation')
    return dict(result, header_and_words_rechecked=True,
        current_owner_identity_rechecked=False, snapshot_atomic=False)
