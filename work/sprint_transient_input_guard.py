"""Read the native transient input guard through the current typed Blackboard.

The bit array has no claimed reflected field or wire handle. No setter, native
accessor, allocation, process API or mutation is provided.
"""
import hashlib
import struct

from fsm_readonly_scope import ROOT, CLIENT, FOLDER, PATHS, sealed

PINS = {
    'native-current-input-first-set-bit-helper-v1.json':
        '15ef6393ba067bcc666683fea4abf1305f3d354720e9e3bf8b92896e59624c2d',
    'native-current-input-bitarray-storage-v1.json':
        '90e057c9592ac6bb2e94d2c106056201397fa5e50b8a5e1d4b3dd94f06b6a681',
    'native-current-input-bitarray-allocation-v1.json':
        'ce6757d0d70cb3de7ba6da98d5b06e72c97cfd351c5fb8120929b1f86730d242',
    'native-current-input-blackboard-class-and-inline-allocator-v1.json':
        'afd2d5fb4af687c6cb639ebf9f3568ac7728480caf5405f0824d9000c697c6fd',
    'native-current-blackboard-initial-state-constructor-v1.json':
        'fe2543274d2f38f78be8847bed543ef11eacadb243982983670435a19aa2ac87',
    'native-current-blackboard-object-constructor-v1.json':
        '346972d10a880afa0857170041b8ccbe0104873e661be8a11e0c97c0924eb307',
    'native-sprint-input-dispatch-and-callers.json':
        '55ba01b690b455d35d87bfdddc1f724539c6a8757ae53c2d250472f03c14d5f9',
}


def contract():
    instructions = {}
    for name, digest in PINS.items():
        doc = sealed(FOLDER+name, digest)
        if doc.get('client_sha256') != CLIENT or doc.get('process_access') is not False:
            raise ValueError('The transient input guard source is not qualified')
        instructions.update({i['rva']: i for f in doc['functions'] for i in f['instructions']})
    for at, mnemonic, operands in (
        ('0x5f9f1ed', 'lea', 'rdx, [rip + 0x10684e3e]'),
        ('0x5f9f215', 'lea', 'rax, [rip + 0x1494]'),
        ('0x5fa06b0', 'mov', 'rcx, qword ptr [rcx]'),
        ('0x5fa06b6', 'jne', '0x3b74620'),
        ('0x3b74648', 'mov', 'rbx, rcx'),
        ('0x3b76c20', 'lea', 'rcx, [rbx + 0xd98]'),
        ('0x3b76c2c', 'call', '0xf50af0'),
        ('0xf50b12', 'mov', 'qword ptr [rcx + 0x10], rax'),
        ('0xf50b16', 'mov', 'qword ptr [rcx + 0x18], rax'),
        ('0xd837d2', 'mov', 'r9d, 4'),
        ('0xd837e7', 'mov', 'eax, dword ptr [rcx + 0x1c]'),
        ('0xd83f7b', 'cmp', 'edi, 4'),
        ('0xd968d0', 'mov', 'rax, qword ptr [rcx]'),
        ('0xd968d3', 'ret', ''),
        ('0x4ef03be', 'mov', 'rsi, qword ptr [rdi + 0x1020]'),
        ('0x4ef03d9', 'mov', 'rbx, rsi'),
        ('0x4ef0831', 'lea', 'rcx, [rbx + 0xd98]'),
        ('0x4ef0838', 'mov', 'dl, 1'),
        ('0x4ef083a', 'call', '0x32e28e0'),
        ('0x4ef083f', 'cmp', 'eax, -1'),
        ('0x32e2906', 'add', 'rcx, 0x10'),
        ('0x32e290a', 'call', 'qword ptr [rip + 0x1a2bb548]'),
        ('0x32e2910', 'mov', 'r9d, dword ptr [rbx + 0x18]'),
        ('0x32e291c', 'cmovne', 'r8, rax'),
        ('0x32e2934', 'cmp', 'dword ptr [r8 + rcx*4], esi'),
        ('0x32e2956', 'bsf', 'eax, ecx'),
        ('0x32e2963', 'cmp', 'edi, r9d'),
        ('0x32e2966', 'cmovl', 'eax, edi')):
        if (instructions[at]['mnemonic'], instructions[at]['operands']) != (mnemonic, operands):
            raise ValueError('The transient input guard instruction source changed: '+at)
    if instructions['0x5f9f1ed']['rip_references'] != [dict(rva='0x16624032',
            immutable_literal_candidate='GPBlackboardComponent')]:
        raise ValueError('The transient input guard native owner class source changed')
    return dict(owner_class='GPBlackboardComponent', owner_member_offset=0xd98,
        current_owner_path='current_pawn.Blackboard', current_pawn_field_offset=0x1020,
        storage_bytes=32, inline_word_count=4, heap_pointer_offset=0x10,
        used_bits_offset=0x18, capacity_bits_offset=0x1c, word_bytes=4,
        data_accessor_cell_rva=0x1d59de58, data_accessor_native_target_rva=0xd968d0,
        native_first_set_function_rva=0x32e28e0, native_no_set_bits_result=-1,
        process_access=False, native_methods_invoked=False, wire_handle_qualified=False)


def source_pins():
    contract()
    return dict({FOLDER+name: digest for name, digest in PINS.items()},
        **{'work/sprint_transient_input_guard.py': hashlib.sha256(
            (ROOT/'work/sprint_transient_input_guard.py').read_bytes()).hexdigest()})


def read_current_guard(read_exact, module_base, board, record):
    """The caller retains/rechecks the current typed Pawn to Blackboard binding."""
    source = contract()
    if (not callable(read_exact) or type(module_base) is not int or type(board) is not int or
            not 0x10000 <= board < (1 << 47)-0xdb8 or board & 7 or
            record.get('class_path') != PATHS['blackboard'] or
            'GPBlackboardComponent' not in record.get('identity', {}).get('class_ancestry', [])):
        raise ValueError('The current typed Pawn Blackboard reference is required')
    def read(at, size):
        if not 0x10000 <= at <= (1 << 47)-size or not 1 <= size <= 512:
            raise ValueError('The transient input guard exceeds its bounded read scope')
        raw = read_exact(at, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ValueError('The transient input guard read was incomplete')
        return raw
    accessor = module_base+source['data_accessor_cell_rva']
    accessor_raw = read(accessor, 8)
    if struct.unpack('<Q',accessor_raw)[0] != module_base+source['data_accessor_native_target_rva']:
        raise ValueError('The native bit-array accessor metadata target changed')
    at = board+source['owner_member_offset']
    header = read(at, 32)
    pointer, count, capacity = struct.unpack_from('<Qii',header,0x10)
    if (not 0 <= count <= capacity <= 4096 or capacity % 32 or
            pointer and (not 0x10000 <= pointer < (1 << 47)-512 or pointer & 7) or
            not pointer and capacity > 128):
        raise ValueError('The transient input guard header is invalid or exceeds its read scope')
    size = ((count+31)//32)*4
    payload = read(pointer,size) if pointer and size else header[:size]
    first = -1
    for index, (word,) in enumerate(struct.iter_unpack('<I', payload)):
        remaining = count-index*32
        if remaining < 32:
            word &= (1 << remaining)-1
        if word:
            first = index*32+(word & -word).bit_length()-1
            break
    if (read(at,32) != header or pointer and size and read(pointer,size) != payload or
            read(accessor,8) != accessor_raw):
        raise ValueError('The transient input guard changed before publication')
    return dict(status='observed', owner_reference_origin=source['current_owner_path'],
        native_consumer_rva='0x4ef083a', owner_member_offset=0xd98,
        used_bit_count=count, capacity_bits=capacity, storage='heap_words' if pointer else 'inline_words',
        header_hex=header.hex(), used_words_hex=payload.hex(), first_set_bit=first,
        native_guard_allows_input_at_observation=first == -1, value_bytes_rechecked=True,
        snapshot_atomic=False, wire_handle_qualified=False, sprint_allowed_inferred=False,
        native_methods_invoked=False, process_memory_written=False)
