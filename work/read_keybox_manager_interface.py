"""Read one verified DataTableSystemManagerLite interface; never call target code.

Witnesses come from PID 116392's fixed capture 1790848383006560400 on
2026-10-01, installed PE SHA256
4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0.
The supplied read(address, size, module_only=True) must perform bounded reads.
Only selector 0's observed signed-idiv fallback is supported.
"""

import struct


MODULE_SIZE = 0x1ff8f000
SELECTOR_RVA = 0x1e318784
STORAGE_RVA = 0x1c9fe850
ARRAY_RVA = 0x1e34ee50
OVERRIDE_RVA = 0x1db3a770
TARGET_CODE_SIZE = 1536
CODE_WITNESSES = (
    # Native Get resolves this weak reference through the observed helper.
    (0xdba671, bytes.fromhex('488d0dd841c41b48895c2460e89e431110')),
    (0x10ecea20, bytes.fromhex(
        '4889742410574883ec208b710485f6747c8b3985ff78763b3d1f04480d7d6e'
        '8bcf48895c2430e8b51ae9ef8bcf4863d8e8ab22e9ef4863c8488b050904480d'
        '488d1449488b0cd8488b5c2430488d04d14885c074383970147533f7400800000030'
        '752a488b15e6bcc60c4885d27410488bc8488b7424384883c4205f48ffe2488b00')),
    # Selector reads, zero-selector branch, and exact fallback division/remainder.
    (0xd60500, bytes.fromhex('8b057e825b1d8bd185c00f84f7050000')),
    (0xd60b07, bytes.fromhex('8bc241b8000001009941f7f8c3')),
    (0xd60d00, bytes.fromhex('8b057e7a5b1d8bd185c00f8422060000')),
    (0xd61332, bytes.fromhex('8bc241b8000001009941f7f88bc2c3')),
    # GetDataTable uses the interface at object+0x30, vtable slot+0x68.
    (0xe2cb11, bytes.fromhex('488d4d30')),
    (0xe2cb33, bytes.fromhex('488b01ff5068')),
)


class _Skip(Exception):
    pass


def capture(read, base):
    """Return captured addresses/code or an explicit skipped reason.

    Heap reads are confined to one chunk pointer, one 24-byte object-array
    item, and the selected manager's first 64 bytes. No account object follows.
    Every invocation validates current code, selector, storage, array and override.
    """
    result = {'status': 'skipped', 'module_base': base, 'read_policy':
              'one verified manager interface; no invocation or account objects'}

    def stop(reason):
        raise _Skip(reason)

    def module_range(address, size):
        return base <= address and address + size <= base + MODULE_SIZE

    def exact(address, size, *, heap=False):
        if not isinstance(address, int) or address <= 0 or address + size > 0x800000000000:
            stop('invalid_pointer')
        if not heap and not module_range(address, size):
            stop('read_outside_module')
        value = read(address, size, module_only=not heap)
        if not isinstance(value, (bytes, bytearray)) or len(value) != size:
            stop('short_read')
        return bytes(value)

    def fresh_globals():
        selector = exact(base + SELECTOR_RVA, 4)
        if struct.unpack('<I', selector)[0] != 0:
            stop('unsupported_selector')
        storage = exact(base + STORAGE_RVA, 16)
        header = exact(base + ARRAY_RVA, 32)
        override = exact(base + OVERRIDE_RVA, 8)
        if struct.unpack('<Q', override)[0]:
            stop('unsupported_accessor_override')
        return selector, storage, header, override

    try:
        if type(base) is not int or base <= 0 or base + MODULE_SIZE >= 0x800000000000:
            stop('invalid_module_base')
        for rva, expected in CODE_WITNESSES:
            if exact(base + rva, len(expected)) != expected:
                stop('code_witness_mismatch')
        globals_before = fresh_globals()
        index, serial = struct.unpack_from('<ii', globals_before[1])
        bound = struct.unpack_from('<i', globals_before[2], 12)[0]
        array = struct.unpack_from('<Q', globals_before[2], 24)[0]
        result.update(selector=0, index=index, serial=serial, object_bound=bound,
                      chunk_array_address=array)
        if serial == 0 or index < 0 or index >= bound:
            stop('invalid_weak_reference')
        if not array:
            stop('null_chunk_array')
        chunk_index, item_index = divmod(index, 65536)
        slot_address = array + chunk_index * 8
        chunk = struct.unpack('<Q', exact(slot_address, 8, heap=True))[0]
        if not chunk:
            stop('null_object_chunk')
        item_address = chunk + item_index * 24
        item = exact(item_address, 24, heap=True)
        item_serial = struct.unpack_from('<i', item, 20)[0]
        flags = struct.unpack_from('<I', item, 8)[0]
        result.update(chunk_index=chunk_index, item_index=item_index,
                      chunk_slot_address=slot_address, chunk_address=chunk,
                      item_address=item_address, item_hex=item.hex(), flags=flags)
        if item_serial != serial:
            stop('stale_serial')
        if flags & 0x30000000:
            stop('invalid_object_flags')
        manager = struct.unpack_from('<Q', item)[0]
        if not manager:
            stop('null_manager')
        # Stop if the weak reference or relevant globals changed during traversal.
        if fresh_globals() != globals_before:
            stop('globals_changed')
        if exact(item_address, 24, heap=True) != item:
            stop('object_item_changed')
        manager_header = exact(manager, 0x40, heap=True)
        vtable = struct.unpack_from('<Q', manager_header, 0x30)[0]
        result.update(manager_address=manager, manager_header_hex=manager_header.hex(),
                      interface_address=manager + 0x30, interface_vtable=vtable)
        if not module_range(vtable, 0x70):
            stop('vtable_outside_module')
        target = struct.unpack('<Q', exact(vtable + 0x68, 8))[0]
        if not module_range(target, TARGET_CODE_SIZE):
            stop('target_outside_module')
        code = exact(target, TARGET_CODE_SIZE)
        result.update(status='captured', reason=None, target_address=target,
                      target_rva=target - base, target_code_size=len(code),
                      target_code_hex=code.hex())
    except _Skip as exc:
        result['reason'] = str(exc)
    except (OSError, ValueError, struct.error) as exc:
        result['reason'] = 'read_failed'
        result['error'] = str(exc)
    return result
