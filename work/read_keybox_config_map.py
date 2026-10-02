"""Capture only the proven configuration-cache header and accessor code.

GetDataTable implementation 0xdbf7f0 was read from the verified manager's
interface vtable in native capture 1790850658408710200, PID 121140.
The source binding names DataTableContentMap (TMap<FName,FDataTableLiteContent*>)
at main-object+0x190; the actual implementation uses interface+0x160.
The observed allocator and find implementation permit bounded live hash chains.
"""

import struct

from read_keybox_manager_interface import MODULE_SIZE, capture as capture_manager


ALLOCATION_ACCESSOR_RVA = 0x1d59de58
ACCESSOR_CODE_SIZE = 512
CODE_WITNESSES = (
    (0xdbf804, bytes.fromhex('4c8bf1')),
    (0xdbf895, bytes.fromhex('498d8e60010000e80f7fffff')),
    (0xdbf8b0, bytes.fromhex('498d8e60010000ff159be57d1c')),
    (0xdbf8bd, bytes.fromhex('488d145b488d1cd0')),
    (0xdbf8ca, bytes.fromhex('488b5b08')),
    (0xdb77cd, bytes.fromhex('8b4108')),
    (0xdb77d9, bytes.fromhex('3b4134')),
    (0xdb77e7, bytes.fromhex('488d7538')),
    (0xdb77ef, bytes.fromhex('488d4e08')),
    (0xdb77f3, bytes.fromhex('ff155f667e1c')),
    (0xdb77f9, bytes.fromhex('48635548')),
    (0xdb780d, bytes.fromhex('8b1c96')),
    (0xdb7826, bytes.fromhex('488d3440ff1528667e1c')),
    (0xdb7830, bytes.fromhex('488b14f0')),
    (0xdb7853, bytes.fromhex('8b5cf010')),
)


def _capture_entries(read, result, header):
    def stop(reason):
        result.update(entries_status='skipped', entries_reason=reason)

    if not result['allocation_accessor_code_hex'].startswith('488b01c3'):
        stop('unsupported_allocation_accessor')
        return
    slots = struct.unpack_from('<Q', header)[0]
    count = struct.unpack_from('<i', header, 8)[0]
    free_count = struct.unpack_from('<i', header, 0x34)[0]
    hash_size = struct.unpack_from('<i', header, 0x48)[0]
    result.update(slot_count=count, free_slot_count=free_count, hash_size=hash_size)
    if not 0 <= free_count <= count <= 16384:
        stop('invalid_configuration_slot_count')
        return
    live_count = count - free_count
    if live_count == 0:
        result.update(entries_status='captured_configuration_keys', entries=[])
        return
    if not slots or not 1 <= hash_size <= 16384 or hash_size & (hash_size - 1):
        stop('invalid_configuration_hash_size')
        return
    buckets = struct.unpack_from('<Q', header, 0x40)[0]
    if buckets:
        if buckets + hash_size * 4 > 0x800000000000:
            stop('invalid_hash_pointer')
            return
        bucket_data = read(buckets, hash_size * 4, module_only=False)
    elif hash_size == 1:
        bucket_data = header[0x38:0x3c]
    else:
        stop('unsupported_inline_hash_size')
        return
    if len(bucket_data) != hash_size * 4:
        stop('short_hash_read')
        return
    entries, seen = [], set()
    for bucket, index in enumerate(struct.unpack('<' + 'i' * hash_size, bucket_data)):
        while index != -1:
            if not 0 <= index < count or index in seen or len(seen) >= live_count:
                stop('invalid_hash_chain')
                return
            seen.add(index)
            address = slots + index * 24
            if address + 24 > 0x800000000000:
                stop('invalid_configuration_slot_pointer')
                return
            item = read(address, 24, module_only=False)
            if len(item) != 24:
                stop('short_configuration_slot_read')
                return
            key, content, index = struct.unpack_from('<QQi', item)
            entries.append({'slot_index': (address - slots) // 24, 'slot_address': address,
                            'fname_hex': struct.pack('<Q', key).hex(), 'content_address': content,
                            'hash_bucket': bucket})
    if len(seen) != live_count:
        stop('configuration_live_count_mismatch')
        return
    if read(result['cache_address'], 80, module_only=False) != header:
        stop('configuration_header_changed')
        return
    result.update(entries_status='captured_configuration_keys', entries=entries)


def capture(read, base):
    """Acquire a fresh manager, then read exactly 80 configuration bytes.

    read has the same bounded signature as read_keybox_manager_interface.
    Configuration keys are followed only for the observed MOV RAX,[RCX] accessor.
    """
    result = {'status': 'skipped', 'module_base': base,
              'read_policy': 'verified configuration cache header and module accessor code only'}
    manager = capture_manager(read, base)
    result['manager_interface'] = manager
    if manager['status'] != 'captured':
        result['reason'] = 'manager_unavailable'
        return result
    if manager.get('target_rva') != 0xdbf7f0:
        result['reason'] = 'unsupported_cache_implementation'
        return result
    try:
        for rva, expected in CODE_WITNESSES:
            if read(base + rva, len(expected)) != expected:
                result['reason'] = 'cache_code_witness_mismatch'
                return result
        pointer = read(base + ALLOCATION_ACCESSOR_RVA, 8)
        if len(pointer) != 8:
            raise ValueError('Short allocation accessor pointer read')
        accessor = struct.unpack('<Q', pointer)[0]
        if not base <= accessor < accessor + ACCESSOR_CODE_SIZE <= base + MODULE_SIZE:
            result['reason'] = 'allocation_accessor_outside_module'
            return result
        accessor_code = read(accessor, ACCESSOR_CODE_SIZE)
        if len(accessor_code) != ACCESSOR_CODE_SIZE:
            raise ValueError('Short accessor code read')
        map_address = manager['interface_address'] + 0x160
        if map_address != manager['manager_address'] + 0x190:
            result['reason'] = 'manager_interface_mismatch'
            return result
        header = read(map_address, 80, module_only=False)
        if len(header) != 80:
            raise ValueError('Short configuration header read')
        result.update(status='captured', reason=None, cache_address=map_address,
                      cache_field='DataTableContentMap', cache_header_size=80,
                      cache_header_hex=header.hex(), allocation_accessor_address=accessor,
                      allocation_accessor_rva=accessor - base,
                      allocation_accessor_code_size=len(accessor_code),
                      allocation_accessor_code_hex=accessor_code.hex(),
                      entries_status='await_allocator_and_index_code_proof')
        _capture_entries(read, result, header)
    except (OSError, ValueError, struct.error) as exc:
        result.update(reason='read_failed', error=str(exc))
    return result
