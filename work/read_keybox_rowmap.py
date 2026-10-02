"""Follow only the verified KeyBox configuration to its actual RowMap accessor."""

import struct

from read_keybox_manager_interface import MODULE_SIZE, capture as capture_manager

CODE_WITNESSES = (
    (0xdc4c73, bytes.fromhex('80be0c02000002')),
    (0xdc4cc7, bytes.fromhex('6683be0e02000001')),
    (0xdc4cd6, bytes.fromhex('488b86f8010000')),
    (0xdc4ce6, bytes.fromhex('488d8ed8010000')),
    (0xdc4cf2, bytes.fromhex('ff1560917d1c')),
    (0xdc4d08, bytes.fromhex('48638ee0010000')),
    (0xdc4d20, bytes.fromhex('488b074885c0')),
    (0xdbb699, bytes.fromhex('ff9270020000')),
    (0xdbb6a9, bytes.fromhex('8b50082b5034')),
    (0xdbb6c5, bytes.fromhex('4d8d7d10')),
    (0xdbb6cc, bytes.fromhex('4d8d6718')),
    (0xdbb6e7, bytes.fromhex('498d4f10ff1567277e1c')),
    (0xdbb6f1, bytes.fromhex('458b04244885c04c0f45f8')),
    (0xdbb7c0, bytes.fromhex('488b4dd7ff158e267e1c')),
    (0xdbb7cd, bytes.fromhex('48637b08488d1449488d34d0')),
    (0xdbb7f7, bytes.fromhex('488b4e0848890cf8')),
)


def capture_rows(read, result):
    """Read only live RowMap slots using the actual GetAllRows allocation bits."""
    def stop(reason):
        result.update(rowmap_status='skipped', rowmap_reason=reason)

    if not result['rowmap_accessor_code_hex'].startswith('488d4130c3'):
        stop('unsupported_rowmap_accessor')
        return
    address = result['source_table_address'] + 0x30
    header = read(address, 56, module_only=False)
    slots, count, capacity = struct.unpack_from('<Qii', header)
    bits, bit_count, bit_capacity = struct.unpack_from('<Qii', header, 0x20)
    free = struct.unpack_from('<i', header, 0x34)[0]
    result.update(rowmap_address=address, rowmap_header_hex=header.hex(),
                  row_slot_count=count, row_free_count=free)
    if not slots or not 0 <= free <= count <= capacity <= 512 or bit_count != count or bit_capacity < count:
        stop('invalid_keybox_rowmap_counts')
        return
    if count == free:
        stop('keybox_source_rows_empty')
        return
    bit_bytes = ((bit_count + 31) // 32) * 4
    if bits:
        if bits + bit_bytes > 0x800000000000:
            stop('invalid_allocation_bits_pointer')
            return
        bit_data = read(bits, bit_bytes, module_only=False)
    elif bit_bytes <= 16:
        bit_data = header[0x10:0x10 + bit_bytes]
    else:
        stop('unsupported_inline_allocation_bits')
        return
    allocated = [index for index in range(count) if bit_data[index // 8] & (1 << (index % 8))]
    if len(allocated) != count - free:
        stop('keybox_allocated_count_mismatch')
        return
    rows, seen = [], set()
    for index in allocated:
        slot_address = slots + index * 24
        if slot_address + 24 > 0x800000000000:
            stop('invalid_row_slot_pointer')
            return
        slot = read(slot_address, 24, module_only=False)
        row = struct.unpack_from('<Q', slot, 8)[0]
        if not row or row + 56 > 0x800000000000 or row in seen:
            stop('invalid_keybox_row_pointer')
            return
        seen.add(row)
        raw = read(row, 56, module_only=False)
        fingerprint = [struct.unpack_from('<i', raw, offset)[0]
                       for offset in (16, 28, 32, 36, 40, 44, 48, 52)]
        rows.append({'slot_index': index, 'slot_address': slot_address,
                     'row_name_fname_hex': slot[:8].hex(), 'row_address': row, 'row_hex': raw.hex(),
                     'item_id_fname_hex': raw[20:28].hex(), 'scalar_fingerprint': fingerprint})
    if read(address, 56, module_only=False) != header or bits and read(bits, bit_bytes, module_only=False) != bit_data:
        stop('keybox_rowmap_changed')
        return
    result.update(rowmap_status='captured_rows', rows=rows)


def capture(read, base, config_map, table_name='Key/KeyBox'):
    result = {'status': 'skipped', 'read_policy': 'only identified KeyBox configuration source table and accessor code'}
    if table_name not in ('KeyBox', 'Key/KeyBox'):
        result['reason'] = 'unsupported_configuration_name'
        return result
    result['table_name'] = table_name
    entries = [entry for entry in config_map.get('entries', [])
               if entry.get('name', entry.get('decoded_name')) == table_name]
    if config_map.get('entries_status') != 'captured_configuration_keys' or len(entries) != 1:
        result['reason'] = 'keybox_not_uniquely_identified'
        return result
    manager = capture_manager(read, base)
    if (manager.get('status') != 'captured' or manager.get('manager_address') !=
            config_map.get('manager_interface', {}).get('manager_address')):
        result['reason'] = 'manager_changed_or_unavailable'
        return result
    try:
        for rva, expected in CODE_WITNESSES:
            if read(base + rva, len(expected)) != expected:
                result['reason'] = 'rowmap_source_code_witness_mismatch'
                return result
        getter = struct.unpack('<Q', read(base + 0x1d59de58, 8))[0]
        if not base <= getter < getter + 4 <= base + MODULE_SIZE or read(getter, 4) != bytes.fromhex('488b01c3'):
            result['reason'] = 'unsupported_allocation_accessor'
            return result
        entry = entries[0]
        if read(config_map['cache_address'], 80, module_only=False).hex() != config_map['cache_header_hex']:
            result['reason'] = 'configuration_header_changed'
            return result
        slot = read(entry['slot_address'], 24, module_only=False)
        content = struct.unpack_from('<Q', slot, 8)[0]
        if slot[:8].hex() != entry['fname_hex'] or content != entry['content_address'] or not content:
            result['reason'] = 'configuration_entry_changed'
            return result
        state = read(content + 0x20c, 1, module_only=False)
        result.update(content_address=content, load_state=state[0])
        if state != b'\x02':
            result['reason'] = 'keybox_content_not_ready'
            return result
        table_count = struct.unpack('<H', read(content + 0x20e, 2, module_only=False))[0]
        combine = struct.unpack('<Q', read(content + 0x1f8, 8, module_only=False))[0]
        table = combine if table_count > 1 and combine else 0
        result.update(combine_table_address=combine, table_count=table_count)
        if not table:
            header = read(content + 0x1d8, 16, module_only=False)
            pointers, count, capacity = struct.unpack('<Qii', header)
            result['table_array_header_hex'] = header.hex()
            if not pointers or not 0 < count <= capacity <= 32 or pointers + count * 8 > 0x800000000000:
                result['reason'] = 'invalid_keybox_source_table_array'
                return result
            pointer_data = read(pointers, count * 8, module_only=False)
            table = next((ptr for ptr in struct.unpack('<' + 'Q' * count, pointer_data) if ptr), 0)
            if read(content + 0x1d8, 16, module_only=False) != header:
                result['reason'] = 'source_table_array_changed'
                return result
        if not table or table + 64 > 0x800000000000:
            result['reason'] = 'invalid_keybox_source_table'
            return result
        table_header = read(table, 64, module_only=False)
        vtable = struct.unpack_from('<Q', table_header)[0]
        if not base <= vtable < vtable + 0x278 <= base + MODULE_SIZE:
            result['reason'] = 'source_table_vtable_outside_module'
            return result
        target = struct.unpack('<Q', read(vtable + 0x270, 8))[0]
        if not base <= target < target + 1536 <= base + MODULE_SIZE:
            result['reason'] = 'rowmap_accessor_outside_module'
            return result
        code = read(target, 1536)
        if len(code) != 1536:
            raise ValueError('Short RowMap accessor code')
        if read(entry['slot_address'], 24, module_only=False) != slot:
            result['reason'] = 'configuration_entry_changed'
            return result
        result.update(status='captured', reason=None, source_table_address=table,
                      source_table_header_hex=table_header.hex(), source_table_vtable=vtable,
                      rowmap_accessor_address=target, rowmap_accessor_rva=target - base,
                      rowmap_accessor_code_hex=code.hex(), rowmap_status='await_actual_accessor_proof')
        capture_rows(read, result)
    except (OSError, ValueError, struct.error) as exc:
        result.update(reason='read_failed', error=str(exc))
    return result
