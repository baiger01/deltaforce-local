"""Read only the decoded KeyBox configuration's already populated rows."""

import struct

from read_keybox_manager_interface import capture as capture_manager

CODE_WITNESSES = (
    (0xe08f20, bytes.fromhex('e9bb26fbff')),
    (0xdbb64a, bytes.fromhex('4183bed001000000')),
    (0xdbb69f, bytes.fromhex('498d9ec8010000')),
    (0xdbb88e, bytes.fromhex('498d86c8010000')),
)


def capture(read, base, config_map):
    result = {'status': 'skipped', 'read_policy': 'only decoded KeyBox configuration rows; no account objects'}
    entries = [entry for entry in config_map.get('entries', [])
               if entry.get('name', entry.get('decoded_name')) == 'KeyBox']
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
                result['reason'] = 'row_code_witness_mismatch'
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
        header_address = content + 0x1c8
        header = read(header_address, 16, module_only=False)
        pointers, count, capacity = struct.unpack('<Qii', header)
        result.update(content_address=content, row_header_address=header_address,
                      row_header_hex=header.hex(), row_count=count, row_capacity=capacity)
        if count == 0:
            result['reason'] = 'keybox_rows_not_populated'
            return result
        if not pointers or not 0 < count <= capacity <= 512 or pointers + count * 8 > 0x800000000000:
            result['reason'] = 'invalid_keybox_row_array'
            return result
        pointer_data = read(pointers, count * 8, module_only=False)
        rows, seen = [], set()
        for array_index, pointer in enumerate(struct.unpack('<' + 'Q' * count, pointer_data)):
            if not pointer or pointer + 56 > 0x800000000000 or pointer in seen:
                result['reason'] = 'invalid_keybox_row_pointer'
                return result
            seen.add(pointer)
            raw = read(pointer, 56, module_only=False)
            # Named native KeyBoxRow reflection: size56, Index16, FName20,
            # Map28, Default32, four levels36..48 and BoxLength52.
            scalar_offsets = (16, 28, 32, 36, 40, 44, 48, 52)
            rows.append({'array_index': array_index, 'row_address': pointer,
                         'row_hex': raw.hex(), 'item_id_fname_hex': raw[20:28].hex(),
                         'scalar_fingerprint': [struct.unpack_from('<i', raw, offset)[0]
                                                for offset in scalar_offsets]})
        if (read(header_address, 16, module_only=False) != header or
                read(entry['slot_address'], 24, module_only=False) != slot or
                read(pointers, count * 8, module_only=False) != pointer_data):
            result['reason'] = 'keybox_rows_changed'
            return result
        result.update(status='captured', reason=None, rows=rows)
    except (OSError, ValueError, struct.error) as exc:
        result.update(reason='read_failed', error=str(exc))
    return result
