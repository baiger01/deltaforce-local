"""Credential-free structural probe for one decrypted business message.

This does not infer account authorization or retain any field values. A valid
protobuf wire walk is a structural observation, not proof of a message schema.
"""
import re

from .business_envelope import parse_business_envelope


SAFE_NAME = re.compile(r'CS[A-Za-z0-9_]{1,96}(?:Req|Res|Ntf)\Z')
SAFE_SERVICE = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')


def _varint(data, offset):
    start = offset
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError('Truncated varint')
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            if value >= 1 << 64:
                raise ValueError('Oversized varint')
            return value, offset, offset - start
    raise ValueError('Oversized varint')


def _walk(data, *, max_fields=48, collect=True):
    offset = 0
    fields = []
    count = 0
    while offset < len(data):
        if count >= max_fields:
            raise ValueError('Too many fields')
        tag, offset, _ = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 536870911 or wire not in (0, 1, 2, 5):
            raise ValueError('Invalid protobuf field tag')
        field = {'number': number, 'wire': wire}
        if wire == 0:
            _, offset, field['varint_bytes'] = _varint(data, offset)
        elif wire == 1:
            offset += 8
        elif wire == 5:
            offset += 4
        else:
            length, offset, _ = _varint(data, offset)
            field['length'] = length
            offset += length
        if offset > len(data):
            raise ValueError('Truncated protobuf field')
        count += 1
        if collect:
            fields.append(field)
    if not count:
        raise ValueError('Empty protobuf candidate')
    return fields


def summarize_message_shape(message):
    """Return only field numbers, wire types and sizes at plausible offsets."""
    if not isinstance(message, bytes) or not 1 <= len(message) <= 65536:
        raise ValueError('Invalid bounded business message')
    candidates = []
    for offset in (0, 2, 4, 8, 12, 16):
        if offset >= len(message):
            continue
        try:
            fields = _walk(message[offset:])
        except ValueError:
            continue
        candidates.append({'offset': offset, 'fields': fields})
    return {'message_length': len(message), 'protobuf_wire_candidates': candidates}


def summarize_prefixed_envelope(message):
    """Inspect a 4-byte prefix and recognized package header, without body values."""
    result = {'four_byte_prefix_present': len(message) > 4}
    if len(message) <= 4:
        return result
    payload = message[4:]
    # The first four bytes are a dedicated envelope prefix, outside the
    # protobuf package. Record only this small protocol scalar, never the
    # credential-bearing package or body.
    result['prefix_word_le'] = int.from_bytes(message[:4], 'little')
    result['prefix_word_be'] = int.from_bytes(message[:4], 'big')
    result.update({'prefix_equals_total_length_le': int.from_bytes(message[:4], 'little') == len(message),
                   'prefix_equals_total_length_be': int.from_bytes(message[:4], 'big') == len(message),
                   'prefix_equals_payload_length_le': int.from_bytes(message[:4], 'little') == len(payload),
                   'prefix_equals_payload_length_be': int.from_bytes(message[:4], 'big') == len(payload)})
    try:
        envelope = parse_business_envelope(payload)
    except ValueError:
        result['candidate_envelope_decoded'] = False
        return result
    result['candidate_envelope_decoded'] = True
    name = envelope.header.get('name')
    service = envelope.header.get('service')
    if isinstance(name, str) and SAFE_NAME.fullmatch(name):
        result['message_name'] = name
    if isinstance(service, str) and SAFE_SERVICE.fullmatch(service):
        result['service'] = service
    result['header_field_names'] = sorted(envelope.header)
    result['body_shape'] = summarize_message_shape(envelope.body) if envelope.body else {'message_length': 0}
    return result
