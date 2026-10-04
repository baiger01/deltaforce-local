"""Packet times for the same PCAP/PCAPNG records accepted by analyze_capture.

Timestamp options follow the PCAPNG interface descriptor, including binary
resolution and signed offsets; source:
https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#section-4.2
No payload or session value is written by this module.
"""
import struct


def packet_unix_times(data):
    if len(data) < 12:
        raise ValueError('Capture header is truncated')
    if data[:4] != b'\x0a\x0d\x0d\x0a':
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 10**6), b'\xa1\xb2\xc3\xd4': ('>', 10**6),
                   b'\x4d\x3c\xb2\xa1': ('<', 10**9), b'\xa1\xb2\x3c\x4d': ('>', 10**9)}
        if data[:4] not in formats or len(data) < 24:
            raise ValueError('Unsupported capture format')
        endian, scale = formats[data[:4]]
        at = 24
        while at < len(data):
            if len(data) - at < 16:
                raise ValueError('PCAP record header is truncated')
            seconds, fraction, caplen, original = struct.unpack_from(endian + '4I', data, at)
            at += 16
            if caplen > len(data) - at or fraction >= scale:
                raise ValueError('Invalid PCAP packet or timestamp')
            yield seconds + fraction / scale
            at += caplen
        return
    at, endian, interfaces = 0, None, []
    while at < len(data):
        if len(data) - at < 12:
            raise ValueError('PCAPNG block header is truncated')
        if data[at:at+4] == b'\x0a\x0d\x0d\x0a':
            endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(data[at+8:at+12])
            interfaces = []
        if endian is None:
            raise ValueError('Invalid or missing PCAPNG section')
        block, length = struct.unpack_from(endian + 'II', data, at)
        if length < 12 or length % 4 or length > len(data) - at:
            raise ValueError('Invalid PCAPNG block length')
        if struct.unpack_from(endian + 'I', data, at + length - 4)[0] != length:
            raise ValueError('PCAPNG block lengths disagree')
        body = data[at+8:at+length-4]
        if block == 1:
            if len(body) < 8:
                raise ValueError('Truncated interface description')
            scale, offset, option_at, seen = 10**6, 0, 8, set()
            while option_at < len(body):
                if len(body) - option_at < 4:
                    raise ValueError('Truncated interface option')
                code, size = struct.unpack_from(endian + 'HH', body, option_at)
                option_at += 4
                padded = (size + 3) & ~3
                if padded > len(body) - option_at:
                    raise ValueError('Invalid interface option length')
                value = body[option_at:option_at+size]
                option_at += padded
                if code == 0:
                    if size:
                        raise ValueError('Invalid option terminator')
                    break
                if code in (9, 14):
                    if code in seen:
                        raise ValueError('Duplicate timestamp option')
                    seen.add(code)
                if code == 9:
                    if size != 1:
                        raise ValueError('Invalid timestamp resolution')
                    scale = (2 if value[0] & 128 else 10) ** (value[0] & 127)
                elif code == 14:
                    if size != 8:
                        raise ValueError('Invalid timestamp offset')
                    offset = struct.unpack(endian + 'q', value)[0]
            interfaces.append((scale, offset))
        elif block == 6:
            if len(body) < 20:
                raise ValueError('Truncated enhanced packet block')
            interface, high, low, caplen, original = struct.unpack_from(endian + '5I', body)
            if interface >= len(interfaces) or caplen > len(body) - 20:
                raise ValueError('Invalid enhanced packet block')
            scale, offset = interfaces[interface]
            yield ((high << 32) | low) / scale + offset
        at += length
