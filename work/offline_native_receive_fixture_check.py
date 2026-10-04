"""Offline receive-field experiment from exact native code, never a server.

Enumerates only possible outer-envelope boundaries in two existing fixtures.
An envelope boundary fitting these fixtures is not a native envelope proof.
"""
import json
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'work/native-client-tests/1790831328076933800/game-server-packets'
EXPECTED = {'09-udp.bin': '1af7dae39fc6b98d0683d0f3bc9236dce8f65357c158066f93ff20e1a5dd9e3a',
            '14-udp.bin': 'e76c10e89e1b9e433dea45d0de738b559cf10ab4df26b45c53a5760ab519f1c5'}


class Bits:
    def __init__(self, data, start):
        self.data, self.pos = data, start
        self.end = (len(data) - 1) * 8 + data[-1].bit_length() - 1
        # Two adjacent fixture envelope terminators: PacketHandler then native
        # raw packet. This is an observed profile, not claimed native proof.
        value = int.from_bytes(data, 'little')
        if (value & ((1 << self.end) - 1)).bit_length() - 1 != self.end - 1:
            raise ValueError('Fixture lacks the observed adjacent terminators')
        self.end -= 1
        self.fields = []

    def read(self, amount, name):
        if amount < 0 or self.pos + amount > self.end:
            raise ValueError('Native bit archive exhausted')
        first, result = self.pos, 0
        for i in range(amount):
            result |= ((self.data[self.pos >> 3] >> (self.pos & 7)) & 1) << i
            self.pos += 1
        self.fields.append({'field': name, 'begin_udp_bit': first,
                            'end_udp_bit_exclusive': self.pos, 'value': result})
        return result

    def bounded(self, maximum, name):
        result, mask, first = 0, 1, self.pos
        while mask and result + mask < maximum:
            result |= self.read(1, '_native_bounded_bit') * mask
            mask = (mask << 1) & 0xffffffff
        self.fields = [f for f in self.fields if f['field'] != '_native_bounded_bit']
        self.fields.append({'field': name, 'begin_udp_bit': first,
                            'end_udp_bit_exclusive': self.pos, 'value': result,
                            'maximum_exclusive_parameter': maximum})
        return result

    def packed(self, name):
        result, first = 0, self.pos
        for group in range(5):
            byte = self.read(8, '_native_packed_group')
            result |= (byte >> 1) << (group * 7)
            if not byte & 1:
                break
        self.fields = [f for f in self.fields if f['field'] != '_native_packed_group']
        self.fields.append({'field': name, 'begin_udp_bit': first,
                            'end_udp_bit_exclusive': self.pos, 'value': result})
        return result & 0xffffffff


def physical_receive(data, start, packet_max_bytes=1024):
    b = Bits(data, start)
    header = b.read(32, 'notify_packed_u32')
    count = (header & 15) + 1
    for index in range(min(count, 8)):
        b.read(32, 'notify_history_u32_' + str(index))
    packet_info = b.read(1, 'packet_info_bit')
    # This fixture experiment chooses the native receiving-server branch; in
    # receiving-client branch a true packet_info bit consumes another u8.
    b.read(8, 'packet_info_ping_index_u8')
    control = b.read(1, 'bunch_control_bit')
    opened = b.read(1, 'bunch_flag_b4_bit0') if control else 0
    closed = b.read(1, 'bunch_flag_b4_bit1') if control else 0
    if closed:
        b.bounded(15, 'bunch_close_reason')
    b.read(1, 'bunch_flag_b4_bit3')
    reliable = b.read(1, 'bunch_flag_b4_bit4')
    b.read(1, 'bunch_flag_b5_bit3')
    channel = b.packed('bunch_channel_index')
    b.read(1, 'bunch_flag_b5_bit0')
    b.read(1, 'bunch_flag_b5_bit1')
    partial = b.read(1, 'bunch_flag_b4_bit5')
    if reliable:
        b.bounded(0x400, 'bunch_reliable_sequence')
    if partial:
        b.read(1, 'bunch_flag_b4_bit6')
        b.read(1, 'bunch_flag_b4_bit7')
    if reliable or opened:
        hardcoded = b.read(1, 'bunch_name_hardcoded_bit')
        if not hardcoded:
            raise ValueError('Nonhardcoded name requires native string path')
        b.packed('bunch_name_hardcoded_index')
    payload_bits = b.bounded(packet_max_bytes * 8, 'bunch_payload_bit_count')
    payload_begin = b.pos
    payload = b.read(payload_bits, 'bunch_payload_bits')
    return {'candidate_envelope_bits': start, 'notify_sequence14': header >> 18,
            'notify_ack14': (header >> 4) & 0x3fff, 'history_word_count': count,
            'packet_info': packet_info, 'channel_index': channel,
            'payload_begin_udp_bit': payload_begin, 'payload_bit_count': payload_bits,
            'payload_hex': payload.to_bytes((payload_bits + 7) // 8, 'little').hex(),
            'remaining_nontermination_bits': b.end - b.pos, 'field_boundaries': b.fields}


def main():
    rows = []
    for name, expected in EXPECTED.items():
        data = (FIXTURES / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError('Saved fixture SHA mismatch')
        candidates = []
        for start in range(81):
            try:
                candidate = physical_receive(data, start)
            except ValueError:
                continue
            if candidate['payload_bit_count'] == 80 and candidate['payload_hex'] == '00012d10334000000000':
                candidates.append(candidate)
        rows.append({'file': name, 'bytes': len(data), 'sha256': actual, 'candidates': candidates})
    out = ROOT / 'work/evidence/native-receive-hello-fixture-physical-check.json'
    result = {'kind': 'exact_native_field_order_saved_hello_fixture_experiment',
              'native_packet_accepted': False, 'process_accessed': False,
              'profile_qualifiers': {'receiving_server_branch': True,
                   'internal_ack': False, 'engine_network_version_at_least7': True,
                   'packet_max_bytes_parameter': 1024,
                   'packet_max_bytes_runtime_value_verified': False,
                   'outer_envelope_native_format_verified': False,
                   'payload_position_hardcoded': False,
                   'expected_payload_only_filters_final_experiment_result': True},
              'fixtures': rows}
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': out.name, 'sha256': hashlib.sha256(out.read_bytes()).hexdigest(),
          'candidate_counts': [len(row['candidates']) for row in rows],
          'candidate_positions': [[(x['candidate_envelope_bits'], x['payload_begin_udp_bit'], x['payload_bit_count'])
                                   for x in row['candidates']] for row in rows]}))


if __name__ == '__main__':
    main()
