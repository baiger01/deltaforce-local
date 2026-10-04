import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from analyze_official_ds_capture import udp_frame, handshake_candidate, entry_parameter_shapes, compare_initial_exchange
from collect_official_runtime_loading import collect
from dfserver.unreal_handshake_payload import LegacyHandshakePayload, encode_payload


def native_log(text):
    return b'\xef\xbb\xbf' + text.encode().translate(bytes(value ^ 0x5c for value in range(256)))


class OfficialDSAnalysisTests(unittest.TestCase):
    def test_exchange_comparison_finds_cookie_without_exporting_it_or_authorizing_native(self):
        cookie = b'private-test-cookie!'
        initial = encode_payload(LegacyHandshakePayload(False, False, 0, bytes(20)))
        challenge = encode_payload(LegacyHandshakePayload(False, True, 1.5, cookie))
        records = [('client_to_server', b'opaque!!' + initial),
                   ('server_to_client', challenge), ('client_to_server', b'opaque!!' + challenge)]
        result = compare_initial_exchange(records)
        self.assertTrue(result['initial_server_packet_then_positive_client_body_observed'])
        self.assertTrue(result['client_echo_cookie_found_as_contiguous_wire_bits'])
        self.assertEqual(result['wire_vs_plain_echo_differing_bits'], 0)
        self.assertFalse(result['server_response_envelope_verified'])
        self.assertNotIn(cookie.hex(), json.dumps(result))
        self.assertNotIn(cookie.decode(), json.dumps(result))
        records[1] = ('server_to_client', bytes(25))
        result = compare_initial_exchange(records)
        self.assertFalse(result['client_echo_cookie_found_as_contiguous_wire_bits'])
        self.assertFalse(result['encryption_algorithm_identified'])

    def test_udp_parser_rejects_fragmented_truncated_and_non_udp_frames(self):
        payload = b'synthetic-payload'
        udp = struct.pack('>4H', 12345, 54321, 8 + len(payload), 0) + payload
        header = bytearray(20)
        header[0], header[9] = 0x45, 17
        struct.pack_into('>H', header, 2, 20 + len(udp))
        header[12:16], header[16:20] = socket.inet_aton('127.0.0.1'), socket.inet_aton('8.8.8.8')
        ip = bytes(header) + udp
        parsed = udp_frame(101, ip)
        self.assertEqual(parsed[0], ('127.0.0.1', 12345))
        self.assertEqual(parsed[1], ('8.8.8.8', 54321))
        self.assertEqual(parsed[2], payload)
        ethernet = bytes(12) + b'\x08\x00' + ip
        vlan = bytes(12) + b'\x81\x00\x00\x01\x08\x00' + ip
        self.assertEqual(udp_frame(1, ethernet), parsed)
        self.assertEqual(udp_frame(1, vlan), parsed)
        fragmented = bytearray(ip)
        fragmented[6] = 0x20
        non_udp = bytearray(ip)
        non_udp[9] = 6
        for invalid in (ip[:-1], bytes(fragmented), bytes(non_udp)):
            self.assertIsNone(udp_frame(101, invalid))

    def test_body_candidate_does_not_export_a_cookie_or_claim_verification(self):
        cookie = b'private-test-cookie!'
        candidate = handshake_candidate(b'opaque!!' + encode_payload(
            LegacyHandshakePayload(False, False, 1.5, cookie)))
        self.assertEqual(candidate['role'], 'positive_time_body_candidate')
        self.assertTrue(candidate['candidate_only'])
        self.assertNotIn(cookie.hex(), json.dumps(candidate))

    def test_entry_shapes_omit_tickets_and_restrict_the_match_window(self):
        prefix = 'UGameFlowGraph::OnLuaGameFlowEvent() MdlName = Preparation, EventName = flowEvtPreparationStartMatchSuccess, '
        text = ('[2026.10.01-01.42.34:628]LogGPGameFlow: ' + prefix +
                '8.8.8.8:54321?Cookie=private-ticket?SecretKey=private-key\n' +
                '[2026.10.01-01.52.34:628]LogGPGameFlow: ' + prefix + '?Other=later-match\n')
        manifest = {'stages': [{'client_wall_time': '2026.10.01-01.42.34:627',
                                'stage_names': ['connection_url_built']}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'client.log'
            path.write_bytes(native_log(text))
            result = entry_parameter_shapes(path, manifest)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['url_parameter_lengths'], {'Cookie': 14, 'SecretKey': 11})
        self.assertNotIn('private-key', json.dumps(result))
        self.assertNotIn('later-match', json.dumps(result))

    def test_runtime_symbols_are_kept_separate_from_later_matches(self):
        manifest = {'stages': [{'client_wall_time': '2026.10.01-01.42.33:026',
                                'stage_names': ['start_connect_requested']}]}
        text = ('[2026.10.01-01.42.32:000]LogStreaming: /Game/Old/Old\n'
                '[2026.10.01-01.42.35:000]LogStreaming: /Game/Maps/Dam/Cell\n'
                '[2026.10.01-01.42.36:000]LogPlayer: APlayerController::OnPossess private-player\n'
                '[2026.10.01-01.50.25:000]LogGPGameFlow: UGameFlowGraph::OnLuaGameFlowEvent() '
                'MdlName = InGame, EventName = flowEvtOnClientQuit, ArgStr = private-ticket\n'
                '[2026.10.01-01.52.35:000]LogStreaming: /Game/Next/Next\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'DeltaForce/Saved/Logs/DeltaForce.log'
            path.parent.mkdir(parents=True)
            path.write_bytes(native_log(text))
            result = collect(root, manifest)
        rendered = json.dumps(result)
        self.assertEqual(result['window_end_reason'], 'first_match_client_quit')
        self.assertIn('/Game/Maps/Dam/Cell', rendered)
        for forbidden in ('/Game/Old/Old', '/Game/Next/Next', 'private-player', 'private-ticket'):
            self.assertNotIn(forbidden, rendered)
