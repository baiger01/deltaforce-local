import json
from pathlib import Path
import socket
import tempfile
import time
import unittest

from dfserver.game_server_probe import GameServerProbe


class GameServerProbeTests(unittest.TestCase):
    def test_captures_both_possible_transports_without_claiming_gameplay(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with GameServerProbe(path, max_packets=2) as probe:
                self.assertTrue(probe.listening)
                with socket.create_connection(('127.0.0.1', probe.port)) as connection:
                    connection.sendall(b'TCP-first-frame')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                    datagram.sendto(b'UDP-first-frame', ('127.0.0.1', probe.port))
                    client_udp_port = datagram.getsockname()[1]
                deadline = time.monotonic() + 3
                while len(probe.records) < 2 and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual({item['transport'] for item in probe.records}, {'tcp', 'udp'})
                self.assertTrue(probe.flush(timeout=3))
                self.assertEqual({(path / item['private_packet_file']).read_bytes()
                                  for item in probe.records},
                                 {b'TCP-first-frame', b'UDP-first-frame'})
            report = json.loads((path / 'report.json').read_text(encoding='utf-8'))
            self.assertFalse(report['listening'])
            self.assertFalse(report['gameplay_server_implemented'])
            self.assertNotIn('TCP-first-frame', json.dumps(report))
            udp_record = next(item for item in report['records'] if item['transport'] == 'udp')
            self.assertEqual(udp_record['peer_port'], client_udp_port)
            self.assertGreaterEqual(udp_record['elapsed_seconds'], 0)

    def test_rejects_invalid_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                GameServerProbe(temporary, max_packets=0)
            with self.assertRaises(ValueError):
                GameServerProbe(temporary, max_bytes=65536)

    def test_records_tcp_connection_even_when_client_sends_no_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with GameServerProbe(path) as probe:
                with socket.create_connection(('127.0.0.1', probe.port)):
                    pass
                deadline = time.monotonic() + 3
                report = {}
                while time.monotonic() < deadline:
                    report = json.loads((path / 'report.json').read_text(encoding='utf-8'))
                    if report['tcp_connections_accepted']:
                        break
                    time.sleep(.01)
                self.assertEqual(report['tcp_connections_accepted'], 1)
                self.assertEqual(len(report['tcp_accept_samples']), 1)
                self.assertEqual(report['records'], [])
                self.assertFalse(report['gameplay_server_implemented'])
