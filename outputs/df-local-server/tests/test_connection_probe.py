import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest

from dfserver.connection_probe import ProbeServer, ProbeState
from dfserver.gcp_framing import BASE, Frame, MAGIC, MAX_BODY


class ConnectionProbeTests(unittest.TestCase):
    def exchange(self, payload):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / 'report.json'
            state = ProbeState(report)
            with ProbeServer(0, state) as server:
                worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
                worker.start()
                try:
                    with socket.create_connection(server.server_address, timeout=2) as connection:
                        connection.settimeout(2)
                        for offset in range(0, len(payload), 3):
                            connection.sendall(payload[offset:offset + 3])
                        connection.shutdown(socket.SHUT_WR)
                        # A completed probe closes without an ACK or payload.
                        self.assertEqual(connection.recv(1), b'')
                    result = json.loads(report.read_text(encoding='utf-8'))
                finally:
                    server.shutdown()
                    worker.join(timeout=2)
            return result

    def test_fragmented_hello_is_metadata_only(self):
        ext = b'\x03' + struct.pack('>H', 1) + b'\x08' + b'S' * 64 + b'\x03'
        result = self.exchange(Frame(11, 0, 0x1001, 0, 0, ext, b'').encode())
        row = result['records'][0]
        self.assertTrue(row['observed_dh_hello_shape_valid'])
        self.assertEqual(row['public_key_length'], 1)
        self.assertFalse(result['ack_sent'])
        self.assertFalse(result['original_client_attribution_performed'])
        self.assertNotIn('client_public_key', json.dumps(result))
        self.assertNotIn('SSSSSSSS', json.dumps(result))

    def test_body_content_is_not_saved(self):
        payload = b'token=TEST_PRIVATE_PAYLOAD'
        result = self.exchange(Frame(11, 0, 0x2001, 0, 0, b'', payload).encode())
        self.assertEqual(result['records'][0]['body_size'], len(payload))
        self.assertNotIn('TEST_PRIVATE_PAYLOAD', json.dumps(result))

    def test_truncated_frame_is_reported(self):
        result = self.exchange(b'\x33\x66')
        self.assertEqual(result['records'][0]['outcome'], 'closed_before_complete_frame')
        self.assertEqual(result['records'][0]['bytes_received'], 2)

    def test_oversized_body_is_rejected_from_header(self):
        payload = BASE.pack(MAGIC, 11, 0, 0x2001, 0, 0, BASE.size, MAX_BODY + 1)
        result = self.exchange(payload)
        self.assertEqual(result['records'][0]['outcome'], 'invalid_frame')
        self.assertEqual(result['records'][0]['bytes_received'], BASE.size)


if __name__ == '__main__':
    unittest.main()
