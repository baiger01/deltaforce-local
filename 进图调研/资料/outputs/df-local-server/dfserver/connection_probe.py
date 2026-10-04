"""Loopback first-frame diagnostic. Does not acknowledge or authorize clients."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import socketserver
import threading

from .gcp_framing import BASE, decode_prefix
from .gcp_handshake import parse_hello


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class ProbeState:
    def __init__(self, report):
        self.report = Path(report)
        self.lock = threading.Lock()
        self.data = {
            'kind': 'loopback_first_frame_probe',
            'started_at_utc': timestamp(),
            'listening': False,
            'connections_received': 0,
            'records': [],
            'ack_sent': False,
            'business_gateway_enabled': False,
            'original_client_attribution_performed': False,
            'game_compatibility_verified': False,
        }

    def _write(self):
        self.report.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.report.with_suffix(self.report.suffix + '.tmp')
        temporary.write_text(json.dumps(self.data, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.report)

    def update(self, **values):
        with self.lock:
            self.data.update(values)
            self._write()

    def record(self, values):
        with self.lock:
            self.data['connections_received'] += 1
            # Persist only framing numbers, sizes and outcome identifiers.
            # Raw data, keys, tokens, addresses and arbitrary error text are absent.
            self.data['records'] = (self.data['records'] + [values])[-32:]
            self._write()


def inspect_connection(connection, timeout=10):
    connection.settimeout(timeout)
    received = bytearray()
    result = {'observed_at_utc': timestamp()}
    expected = BASE.size
    try:
        while len(received) < expected:
            part = connection.recv(min(65536, expected - len(received)))
            if not part:
                result['outcome'] = 'closed_before_complete_frame'
                break
            received.extend(part)
            if len(received) == BASE.size:
                # Validates the base header before accepting a body length.
                decode_prefix(received)
                values = BASE.unpack(received)
                expected = values[-2] + values[-1]
        else:
            frame, consumed = decode_prefix(received)
            result.update({
                'outcome': 'complete_first_frame',
                'version': frame.version,
                'command': frame.command,
                'encryption_flag': frame.payload_encryption_flag,
                'header_size': BASE.size + len(frame.extra_header),
                'body_size': len(frame.body),
                'wire_size': consumed,
                'observed_dh_hello_shape_valid': False,
            })
            if frame.command == 0x1001:
                try:
                    hello = parse_hello(frame)
                except ValueError:
                    result['outcome'] = 'unsupported_hello_shape'
                else:
                    result.update({
                        'observed_dh_hello_shape_valid': True,
                        'encryption_method': hello.encryption_method,
                        'public_key_length': len(hello.client_public_key),
                        'opaque_context_length': len(hello.opaque_dh_context),
                        'remaining_header_length': len(hello.opaque_remaining_header),
                    })
    except (TimeoutError, socket.timeout):
        result['outcome'] = 'receive_timeout'
    except ValueError:
        result['outcome'] = 'invalid_frame'
    except OSError:
        result['outcome'] = 'socket_error'
    finally:
        result['bytes_received'] = len(received)
        received.clear()
    return result


class ProbeServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port, state):
        self.state = state
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', port), ProbeHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class ProbeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        result = inspect_connection(self.request)
        self.server.state.record(result)
        print(json.dumps(result), flush=True)


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description='Local first-frame probe; original game login unavailable')
    parser.add_argument('--port', type=int, default=65010)
    parser.add_argument('--report', type=Path, default=root / 'data/local-connection-probe.json')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error('port must be between 0 and 65535')
    state = ProbeState(args.report)
    with ProbeServer(args.port, state) as server:
        state.update(listening=True, address='127.0.0.1', port=server.server_address[1])
        print(f'First-frame probe listening on 127.0.0.1:{server.server_address[1]}', flush=True)
        print('No handshake ACK or game login response will be sent.', flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            state.update(listening=False, stopped_at_utc=timestamp())


if __name__ == '__main__':
    main()
