"""Exercise our codecs over real loopback TCP; no original game is launched."""
import hashlib
from pathlib import Path
import socket
import unittest

from dfserver.gcp_control import AuthRequest, AuthResponse, CommonAuthResponse, parse_auth_request, parse_auth_response
from dfserver.gcp_crypto import decode_received_body, encrypt_body
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import Frame, StreamDecoder
from dfserver.gcp_handshake import DhAckBody, create_server_ack, parse_ack_body, parse_ack_header
from dfserver.candidate_business import CandidateBusinessCodec

PROJECT = Path(__file__).resolve().parent.parent


def send_fragmented(connection, frame):
    wire = frame.encode()
    for offset in range(0, len(wire), 3):
        connection.sendall(wire[offset:offset + 3])


def receive_one(connection):
    decoder = StreamDecoder()
    while True:
        data = connection.recv(7)
        if not data:
            raise AssertionError('Peer closed before a complete frame')
        frames = decoder.feed(data)
        if frames:
            if len(frames) != 1 or decoder.pending_bytes:
                raise AssertionError('Unexpected trailing or coalesced frames')
            decoder.finish()
            return frames[0]


class GcpTransportSocketTests(unittest.TestCase):
    def test_fresh_handshake_and_encrypted_control_exchange_over_loopback_tcp(self):
        business_codec = CandidateBusinessCodec(PROJECT / 'protocol/candidate_business.pb',
                                                PROJECT / 'protocol/generated_class_metadata.json')
        # Tiny own parameters isolate transport integration from the unresolved
        # original-client configuration and account authentication policy.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(3)
            with socket.create_connection(listener.getsockname(), timeout=3) as client:
                server, _ = listener.accept()
                with server:
                    server.settimeout(3)
                    hello = Frame(11, 13, 0x1001, 0, 0,
                                  b'\x03\x00\x01\x12' + bytes(64) + b'\x03opaque tail', b'')
                    send_fragmented(client, hello)
                    ack = create_server_ack(receive_one(server), (23).to_bytes(64, 'big'),
                                            body=DhAckBody(b'own context'), header_word4=13, header_word9=0,
                                            compression_method=1, compression_threshold=0,
                                            compression_maximum=0)
                    send_fragmented(server, ack.frame)
                    received_ack = receive_one(client)
                    public = int.from_bytes(parse_ack_header(received_ack).server_public_key, 'big')
                    self.assertEqual(parse_ack_header(received_ack).compression_method, 1)
                    shared = pow(public, 6, 23)
                    client_key = hashlib.md5(shared.to_bytes((shared.bit_length() + 7) // 8, 'big')).digest()
                    self.assertEqual(parse_ack_body(decode_received_body(received_ack, client_key,
                                                                         direction='server_to_client')),
                                     DhAckBody(b'own context'))

                    request = AuthRequest(1, b'own credential', b'own opaque data', b'own context')
                    # Native C2S encryption uses the negotiated method even with flag zero.
                    send_fragmented(client, Frame(11, 13, 0x2001, 0, 0, b'',
                                                  encrypt_body(request.encode(), client_key)))
                    received_request = receive_one(server)
                    self.assertEqual(received_request.command, 0x2001)
                    self.assertEqual(parse_auth_request(decode_received_body(received_request, ack.session_key,
                                                                            direction='client_to_server')),
                                     request)

                    # These opaque values are test data, not an account authorization result.
                    response = AuthResponse(CommonAuthResponse(7, 3, b'own response\x00', 17),
                                            2, b'one', 3, b'two', 4, 5, b'three')
                    send_fragmented(server, Frame(11, 13, 0x2002, 1, 0, b'',
                                                  encrypt_body(response.encode(), ack.session_key)))
                    received_response = receive_one(client)
                    self.assertEqual(received_response.command, 0x2002)
                    self.assertEqual(parse_auth_response(decode_received_body(received_response, client_key,
                                                                             direction='server_to_client')),
                                     response)

                    request_fields = {'grid_page_id': 1, 'get_prop_type': 2, 'invoke_event': 1}
                    business = business_codec.encode('CSDepositGetPropsReq', request_fields, sequence=42)
                    next_fields = {'grid_page_id': 2, 'get_prop_type': 2, 'invoke_event': 1}
                    next_business = business_codec.encode('CSDepositGetPropsReq', next_fields, sequence=43)
                    send_fragmented(client, encode_data_frame((business, next_business), client_key,
                        direction='client_to_server', compression_method=1, compressed=True))
                    received_business = receive_one(server)
                    messages = decode_data_frame(received_business, ack.session_key,
                        direction='client_to_server', compression_method=1).messages
                    self.assertEqual(len(messages), 2)
                    decoded, decoded_next = map(business_codec.decode, messages)
                    self.assertEqual(decoded.fields, request_fields)
                    self.assertEqual((decoded.name, decoded.service, decoded.sequence),
                                     ('CSDepositGetPropsReq', 'deposit', 42))
                    self.assertEqual(decoded_next.fields, next_fields)
                    self.assertEqual(decoded_next.sequence, 43)

                    # Test-only page and item IDs are explicit. No original game
                    # content definitions or native item placement are assumed.
                    response_fields = {'result': 0, 'grid_pages': [
                        {'grid_page_id': 1, 'grid_length': 10, 'grid_width': 12,
                         'props': [{'id': '6001', 'gid': '1001', 'num': '2', 'length': 1, 'width': 2}]}]}
                    next_response_fields = {'result': 0, 'grid_pages': [
                        {'grid_page_id': 2, 'grid_length': 10, 'grid_width': 12}]}
                    send_fragmented(server, encode_data_frame((
                        business_codec.response(decoded, response_fields),
                        business_codec.response(decoded_next, next_response_fields)), ack.session_key,
                        direction='server_to_client', compression_method=1, compressed=True))
                    received_business_response = receive_one(client)
                    responses = decode_data_frame(received_business_response, client_key,
                        direction='server_to_client', compression_method=1).messages
                    self.assertEqual(len(responses), 2)
                    decoded_response, decoded_next_response = map(business_codec.decode, responses)
                    self.assertEqual((decoded_response.name, decoded_response.service, decoded_response.sequence),
                                     ('CSDepositGetPropsRes', 'deposit', 42))
                    self.assertEqual(decoded_response.fields, response_fields)
                    self.assertEqual(decoded_next_response.fields, next_response_fields)
                    self.assertEqual(decoded_next_response.sequence, 43)


if __name__ == '__main__':
    unittest.main()
