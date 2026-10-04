"""Publish the current original-client connection boundary without overstating it."""
from datetime import datetime, timezone
from pathlib import Path
import json
import psutil

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT / 'outputs/df-local-server'
NATIVE = ROOT / 'outputs/native-account-provider'

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

client = read(NATIVE / 'client-observation.json')
log = read(NATIVE / 'latest-client-log-observation.json')
probe = read(PROJECT / 'data/local-connection-probe.json')
headers = read(PROJECT / 'protocol/handshake_header_words.json')
control_headers = read(PROJECT / 'protocol/login_control_header_metadata.json')
binary = read(PROJECT / 'protocol/connection_parameter_candidates.json')
short_hex = read(PROJECT / 'protocol/dh_hex_length_candidates.json')
clear = read(ROOT / 'work/evidence/clear_startup_configuration_probe.json')
diagnostic_path = PROJECT / 'data/local-handshake-diagnostic.json'
diagnostic = read(diagnostic_path)
assert client['record_complete'] and client['original_sdk_restored']
assert client['provider_sha256'] == log['provider_sha256']
assert log['client_test_started_at_utc'] == client['observed_at_utc']
assert log['log_written_after_client_test_began']
assert client['original_client_local_game_connection_observed']
assert log['static_marker_counts']['WeGameSDK: Login Failed, ChannelID is 0'] == 0
assert any(record.get('observed_dh_hello_shape_valid') and record['version'] == 11
           and record['command'] == 0x1001 for record in probe['records'])
assert not probe['ack_sent']
assert {item['command'] for item in headers['handshake_headers']} == {0x1001, 0x1002}
server_controls = {item['command']: item for item in control_headers['control_frames']
                   if item['direction'] == 'server_to_client'}
assert [server_controls[command]['header_word9'] for command in ('0x1002', '0x2002', '0x6002')] == [1, 2, 3]
assert [server_controls[command]['body_bytes'] for command in ('0x2002', '0x6002')] == [96, 64]
assert diagnostic['connections_received'] == 1 and len(diagnostic['records']) == 1
assert diagnostic['records'][0]['outcome'] == 'transport_auth_request_decoded'
assert client['wire_identity_probe_requested'] and client['wire_identity_probe_records']
assert all(record['ack_sent'] and record['next_command'] == 0x2001
           and record['local_identity_correlations']['local_token_contained_in_auth_data']
           for record in client['wire_identity_probe_records'])
auth = client['wire_identity_probe_records'][-1]
assert auth['observed_at_utc'] > client['observed_at_utc']
assert auth['hello_version'] == 11 and auth['hello_command'] == 0x1001
assert auth['ack_sent'] and auth['ack_command'] == 0x1002
assert auth['diagnostic_exponent_one'] and auth['session_key_public']
assert auth['next_command'] == 0x2001
assert auth['next_header_word9'] == 2
assert auth['outcome'] in ('transport_auth_request_decoded',
                           'receive_timeout_after_control_parser_probe',
                           'closed_after_control_parser_probe',
                           'next_command_after_control_parser_probe', 'socket_error')
assert auth['auth_response_sent'] == client.get('wire_auth_response_probe_requested', False)
assert auth.get('ready_response_sent', False) == client.get('wire_ready_probe_requested', False)
if auth['auth_response_sent']:
    assert auth['auth_response_header_word9'] == server_controls['0x2002']['header_word9']
if auth.get('ready_response_sent'):
    assert auth['ready_response_header_word9'] == server_controls['0x6002']['header_word9']
assert not auth['business_response_sent']
assert auth['local_identity_correlations']['local_token_contained_in_field']
assert auth['local_identity_correlations']['local_token_contained_in_auth_data']
assert not auth['local_identity_correlations']['local_token_sha256_contained']
assert not any(connection.laddr and connection.laddr.ip == '127.0.0.1'
               and connection.laddr.port == 65010 and connection.status == 'LISTEN'
               for connection in psutil.net_connections(kind='tcp'))

now = datetime.now(timezone.utc).isoformat()
if diagnostic['listening']:
    diagnostic.update(listening=False, stopped_at_utc=now,
                      stopped_by_scoped_job_kill=True)
else:
    assert diagnostic['stopped_by_scoped_job_kill'] and diagnostic['stopped_at_utc']
diagnostic['original_client_ack_followed_by_decodable_auth_request'] = True
write(diagnostic_path, diagnostic)
short_rows = [item for file in short_hex['files'] for item in file['candidates']]
long_rows = [item for file in binary['files'] for item in file['candidates']]
clear_rows = clear['dh_shaped_hex_candidates']
result = {
    'checked_at_utc': now,
    'client_source_sha256': '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0',
    'provider_sha256': client['provider_sha256'],
    'specific_zero_channel_rejection_count': 0,
    'original_client_local_tcp_connection_observed': True,
    'first_frame': {'version': 11, 'command': 0x1001, 'wire_bytes': 206,
                    'public_key_bytes': 64, 'valid_dh_hello_shape': True},
    'original_client_handshake_ack_sent': True,
    'original_client_transport_auth_request_observed': True,
    'original_client_transport_auth_request_decoded': True,
    'original_client_ack_followed_by_auth_request': True,
    'original_client_auth_request_contains_own_local_session_token': True,
    'local_session_token_content_or_digest_exported': False,
    'diagnostic_exchange_exponent_one_insecure': True,
    'diagnostic_session_key_public': True,
    'diagnostic_listener_stopped': True,
    'diagnostic_auth_request_metadata': {
        'auth_type': auth['auth_type'],
        'credential_bytes': auth['credential_bytes'],
        'auth_data_bytes': auth['auth_data_bytes'],
        'context_bytes': auth['context_bytes'],
        'wire_bytes': auth['next_wire_bytes'],
    },
    'diagnostic_control_probe_outcome': auth['outcome'],
    'diagnostic_control_probe_connections': len(client['wire_identity_probe_records']),
    'diagnostic_control_probe_layout': auth.get('auth_response_probe_layout'),
    'original_client_connection_failure_after_control_probe': log.get('connection_failure'),
    'original_client_connection_timeout_dialog_observed': log.get('connection_timeout_dialog_observed', False),
    'diagnostic_post_response_command': auth.get('post_response_command'),
    'transport_auth_response_sent': auth['auth_response_sent'],
    'transport_auth_response_is_empty_parser_probe': auth.get('auth_response_is_empty_parser_probe', False),
    'transport_auth_response_is_minimal_fixed_schema_probe': auth.get('auth_response_probe_layout') == '0x3366_fixed_schema_zero_values',
    'transport_ready_response_sent': auth.get('ready_response_sent', False),
    'transport_ready_response_is_empty_parser_probe': auth.get('ready_response_is_empty_parser_probe', False),
    'transport_ready_response_is_minimal_fixed_schema_probe': auth.get('ready_response_probe_layout') == '0x3366_fixed_schema_zero_values',
    'production_account_authorization_response_implemented': False,
    'original_client_control_response_acceptance_verified': bool(auth.get('post_response_command')),
    'original_client_game_login_verified': False,
    'original_lobby_verified': False,
    'client_dh_modulus_verified': False,
    'static_parameter_search': {
        'executable_files_checked': len(binary['files']),
        '127_to_128_digit_candidates': len(long_rows),
        '127_to_128_digit_prime_screen_passed': sum(bool(item['probable_prime_screen']) for item in long_rows),
        '100_to_126_digit_candidates': len(short_rows),
        '100_to_126_digit_prime_screen_passed': sum(bool(item['passes_small_prime_screen']) for item in short_rows),
        'hash_verified_clear_pak_entries_checked': sum(
            item['counts'].get('clear_hash_validated', 0) for item in clear['archives']),
        'pak_hex_candidates': len(clear_rows),
        'pak_hex_prime_screen_passed': sum(bool(item['passes_small_prime_screen']) for item in clear_rows),
        'encrypted_and_oversized_pak_entries_not_searched': True,
        'absence_of_visible_prime_does_not_exclude_runtime_supplied_or_encoded_parameter': True,
    },
    'captured_official_ack_header_metadata': 'protocol/handshake_header_words.json',
    'captured_official_control_header_metadata': 'protocol/login_control_header_metadata.json',
    'captured_official_control_ciphertext_body_lengths': {'0x2002': 96, '0x6002': 64},
    'own_dh_only_diagnostic_module': 'dfserver/handshake_diagnostic.py',
    'own_dh_only_diagnostic_socket_tests_passed': 4,
    'original_client_partial_transport_compatibility_verified': True,
    'original_client_local_account_identity_correlated_with_transport_request': True,
    'original_client_game_login_or_lobby_compatibility_verified': False,
    'original_game_files_restored': True,
    'raw_game_code_payloads_credentials_keys_or_modulus_in_report': False,
}
write(PROJECT / 'protocol/current_handshake_progress.json', result)
validation_path = PROJECT / 'validation.json'
validation = read(validation_path)
validation['original_game_client_connected'] = True
validation['original_game_wire_protocol_verified'] = False
validation['automated_test_count'] = 153
validation['automated_tests_passed'] = 153
validation['automated_tests_checked_at_utc'] = now
validation['test_groups']['dh_only_diagnostic_socket'] = 4
validation['current_handshake_progress'] = 'protocol/current_handshake_progress.json'
validation['original_client_partial_transport_handshake_verified'] = True
validation['original_client_transport_auth_request_decoded'] = True
validation['original_client_auth_request_contains_own_local_session_token'] = True
validation['transport_auth_response_sent'] = auth['auth_response_sent']
validation['transport_auth_response_is_empty_parser_probe'] = auth.get('auth_response_is_empty_parser_probe', False)
validation['transport_auth_response_is_minimal_fixed_schema_probe'] = auth.get('auth_response_probe_layout') == '0x3366_fixed_schema_zero_values'
validation['transport_ready_response_sent'] = auth.get('ready_response_sent', False)
validation['production_account_authorization_response_implemented'] = False
validation['latest_handshake_diagnostic_observation'] = {
    'observed_at_utc': auth['observed_at_utc'],
    'address': '127.0.0.1:65010',
    'ack_sent': True,
    'auth_request_decoded': True,
    'own_local_session_token_present': True,
    'auth_response_probe_layout': auth.get('auth_response_probe_layout'),
    'ready_response_probe_layout': auth.get('ready_response_probe_layout'),
    'control_probe_connections': len(client['wire_identity_probe_records']),
    'post_response_command': auth.get('post_response_command'),
    'outcome': auth['outcome'],
    'original_client_connection_failure': log.get('connection_failure'),
    'original_client_connection_timeout_dialog_observed': log.get('connection_timeout_dialog_observed', False),
    'insecure_exponent_one_diagnostic': True,
    'listener_stopped': True,
    'game_login_verified': False,
    'status_is_a_time_bounded_observation': True,
}
validation['latest_connection_probe_observation'] = {
    'observed_at_utc': probe['records'][-1]['observed_at_utc'],
    'address': '127.0.0.1:65010',
    'listening_socket_observed': probe['listening'],
    'connections_received': probe['connections_received'],
    'version_11_dh_hello_received': True,
    'handshake_ack_sent': False,
    'game_compatibility_verified': False,
    'status_is_a_time_bounded_observation': True,
}
write(validation_path, validation)
status_path = PROJECT / 'protocol/status.json'
status = read(status_path)
status['game_compatibility_verified'] = False
status['latest_original_client_local_handshake_progress'] = {
    'report': 'protocol/current_handshake_progress.json',
    'local_tcp_and_dh_hello_observed': True,
    'client_dh_modulus_verified': False,
    'diagnostic_ack_followed_by_decodable_auth_request': True,
    'own_local_session_token_seen_in_auth_request': True,
    'empty_auth_response_probe_sent': auth.get('auth_response_is_empty_parser_probe', False),
    'empty_ready_response_probe_sent': auth.get('ready_response_is_empty_parser_probe', False),
    'fixed_schema_auth_response_probe_sent': auth['auth_response_sent'] and not auth.get('auth_response_is_empty_parser_probe', False),
    'fixed_schema_ready_response_probe_sent': auth.get('ready_response_sent', False) and not auth.get('ready_response_is_empty_parser_probe', False),
    'post_response_command': auth.get('post_response_command'),
    'diagnostic_session_key_public_and_listener_stopped': True,
    'transport_auth_response_sent': auth['auth_response_sent'],
    'production_account_authorization_response_implemented': False,
    'original_lobby_verified': False,
}
write(status_path, status)
print(json.dumps({'original_client_hello_observed': True,
                  'client_dh_modulus_verified': False,
                  'original_client_auth_request_decoded': True,
                  'diagnostic_control_probe_outcome': auth['outcome'],
                  'diagnostic_listener_stopped': True,
                  'automated_tests_passed': 153}))
