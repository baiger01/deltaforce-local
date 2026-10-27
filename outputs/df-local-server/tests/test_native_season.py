"""Check original season metadata over the business response codec."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dfserver.client_errors import error_code
from dfserver.core import Backend
from dfserver.gcp_data import decode_data_frame, encode_data_frame
from dfserver.gcp_framing import StreamDecoder
from dfserver.handshake_diagnostic import (
    _candidate_codec, _candidate_local_auxiliary_response, _continue_local_lobby,
    _log_request_progress,
)


ROOT = Path(__file__).resolve().parent.parent
CN = timezone(timedelta(hours=8))
NOW = int(datetime(2026, 10, 6, tzinfo=CN).timestamp())


class NativeSeasonTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.backend = Backend(Path(directory.name) / 'save.sqlite3', ROOT / 'definitions.json')
        self.token = self.backend.register('season-wire', 'local-password-123')['session']
        self.codec = _candidate_codec()
        self.key = b'0123456789abcdef'

    def reply(self, fields, token=None, entry=None):
        if entry is None:
            entry = {}
        message = b'ABCD' + self.codec.encode('CSSeasonGetInfoReq', fields, sequence=43)
        frame = _candidate_local_auxiliary_response(message, self.backend,
            token or self.token, self.key, header_word4=12, header_word9=81,
            diagnostic_entry=entry)
        decoded = decode_data_frame(frame, self.key, direction='server_to_client',
                                    compression_method=1).messages[0]
        response = self.codec.decode(decoded)
        self.assertEqual(response.name, 'CSSeasonGetInfoRes')
        self.assertEqual(response.sequence, 43)
        self.assertTrue(entry['local_auxiliary_response_expected'])
        return response.fields

    def test_current_season_query_contains_serial_and_original_dates(self):
        from dfserver import native_season
        before = self.backend.native_lobby_profile(self.token)
        with patch.object(native_season.time, 'time', return_value=NOW):
            for mode in (1, 2):
                with self.subTest(mode=mode):
                    response = self.reply({'serial': 0, 'mode': mode})
                    self.assertEqual(response['result'], 0)
                    self.assertEqual(response['cur_serial'], 11)
                    self.assertEqual(response['season_info']['serial'], 11)
                    self.assertEqual(response['start_time'], 1788458400)
                    self.assertEqual(response['end_time'], 1793815200)
                    self.assertFalse(response['season_info']['rank_summary']['has_attended'])
                    self.assertEqual(response.get('awards', []), [])
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_original_default_sol_request_accepts_absent_and_zero_mode(self):
        from dfserver import native_season
        before = self.backend.native_lobby_profile(self.token)
        with patch.object(native_season.time, 'time', return_value=NOW):
            expected = self.reply({'mode': 1})
            for fields in ({}, {'mode': 0}, {'serial': 0, 'mode': 0}):
                with self.subTest(fields=fields):
                    self.assertEqual(self.reply(fields), expected)
            direct = native_season.response_fields(
                SimpleNamespace(name='CSSeasonGetInfoReq', fields={}), self.backend, self.token)
            self.assertEqual((direct['result'], direct['cur_serial']), (0, 11))
            for serial in (-1, 99):
                with self.subTest(serial=serial):
                    self.assertEqual(self.reply({'mode': 0, 'serial': serial})['result'],
                                     error_code('SeasonInvalidSerial'))
        self.assertEqual(self.backend.native_lobby_profile(self.token), before)

    def test_unknown_modes_do_not_publish_season_metadata(self):
        from dfserver import native_season
        with patch.object(native_season.time, 'time', return_value=NOW):
            for mode in (3, 99, 2**32 - 1):
                with self.subTest(mode=mode):
                    response = self.reply({'mode': mode})
                    self.assertEqual(response['result'], error_code('SeasonInvalidSerial'))
                    self.assertNotIn('season_info', response)
                    self.assertNotIn('cur_serial', response)

    def test_season_diagnostic_records_mode_and_serial_without_player_identity(self):
        from dfserver import native_season
        entry = {'request_name': 'CSSeasonGetInfoReq'}
        own = self.backend.native_identity(self.token)['native_id']
        with patch.object(native_season.time, 'time', return_value=NOW):
            self.reply({'mode': 0, 'serial': 0, 'player_id': own}, entry=entry)
        self.assertEqual(entry['local_season_request'], {'mode': 0, 'serial': 0})
        with patch('builtins.print') as output:
            _log_request_progress(entry, 'processed')
        event = json.loads(output.call_args.args[0])
        self.assertEqual(event['local_season_request'], {'mode': 0, 'serial': 0})
        self.assertNotIn(str(own), output.call_args.args[0])

    def test_transition_uses_original_time_window_and_rejects_unknown_future(self):
        from dfserver import native_season
        boundary = datetime(2026, 9, 4, 2, tzinfo=CN).timestamp()
        for instant, serial in ((boundary - 1, 10), (boundary, 11)):
            with patch.object(native_season.time, 'time', return_value=instant):
                self.assertEqual(self.reply({'mode': 1})['cur_serial'], serial)
        with patch.object(native_season.time, 'time', return_value=1793815200):
            self.assertNotEqual(self.reply({'mode': 1})['result'], 0)

    def test_historical_query_keeps_current_header_and_does_not_invent_matches(self):
        from dfserver import native_season
        with patch.object(native_season.time, 'time', return_value=NOW):
            response = self.reply({'serial': 5, 'mode': 1})
            self.assertEqual((response['cur_serial'], response['season_info']['serial']), (11, 5))
            self.assertEqual(response['season_info']['level'], 0)
            self.assertEqual(response['season_info'].get('total_fight', 0), 0)
            self.assertEqual(response.get('prev_serial', 0), 0)
            self.assertEqual(self.reply({'serial': 99, 'mode': 1})['result'],
                             error_code('SeasonInvalidSerial'))

    def test_unauthorized_query_and_other_player_do_not_publish_profile(self):
        from dfserver import native_season
        with patch.object(native_season.time, 'time', return_value=NOW):
            self.assertNotEqual(self.reply({'mode': 1}, token='invalid')['result'], 0)
            own = self.backend.native_identity(self.token)['native_id']
            response = self.reply({'mode': 1, 'player_id': own + 1})
            self.assertNotEqual(response['result'], 0)
            self.assertNotIn('season_info', response)

    def test_lobby_dispatch_sends_metadata_instead_of_an_empty_read_probe(self):
        from dfserver import native_season
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        client.settimeout(2)
        server.settimeout(2)
        message = (43).to_bytes(4, 'big') + self.codec.encode(
            'CSSeasonGetInfoReq', {'mode': 1}, sequence=43)
        current = encode_data_frame((message,), self.key, direction='client_to_server',
                                    header_word4=12, header_word9=9)
        client.shutdown(socket.SHUT_WR)
        result = {}
        with patch.object(native_season.time, 'time', return_value=NOW):
            _continue_local_lobby(server, StreamDecoder(), [], current,
                SimpleNamespace(session_key=self.key), self.backend.native_identity(self.token),
                self.backend, self.token, 10, result, continuation_seconds=2)
        frame = StreamDecoder().feed(client.recv(4096))[0]
        response = self.codec.decode(decode_data_frame(frame, self.key,
            direction='server_to_client', compression_method=1).messages[0])
        self.assertEqual(response.fields['cur_serial'], 11)
        entry = result['bounded_business_continuation'][0]
        self.assertTrue(entry['response_sent'])
        self.assertNotIn('empty_read_only_response_probe', entry)


if __name__ == '__main__':
    unittest.main()
