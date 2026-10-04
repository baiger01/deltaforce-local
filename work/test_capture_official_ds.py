"""Check fresh-session scoping and credential-free evidence before live capture."""
import json
from pathlib import Path
import tempfile
import unittest

from capture_official_ds import FreshLogTail, XOR_TABLE, endpoint_from_line, safe_line_evidence, recent_ds_hosts


def encoded(text):
    return b'\xef\xbb\xbf' + text.encode('utf-8').translate(XOR_TABLE)


class OfficialCaptureScopeTests(unittest.TestCase):
    def test_prearm_uses_only_recent_unique_logged_ds_hosts(self):
        prefix = '[2026.10.01-01.20.00:000]LuaSMatch: [GetLevelUrlAsync] url = , '
        lines = [prefix + f'8.8.8.{index}:32123?SecretKey=private-key' for index in range(1, 10)]
        lines += [prefix + '8.8.8.9:32124?Cookie=private-ticket',
                  prefix.replace('LuaSMatch:', 'LogHttp:') + '1.1.1.1:32123',
                  prefix + '127.0.0.1:32123']
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            path.write_bytes(encoded('\n'.join(lines) + '\n'))
            hosts, evidence = recent_ds_hosts(path)
        self.assertEqual(hosts, ['8.8.8.9', '8.8.8.8', '8.8.8.7', '8.8.8.6', '8.8.8.5', '8.8.8.4'])
        for private in ('private-key', 'private-ticket', '1.1.1.1', '127.0.0.1'):
            self.assertNotIn(private, json.dumps([hosts, evidence]))

    def test_prearm_truncated_tail_does_not_accept_partial_first_line(self):
        text = ('LuaSMatch: [GetLevelUrlAsync] url = , 8.8.8.8:32123\n'
                'LuaSMatch: [GetLevelUrlAsync] url = , 8.8.4.4:32123\n')
        raw = encoded(text)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            path.write_bytes(raw)
            hosts, evidence = recent_ds_hosts(path, max_bytes=len(raw)-4)
        self.assertEqual(hosts, ['8.8.4.4'])
        self.assertEqual(evidence['source_offset'], 4)

    def test_only_match_subsystem_endpoints_arm_capture(self):
        prefix = '[2026.10.01-01.20.00:000]LuaSMatch: Warning: '
        expected = ('8.8.8.8', 32123)
        self.assertEqual(endpoint_from_line(prefix + '[GetLevelUrlAsync] url = , '
                         '8.8.8.8:32123?Cookie=private-ticket'), expected)
        self.assertEqual(endpoint_from_line(prefix + '[OnDnsAsyncResloved] '
                         'ip and port:, 8.8.8.8, 32123'), expected)
        for line in [
            prefix + 'MakeConnectInfo selectedUrl tcp://8.8.8.8:65010',
            prefix.replace('LuaSMatch:', 'LogHttp:') + '[OnDnsAsyncResloved] ip and port:, 8.8.8.8, 32123',
            prefix + '[GetLevelUrlAsync] url = , invalid?Cookie=8.8.8.8:32123',
            prefix + '[GetLevelUrlAsync] url = , 127.0.0.1:32123?Cookie=private',
            prefix + '[GetLevelUrlAsync] url = , 192.168.1.1:32123',
            prefix + '[GetLevelUrlAsync] url = , 8.8.8.8:443',
            prefix + '[GetLevelUrlAsync] url = , 8.8.8.8:70000',
            prefix + '[GetLevelUrlAsync] url = , 999.8.8.8:32123',
        ]:
            self.assertIsNone(endpoint_from_line(line))

    def test_report_keeps_shapes_not_session_values(self):
        line = ('[2026.10.01-01.20.00:000]LuaSMatch: [GetLevelUrlAsync] url = , '
                '8.8.8.8:32123?PlayerId=private-player?Cookie=private-ticket?SecretKey=private-key')
        report = safe_line_evidence(line)
        self.assertEqual(report['url_parameter_lengths'], {'PlayerId': 14, 'Cookie': 14, 'SecretKey': 11})
        rendered = json.dumps(report)
        for value in ['private-player', 'private-ticket', 'private-key', '8.8.8.8:32123']:
            self.assertNotIn(value, rendered)

    def test_old_session_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            path.write_bytes(encoded('old-session-must-not-be-captured\n'))
            tail = FreshLogTail(path)
            self.assertEqual(tail.poll(), [])
            with path.open('ab') as stream:
                stream.write('fresh-session\n'.encode().translate(XOR_TABLE))
            self.assertEqual(tail.poll(), ['fresh-session'])

    def test_split_unicode_and_lines_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            tail = FreshLogTail(path)
            raw = encoded('零号大坝 fresh\n')
            path.write_bytes(raw[:4])
            self.assertEqual(tail.poll(), [])
            with path.open('ab') as stream:
                stream.write(raw[4:-1])
            self.assertEqual(tail.poll(), [])
            with path.open('ab') as stream:
                stream.write(raw[-1:])
            self.assertEqual(tail.poll(), ['零号大坝 fresh'])

    def test_log_truncation_starts_a_new_session(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            path.write_bytes(encoded('old-' + 'x'*200 + '\n'))
            tail = FreshLogTail(path)
            path.write_bytes(encoded('new-short-session\n'))
            self.assertEqual(tail.poll(), ['new-short-session'])

    def test_same_path_rewritten_with_larger_log_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'DeltaForce.log'
            path.write_bytes(encoded('old-' + 'x'*70 + '\n'))
            tail = FreshLogTail(path)
            new = 'new-' + 'y'*150
            path.write_bytes(encoded(new + '\n'))
            self.assertEqual(tail.poll(), [new])


if __name__ == '__main__':
    unittest.main()
