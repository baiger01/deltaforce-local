import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ClientLogWatcherTests(unittest.TestCase):
    def test_legacy_console_encoding_does_not_stop_log_capture(self):
        script = Path(__file__).resolve().parents[3] / 'work/watch_client_log.py'
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'client.log', Path(directory) / 'alerts.log'
            line = 'LuaMStore: Error: Mandel asset path \u00bb\n'
            source.write_bytes(bytes(value ^ 0x5C for value in line.encode('utf-8')))
            result = subprocess.run([sys.executable, str(script), '--source', str(source),
                '--output', str(output), '--duration-seconds', '1', '--from-start'],
                env={**os.environ, 'PYTHONIOENCODING': 'gbk'}, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', 'replace'))
            self.assertEqual(output.read_text(encoding='utf-8'), line)
            self.assertIn('client_log_alerts=1', result.stdout.decode('utf-8'))
