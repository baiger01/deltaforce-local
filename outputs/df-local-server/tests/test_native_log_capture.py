import io
from pathlib import Path
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'work'))
from watch_client_log import follow


class NativeLogCaptureTests(unittest.TestCase):
    def start_capture(self, source, output, from_start=False):
        ready, stop = threading.Event(), threading.Event()
        worker = threading.Thread(target=follow, args=(source, output, 3),
                                  kwargs={'from_start': from_start, 'ready': ready, 'stop': stop})
        worker.start()
        self.addCleanup(lambda: (stop.set(), worker.join(2)))
        self.assertTrue(ready.wait(1))
        return stop, worker

    @staticmethod
    def encoded(text):
        return bytes(value ^ 0x5c for value in text.encode('utf-8'))

    def test_existing_log_is_skipped_but_new_error_is_captured_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            source, output = Path(directory) / 'DeltaForce.log', Path(directory) / 'alerts.log'
            source.write_bytes(self.encoded('old ScriptError token=secret\n'))
            stop, worker = self.start_capture(source, output)
            with source.open('ab') as stream:
                stream.write(self.encoded('new ScriptError token=secret\n'))
            time.sleep(.1)
            stop.set()
            worker.join(2)
            self.assertEqual(output.read_text(encoding='utf-8'),
                             'new ScriptError token=[redacted]\n')

    def test_new_log_and_unterminated_error_line_are_captured_at_stop(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            source, output = Path(directory) / 'DeltaForce.log', Path(directory) / 'alerts.log'
            stop, worker = self.start_capture(source, output)
            source.write_bytes(self.encoded('ScriptError final line'))
            stop.set()
            worker.join(2)
            self.assertEqual(output.read_text(encoding='utf-8'), 'ScriptError final line\n')

    def test_log_replacement_drops_partial_old_line(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            source, output = Path(directory) / 'DeltaForce.log', Path(directory) / 'alerts.log'
            source.write_bytes(self.encoded('ScriptError discarded'))
            stop, worker = self.start_capture(source, output, from_start=True)
            replacement = Path(directory) / 'replacement.log'
            replacement.write_bytes(self.encoded('ScriptError current\n'))
            replacement.replace(source)
            time.sleep(.1)
            stop.set()
            worker.join(2)
            self.assertEqual(output.read_text(encoding='utf-8'), 'ScriptError current\n')


if __name__ == '__main__':
    unittest.main()
