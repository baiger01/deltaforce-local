"""Independent UDP-worker recovery checks; no game client or fixed DS port."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from dfserver.game_server_probe import GameServerProbe


PRIVATE_ERROR_MESSAGE = 'private-socket-error-must-not-enter-report'


class ObservedProbe(GameServerProbe):
    def __init__(self, *args, **kwargs):
        self.packet_recorded = threading.Event()
        self.failure_reported = threading.Event()
        self.retry_polled = threading.Event()
        self.retry_poll_count = 0
        super().__init__(*args, **kwargs)

    def _record(self, transport, payload, **kwargs):
        super()._record(transport, payload, **kwargs)
        if transport == 'udp' and kwargs.get('direction', 'received') == 'received':
            self.packet_recorded.set()

    def _write_report(self):
        super()._write_report()
        if getattr(self, '_udp_receive_state', None) == 'failed':
            self.failure_reported.set()

    def _send_control_retries(self):
        self.retry_poll_count += 1
        self.retry_polled.set()
        return super()._send_control_retries()


class InjectOnceSocket:
    """Inject one error, then receive from the probe's independent real socket."""
    def __init__(self, delegate, error):
        self.delegate = delegate
        self.error = error
        self.recv_calls = 0
        self.real_receive_entered = threading.Event()

    def recvfrom(self, size):
        self.recv_calls += 1
        if self.recv_calls == 1 and self.error is not None:
            raise self.error
        self.real_receive_entered.set()
        return self.delegate.recvfrom(size)

    def __getattr__(self, name):
        return getattr(self.delegate, name)


class StopReleasedSocket:
    """Deterministically raise after close; no timing-dependent socket close race."""
    def __init__(self, delegate, *, immediate_error=False):
        self.delegate = delegate
        self.immediate_error = immediate_error
        self.recv_calls = 0
        self.receive_entered = threading.Event()
        self.closed = threading.Event()

    def recvfrom(self, _size):
        self.recv_calls += 1
        self.receive_entered.set()
        if self.immediate_error and self.recv_calls == 1:
            raise OSError(5, PRIVATE_ERROR_MESSAGE)
        if not self.closed.wait(3):
            raise AssertionError('Test socket was not released by close')
        raise OSError(5, PRIVATE_ERROR_MESSAGE)

    def close(self):
        self.closed.set()
        return self.delegate.close()

    def __getattr__(self, name):
        return getattr(self.delegate, name)


class ThreadStatus:
    def __init__(self, alive):
        self.alive = alive

    def is_alive(self):
        return self.alive

    def join(self, timeout=None):
        pass


class UDPReceiveErrorTests(unittest.TestCase):
    def make_probe(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        probe = ObservedProbe(temporary.name, max_packets=8)
        self.addCleanup(probe.close)
        return probe

    def report(self, probe):
        text = (Path(probe.capture_dir) / 'report.json').read_text(encoding='utf-8')
        self.assertNotIn(PRIVATE_ERROR_MESSAGE, text)
        return json.loads(text)

    def exercise_recovery(self, error):
        probe = self.make_probe()
        wrapped = InjectOnceSocket(probe._udp, error)
        probe._udp = wrapped
        probe.start()
        self.assertTrue(wrapped.real_receive_entered.wait(3), 'Worker stopped after recoverable error')
        self.assertTrue(probe.listening)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'isolated-worker-recovery', ('127.0.0.1', probe.port))
        self.assertTrue(probe.packet_recorded.wait(3), 'Recovered worker did not record real UDP')
        self.assertTrue(probe.flush(timeout=3), 'Recovered packet was not persisted')
        received = [r for r in probe.records if r['direction'] == 'received' and r['transport'] == 'udp']
        self.assertEqual(len(received), 1)
        self.assertEqual((probe.capture_dir / received[0]['private_packet_file']).read_bytes(),
                         b'isolated-worker-recovery')
        self.assertEqual(probe._udp_receive_errors[10054], 1)
        self.assertIsNone(probe._udp_receive_failure)
        report = self.report(probe)
        self.assertEqual(report['udp_receive_state'], 'running')
        self.assertTrue(report['udp_receive_thread_alive'])
        self.assertEqual(report['udp_receive_errors']['10054'], 1)
        self.assertIsNone(report['udp_receive_failure'])
        self.assertFalse(report['gameplay_server_implemented'])

    def test_windows_winerror_reset_recovers_and_records_actual_loopback_packet(self):
        error = ConnectionResetError(22, PRIVATE_ERROR_MESSAGE)
        error.winerror = 10054  # Exercise Windows code even when errno differs.
        self.exercise_recovery(error)

    def test_errno_only_10054_reset_recovers_and_records_actual_loopback_packet(self):
        self.exercise_recovery(OSError(10054, PRIVATE_ERROR_MESSAGE))

    def test_fatal_error_stops_once_updates_report_and_does_not_poll_retries(self):
        probe = self.make_probe()
        wrapped = StopReleasedSocket(probe._udp, immediate_error=True)
        probe._udp = wrapped
        probe.start()
        self.assertTrue(probe.failure_reported.wait(3), 'Fatal receive error was not reported')
        probe._udp_receive_thread.join(3)
        self.assertFalse(probe._udp_receive_thread.is_alive())
        self.assertEqual(wrapped.recv_calls, 1)
        self.assertEqual(probe.retry_poll_count, 0)
        self.assertFalse(probe.listening)
        self.assertEqual(probe._udp_receive_state, 'failed')
        self.assertEqual(probe._udp_receive_failure, {'error_type': 'OSError', 'error_code': 5})
        self.assertEqual(probe._udp_receive_errors[5], 1)
        report = self.report(probe)
        self.assertEqual(report['udp_receive_state'], 'failed')
        self.assertFalse(report['listening'])
        self.assertEqual(report['udp_receive_failure'], {'error_type': 'OSError', 'error_code': 5})
        self.assertEqual(report['records'], [])
        probe.close()
        closed_report = self.report(probe)
        self.assertEqual(closed_report['udp_receive_state'], 'failed')
        self.assertFalse(closed_report['udp_receive_thread_alive'])

    def test_shutdown_error_does_not_count_as_failure(self):
        probe = self.make_probe()
        wrapped = StopReleasedSocket(probe._udp)
        probe._udp = wrapped
        probe.start()
        self.assertTrue(wrapped.receive_entered.wait(3))
        probe.close()  # Sets stop before the fake socket raises code 5.
        self.assertFalse(probe._udp_receive_thread.is_alive())
        self.assertEqual(probe._udp_receive_state, 'stopped')
        self.assertEqual(dict(probe._udp_receive_errors), {})
        self.assertIsNone(probe._udp_receive_failure)
        report = self.report(probe)
        self.assertEqual(report['udp_receive_state'], 'stopped')
        self.assertEqual(report['udp_receive_errors'], {})
        self.assertIsNone(report['udp_receive_failure'])
        self.assertFalse(report['listening'])

    def test_normal_close_stops_worker_without_fault_and_remains_idempotent(self):
        probe = self.make_probe()
        wrapped = InjectOnceSocket(probe._udp, None)
        probe._udp = wrapped
        probe.start()
        self.assertTrue(wrapped.real_receive_entered.wait(3))
        self.assertTrue(probe.listening)
        probe.close()
        probe.close()
        self.assertFalse(probe.listening)
        self.assertFalse(probe._udp_receive_thread.is_alive())
        report = self.report(probe)
        self.assertEqual(report['udp_receive_state'], 'stopped')
        self.assertEqual(report['udp_receive_errors'], {})
        self.assertIsNone(report['udp_receive_failure'])

    def test_dead_udp_thread_is_not_listening_even_with_nonempty_thread_list(self):
        probe = self.make_probe()
        dead = ThreadStatus(False)
        probe._threads = [dead]
        probe._udp_receive_thread = dead
        probe._udp_receive_state = 'running'
        self.assertFalse(probe.listening)
        probe._write_report()
        report = self.report(probe)
        self.assertFalse(report['udp_receive_thread_alive'])
        self.assertFalse(report['listening'])

    def test_failed_state_is_not_listening_even_if_thread_has_not_returned_yet(self):
        probe = self.make_probe()
        live = ThreadStatus(True)
        probe._threads = [live]
        probe._udp_receive_thread = live
        probe._udp_receive_state = 'failed'
        self.assertFalse(probe.listening)

    def test_timeout_polls_retries_and_continues_without_error_count(self):
        probe = self.make_probe()
        wrapped = InjectOnceSocket(probe._udp, socket.timeout())
        probe._udp = wrapped
        probe.start()
        self.assertTrue(probe.retry_polled.wait(3))
        self.assertTrue(wrapped.real_receive_entered.wait(3))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'after-timeout', ('127.0.0.1', probe.port))
        self.assertTrue(probe.packet_recorded.wait(3))
        self.assertTrue(probe.listening)
        self.assertEqual(dict(probe._udp_receive_errors), {})
        self.assertIsNone(probe._udp_receive_failure)
        self.assertEqual(self.report(probe)['udp_receive_state'], 'running')


if __name__ == '__main__':
    unittest.main()
