"""The transport elapsed clock must distinguish receives inside one Windows tick."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dfserver import game_server_probe as module


class GameProbeClockTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.now = 1000.0
        self.clock = SimpleNamespace(perf_counter=lambda: self.now,
            monotonic=lambda: 900000.0+int((self.now-1000.0)*64)/64)
        clock_patch = patch.object(module, 'time', self.clock)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)
        self.probe = module.GameServerProbe(Path(self.folder.name))
        self.addCleanup(self.probe.close)
        self.addCleanup(setattr, self.probe, '_handshake', None)

    def test_start_and_record_elapsed_use_the_high_resolution_clock(self):
        self.assertEqual(self.probe._started_at, 1000.0)
        self.probe._write_report = lambda: None
        self.now += .001
        self.probe._record('udp', b'fixture packet')
        self.now += .001
        self.probe._record('udp', b'fixture packet')
        self.assertAlmostEqual(self.probe.records[0]['elapsed_seconds'], .001, places=6)
        self.assertAlmostEqual(self.probe.records[1]['elapsed_seconds'], .002, places=6)

    def test_receives_timer_expiry_and_full_send_share_one_precise_elapsed_domain(self):
        probe = self.probe
        received, expired, sent = [], [], []
        probe._record = lambda *args, **kwargs: None
        probe._write_report = lambda: None
        probe._queue_registered_bootstraps_locked = lambda: None
        probe._pump_static_box_runtimes_locked = lambda: None
        connection = SimpleNamespace(control_peers={}, peers={},
            _note_actual_application_send=lambda *args, **kwargs: sent.append(kwargs['sent_at']) or True)
        probe._handshake = SimpleNamespace(packet_ack_probe=connection,
            _expire=lambda now: expired.append(now), poll=lambda now: [],
            handle=lambda payload, peer, now: received.append(now) or SimpleNamespace(
                response=None, rebound_from_peer=None, event='fixture'))
        peer = ('127.0.0.1', 1)
        coarse_before = self.clock.monotonic()
        self.now += .001
        probe._handle_udp_datagram(b'fixture packet', peer)
        self.now += .001
        probe._handle_udp_datagram(b'fixture packet', peer)
        self.assertEqual(self.clock.monotonic(), coarse_before)
        self.assertAlmostEqual(received[0], .001, places=6)
        self.assertAlmostEqual(received[1], .002, places=6)
        self.assertGreater(received[1], received[0])
        self.assertAlmostEqual(expired[-1], .002, places=6)
        owner = (object(), object(), object())
        probe._actual_application_send_owner_locked = lambda peer: owner
        self.now += .001
        self.assertTrue(probe._note_actual_application_send_locked(peer, b'fixture response', owner))
        self.assertAlmostEqual(sent[-1], .003, places=6)
        probe._handshake = None

    def test_fashion_retry_elapsed_uses_the_probe_counter_and_keeps_its_deadline_clock(self):
        from dfserver import legacy_ds_fashion_async_bridge as fashion
        peer, payload, attempt = ('127.0.0.1', 1), b'fixture response', object()
        absolute_times = []
        box = SimpleNamespace(_pending_send=(SimpleNamespace(application_payload=payload), object()),
            consume_send_permit_locked=lambda view, now: absolute_times.append(now) or ('ready', attempt))
        transport = SimpleNamespace(out_sequence=1, replies=0)
        binding = SimpleNamespace(box=box, view_locked=lambda: object(), active_attempt=None,
            contract=SimpleNamespace(transport=transport), last_attempt_at=None)
        self.probe._handshake = SimpleNamespace(packet_ack_probe=SimpleNamespace(
            control_peers={peer: SimpleNamespace(fashion_async_binding=binding)}))
        bridge = object.__new__(fashion.AsyncFashionTransportBridge)
        bridge.probe, bridge.bindings, bridge.clock = self.probe, [binding], lambda: 900000.0
        self.now += .001
        with patch.object(fashion, 'time', self.clock):
            self.assertTrue(bridge.before_socket_locked(peer, payload))
        self.assertAlmostEqual(binding.last_attempt_at, .001, places=6)
        self.assertEqual(absolute_times, [900000.0])
        self.assertIs(binding.active_attempt, attempt)


if __name__ == '__main__':
    unittest.main()
