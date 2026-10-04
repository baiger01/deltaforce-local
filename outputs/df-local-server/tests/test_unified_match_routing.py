"""A stopped map probe must retain the authenticated maintenance response."""

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dfserver.handshake_diagnostic import inspect_exchange
import test_native_auxiliary_wire as auxiliary_wire
import test_native_match_unavailable as unavailable_wire


class UnifiedMatchRoutingTests(unittest.TestCase):
    def exercise_stopped_probe(self, *, registered):
        stopped_probe = SimpleNamespace(listening=False)

        def inspect_with_stopped_probe(*args, **kwargs):
            return inspect_exchange(*args, game_server_probe=stopped_probe, **kwargs)

        with patch.object(unavailable_wire, 'inspect_exchange', inspect_with_stopped_probe):
            unavailable_wire.NativeMatchUnavailableWireTests.exercise_route(
                self, registered=registered)

    def test_normal_login_with_stopped_probe_keeps_maintenance_reply(self):
        self.exercise_stopped_probe(registered=True)

    def test_registration_with_stopped_probe_keeps_maintenance_reply(self):
        self.exercise_stopped_probe(registered=False)

    def exercise_stopped_probe_auxiliary(self, *, registered):
        stopped_probe = SimpleNamespace(listening=False)

        def inspect_with_stopped_probe(*args, **kwargs):
            return inspect_exchange(*args, game_server_probe=stopped_probe, **kwargs)

        with patch.object(auxiliary_wire, 'inspect_exchange', inspect_with_stopped_probe):
            auxiliary_wire.NativeAuxiliaryWireTests.exercise_route(
                self, registered=registered)

    def test_normal_login_with_stopped_probe_keeps_rank_disabled(self):
        self.exercise_stopped_probe_auxiliary(registered=True)

    def test_registration_with_stopped_probe_keeps_rank_disabled(self):
        self.exercise_stopped_probe_auxiliary(registered=False)


if __name__ == '__main__':
    unittest.main()
