"""Exercise the real argparse/preflight prefix without UAC or client mutation."""
import ast
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("run_native_elevated_trial.py")
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
# Stop before staging, sealing a request, or calling Windows APIs.
END = next(i for i, node in enumerate(TREE.body)
           if isinstance(node, ast.Assign) and any(
               isinstance(target, ast.Name) and target.id == "selected_game"
               for target in node.targets))
PREFLIGHT = compile(ast.fix_missing_locations(ast.Module(
    body=TREE.body[:END], type_ignores=[])), str(SOURCE), "exec")
SHADOW = str(SOURCE.parent / "cli-profile-shadow")
BASE_ARGS = [str(SOURCE), "--entry", "shipping", "--game-root", SHADOW,
    "--shadow-game", SHADOW, "--source-game", str(SOURCE.parent / "cli-profile-source"),
    "--wire-identity-probe", "--wire-auth-response-probe",
    "--wire-auth-identity-probe", "--wire-ready-probe", "--wire-ready-identity-probe",
    "--wire-business-login-probe", "--wire-business-bootstrap-probe",
    "--game-server-probe", "--ds-handshake-probe", "--ds-packet-ack-probe",
    "--ds-control-probe"]


class NativeControlProfileTests(unittest.TestCase):
    def preflight(self, extra):
        errors = io.StringIO()
        scope = {"__file__": str(SOURCE), "__name__": "__preflight_test__"}
        with (patch.object(sys, "argv", BASE_ARGS + extra),
              patch.object(sys, "path", [str(SOURCE.parent), *sys.path]),
              contextlib.redirect_stderr(errors)):
            try:
                exec(PREFLIGHT, scope)
            except SystemExit as error:
                return error.code, errors.getvalue(), scope
        return 0, errors.getvalue(), scope

    def test_missing_handoff_stops_before_authorization(self):
        code, error, scope = self.preflight(["--disable-device-seamless"])
        self.assertEqual(code, 2)
        self.assertIn("no local match handoff is sent", error)
        self.assertNotIn("request_path", scope)
        self.assertNotIn("shell", scope)

    def test_missing_ordinary_entry_stops_before_authorization(self):
        code, error, scope = self.preflight(["--ds-join-after-ready"])
        self.assertEqual(code, 2)
        self.assertIn("ordinary entry path", error)
        self.assertNotIn("request_path", scope)
        self.assertNotIn("shell", scope)

    def test_complete_profile_passes_and_preserves_both_flags(self):
        code, error, scope = self.preflight([
            "--ds-join-after-ready", "--disable-device-seamless"])
        self.assertEqual((code, error), (0, ""))
        self.assertTrue(scope["args"].ds_join_after_ready)
        self.assertTrue(scope["args"].disable_device_seamless)
        self.assertNotIn("request_path", scope)
        self.assertNotIn("shell", scope)


if __name__ == "__main__":
    unittest.main()
