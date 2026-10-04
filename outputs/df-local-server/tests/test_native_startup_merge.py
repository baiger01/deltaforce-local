"""Offline startup checks; no launcher, UAC, or native process is started."""
import argparse
import ast
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[3]
WRAPPER = ROOT / "work/run_native_elevated_trial.py"
RUNNER = ROOT / "work/verify_local_provider_client.py"
TREES = {path: ast.parse(path.read_text(encoding="utf-8"))
         for path in (WRAPPER, RUNNER)}


def run_nodes(nodes, scope):
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, "<offline startup merge>", "exec"), scope)


def parser_only(path):
    nodes = [node for node in TREES[path].body if
        (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
         and target.id == "parser" for target in node.targets)) or
        (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
         and isinstance(node.value.func, ast.Attribute)
         and isinstance(node.value.func.value, ast.Name)
         and node.value.func.value.id == "parser"
         and node.value.func.attr == "add_argument")]
    scope = {"argparse": argparse, "Path": Path, "SOURCE_GAME": Path("source")}
    run_nodes(nodes, scope)
    return scope["parser"]


class NativeStartupMergeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.environment = {
            "DF_LOCAL_RESOURCE_PROBE_SHA256": "sealed",
            "DF_LOCAL_RESOURCE_REGISTRATION_SHA256": "sealed",
        }
        self.process = SimpleNamespace(create_time=lambda: 1.5,
                                       exe=lambda: str(Path("shadow/client.exe")))
        self.run = Mock(return_value=SimpleNamespace(returncode=0))
        self.scope = {
            "Path": Path,
            "os": SimpleNamespace(environ=self.environment),
            "args": SimpleNamespace(entry="shipping"),
            "GAME": Path("shadow"), "SHADOW_GAME": Path("shadow"),
            "ENTRY": Path("shadow/client.exe"), "ROOT": ROOT,
            "TEST_ROOT": self.folder,
            "child": SimpleNamespace(pid=42, poll=lambda: None),
            "owned": {42: 1.5},
            "psutil": SimpleNamespace(Process=lambda pid: self.process,
                                      NoSuchProcess=LookupError, AccessDenied=PermissionError),
            "report": {"elapsed_seconds": 31},
            "resource_evidence_captured": False,
            "socket_evidence_captured": False,
            "keybox_probe_attempts": 0, "keybox_probe_next_at": 30,
            "keybox_probe_digest": None,
            "digest": lambda path: "sealed",
            "subprocess": SimpleNamespace(run=self.run, STDOUT=-2,
                                          TimeoutExpired=TimeoutError),
            "sys": SimpleNamespace(executable="offline-python"),
        }

    def collect(self):
        nodes = []
        for node in ast.walk(TREES[RUNNER]):
            if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                    and target.id == "auxiliary_client_verified" for target in node.targets)
                    and isinstance(node.value, ast.Constant)):
                nodes.append(node)
            elif isinstance(node, ast.If):
                condition = ast.unparse(node.test)
                if (("DF_LOCAL_RESOURCE_EVIDENCE" in condition
                     and "DF_LOCAL_SOCKET_EVIDENCE" in condition) or
                        condition.startswith("auxiliary_client_verified")):
                    nodes.append(node)
        run_nodes(sorted(nodes, key=lambda node: node.lineno), self.scope)
        return [Path(call.args[0][1]).name for call in self.run.call_args_list]

    def test_both_entry_points_default_to_thirty_minutes_and_keep_ds_flags(self):
        for path in TREES:
            parser = parser_only(path)
            self.assertEqual(parser.parse_args([]).observation_seconds, 1800)
            parsed = parser.parse_args(["--game-server-probe", "--ds-control-probe",
                                       "--replication-metadata-export"])
            self.assertTrue(parsed.game_server_probe)
            self.assertTrue(parsed.ds_control_probe)
            self.assertTrue(parsed.replication_metadata_export)

    def test_default_launch_does_not_start_optional_collectors(self):
        self.assertEqual(self.collect(), [])

    def test_resource_flag_does_not_start_socket_or_keybox_collectors(self):
        self.environment["DF_LOCAL_RESOURCE_EVIDENCE"] = "1"
        self.assertEqual(self.collect(), ["probe_live_resource_implementations.py"])
        self.assertIn("resource_loader_readonly_evidence", self.scope["report"])
        self.assertNotIn("socket_helper_readonly_evidence", self.scope["report"])

    def test_socket_flag_does_not_start_resource_collector(self):
        self.environment["DF_LOCAL_SOCKET_EVIDENCE"] = "1"
        self.assertEqual(self.collect(), ["probe_gunsmith_native.py",
                                         "probe_live_keybox_registration.py"])
        self.assertNotIn("resource_loader_readonly_evidence", self.scope["report"])

    def test_both_flags_preserve_all_three_collectors(self):
        self.environment.update(DF_LOCAL_RESOURCE_EVIDENCE="1", DF_LOCAL_SOCKET_EVIDENCE="1")
        self.assertEqual(self.collect(), ["probe_live_resource_implementations.py",
                                         "probe_gunsmith_native.py",
                                         "probe_live_keybox_registration.py"])

    def test_unverified_process_blocks_every_optional_read(self):
        self.environment.update(DF_LOCAL_RESOURCE_EVIDENCE="1", DF_LOCAL_SOCKET_EVIDENCE="1")
        changes = (
            {"args": SimpleNamespace(entry="bootstrap")},
            {"GAME": Path("source")},
            {"owned": {}},
            {"owned": {42: 2.5}},
            {"ENTRY": Path("another/client.exe")},
            {"child": SimpleNamespace(pid=42, poll=lambda: 0)},
        )
        for values in changes:
            with self.subTest(values=values):
                previous = {key: self.scope[key] for key in values}
                self.scope.update(values)
                self.assertEqual(self.collect(), [])
                self.scope.update(previous)
        self.assertEqual(self.scope["report"]["readonly_auxiliary_skip_reason"],
                         "owned_shipping_shadow_identity_not_verified")

    def test_changed_resource_source_hash_stops_before_subprocess(self):
        self.environment["DF_LOCAL_RESOURCE_EVIDENCE"] = "1"
        for field in ("DF_LOCAL_RESOURCE_PROBE_SHA256", "DF_LOCAL_RESOURCE_REGISTRATION_SHA256"):
            with self.subTest(field=field):
                self.environment[field] = "changed"
                self.scope["resource_evidence_captured"] = False
                self.assertEqual(self.collect(), [])
                self.assertEqual(self.scope["report"]["resource_loader_readonly_evidence"]["error"],
                                 "RuntimeError")
                self.environment[field] = "sealed"

    def test_worker_preserves_resource_opt_in_and_sealed_source_hashes(self):
        worker = next(node for node in TREES[WRAPPER].body
                      if isinstance(node, ast.If) and ast.unparse(node.test) == "args.worker")
        checks = [node for node in worker.body if
            (isinstance(node, ast.Assert) and "resource_helper_readonly_evidence" in ast.unparse(node)) or
            (isinstance(node, ast.If) and "resource_helper_readonly_evidence" in ast.unparse(node.test)
             and any(isinstance(child, ast.Assert) for child in node.body))]
        request = {"resource_helper_readonly_evidence": True,
                   "resource_helper_sha256": "sealed",
                   "resource_registration_sha256": "sealed"}
        scope = {"request": request, "digest": lambda path: "sealed",
                 "RESOURCE_PROBE": Path("probe.py"), "RESOURCE_REGISTRATION": Path("registration.py")}
        run_nodes(checks, scope)
        for field, value in (("resource_helper_readonly_evidence", 1),
                             ("resource_helper_sha256", "changed"),
                             ("resource_registration_sha256", "changed")):
            with self.subTest(field=field):
                previous = request[field]
                request[field] = value
                with self.assertRaises(AssertionError):
                    run_nodes(checks, scope)
                request[field] = previous


if __name__ == "__main__":
    unittest.main()
