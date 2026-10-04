"""AST-isolated launch exit tests. Never execute the wrapper module or Windows APIs."""
import ast
from pathlib import Path
from types import SimpleNamespace
import json
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).with_name("run_native_elevated_trial.py")
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))


def key_assignment(node, key):
    return (isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and
        target.value.id == "report" and isinstance(target.slice, ast.Constant) and
        target.slice.value == key for target in node.targets))


def helper():
    function = next(node for node in TREE.body
                    if isinstance(node, ast.FunctionDef) and node.name == "launch_exit_status")
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                 "<isolated-exit-helper>", "exec"), namespace)
    return namespace["launch_exit_status"]


class LaunchExitTests(unittest.TestCase):
    def run_state_branch(self, success, handle, worker_exit=0, windows_error=1223):
        branch = next(node for node in TREE.body if isinstance(node, ast.If) and
            isinstance(node.test, ast.BoolOp) and
            any(isinstance(item, ast.Name) and item.id == "success" for item in node.test.values))
        assignments = [next(node for node in TREE.body if key_assignment(node, key)) for key in
                       ("shell_execute_succeeded", "helper_process_handle_available")]
        final_assignment = next(node for node in TREE.body if key_assignment(node, "wrapper_exit_code"))
        final_raise = TREE.body[-1]
        self.assertIsInstance(final_raise, ast.Raise)
        kernel = SimpleNamespace(GetProcessId=Mock(return_value=100),
            WaitForSingleObject=Mock(return_value=0), CloseHandle=Mock())
        def get_exit_code(_handle, value):
            value.value = worker_exit
            return True
        kernel.GetExitCodeProcess = Mock(side_effect=get_exit_code)
        namespace = {"success": success, "info": SimpleNamespace(hProcess=handle),
            "report": {}, "kernel": kernel, "C": SimpleNamespace(byref=lambda item:item,
                get_last_error=lambda:windows_error),
            "W": SimpleNamespace(DWORD=lambda:SimpleNamespace(value=0)),
            "REPORT": SimpleNamespace(write_text=Mock()), "json": json,
            "args": SimpleNamespace(entry="shipping", ds_control_code_probe=False,
                                    ds_image_code_cache=False,
                                    replication_metadata_export=False,
                                    ds_initial_actor_bootstrap=False),
            "forward_control_collection_progress": Mock(),
            "forward_replication_metadata_progress": Mock(),
            "forward_initial_actor_bootstrap_progress": Mock(), "print": Mock(),
            "launch_exit_status": helper()}
        selected = ast.Module(body=assignments+[branch, final_assignment, final_raise], type_ignores=[])
        with self.assertRaises(SystemExit) as caught:
            exec(compile(ast.fix_missing_locations(selected), "<isolated-launch-state>", "exec"), namespace)
        return caught.exception.code, namespace["report"], kernel

    def test_windows_cancel_1223_is_nonzero_and_preserves_error(self):
        code, report, kernel = self.run_state_branch(False, None)
        self.assertEqual(code, 1)
        self.assertEqual(report["windows_error"], 1223)
        self.assertEqual(report["wrapper_exit_code"], 1)
        kernel.GetProcessId.assert_not_called()
        kernel.CloseHandle.assert_not_called()

    def test_other_shell_execute_failure_is_nonzero(self):
        code, report, _ = self.run_state_branch(False, None, windows_error=5)
        self.assertEqual((code, report["windows_error"]), (1, 5))

    def test_success_without_monitored_process_handle_is_nonzero(self):
        code, report, kernel = self.run_state_branch(True, None)
        self.assertEqual(code, 1)
        self.assertEqual(report["launch_error"], "missing_helper_process_handle")
        self.assertNotIn("helper_exit_code", report)
        kernel.GetExitCodeProcess.assert_not_called()
        kernel.CloseHandle.assert_not_called()

    def test_nonzero_worker_result_propagates_failure_and_closes_handle(self):
        for worker_exit in (1, 28, 1223, 0xffffffff):
            with self.subTest(worker_exit=worker_exit):
                code, report, kernel = self.run_state_branch(True, 99, worker_exit)
                self.assertEqual(code, 1)
                self.assertEqual(report["helper_exit_code"], worker_exit)
                kernel.CloseHandle.assert_called_once_with(99)

    def test_clean_monitored_worker_is_the_only_zero_result(self):
        code, report, kernel = self.run_state_branch(True, 99, 0)
        self.assertEqual(code, 0)
        self.assertEqual(report["helper_pid"], 100)
        self.assertEqual(report["wrapper_exit_code"], 0)
        kernel.CloseHandle.assert_called_once_with(99)

    def test_missing_or_noninteger_worker_exit_cannot_claim_success(self):
        for value in (None, False, "0", 0.0):
            with self.subTest(value=value):
                self.assertEqual(helper()({"shell_execute_succeeded": True,
                    "helper_process_handle_available": True, "helper_exit_code": value}), 1)

    def test_status_is_written_to_final_report_before_process_exit(self):
        assignment = next(i for i,node in enumerate(TREE.body)
                          if key_assignment(node, "wrapper_exit_code"))
        self.assertLess(assignment, len(TREE.body)-3)
        self.assertTrue(any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
            isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "write_text"
            for node in TREE.body[assignment+1:-1]))


if __name__ == "__main__":
    unittest.main()
