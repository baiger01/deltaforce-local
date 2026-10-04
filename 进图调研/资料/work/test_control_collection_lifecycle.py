"""Offline checks: parse sources and execute isolated pure/argument blocks only.

Neither runner is imported or run. No game, worker, Windows API or collector starts.
"""
import argparse
import ast
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


WORK = Path(__file__).resolve().parent
RUNNER = WORK / "verify_local_provider_client.py"
WRAPPER = WORK / "run_native_elevated_trial.py"
SOURCES = {path: path.read_text(encoding="utf-8") for path in (RUNNER, WRAPPER)}
TREES = {path: ast.parse(source, filename=str(path)) for path, source in SOURCES.items()}
OPTION = "--stop-after-code-collection"


def run_nodes(nodes, namespace):
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, "<isolated offline runner block>", "exec"), namespace)


def load_function(path, name, namespace=None):
    scope = {"json": json}
    scope.update(namespace or {})
    definition = next(node for node in TREES[path].body
                      if isinstance(node, ast.FunctionDef) and node.name == name)
    run_nodes([definition], scope)
    return scope[name]


def parser_only(path):
    nodes = []
    for node in TREES[path].body:
        if (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == "parser" for target in node.targets)):
            nodes.append(node)
        elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and
                isinstance(node.value.func, ast.Attribute) and
                isinstance(node.value.func.value, ast.Name) and
                node.value.func.value.id == "parser" and node.value.func.attr == "add_argument"):
            nodes.append(node)
    scope = {"argparse": argparse, "Path": Path, "SOURCE_GAME": Path("offline-source")}
    run_nodes(nodes, scope)
    return scope["parser"]


class ControlCollectionLifecycleTests(unittest.TestCase):
    def test_option_defaults_to_continuing_and_help_is_available_offline(self):
        for path in TREES:
            with self.subTest(path=path.name):
                parser = parser_only(path)
                self.assertFalse(parser.parse_args([]).stop_after_code_collection)
                self.assertFalse(parser.parse_args([]).ds_control_candidate_interval)
                self.assertFalse(parser.parse_args([]).ds_control_field_helpers)
                self.assertFalse(parser.parse_args([]).ds_control_followup_code)
                self.assertFalse(parser.parse_args([]).ds_control_sender_body)
                self.assertIn(OPTION, parser.format_help())
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as ended:
                        parser.parse_args(["--help"])
                self.assertEqual(ended.exception.code, 0)

    def test_stopping_requires_the_control_collection_profile(self):
        for path in TREES:
            parser = parser_only(path)
            validation = next(node for node in TREES[path].body
                              if isinstance(node, ast.If) and
                              "args.stop_after_code_collection" in ast.unparse(node.test))
            scope = {"parser": parser, "args": parser.parse_args([OPTION])}
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ended:
                    run_nodes([validation], scope)
            self.assertEqual(ended.exception.code, 2)
            scope["args"] = parser.parse_args([OPTION, "--ds-control-code-probe"])
            run_nodes([validation], scope)

    def test_candidate_interval_requires_control_profile_and_reaches_collector(self):
        option = "--ds-control-candidate-interval"
        for path in TREES:
            parser = parser_only(path)
            validation = next(node for node in TREES[path].body
                              if isinstance(node, ast.If) and
                              "args.ds_control_candidate_interval" in ast.unparse(node.test))
            scope = {"parser": parser, "args": parser.parse_args([option])}
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ended:
                    run_nodes([validation], scope)
            self.assertEqual(ended.exception.code, 2)
            scope["args"] = parser.parse_args([option, "--ds-control-code-probe"])
            run_nodes([validation], scope)
        call = next(node for node in ast.walk(TREES[RUNNER]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "collect_native_control_code")
        forwarded = next(key.value for key in call.keywords if key.arg == "candidate_interval")
        self.assertEqual(ast.unparse(forwarded), "args.ds_control_candidate_interval")

    def test_candidate_interval_request_and_both_hops_preserve_exact_bool(self):
        field, option = "ds_control_candidate_interval", "--ds-control-candidate-interval"
        dictionary = next(node.value for node in TREES[WRAPPER].body
                          if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                          and any(isinstance(target, ast.Name) and target.id == "request" for target in node.targets))
        value = next(value for key, value in zip(dictionary.keys, dictionary.values)
                     if isinstance(key, ast.Constant) and key.value == field)
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args." + field
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        self.assertEqual(len(hops), 2)
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and field in ast.unparse(node.test)]
        self.assertEqual(len(assertions), 2)
        for flag in (False, True):
            scope = {"args": SimpleNamespace(**{field: flag}),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            expression = ast.fix_missing_locations(ast.Expression(body=value))
            self.assertIs(eval(compile(expression, "<candidate option>", "eval"), scope), flag)
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [option] if flag else [])
            self.assertEqual(scope["parameters"], [option] if flag else [])
        for requested, parsed in ((True, False), (False, True), (1, True), (0, False)):
            with self.assertRaises(AssertionError):
                run_nodes(assertions, {"request": {field: requested},
                          "args": SimpleNamespace(**{field: parsed})})

    def test_field_helpers_require_control_profile_and_reject_combined_reads(self):
        option = "--ds-control-field-helpers"
        for path in TREES:
            parser = parser_only(path)
            validations = [node for node in TREES[path].body if isinstance(node, ast.If)
                           and isinstance(node.test, ast.BoolOp)
                           and ast.unparse(node.test.values[0]) == "args.ds_control_field_helpers"
                           and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                                   and isinstance(child.func.value, ast.Name)
                                   and child.func.value.id == "parser" and child.func.attr == "error"
                                   for child in ast.walk(node))]
            self.assertEqual(len(validations), 2)
            for supplied, accepted in (([option], False),
                    ([option, "--ds-control-code-probe"], True),
                    ([option, "--ds-control-code-probe", "--ds-control-candidate-interval"], False)):
                scope = {"parser": parser, "args": parser.parse_args(supplied)}
                if accepted:
                    run_nodes(validations, scope)
                else:
                    with contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as ended:
                            run_nodes(validations, scope)
                    self.assertEqual(ended.exception.code, 2)
        call = next(node for node in ast.walk(TREES[RUNNER]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "collect_native_control_code")
        forwarded = next(key.value for key in call.keywords if key.arg == "field_helpers")
        self.assertEqual(ast.unparse(forwarded), "args.ds_control_field_helpers")

    def test_field_helper_request_and_both_hops_preserve_exact_bool(self):
        field, option = "ds_control_field_helpers", "--ds-control-field-helpers"
        dictionary = next(node.value for node in TREES[WRAPPER].body
                          if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                          and any(isinstance(target, ast.Name) and target.id == "request" for target in node.targets))
        value = next(value for key, value in zip(dictionary.keys, dictionary.values)
                     if isinstance(key, ast.Constant) and key.value == field)
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args." + field
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        self.assertEqual(len(hops), 2)
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and field in ast.unparse(node.test)]
        self.assertEqual(len(assertions), 2)
        for flag in (False, True):
            scope = {"args": SimpleNamespace(**{field: flag}),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            expression = ast.fix_missing_locations(ast.Expression(body=value))
            self.assertIs(eval(compile(expression, "<field helper option>", "eval"), scope), flag)
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [option] if flag else [])
            self.assertEqual(scope["parameters"], [option] if flag else [])
        for requested, parsed in ((True, False), (False, True), (1, True), (0, False)):
            with self.assertRaises(AssertionError):
                run_nodes(assertions, {"request": {field: requested},
                          "args": SimpleNamespace(**{field: parsed})})

    def test_followup_profile_requirements_and_request_hops(self):
        field, option = "ds_control_followup_code", "--ds-control-followup-code"
        for path in TREES:
            parser = parser_only(path)
            validations = [node for node in TREES[path].body if isinstance(node, ast.If)
                           and isinstance(node.test, ast.BoolOp)
                           and ast.unparse(node.test.values[0]) == "args." + field
                           and "parser.error" in ast.unparse(node)]
            self.assertEqual(len(validations), 2)
            for supplied, accepted in (([option], False),
                    ([option, "--ds-control-code-probe"], True),
                    ([option, "--ds-control-code-probe", "--ds-control-field-helpers"], False),
                    ([option, "--ds-control-code-probe", "--ds-control-candidate-interval"], False)):
                scope = {"parser": parser, "args": parser.parse_args(supplied)}
                if accepted:
                    run_nodes(validations, scope)
                else:
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        run_nodes(validations, scope)
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args." + field
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        self.assertEqual(len(hops), 2)
        for flag in (False, True):
            scope = {"args": SimpleNamespace(**{field: flag}),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [option] if flag else [])
            self.assertEqual(scope["parameters"], [option] if flag else [])
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and field in ast.unparse(node.test)]
        self.assertEqual(len(assertions), 2)
        for requested, parsed, accepted in ((True, True, True), (False, False, True),
                                           (True, False, False), (1, True, False), (0, False, False)):
            scope = {"request": {field: requested}, "args": SimpleNamespace(**{field: parsed})}
            if accepted:
                run_nodes(assertions, scope)
            else:
                with self.assertRaises(AssertionError):
                    run_nodes(assertions, scope)
        wrapper = ast.unparse(TREES[WRAPPER])
        self.assertIn("request['control_followup_reader_sha256'] == digest(", wrapper)
        self.assertIn("request['sender_reader_sha256'] == digest(", wrapper)

    def test_sender_body_requires_its_own_fixed_profile_and_pinned_request(self):
        field, option = "ds_control_sender_body", "--ds-control-sender-body"
        for path in TREES:
            parser = parser_only(path)
            validations = [node for node in TREES[path].body if isinstance(node, ast.If)
                           and isinstance(node.test, ast.BoolOp)
                           and ast.unparse(node.test.values[0]) == "args." + field
                           and "parser.error" in ast.unparse(node)]
            self.assertEqual(len(validations), 2)
            combinations = (([option], False),
                ([option, "--ds-control-code-probe"], True)) + tuple(
                ([option, "--ds-control-code-probe", other], False) for other in
                ("--ds-control-followup-code", "--ds-control-field-helpers", "--ds-control-candidate-interval"))
            for supplied, accepted in combinations:
                scope = {"parser": parser, "args": parser.parse_args(supplied)}
                if accepted:
                    run_nodes(validations, scope)
                else:
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        run_nodes(validations, scope)
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args." + field
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        self.assertEqual(len(hops), 2)
        for flag in (False, True):
            scope = {"args": SimpleNamespace(**{field: flag}),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [option] if flag else [])
            self.assertEqual(scope["parameters"], [option] if flag else [])
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and field in ast.unparse(node.test)]
        self.assertEqual(len(assertions), 2)
        for requested, parsed in ((True, False), (False, True), (1, True), (0, False)):
            with self.assertRaises(AssertionError):
                run_nodes(assertions, {"request": {field: requested},
                          "args": SimpleNamespace(**{field: parsed})})
        self.assertIn("request['sender_body_reader_sha256'] == digest(",
                      ast.unparse(TREES[WRAPPER]))

    def test_sender_body_routing_never_starts_another_collector(self):
        node = next(node for node in ast.walk(TREES[RUNNER]) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "args.ds_control_sender_body"
                    and any(isinstance(child, ast.ImportFrom) for child in node.body))
        calls = []
        collector = SimpleNamespace(collect=lambda game, folder:
            calls.append((game, folder)) or {"status": "offline_mock", "functions": []})
        scope = {"args": SimpleNamespace(ds_control_sender_body=True), "GAME": "pinned-game",
                 "transport_folder": "bounded-output", "report": {}}
        with patch.dict("sys.modules", {"read_native_sender_body": collector}):
            run_nodes([node], scope)
        self.assertEqual(calls, [("pinned-game", "bounded-output")])
        self.assertEqual(scope["report"]["bounded_named_transport_collection"]["status"], "offline_mock")

    def test_followup_empty_or_exception_cannot_hide_a_failed_reader(self):
        collect = load_function(RUNNER, "collect_control_followup")
        summarize = load_function(RUNNER, "control_collection_summary")
        good = {"status": "bounded_read_attempt_complete", "functions": [{"name": "one", "read_succeeded": True}]}
        examples = ((good, "success"),
                    ({"status": "read_not_permitted", "functions": []}, "failure"),
                    ({"status": "bounded_read_attempt_complete", "functions": []}, "failure"),
                    (RuntimeError("offline mock failure"), "failure"))
        for sender_result, expected in examples:
            calls = []
            def continuation_reader(game, folder):
                calls.append(("continuations", folder.name))
                return good
            def sender_reader(game, folder):
                calls.append(("sender", folder.name))
                if isinstance(sender_result, Exception):
                    raise sender_result
                return sender_result
            modules = {"read_native_control_continuations": SimpleNamespace(collect=continuation_reader),
                       "read_native_sender_code": SimpleNamespace(collect=sender_reader)}
            with tempfile.TemporaryDirectory() as folder, patch.dict("sys.modules", modules):
                result = collect("offline-game", Path(folder))
                self.assertEqual(calls, [("continuations", "continuations"), ("sender", "sender")])
                self.assertEqual(summarize(result, 1, False)["collection_outcome"], expected)
                self.assertEqual(json.loads((Path(folder) / "result.json").read_text()), result)
                self.assertFalse(result["native_control_message_accepted"])

    def test_read_failure_and_partial_reads_are_not_reported_as_success(self):
        summarize = load_function(RUNNER, "control_collection_summary")
        examples = [
            ({"status": "bounded_read_attempt_complete", "functions": [{"read_succeeded": True}]}, "success"),
            ({"status": "bounded_read_attempt_complete", "functions": [
                {"read_succeeded": True}, {"read_succeeded": False}]}, "partial_failure"),
            ({"status": "bounded_read_failed", "error_type": "OSError"}, "failure"),
            ({"status": "read_not_permitted"}, "failure"),
            ({"status": "bounded_read_attempt_complete", "functions": []}, "failure"),
        ]
        for collection, expected in examples:
            with self.subTest(status=collection["status"], expected=expected):
                event = summarize(collection, 21.5, False)
                self.assertEqual(event["collection_outcome"], expected)
                self.assertEqual(event["observation_action"], "continue")

    def test_actual_completion_branch_continues_on_success_or_failure_by_default(self):
        branch = next(node for node in ast.walk(TREES[RUNNER])
                      if isinstance(node, ast.If) and ast.unparse(node.test) == "args.ds_control_code_probe or args.ds_image_code_cache"
                      and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                              and child.func.id == "control_collection_summary" for child in ast.walk(node)))
        marker = ast.parse("continued = True").body[0]
        isolated_loop = ast.For(target=ast.Name(id="once", ctx=ast.Store()),
                               iter=ast.Tuple(elts=[ast.Constant(0)], ctx=ast.Load()),
                               body=[branch, marker], orelse=[])
        for stop in (False, True):
            for status in ("bounded_read_attempt_complete", "bounded_read_failed", "code_cache_complete", "code_cache_partial"):
                with self.subTest(stop=stop, status=status):
                    saves = []
                    report = {"bounded_named_transport_collection": {
                        "status": status, "complete": status == "code_cache_complete",
                        "functions": [{"read_succeeded": True}]}}
                    scope = {"args": SimpleNamespace(ds_control_code_probe=not status.startswith("code_cache"),
                                ds_image_code_cache=status.startswith("code_cache"),
                                stop_after_code_collection=stop), "report": report,
                             "control_collection_summary": load_function(RUNNER, "control_collection_summary"),
                             "save": lambda: saves.append(dict(report)), "json": json,
                             "time": SimpleNamespace(monotonic=lambda: 21.5), "start": 0}
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        run_nodes([isolated_loop], scope)
                    self.assertEqual(scope.get("continued", False), not stop)
                    self.assertTrue(saves)
                    self.assertEqual(json.loads(output.getvalue())["stage"],
                                     "native_control_code_collection_completed")
                    if stop:
                        self.assertEqual(report["observation_stop_reason"], "explicit_stop_after_code_collection")
                    else:
                        self.assertNotIn("observation_stop_reason", report)

    def test_image_cache_hops_and_strict_request_bool(self):
        field, option = "ds_image_code_cache", "--ds-image-code-cache"
        dictionary = next(node.value for node in TREES[WRAPPER].body
                          if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                          and any(isinstance(target, ast.Name) and target.id == "request" for target in node.targets))
        value = next(value for key, value in zip(dictionary.keys, dictionary.values)
                     if isinstance(key, ast.Constant) and key.value == field)
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args." + field
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and field in ast.unparse(node.test)]
        self.assertEqual(len(hops), 2)
        self.assertEqual(len(assertions), 2)
        for flag in (False, True):
            scope = {"args": SimpleNamespace(**{field: flag}),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            expression = ast.fix_missing_locations(ast.Expression(body=value))
            self.assertIs(eval(compile(expression, "<cache request>", "eval"), scope), flag)
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [option] if flag else [])
            self.assertEqual(scope["parameters"], [option] if flag else [])
        for requested, parsed in ((True, False), (False, True), (1, True), (0, False)):
            with self.assertRaises(AssertionError):
                run_nodes(assertions, {"request": {field: requested},
                          "args": SimpleNamespace(**{field: parsed})})

    def test_image_cache_before_sdk_work_requires_pinned_collector(self):
        branch = next(node for node in ast.walk(TREES[WRAPPER])
                      if isinstance(node, ast.If) and ast.unparse(node.test) == "args.ds_image_code_cache"
                      and any(isinstance(child, ast.Assert) for child in ast.walk(node)))
        assertion = next(node for node in branch.body if isinstance(node, ast.Assert))
        for actual, expected in (("a", "a"), ("a", "b")):
            scope = {"request": {"image_code_reader_sha256": expected},
                     "ROOT": Path("offline"), "digest": lambda _: actual}
            if actual == expected:
                run_nodes([assertion], scope)
            else:
                with self.assertRaises(AssertionError):
                    run_nodes([assertion], scope)

    def test_image_cache_requires_shadow_shipping_and_excludes_other_reads(self):
        for path in TREES:
            parser = parser_only(path)
            nodes = [node for node in TREES[path].body if isinstance(node, ast.If)
                     and "args.ds_image_code_cache" in ast.unparse(node.test)]
            image_guard = next(node for node in nodes if "requires the shipping shadow" in ast.unparse(node))
            mutual_guard = next(node for node in nodes if "sum(" in ast.unparse(node.test))
            entry_guard = next(node for node in nodes
                               if "control code profile cannot be combined with entry" in ast.unparse(node))
            source, shadow = Path("source").resolve(), Path("shadow").resolve()
            for target, entry, server, accepted in ((shadow, "shipping", True, True),
                    (source, "shipping", True, False), (shadow, "bootstrap", True, False),
                    (shadow, "shipping", False, False)):
                args = parser.parse_args(["--ds-image-code-cache"])
                args.game_root, args.shadow_game = target, shadow
                args.entry, args.game_server_probe = entry, server
                scope = {"parser": parser, "args": args, "GAME": target, "SHADOW_GAME": shadow}
                with contextlib.redirect_stderr(io.StringIO()):
                    if accepted:
                        run_nodes([image_guard], scope)
                    else:
                        with self.assertRaises(SystemExit):
                            run_nodes([image_guard], scope)
                args.ds_control_code_probe = True
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    run_nodes([mutual_guard], scope)
                args.ds_control_code_probe, args.entry_code_probe = False, True
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    run_nodes([entry_guard], scope)

    def test_request_and_both_argument_hops_preserve_the_bool(self):
        dictionary = next(node.value for node in TREES[WRAPPER].body
                          if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                          and any(isinstance(target, ast.Name) and target.id == "request" for target in node.targets))
        value = next(value for key, value in zip(dictionary.keys, dictionary.values)
                     if isinstance(key, ast.Constant) and key.value == "stop_after_code_collection")
        hops = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.If)
                and ast.unparse(node.test) == "args.stop_after_code_collection"
                and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                        and child.func.attr == "append" for child in ast.walk(node))]
        self.assertEqual(len(hops), 2)
        for stop in (False, True):
            scope = {"args": SimpleNamespace(stop_after_code_collection=stop),
                     "sys": SimpleNamespace(argv=[]), "parameters": []}
            expression = ast.fix_missing_locations(ast.Expression(body=value))
            self.assertIs(eval(compile(expression, "<isolated request value>", "eval"), scope), stop)
            run_nodes(hops, scope)
            self.assertEqual(scope["sys"].argv, [OPTION] if stop else [])
            self.assertEqual(scope["parameters"], [OPTION] if stop else [])

    def test_worker_rejects_mismatched_or_non_bool_stop_requests(self):
        assertions = [node for node in ast.walk(TREES[WRAPPER]) if isinstance(node, ast.Assert)
                      and "stop_after_code_collection" in ast.unparse(node.test)]
        self.assertEqual(len(assertions), 2)
        for requested, parsed, accepted in ((False, False, True), (True, True, True),
                                             (True, False, False), (False, True, False),
                                             (0, False, False), (1, True, False)):
            scope = {"request": {"stop_after_code_collection": requested},
                     "args": SimpleNamespace(stop_after_code_collection=parsed)}
            if accepted:
                run_nodes(assertions, scope)
            else:
                with self.assertRaises(AssertionError):
                    run_nodes(assertions, scope)

    def test_wrapper_relays_completion_before_exit_and_only_once(self):
        forward = load_function(WRAPPER, "forward_control_collection_progress")
        with tempfile.TemporaryDirectory() as folder:
            log_path, report_path = Path(folder) / "worker.log", Path(folder) / "report.json"
            report = {"runner_sha256": "offline-fixture", "stop_after_code_collection": False}
            forward(report, log_path, report_path)
            self.assertFalse(report_path.exists())
            event = {"stage": "native_control_code_collection_completed",
                     "collection_outcome": "failure", "observation_action": "continue"}
            log_path.write_text("not-json\n" + json.dumps(event) + "\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                forward(report, log_path, report_path)
                forward(report, log_path, report_path)
            self.assertEqual(json.loads(output.getvalue()), event)
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))
                             ["native_control_code_collection_progress"], event)
            self.assertEqual(report["runner_sha256"], "offline-fixture")
            self.assertFalse(report["stop_after_code_collection"])

    def test_existing_worker_hash_and_cleanup_guards_remain(self):
        wrapper_asserts = [ast.unparse(node.test) for node in ast.walk(TREES[WRAPPER])
                           if isinstance(node, ast.Assert)]
        self.assertIn("request['runner_sha256'] == digest(RUNNER)", wrapper_asserts)
        self.assertIn("request['wrapper_sha256'] == digest(Path(__file__))", wrapper_asserts)
        self.assertTrue(any("control_reader_sha256" in test and "digest(" in test
                            for test in wrapper_asserts))
        trial = next(node for node in TREES[RUNNER].body if isinstance(node, ast.Try) and node.finalbody)
        cleanup = ast.unparse(ast.Module(body=trial.finalbody, type_ignores=[]))
        self.assertIn("process.create_time() - created_at", cleanup)
        self.assertIn("os.replace(ALIAS, SDK)", cleanup)
        self.assertIn("digest(SDK) == SDK_SHA", cleanup)


if __name__ == "__main__":
    unittest.main(verbosity=2)
