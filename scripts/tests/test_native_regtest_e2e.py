"""Pure stdlib regression tests; no Docker, GUI, SSH or network listener is used."""
import importlib.util
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "native-regtest-e2e.py"
SPEC = importlib.util.spec_from_file_location("native_regtest_supervisor", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class JsonBounds(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, data):
        path = self.root / "fixture.json"
        path.write_bytes(data)
        return path

    def test_duplicate_fields_are_rejected_at_every_object_depth(self):
        for body in [b'{"sequence":1,"sequence":2}', b'{"params":{"enabled":true,"enabled":false}}']:
            with self.subTest(body=body), self.assertRaises(RUNNER.Failure):
                RUNNER.bounded_json(self.fixture(body))

    def test_symlink_cannot_substitute_a_request_file(self):
        target = self.fixture(b'{"sequence":1}')
        link = self.root / "request.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            RUNNER.bounded_json(link)

    def test_size_limit_accepts_exact_bound_and_rejects_one_byte_over(self):
        body = b'{"sequence":1}'
        path = self.fixture(body)
        self.assertEqual(RUNNER.bounded_json(path, len(body)), {"sequence": 1})
        with self.assertRaises(RUNNER.Failure):
            RUNNER.bounded_json(path, len(body) - 1)

    def test_nonfinite_json_never_reaches_ipc_actions(self):
        for token in [b"NaN", b"Infinity", b"-Infinity"]:
            with self.subTest(token=token), self.assertRaises(RUNNER.Failure):
                RUNNER.bounded_json(self.fixture(b'{"value":' + token + b'}'))


class ActionTypes(unittest.TestCase):
    def test_mine_requires_an_actual_integer_not_coercible_values(self):
        supervisor = object.__new__(RUNNER.Supervisor)
        supervisor.rpc = SimpleNamespace(call=lambda *_args: self.fail("Invalid request reached Core"))
        for value in [True, 1.0, "1", 0, -1]:
            with self.subTest(value=value), self.assertRaises(RUNNER.Failure):
                supervisor.action("mine", {"blocks": value})
        calls = []
        def rpc(method, params=None, wallet=None):
            calls.append((method, params))
            return {"getblockchaininfo": {"chain": "regtest"}, "generatetoaddress": ["c" * 64],
                    "getnewaddress": "fresh-public-mining-fixture",
                    "getblockcount": 103, "getrawmempool": []}[method]
        supervisor.rpc = SimpleNamespace(call=rpc)
        supervisor.mining_address = "public-regtest-fixture"
        supervisor.wallet = "owned-funding-wallet"
        self.assertEqual(supervisor.action("mine", {"blocks": 1})["height"], 103)
        self.assertIn(("generatetoaddress", [1, "fresh-public-mining-fixture"]), calls)


class OutputRetention(unittest.TestCase):
    def child(self, label):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        private, public = root / "private", root / "evidence"
        private.mkdir(mode=0o700)
        public.mkdir(mode=0o700)
        child = RUNNER.Child([sys.executable, "-c", "print('owned-output-marker')"], root,
                             dict(os.environ), private, label, public)
        self.addCleanup(child.stop)
        child.process.wait(timeout=10)
        return child, public

    def test_whitelisted_native_output_is_readable_and_finishing_is_idempotent(self):
        child, evidence = self.child("native-driver")
        first = child.finish()
        self.assertIs(child.finish(), first)
        stdout = evidence / "native-driver.stdout.log"
        self.assertEqual(stdout.read_text(), "owned-output-marker\n")
        self.assertEqual(first["retained_safe_output"]["stdout"]["sha256"], RUNNER.digest(stdout))

    def test_rehearsal_output_stays_private_even_when_public_logs_are_requested(self):
        child, evidence = self.child("backend-fixture")
        record = child.finish()
        self.assertEqual(list(evidence.iterdir()), [])
        self.assertNotIn("retained_safe_output", record)
        self.assertIn("hash-only", record["output_retention"])


class ContainerOwnership(unittest.TestCase):
    def test_nonce_recovery_stops_only_exact_owned_name_and_label(self):
        for altered in [None, "name", "label"]:
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                private = root / "private"
                private.mkdir(mode=0o700)
                supervisor = object.__new__(RUNNER.Supervisor)
                supervisor.children, supervisor.proxy, supervisor.tunnel = [], None, None
                supervisor.node_create_attempted, supervisor.container_id = True, None
                supervisor.name, supervisor.token = "p71-unit-owned", "b" * 32
                supervisor.args = SimpleNamespace(docker_ssh_host=None)
                supervisor.backend_port = 54321  # port_free is replaced below; no socket is opened.
                supervisor.private = private
                supervisor.private_identity = (private.stat().st_dev, private.stat().st_ino)
                supervisor.report = {"commands": []}
                cid = "a" * 64
                observed = []
                def command(label, argv, **_kwargs):
                    observed.append((label, argv))
                    if label == "find-own-node":
                        self.assertIn("name=^/p71-unit-owned$", argv)
                        self.assertIn("label=p71.native-regtest-run=" + "b" * 32, argv)
                        return cid
                    if label.startswith("inspect-"):
                        return json.dumps([{"Id": cid,
                            "Name": "/foreign" if altered == "name" else "/p71-unit-owned",
                            "Config": {"Labels": {"p71.native-regtest-run": "foreign" if altered == "label" else "b" * 32}}}])
                    if label == "node-stop":
                        self.assertEqual(argv[-1], cid)
                        return cid
                    if label == "node-absence":
                        return ""
                    self.fail("Unexpected command")
                supervisor.command = command
                with patch.object(RUNNER, "port_free", return_value=True):
                    if altered:
                        with self.assertRaises(RUNNER.Failure):
                            supervisor.cleanup()
                        self.assertFalse(any(label == "node-stop" for label, _argv in observed))
                        self.assertTrue(private.exists())
                    else:
                        supervisor.cleanup()
                        self.assertTrue(any(label == "node-stop" for label, _argv in observed))
                        self.assertFalse(private.exists())


class NativeReporting(unittest.TestCase):
    def test_failed_prefix_preserves_pass_fail_and_not_executed_counts(self):
        expected = ["case-" + str(index) for index in range(8)]
        cases = [{"id": name, "passed": index < 3} for index, name in enumerate(expected[:4])]
        result = RUNNER.native_case_counts(expected, {"schema": 1, "passed": False, "cases": cases})
        self.assertEqual(result, {"expected": 8, "executed": 4, "passed": 3, "failed": 1, "not_executed": 4})

    def test_duplicate_reordered_or_nonboolean_results_are_rejected(self):
        for cases in [[{"id": "a", "passed": True}, {"id": "a", "passed": True}],
                      [{"id": "b", "passed": True}], [{"id": "a", "passed": 1}]]:
            with self.subTest(cases=cases), self.assertRaises(RUNNER.Failure):
                RUNNER.native_case_counts(["a", "b"], {"schema": 1, "cases": cases})

    def test_fixture_funding_meets_the_existing_production_balance_guard(self):
        source = (RUNNER.ROOT / "src/claim/service.rs").read_text()
        match = re.search(r"MIN_EXPECTED_ECONOMIC_TOTAL_SAT\s*:\s*u64\s*=\s*([0-9_]+)\s*;", source)
        self.assertIsNotNone(match, "Locate the actual product guard rather than copying its threshold")
        self.assertGreaterEqual(RUNNER.FUNDING_SAT, int(match.group(1).replace("_", "")))


if __name__ == "__main__":
    unittest.main()
