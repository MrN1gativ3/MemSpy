#!/usr/bin/env python3

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[2] / "tools" / "memspy_lab_runner.py"
SPEC = importlib.util.spec_from_file_location("memspy_lab_runner", MODULE_PATH)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class LabRunnerTest(unittest.TestCase):
    def healthy(self, **changes):
        values = {
            "is_root": False,
            "is_vm": True,
            "active_interfaces": [],
            "shared_filesystems": [],
            "user_systemd_available": True,
            "health": {
                "state": 1,
                "storage_available": True,
                "response_requested": False,
                "response_active": False,
                "lost_events": 0,
            },
        }
        values.update(changes)
        return lab.Preflight(**values)

    def test_preflight_accepts_only_isolated_healthy_vm(self):
        lab.validate_preflight(self.healthy())

        unsafe = [
            self.healthy(is_root=True),
            self.healthy(is_vm=False),
            self.healthy(active_interfaces=["eth0"]),
            self.healthy(shared_filesystems=["virtiofs"]),
            self.healthy(user_systemd_available=False),
            self.healthy(health={"state": 2, "storage_available": True,
                                 "response_requested": False, "response_active": False,
                                 "lost_events": 0}),
            self.healthy(health={"state": 1, "storage_available": True,
                                 "response_requested": True, "response_active": True,
                                 "lost_events": 0}),
        ]
        for state in unsafe:
            with self.subTest(state=state):
                with self.assertRaises(lab.SafetyError):
                    lab.validate_preflight(state)

    def test_selects_only_alerts_created_after_baseline(self):
        alerts = [{"id": 12, "rule_id": "MEMFD_EXEC"},
                  {"id": 11, "rule_id": "PTRACE_WRITE"},
                  {"id": 10, "rule_id": "MEMFD_EXEC"}]
        self.assertEqual(lab.new_alerts(alerts, 10), alerts[:2])

    def test_sandbox_has_cgroup_timeout_and_no_network_families(self):
        command = lab._sandbox_command(pathlib.Path("/run/user/1000/sample"),
                                       pathlib.Path("/run/user/1000/lab"), "memspy-lab-test")
        self.assertIn("--property=KillMode=control-group", command)
        self.assertIn("--property=RuntimeMaxSec=35", command)
        self.assertIn("--property=RestrictAddressFamilies=AF_UNIX", command)
        self.assertIn("--property=NoNewPrivileges=yes", command)
        self.assertIn("--property=PrivateDevices=yes", command)
        self.assertIn("--property=RestrictNamespaces=yes", command)

    def test_writes_json_and_markdown_results(self):
        result = {
            "generated_at": "2026-10-13T00:00:00Z",
            "memspy_version": "memspyctl 0.1.0",
            "samples": [{
                "name": "<loader>|`test`",
                "sha256": "a" * 64,
                "file_type": "ELF 64-bit LSB executable, x86-64",
                "outcome": "exited",
                "exit_code": 0,
                "alerts": [{"id": 42, "rule_id": "MEMFD_EXEC", "severity": "high"}],
                "alerts_truncated": False,
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            lab.write_results(pathlib.Path(directory), result)
            stored = json.loads((pathlib.Path(directory) / "results.json").read_text())
            report = (pathlib.Path(directory) / "report.md").read_text()

        self.assertEqual(stored, result)
        self.assertIn("`" + "a" * 64 + "`", report)
        self.assertIn("MEMFD_EXEC (high, alert 42)", report)
        self.assertIn("&lt;loader&gt;\\|&#96;test&#96;", report)

    def test_refuses_to_overwrite_existing_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            samples = root / "samples"
            results = root / "results"
            samples.mkdir()
            results.mkdir()
            (results / "report.md").write_text("existing\n")
            with mock.patch.dict("os.environ", {"MEMSPY_LAB_ACK": lab.ACKNOWLEDGEMENT}):
                status = lab.main(["memspy_lab_runner.py", str(samples), str(results)])

        self.assertEqual(status, 2)


if __name__ == "__main__":
    unittest.main()
