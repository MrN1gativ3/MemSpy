#!/usr/bin/env python3
"""Check the manual fixture runner's alert attribution and rule matrix."""

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "tools/memspy_manual_test.py"
SPEC = importlib.util.spec_from_file_location("memspy_manual_test", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ManualTestTests(unittest.TestCase):
    def test_each_rule_has_a_fixture_in_both_modes(self):
        detected = {case[1] for case in runner.CASES if case[1]}
        blocked = {case[2] for case in runner.CASES if case[2]}
        self.assertEqual(detected, {"MEMFD_EXEC", "DELETED_EXEC", "PROCESS_VM_WRITE",
                                    "PTRACE_WRITE", "PROC_MEM_WRITE", "INJECTION_CHAIN"})
        self.assertEqual(blocked, {"BLOCKED_MEMFD_EXEC", "BLOCKED_DELETED_EXEC",
                                   "BLOCKED_PROCESS_VM_WRITE", "BLOCKED_PTRACE_ACCESS",
                                   "BLOCKED_PROC_MEM_WRITE"})

    def test_alert_must_belong_to_fixture_pid_or_child(self):
        unrelated = [{"id": 2, "pid": 900, "ppid": 1,
                      "rule_id": "MEMFD_EXEC", "action": "detected"}]
        self.assertTrue(runner.assess("memfd_exec", 100, 0, unrelated, False))
        related = [{"id": 3, "pid": 101, "ppid": 100,
                    "rule_id": "MEMFD_EXEC", "action": "detected"}]
        self.assertEqual(runner.assess("memfd_exec", 100, 0, related, False), [])

    def test_blocked_outcome_and_negative_controls(self):
        wrong_action = [{"id": 4, "pid": 100, "ppid": 1,
                         "rule_id": "BLOCKED_DELETED_EXEC", "action": "detected"}]
        self.assertTrue(runner.assess("deleted_exec", 100, 1, wrong_action, True))
        blocked = [dict(wrong_action[0], action="blocked")]
        self.assertEqual(runner.assess("deleted_exec", 100, 1, blocked, True), [])
        self.assertTrue(runner.assess("ordinary_exec", 100, 0, blocked, True))

    def test_injection_chain_requires_write_and_exec_alerts(self):
        write = {"id": 5, "pid": 100, "ppid": 1,
                 "rule_id": "PROCESS_VM_WRITE", "action": "detected"}
        chain = {"id": 6, "pid": 101, "ppid": 100,
                 "rule_id": "INJECTION_CHAIN", "action": "detected"}
        self.assertTrue(runner.assess("injection_chain", 100, 0, [write], False))
        self.assertEqual(runner.assess("injection_chain", 100, 0, [write, chain], False), [])
        blocked_write = dict(write, rule_id="BLOCKED_PROCESS_VM_WRITE", action="blocked")
        blocked_exec = dict(chain, rule_id="BLOCKED_MEMFD_EXEC", action="blocked")
        self.assertTrue(runner.assess("injection_chain", 100, 1, [blocked_exec], True))
        self.assertEqual(runner.assess("injection_chain", 100, 1,
                                       [blocked_write, blocked_exec], True), [])


if __name__ == "__main__":
    unittest.main()
