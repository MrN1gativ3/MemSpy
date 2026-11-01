#!/usr/bin/env python3
"""Check that the desktop smoke report catches missed or misclassified events."""

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "tools/memspy_desktop_smoke.py"
SPEC = importlib.util.spec_from_file_location("memspy_desktop_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class DesktopSmokeTests(unittest.TestCase):
    def test_detected_and_blocked_events_are_checked_by_pid(self):
        before = {"state": 1, "lost_events": 0, "dropped_alerts": 0,
                  "blocked_execs": 0}
        after = dict(before)
        alerts = [{"id": 6, "pid": 111, "rule_id": "MEMFD_EXEC",
                   "action": "detected"}]
        self.assertEqual(smoke.assess(before, after, 5, 100, [(111, 0)], alerts,
                                      response_active=False), [])

        after["blocked_execs"] = 1
        alerts[0].update(rule_id="BLOCKED_MEMFD_EXEC", action="blocked")
        self.assertEqual(smoke.assess(before, after, 5, 100, [(111, 1)], alerts,
                                      response_active=True), [])

    def test_missing_alert_and_negative_control_fail(self):
        health = {"state": 1, "lost_events": 0, "dropped_alerts": 0,
                  "blocked_execs": 0}
        alerts = [{"id": 6, "pid": 100, "rule_id": "MEMFD_EXEC",
                   "action": "detected"}]
        failures = smoke.assess(health, health, 5, 100, [(111, 0)], alerts,
                                response_active=False)
        self.assertTrue(any("ordinary" in failure for failure in failures))
        self.assertTrue(any("111" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
