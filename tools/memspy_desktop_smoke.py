#!/usr/bin/env python3
"""Check benign MemSpy fixture alerts on the installed desktop."""

import json
import pathlib
import subprocess
import sys
import time


ITERATIONS = 20


def assess(before, after, baseline_id, ordinary_pid, runs, alerts, response_active):
    failures = []
    recent = [alert for alert in alerts if alert.get("id", 0) > baseline_id]
    if any(alert.get("pid") == ordinary_pid for alert in recent):
        failures.append("ordinary executable generated an alert")

    expected_rule = "BLOCKED_MEMFD_EXEC" if response_active else "MEMFD_EXEC"
    expected_action = "blocked" if response_active else "detected"
    expected_exit = 1 if response_active else 0
    for pid, exit_code in runs:
        if exit_code != expected_exit:
            failures.append(f"fixture PID {pid} exited {exit_code}, expected {expected_exit}")
        if not any(alert.get("pid") == pid and alert.get("rule_id") == expected_rule
                   and alert.get("action") == expected_action for alert in recent):
            failures.append(f"fixture PID {pid} has no {expected_rule} {expected_action} alert")

    for counter in ("lost_events", "lost_block_events", "dropped_alerts", "map_pressure"):
        if after.get(counter, 0) > before.get(counter, 0):
            failures.append(f"{counter} increased during the test")
    if after.get("state") != 1 or not after.get("storage_available", True):
        failures.append("detector or alert storage is unhealthy after the test")
    if after.get("response_active") != before.get("response_active"):
        failures.append("response state changed during the test")
    if response_active and after.get("blocked_execs", 0) - before.get("blocked_execs", 0) < len(runs):
        failures.append("blocked execution counter increased less than the fixture count")
    return failures


def cli(*args):
    result = subprocess.run(("memspyctl", "--json", *args), capture_output=True,
                            text=True, check=False, timeout=10)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "memspyctl failed")
    return json.loads(result.stdout)


def fixture(path):
    process = subprocess.Popen((str(path),), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        return process.pid, process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError(f"fixture timed out: {path.name}") from None


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: python3 tools/memspy_desktop_smoke.py BUILD_DIR")
    build_dir = pathlib.Path(sys.argv[1]).resolve()
    memfd = build_dir / "tests/memfd_exec"
    ordinary = build_dir / "tests/ordinary_exec"
    if not memfd.is_file() or not ordinary.is_file():
        raise RuntimeError("build fixtures first: meson compile -C BUILD_DIR tests/memfd_exec tests/ordinary_exec")

    before = cli("status")
    if before.get("state") != 1 or not before.get("storage_available"):
        raise RuntimeError("MemSpy must be healthy with alert storage available")
    baseline = cli("alerts", "--limit", "200")
    baseline_id = max((alert.get("id", 0) for alert in baseline), default=0)
    ordinary_pid, ordinary_exit = fixture(ordinary)
    if ordinary_exit:
        raise RuntimeError(f"ordinary fixture exited {ordinary_exit}")

    runs = []
    for _ in range(ITERATIONS):
        runs.append(fixture(memfd))
        time.sleep(0.1)
    time.sleep(2)
    after = cli("status")
    alerts = cli("alerts", "--limit", "200")
    failures = assess(before, after, baseline_id, ordinary_pid, runs, alerts,
                      bool(before.get("response_active")))
    print(f"Benign memfd runs: {len(runs)}; response active: {bool(before.get('response_active'))}")
    print(f"New alerts: {sum(alert.get('id', 0) > baseline_id for alert in alerts)}")
    for counter in ("lost_events", "lost_block_events", "dropped_alerts",
                    "map_pressure", "incomplete_observations", "blocked_execs"):
        print(f"{counter}: {before.get(counter, 0)} -> {after.get(counter, 0)}")
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Smoke test could not run: {error}", file=sys.stderr)
        sys.exit(2)
