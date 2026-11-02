#!/usr/bin/env python3
"""Run benign detection and response fixtures against the installed daemon."""

import json
import os
import pathlib
import signal
import subprocess
import sys
import time

CASES = (
    ("memfd_exec", "MEMFD_EXEC", "BLOCKED_MEMFD_EXEC"),
    ("deleted_exec", "DELETED_EXEC", "BLOCKED_DELETED_EXEC"),
    ("process_vm_write", "PROCESS_VM_WRITE", "BLOCKED_PROCESS_VM_WRITE"),
    ("ptrace_write", "PTRACE_WRITE", "BLOCKED_PTRACE_ACCESS"),
    ("proc_mem_write", "PROC_MEM_WRITE", "BLOCKED_PROC_MEM_WRITE"),
    ("injection_chain", "INJECTION_CHAIN", "BLOCKED_MEMFD_EXEC"),
    ("ordinary_exec", None, None),
    ("ordinary_write", None, None),
)


def assess(name, pid, exit_code, alerts, response_active):
    detected, blocked = next((detection, response) for fixture, detection, response in CASES
                             if fixture == name)
    related = [alert for alert in alerts
               if alert.get("pid") == pid or alert.get("ppid") == pid]
    if detected is None:
        failures = []
        if related:
            failures.append("ordinary operation generated an alert")
        if exit_code != 0:
            failures.append(f"fixture exited {exit_code}, expected 0")
        return failures

    expected = {blocked if response_active else detected}
    if name == "injection_chain":
        expected.add("BLOCKED_PROCESS_VM_WRITE" if response_active else
                     "PROCESS_VM_WRITE")
    action = "blocked" if response_active else "detected"
    failures = []
    if exit_code != (1 if response_active else 0):
        failures.append(f"fixture exited {exit_code}, expected {1 if response_active else 0}")
    for rule in expected:
        if not any(alert.get("rule_id") == rule and alert.get("action") == action
                   for alert in related):
            failures.append(f"no {rule} {action} alert for fixture PID {pid} or its child")
    return failures


def cli(*args):
    result = subprocess.run(("memspyctl", "--json", *args), capture_output=True,
                            text=True, check=False, timeout=10)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "memspyctl failed")
    return json.loads(result.stdout)


def recent_alerts(baseline):
    return [alert for alert in cli("alerts", "--limit", "200")
            if alert.get("id", 0) > baseline]


def main():
    if len(sys.argv) != 2:
        raise RuntimeError("usage: python3 tools/memspy_manual_test.py BUILD_DIR")
    if os.geteuid() == 0:
        raise RuntimeError("run as your normal user, without sudo")
    build_dir = pathlib.Path(sys.argv[1]).resolve()
    fixtures = [name for name, _, _ in CASES]
    subprocess.run(("meson", "compile", "-C", str(build_dir)), check=True)
    before = cli("status")
    if before.get("state") != 1 or not before.get("storage_available"):
        raise RuntimeError("MemSpy detector and alert storage must be healthy")
    response_active = bool(before.get("response_active"))
    if before.get("response_requested") and not response_active:
        raise RuntimeError("Response mode was requested but is not active")
    print(f"Response mode: {'on' if response_active else 'off'}; running {len(CASES)} benign fixtures")
    failures = []
    passed = 0
    for name in fixtures:
        path = build_dir / "tests" / name
        baseline = max((alert.get("id", 0) for alert in cli("alerts", "--limit", "1")),
                       default=0)
        process = subprocess.Popen((str(path),), stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            _, stderr = process.communicate(timeout=30 if name == "ordinary_write" else 10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            failures.append(f"{name}: fixture timed out")
            print(f"FAIL {name}: fixture timed out")
            continue
        deadline = time.monotonic() + (1.0 if name.startswith("ordinary_") else 5.0)
        while True:
            alerts = recent_alerts(baseline)
            problems = assess(name, process.pid, process.returncode, alerts, response_active)
            if not problems and (not name.startswith("ordinary_") or
                                 time.monotonic() >= deadline):
                break
            if time.monotonic() >= deadline:
                failures.extend(f"{name}: {problem}" for problem in problems)
                break
            time.sleep(0.2)
        related = [alert for alert in alerts
                   if alert.get("pid") == process.pid or alert.get("ppid") == process.pid]
        observed = ", ".join(f"{alert.get('rule_id')} #{alert.get('id')}"
                             for alert in related) or "none"
        print(f"{'FAIL' if problems else 'PASS'} {name}: exit={process.returncode}; alerts={observed}")
        if not problems:
            passed += 1
        if problems and stderr.strip():
            print(f"  fixture: {stderr.strip()}")

    after = cli("status")
    if after.get("state") != 1 or not after.get("storage_available"):
        failures.append("detector or storage became unhealthy")
    if bool(after.get("response_active")) != response_active:
        failures.append("response mode changed during the run")
    for counter in ("lost_events", "lost_block_events", "dropped_alerts", "map_pressure"):
        if after.get(counter, 0) > before.get(counter, 0):
            failures.append(f"{counter} increased: {before.get(counter)} -> {after.get(counter)}")
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    print(f"Result: {passed}/{len(CASES)} fixtures passed")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        print(f"Manual test could not run: {error}", file=sys.stderr)
        sys.exit(2)
