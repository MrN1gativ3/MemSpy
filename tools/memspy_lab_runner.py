#!/usr/bin/env python3
"""Run local samples in an offline disposable VM and record MemSpy alerts."""

from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, NamedTuple


ACKNOWLEDGEMENT = "disposable-offline-vm"
MAX_SAMPLE_BYTES = 128 * 1024 * 1024
SAMPLE_TIMEOUT_SECONDS = 30
ALERT_SETTLE_SECONDS = 2
SHARED_FILESYSTEMS = {"9p", "vboxsf", "virtiofs", "fuse.vmhgfs", "fuse.vmhgfs-fuse"}


class SafetyError(RuntimeError):
    pass


class Preflight(NamedTuple):
    is_root: bool
    is_vm: bool
    active_interfaces: list[str]
    shared_filesystems: list[str]
    user_systemd_available: bool
    health: dict[str, Any]


def validate_preflight(state: Preflight) -> None:
    if state.is_root:
        raise SafetyError("refusing to execute samples as root")
    if not state.is_vm:
        raise SafetyError("a hardware virtual machine was not detected")
    if state.active_interfaces:
        raise SafetyError("non-loopback interfaces are active: " + ", ".join(state.active_interfaces))
    if state.shared_filesystems:
        raise SafetyError("shared-folder filesystems are mounted: " +
                          ", ".join(state.shared_filesystems))
    if not state.user_systemd_available:
        raise SafetyError("a sandbox-capable user systemd manager is unavailable")
    health = state.health
    if health.get("state") != 1 or not health.get("storage_available"):
        raise SafetyError("MemSpy must be healthy with storage available")
    if health.get("response_requested") or health.get("response_active"):
        raise SafetyError("turn response mode off before detection-only validation")
    if health.get("lost_events", 0) != 0:
        raise SafetyError("restart memspyd to clear existing lost-event health state")


def new_alerts(alerts: list[dict[str, Any]], baseline_id: int) -> list[dict[str, Any]]:
    return [alert for alert in alerts if isinstance(alert.get("id"), int) and
            alert["id"] > baseline_id]


def _markdown(value: Any) -> str:
    return html.escape(str(value), quote=False).replace("`", "&#96;").replace(
        "\n", " ").replace("\r", " ").replace("|", "\\|")


def write_results(directory: pathlib.Path, result: dict[str, Any]) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    json_path = directory / "results.json"
    report_path = directory / "report.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# MemSpy isolated sample validation",
        "",
        "These are observations from an offline disposable VM, not claims of complete malware coverage.",
        "",
        f"Generated: `{_markdown(result.get('generated_at', ''))}`  ",
        f"MemSpy: `{_markdown(result.get('memspy_version', 'unknown'))}`",
        "",
        "| Sample | SHA-256 | Outcome | MemSpy alerts |",
        "| --- | --- | --- | --- |",
    ]
    for sample in result.get("samples", []):
        alerts = sample.get("alerts", [])
        alert_text = ", ".join(
            f"{_markdown(alert.get('rule_id', 'unknown'))} "
            f"({_markdown(alert.get('severity', 'unknown'))}, alert {_markdown(alert.get('id', '?'))})"
            for alert in alerts
        ) or "None"
        if sample.get("alerts_truncated"):
            alert_text += " (result may be truncated)"
        lines.append(
            f"| {_markdown(sample.get('name', ''))} | `"
            f"{_markdown(sample.get('sha256', ''))}` | "
            f"{_markdown(sample.get('outcome', ''))} | {alert_text} |"
        )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _command(*arguments: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=timeout)


def _json_command(*arguments: str) -> Any:
    result = _command(*arguments)
    if result.returncode != 0:
        raise SafetyError(result.stderr.strip() or f"{arguments[0]} failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SafetyError(f"{arguments[0]} returned invalid JSON") from error


def _active_interfaces() -> list[str]:
    interfaces = []
    for interface in pathlib.Path("/sys/class/net").iterdir():
        if interface.name != "lo" and (interface / "operstate").read_text().strip() == "up":
            interfaces.append(interface.name)
    return sorted(interfaces)


def _shared_filesystems() -> list[str]:
    found = set()
    for line in pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        separator = line.find(" - ")
        if separator >= 0:
            filesystem = line[separator + 3:].split(" ", 1)[0]
            if filesystem in SHARED_FILESYSTEMS:
                found.add(filesystem)
    return sorted(found)


def _sandbox_command(executable: pathlib.Path, runtime: pathlib.Path,
                     unit: str) -> list[str]:
    return [
        "systemd-run", "--user", "--wait", "--collect", "--quiet",
        f"--unit={unit}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        f"--property=RuntimeMaxSec={SAMPLE_TIMEOUT_SECONDS + 5}",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=RestrictNamespaces=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=MemoryMax=512M",
        "--property=TasksMax=128",
        "--property=StandardOutput=null",
        "--property=StandardError=null",
        f"--working-directory={runtime}",
        f"--setenv=HOME={runtime}",
        f"--setenv=TMPDIR={runtime}",
        "--setenv=PATH=/usr/bin:/bin",
        "/usr/bin/timeout", "--signal=KILL", str(SAMPLE_TIMEOUT_SECONDS),
        str(executable),
    ]


def collect_preflight(memspyctl: str) -> Preflight:
    vm_tool = shutil.which("systemd-detect-virt")
    vm = vm_tool is not None and _command(vm_tool, "--vm", "--quiet").returncode == 0
    probe_runtime = pathlib.Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    probe = _sandbox_command(pathlib.Path("/usr/bin/true"), probe_runtime,
                             f"memspy-lab-probe-{os.getpid()}")
    systemd_available = _command(*probe, timeout=20).returncode == 0
    health = _json_command(memspyctl, "--json", "status")
    return Preflight(os.geteuid() == 0, vm, _active_interfaces(), _shared_filesystems(),
                     systemd_available, health)


def _alerts(memspyctl: str) -> list[dict[str, Any]]:
    value = _json_command(memspyctl, "--json", "alerts", "--limit", "200")
    if not isinstance(value, list):
        raise SafetyError("memspyctl returned an invalid alert list")
    return value


def _highest_alert_id(alerts: list[dict[str, Any]]) -> int:
    return max((alert.get("id", 0) for alert in alerts if isinstance(alert.get("id"), int)),
               default=0)


def _sample_kind(path: pathlib.Path) -> str:
    tool = shutil.which("file")
    if tool is None:
        raise SafetyError("the file command is required")
    result = _command(tool, "--brief", "--", str(path))
    if result.returncode != 0:
        raise SafetyError(f"cannot identify {path.name}")
    return result.stdout.strip()


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run_sample(path: pathlib.Path, memspyctl: str, baseline_id: int) -> dict[str, Any]:
    started = datetime.datetime.now(datetime.timezone.utc)
    metadata: dict[str, Any] = {
        "name": path.name,
        "sha256": _sha256(path),
        "file_type": _sample_kind(path),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "alerts": [],
        "alerts_truncated": False,
    }
    if path.stat().st_size > MAX_SAMPLE_BYTES:
        metadata.update(outcome="skipped-too-large", exit_code=None, duration_ms=0)
        return metadata
    runtime_root = pathlib.Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    with tempfile.TemporaryDirectory(prefix="memspy-lab-", dir=runtime_root) as directory:
        runtime = pathlib.Path(directory)
        executable = runtime / "sample"
        shutil.copyfile(path, executable, follow_symlinks=False)
        executable.chmod(0o500)
        unit = f"memspy-lab-{os.getpid()}-{uuid.uuid4().hex[:10]}"
        before = time.monotonic()
        process = subprocess.run(_sandbox_command(executable, runtime, unit), check=False,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=SAMPLE_TIMEOUT_SECONDS + 15)
        duration_ms = int((time.monotonic() - before) * 1000)
    time.sleep(ALERT_SETTLE_SECONDS)
    alerts = _alerts(memspyctl)
    observed = new_alerts(alerts, baseline_id)
    metadata.update(
        outcome="timed-out" if process.returncode in (124, 137) else "exited",
        exit_code=process.returncode,
        duration_ms=duration_ms,
        alerts=observed,
        alerts_truncated=len(alerts) == 200 and bool(observed) and
                         min(alert["id"] for alert in observed) > baseline_id + 1,
    )
    return metadata


def run(sample_directory: pathlib.Path, result_directory: pathlib.Path) -> dict[str, Any]:
    memspyctl = shutil.which("memspyctl")
    if memspyctl is None:
        raise SafetyError("memspyctl is not installed")
    state = collect_preflight(memspyctl)
    validate_preflight(state)
    samples = sorted(path for path in sample_directory.iterdir()
                     if path.is_file() and not path.is_symlink())
    if not samples:
        raise SafetyError("the sample directory contains no regular files")
    initial_alerts = _alerts(memspyctl)
    baseline_id = _highest_alert_id(initial_alerts)
    result: dict[str, Any] = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"),
        "memspy_version": _command(memspyctl, "version").stdout.strip(),
        "initial_health": state.health,
        "samples": [],
    }
    for sample in samples:
        observation = _run_sample(sample, memspyctl, baseline_id)
        result["samples"].append(observation)
        baseline_id = max(baseline_id, _highest_alert_id(observation["alerts"]))
        write_results(result_directory, result)
    result["final_health"] = _json_command(memspyctl, "--json", "status")
    write_results(result_directory, result)
    return result


def main(arguments: list[str]) -> int:
    if len(arguments) not in (2, 3):
        print("Usage: memspy_lab_runner.py SAMPLE_DIRECTORY [RESULT_DIRECTORY]", file=sys.stderr)
        return 2
    if os.environ.get("MEMSPY_LAB_ACK") != ACKNOWLEDGEMENT:
        print(f"Refusing to run: set MEMSPY_LAB_ACK={ACKNOWLEDGEMENT}", file=sys.stderr)
        return 2
    samples = pathlib.Path(arguments[1]).expanduser().resolve()
    result_argument = (pathlib.Path(arguments[2]).expanduser() if len(arguments) == 3 else
                       pathlib.Path.cwd() / ("memspy-lab-results-" +
                                             datetime.datetime.now().strftime("%Y%m%d-%H%M%S")))
    if result_argument.is_symlink():
        print("Refusing to run: result directory must not be a symbolic link", file=sys.stderr)
        return 2
    results = result_argument.resolve()
    if not samples.is_dir():
        print(f"Refusing to run: sample directory does not exist: {samples}", file=sys.stderr)
        return 2
    if results == samples or samples in results.parents:
        print("Refusing to run: result directory must be outside the sample directory",
              file=sys.stderr)
        return 2
    if results.exists() and (not results.is_dir() or any(results.iterdir())):
        print("Refusing to run: result directory must be new or empty", file=sys.stderr)
        return 2
    try:
        run(samples, results)
    except (OSError, SafetyError, subprocess.SubprocessError) as error:
        print(f"Refusing to run: {error}", file=sys.stderr)
        return 2
    print(f"Results written to {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
