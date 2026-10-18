# MemSpy

MemSpy is an open-source Linux security monitor for x86_64 systems. It uses eBPF to detect fileless execution and process-injection behavior, stores alerts locally for 30 days, and provides a CLI plus an optional GTK dashboard.

MemSpy is a focused host monitor, not a full EDR or antivirus product. Test Response mode in a disposable VM before enabling it on a production server.

## What it detects

| Rule | Behavior |
| --- | --- |
| `MEMFD_EXEC` | Execution from a `memfd`-backed image |
| `DELETED_EXEC` | Execution of an image deleted from the filesystem |
| `PROCESS_VM_WRITE` | Cross-process `process_vm_writev` memory writes |
| `PTRACE_WRITE` | Modifying `ptrace` operations |
| `PROC_MEM_WRITE` | Writes through `/proc/<pid>/mem` |
| `INJECTION_CHAIN` | Injection followed by suspicious execution |

Detection remains active when Response mode is off or unsupported. Response mode is optional, off by default, and uses BPF LSM to deny supported suspicious operations before they complete.

## Requirements

- x86_64 Linux
- Linux kernel 5.4 or newer
- systemd and readable BTF at `/sys/kernel/btf/vmlinux`
- Ubuntu/Debian, Fedora, or Arch Linux
- Optional desktop UI: GNOME or KDE Plasma

## Install

```sh
git clone https://github.com/MrN1gativ3/MemSpy.git
cd MemSpy
sudo ./install.sh
```

Profiles can be selected explicitly:

```sh
sudo ./install.sh "$USER" gnome
sudo ./install.sh "$USER" kde
sudo ./install.sh "$USER" headless
```

The application is installed under `/opt/memspy`. Configuration remains in `/etc/memspy`, persistent state in `/var/lib/memspy`, and runtime state in `/run/memspy`.

Log out and back in once after a GUI installation, then run `memspy-ui`.

## CLI

`memspyctl` is the primary interface for headless servers. For non-root access, install with `sudo ./install.sh "$USER" headless`, then log out and back in so your `memspy-ui` group membership takes effect.

Check whether the detector and alert storage are healthy, whether events were lost, and whether Response mode is actually active:

```sh
memspyctl status
```

Investigate recent incidents. Use the ID from `alerts` in place of `42`; `show` prints readable details, while `export` saves the complete JSON record, including available hashes:

```sh
memspyctl alerts --limit 20
memspyctl alerts --minimum high --limit 20
memspyctl show 42
memspyctl export 42 > alert-42.json
```

Turn blocking on or off when needed, then confirm the reported state. Changing Response mode requires PolicyKit administrator authorization; a requested mode is not necessarily active:

```sh
memspyctl response on
memspyctl status
memspyctl response off
```

For automation, put `--json` before the command, for example `memspyctl --json status` or `memspyctl --json alerts --limit 20`. MemSpy exposes no network listener; the CLI and GTK application use the local Unix socket at `/run/memspy/memspy.sock`.

Expanded incidents show the applicable actor, executed image, target, launcher, and parent paths. MemSpy records MD5 for IOC compatibility, SHA-256 as the primary hash, and an exact reason when an image cannot be hashed. Images larger than 128 MiB are not hashed.

## Response allowlist

Add one exact rule and executable path per line in `/etc/memspy/response-allowlist.conf`:

```text
MEMFD_EXEC /usr/bin/firefox
MEMFD_EXEC /usr/bin/chromium
PTRACE_WRITE /usr/bin/gdb
PROCESS_VM_WRITE /usr/bin/gdb
PROC_MEM_WRITE /opt/company/bin/diagnostic-agent
```

The same executable needs a separate entry for each permitted rule. Legacy path-only entries apply only to `MEMFD_EXEC`. Avoid allowlisting shells or general-purpose interpreters.

Restart the daemon after editing:

```sh
sudo systemctl restart memspyd
```

## Service and health

```sh
systemctl status memspyd
journalctl -u memspyd -n 100 --no-pager
memspyctl status
sudo memspyd --check-response
```

Response mode requires `bpf` in `/sys/kernel/security/lsm`. The installer enables it through a supported bootloader configuration when possible and asks you to reboot; it never reboots automatically.

## Build and test

```sh
meson setup build --buildtype=debug -Db_sanitize=address,undefined
meson compile -C build
ASAN_OPTIONS=detect_leaks=0 \
  meson test -C build --no-suite privileged --print-errorlogs
```

## Important paths

| Path | Purpose |
| --- | --- |
| `/opt/memspy` | Installed application |
| `/etc/memspy` | Detection and response allowlists |
| `/var/lib/memspy/alerts.db` | Local SQLite alert history |
| `/run/memspy/memspy.sock` | Local CLI/UI endpoint |
| `/sys/fs/bpf/memspy` | MemSpy-owned response maps and links |

Only trusted users should belong to the `memspy-ui` group because alerts can contain process metadata from other local users.

## Uninstall

```sh
sudo ./uninstall.sh
```

The uninstall script preserves `/etc/memspy` configuration but removes alert history and saved Response-mode state.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
