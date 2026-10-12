# memspyd(8)

`memspyd` is the privileged eBPF detection service and optional memfd-execution response authority. It accepts `--config`, `--database`, `--socket`, `--foreground`, `--check-response`, `--version`, and `--help`. Package defaults are `/etc/memspy/allowlist.conf`, `/var/lib/memspy/alerts.db`, and `/run/memspy/memspy.sock`.

The service requires x86_64 Linux 5.4+ and readable BTF at `/sys/kernel/btf/vmlinux`. It stores alerts for 30 days, exposes only a local Unix socket, and emits structured journald fields including `MEMSPY_RULE`, `MEMSPY_SEVERITY`, and `MEMSPY_ALERT_JSON`. Review health with `memspyctl status` and service output with `journalctl -u memspyd`.

If the SQLite database cannot open, the service preserves it, continues bounded live detection in degraded health, and retries storage every 60 seconds.

Response mode blocks only memfd-backed execution and requires BPF LSM support. Other detections, including confirmed writes through `/proc/<pid>/mem`, remain observational. Process context is bounded and may be incomplete when short-lived `/proc` entries disappear.
