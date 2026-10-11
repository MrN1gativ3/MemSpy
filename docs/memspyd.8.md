# memspyd(8)

`memspyd` is the privileged, detection-only eBPF service. It accepts `--config`, `--database`, `--socket`, `--foreground`, `--version`, and `--help`. Package defaults are `/etc/memspy/allowlist.conf`, `/var/lib/memspy/alerts.db`, and `/run/memspy/memspy.sock`.

The service requires x86_64 Linux 5.4+ and readable BTF at `/sys/kernel/btf/vmlinux`. Review failures with `journalctl -u memspyd`.

If the SQLite database cannot open, the service preserves it, continues bounded live detection in degraded health, and retries storage every 60 seconds.
