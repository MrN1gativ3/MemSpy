# filelessd(8)

`filelessd` is the privileged, detection-only eBPF service. It accepts `--config`, `--database`, `--socket`, `--foreground`, `--version`, and `--help`. Package defaults are `/etc/filelessd/allowlist.conf`, `/var/lib/filelessd/alerts.db`, and `/run/filelessd/filelessd.sock`.

The service requires x86_64 Linux 5.4+ and readable BTF at `/sys/kernel/btf/vmlinux`. Review failures with `journalctl -u filelessd`.

If the SQLite database cannot open, the service preserves it, continues bounded live detection in degraded health, and retries storage every 60 seconds.
