# MemSpy CLI guide

`memspyctl` is MemSpy's non-interactive local administration client. It connects only to `/run/memspy/memspy.sock`; membership in the trusted `memspy-ui` group is required for unprivileged access.

Commands:

- `memspyctl status [--json]`
- `memspyctl alerts [--limit 1..200] [--minimum medium|high] [--json]`
- `memspyctl show ALERT_ID [--json]`
- `memspyctl export ALERT_ID`
- `memspyctl response on|off [--json]`
- `memspyctl version`

`export` writes one canonical alert JSON document to standard output. Response changes use PolicyKit; passwords are handled by the system authentication agent, never by MemSpy.

Exit status is 0 on success, 2 for invalid usage, 3 when the detector/API is unavailable, 4 for authorization failure, and 5 when an alert does not exist. In JSON mode stdout contains only the JSON document and diagnostics go to stderr.
