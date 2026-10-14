# memspy-ui(1)

`memspy-ui` is the unprivileged GNOME and KDE Plasma indicator and alert window. Add the desktop user to `memspy-ui`, then log out and back in. It displays High and Medium alerts but sends native notifications only for High alerts.

Expanded alert details show bounded execution, parent/grandparent, workload/container, terminal/SSH-origin, namespace, target, and role-specific executable evidence when available. Paths and MD5/SHA-256 hashes remain selectable, and missing evidence shows its exact collection reason. The response switch requests PolicyKit authorization before enabling the complete supported response policy; MemSpy never reads the administrator password.

On GNOME, use the standard AppIndicator extension supplied by the distribution. KDE Plasma uses its built-in StatusNotifier support. No custom desktop extension is included.
