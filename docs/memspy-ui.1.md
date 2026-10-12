# memspy-ui(1)

`memspy-ui` is the unprivileged GNOME and KDE Plasma indicator and alert window. Add the desktop user to `memspy-ui`, then log out and back in. It displays High and Medium alerts but sends native notifications only for High alerts.

Expanded alert details show bounded execution, parent/grandparent, workload/container, terminal/SSH-origin, namespace, target, and detection evidence when available. Missing context is not guessed. The response switch requests PolicyKit authorization and blocks only memfd-backed execution; MemSpy never reads the administrator password.

On GNOME, use the standard AppIndicator extension supplied by the distribution. KDE Plasma uses its built-in StatusNotifier support. No custom desktop extension is included.
