#!/bin/sh
set -eu

installer=$1

test -x "$installer"
sh -n "$installer"
grep -q 'ID.*ubuntu' "$installer"
grep -q '/sys/kernel/btf/vmlinux' "$installer"
grep -q 'XDG_CURRENT_DESKTOP' "$installer"
grep -q 'gnome-shell' "$installer"
grep -q 'plasmashell' "$installer"
grep -q 'desktop_environment.*gnome' "$installer"
grep -q 'desktop_environment.*kde' "$installer"
grep -q 'GNOME is not installed; no changes were made' "$installer"
grep -q 'KDE Plasma is not installed; no changes were made' "$installer"
grep -q 'gnome-shell-extension-appindicator' "$installer"
grep -q 'meson test.*--no-suite privileged' "$installer"
grep -q 'systemd-sysusers' "$installer"
grep -q 'systemctl enable --now filelessd' "$installer"
grep -q 'usermod -aG filelessd-ui' "$installer"
! grep -q 'meson test.* --suite privileged' "$installer"
