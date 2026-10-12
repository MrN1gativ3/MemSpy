#!/bin/sh
set -eu

installer=$1
legacy_installer=$2

test -x "$installer"
test -x "$legacy_installer"
sh -n "$installer"
sh -n "$legacy_installer"

help=$("$installer" --help)
printf '%s\n' "$help" | grep -q '^Usage: sudo ./install.sh'
printf '%s\n' "$help" | grep -q 'Ubuntu, Debian, Fedora, and Arch Linux'
test "$("$legacy_installer" --help)" = "$help"
grep -q 'libpolkit-gobject-1-dev' "$installer"
grep -q 'polkit-devel' "$installer"
grep -q '"$build_dir/memspyd" --check-response' "$installer"
grep -q 'response-allowlist.conf' "$installer"

if [ "$(id -u)" -ne 0 ]; then
    error_file=$(mktemp)
    trap 'rm -f "$error_file"' EXIT
    if "$installer" >"$error_file" 2>&1; then
        echo "installer unexpectedly ran without root privileges" >&2
        exit 1
    fi
    grep -q 'run with sudo' "$error_file"
fi
