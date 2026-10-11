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

if [ "$(id -u)" -ne 0 ]; then
    error_file=$(mktemp)
    trap 'rm -f "$error_file"' EXIT
    if "$installer" >"$error_file" 2>&1; then
        echo "installer unexpectedly ran without root privileges" >&2
        exit 1
    fi
    grep -q 'run with sudo' "$error_file"
fi
