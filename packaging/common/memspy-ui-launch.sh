#!/bin/sh
set -eu

binary=/opt/memspy/bin/memspy-ui

# A desktop session started before group enrollment keeps its old group list.
# Re-enter the already-authorized group for the UI without changing socket access.
if ! id -nG | tr ' ' '\n' | grep -qx memspy-ui &&
    id -nG "$(id -un)" | tr ' ' '\n' | grep -qx memspy-ui; then
    case "$#:${1:-}" in
        0:) exec sg memspy-ui -c "$binary" ;;
        1:--background) exec sg memspy-ui -c "$binary --background" ;;
    esac
fi

exec "$binary" "$@"
