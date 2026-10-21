#!/bin/sh
set -eu

binary=$1
case "$binary" in
    /*) ;;
    *) binary="$(pwd)/$binary" ;;
esac
cd "$2"
test -r data/memspy-ui.css || {
    echo 'source UI stylesheet is unavailable' >&2
    exit 1
}
test -n "${DISPLAY:-}" || exit 77
command -v xwininfo >/dev/null 2>&1 || exit 77

app_window_visible() {
    # The tray icon also owns a tiny window named MemSpy; identify the GTK app by class.
    window_id=$(xwininfo -root -tree 2>/dev/null |
        awk '/"MemSpy": \("memspy-ui"/ { print $1; exit }')
    test -n "$window_id" &&
        xwininfo -id "$window_id" 2>/dev/null | grep -q 'Map State: IsViewable'
}

GDK_BACKEND=x11 "$binary" --background &
background_pid=$!
trap 'kill "$background_pid" 2>/dev/null || true; wait "$background_pid" 2>/dev/null || true' EXIT INT TERM

ready=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$background_pid" 2>/dev/null || { echo 'background UI exited' >&2; exit 1; }
    if gdbus call --session --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.memspy.MemSpyUI 2>/dev/null |
        grep -q '(true,)'; then
        ready=true
        break
    fi
    sleep 1
done
test "$ready" = true || { echo 'background UI did not register on D-Bus' >&2; exit 1; }
if app_window_visible; then
    echo 'background UI opened a window before foreground activation' >&2
    exit 1
fi

GDK_BACKEND=x11 "$binary"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if app_window_visible; then
        exit 0
    fi
    sleep 1
done
echo 'foreground activation did not show the existing UI window' >&2
xwininfo -root -tree >&2 || true
exit 1
