#!/bin/sh
set -eu

fail()
{
    echo "MemSpy uninstaller: $*" >&2
    exit 2
}

remove_data=false
case "${1:-}" in
    "") ;;
    --remove-data) remove_data=true ;;
    -h|--help)
        echo "Usage: sudo ./uninstall.sh [--remove-data]"
        exit 0
        ;;
    *) fail "usage: sudo ./uninstall.sh [--remove-data]" ;;
esac
test "$#" -le 1 || fail "usage: sudo ./uninstall.sh [--remove-data]"
test "$(id -u)" -eq 0 || fail "run with sudo: sudo ./uninstall.sh"

systemctl disable --now memspyd.service >/dev/null 2>&1 || true
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cleanup=/usr/libexec/memspy/cleanup-bpf
if [ ! -x "$cleanup" ]; then
    cleanup=$script_dir/packaging/common/cleanup-bpf.sh
fi
"$cleanup"

rm -f -- \
    /usr/bin/memspyd \
    /usr/bin/memspy-ui \
    /usr/libexec/memspy/memspy.bpf.o \
    /usr/libexec/memspy/memspy_enforce.bpf.o \
    /usr/libexec/memspy/migrate-legacy \
    /usr/libexec/memspy/cleanup-bpf \
    /usr/lib/systemd/system/memspyd.service \
    /usr/lib/tmpfiles.d/memspyd.conf \
    /usr/lib/sysusers.d/memspyd.conf \
    /usr/share/polkit-1/actions/org.memspy.response.policy \
    /usr/share/applications/org.memspy.MemSpyUI.desktop \
    /etc/xdg/autostart/org.memspy.MemSpyUI.desktop \
    /usr/share/memspy/memspy-ui.css \
    /usr/share/icons/hicolor/scalable/status/memspy-healthy-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/memspy-medium-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/memspy-high-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/memspy-offline-symbolic.svg \
    /usr/share/man/man1/memspy-ui.1 \
    /usr/share/man/man1/memspy-ui.1.gz \
    /usr/share/man/man8/memspyd.8 \
    /usr/share/man/man8/memspyd.8.gz

if [ "$remove_data" = true ]; then
    rm -f -- \
        /var/lib/memspy/alerts.db \
        /var/lib/memspy/alerts.db-shm \
        /var/lib/memspy/alerts.db-wal \
        /var/lib/memspy/response-mode
    rmdir -- /var/lib/memspy 2>/dev/null || true
fi

rmdir -- /usr/libexec/memspy /usr/share/memspy 2>/dev/null || true
systemctl daemon-reload
if [ "$remove_data" = true ]; then
    echo "MemSpy removed. Configuration was preserved; alert history and response state were removed."
else
    echo "MemSpy removed. Configuration, alert history, and response state were preserved."
fi
