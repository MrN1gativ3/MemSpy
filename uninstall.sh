#!/bin/sh
set -eu

fail()
{
    echo "MemSpy uninstaller: $*" >&2
    exit 2
}

case "${1:-}" in
    "") ;;
    --remove-data) ;; # Retained for compatibility with earlier releases.
    -h|--help)
        echo "Usage: sudo ./uninstall.sh"
        exit 0
        ;;
    *) fail "usage: sudo ./uninstall.sh" ;;
esac
test "$#" -le 1 || fail "usage: sudo ./uninstall.sh"
test "$(id -u)" -eq 0 || fail "run with sudo: sudo ./uninstall.sh"

systemctl disable --now memspyd.service >/dev/null 2>&1 || true
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cleanup=/opt/memspy/libexec/memspy/cleanup-bpf
if [ ! -x "$cleanup" ]; then
    cleanup=$script_dir/packaging/common/cleanup-bpf.sh
fi
"$cleanup"
sh "$script_dir/packaging/common/remove-state.sh" /var/lib/memspy

rm -f -- \
    /usr/local/bin/memspyd \
    /usr/local/bin/memspyctl \
    /usr/local/bin/memspy-ui \
    /opt/memspy/bin/memspyd \
    /opt/memspy/bin/memspyctl \
    /opt/memspy/bin/memspy-ui \
    /opt/memspy/libexec/memspy/memspy.bpf.o \
    /opt/memspy/libexec/memspy/memspy_enforce.bpf.o \
    /opt/memspy/libexec/memspy/migrate-legacy \
    /opt/memspy/libexec/memspy/cleanup-bpf \
    /opt/memspy/share/memspy/memspy-ui.css \
    /etc/systemd/system/memspyd.service \
    /usr/bin/memspyd \
    /usr/bin/memspyctl \
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

rmdir -- /opt/memspy/bin /opt/memspy/libexec/memspy /opt/memspy/libexec \
    /opt/memspy/share/memspy /opt/memspy/share /opt/memspy \
    /usr/libexec/memspy /usr/share/memspy 2>/dev/null || true
systemctl daemon-reload
echo "MemSpy removed. Configuration was preserved; alert history and response state were removed."
