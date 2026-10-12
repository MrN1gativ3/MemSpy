#!/bin/sh
set -eu

build_dir=${1:-build-package}
profile=${2:-desktop}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

DESTDIR="$stage" meson install -C "$build_dir" >/dev/null

for path in \
    opt/memspy/bin/memspyd \
    opt/memspy/bin/memspyctl \
    opt/memspy/libexec/memspy/memspy.bpf.o \
    opt/memspy/libexec/memspy/memspy_enforce.bpf.o \
    opt/memspy/libexec/memspy/migrate-legacy \
    opt/memspy/libexec/memspy/cleanup-bpf \
    etc/memspy/allowlist.conf \
    etc/memspy/response-allowlist.conf \
    etc/systemd/system/memspyd.service \
    usr/lib/tmpfiles.d/memspyd.conf \
    usr/lib/sysusers.d/memspyd.conf \
    usr/share/polkit-1/actions/org.memspy.response.policy \
    usr/share/man/man1/memspyctl.1 \
    usr/share/man/man8/memspyd.8; do
    test -e "$stage/$path" || { echo "missing installed path: $path" >&2; exit 1; }
done

for path in usr/bin/memspyd usr/bin/memspyctl usr/libexec/memspy; do
    test ! -e "$stage/$path" || { echo "unexpected legacy payload path: $path" >&2; exit 1; }
done

if [ "$profile" = desktop ]; then
    for path in opt/memspy/bin/memspy-ui \
        opt/memspy/share/memspy/memspy-ui.css \
        usr/share/applications/org.memspy.MemSpyUI.desktop \
        etc/xdg/autostart/org.memspy.MemSpyUI.desktop usr/share/man/man1/memspy-ui.1; do
        test -e "$stage/$path" || { echo "missing desktop path: $path" >&2; exit 1; }
    done
else
    for path in opt/memspy/bin/memspy-ui \
        opt/memspy/share/memspy/memspy-ui.css \
        usr/share/applications/org.memspy.MemSpyUI.desktop \
        etc/xdg/autostart/org.memspy.MemSpyUI.desktop usr/share/man/man1/memspy-ui.1; do
        test ! -e "$stage/$path" || { echo "unexpected headless path: $path" >&2; exit 1; }
    done
    test ! -L "$stage/usr/local/bin/memspy-ui" || {
        echo "unexpected headless command link: usr/local/bin/memspy-ui" >&2
        exit 1
    }
fi

test "$(stat -c %a "$stage/etc/memspy/allowlist.conf")" = 644
test "$(stat -c %a "$stage/etc/memspy/response-allowlist.conf")" = 644
test "$(stat -c %a "$stage/opt/memspy/libexec/memspy/cleanup-bpf")" = 755
test -L "$stage/usr/local/bin/memspyd"
test -L "$stage/usr/local/bin/memspyctl"
test "$(readlink "$stage/usr/local/bin/memspyd")" = /opt/memspy/bin/memspyd
test "$(readlink "$stage/usr/local/bin/memspyctl")" = /opt/memspy/bin/memspyctl
grep -q '^ExecStart=/opt/memspy/bin/memspyd --foreground$' "$stage/etc/systemd/system/memspyd.service"
grep -q '^Group=memspy-ui$' "$stage/etc/systemd/system/memspyd.service"
grep -q 'RestrictAddressFamilies=AF_UNIX' "$stage/etc/systemd/system/memspyd.service"
grep -q 'CapabilityBoundingSet=.*CAP_BPF' "$stage/etc/systemd/system/memspyd.service"
grep -q 'CapabilityBoundingSet=.*CAP_PERFMON' "$stage/etc/systemd/system/memspyd.service"
grep -q 'ReadWritePaths=.*/sys/fs/bpf/memspy' "$stage/etc/systemd/system/memspyd.service"
grep -q '^d /sys/fs/bpf/memspy 0700 root root -$' "$stage/usr/lib/tmpfiles.d/memspyd.conf"
grep -q '^g memspy-ui ' "$stage/usr/lib/sysusers.d/memspyd.conf"
if [ "$profile" = desktop ]; then
    test -L "$stage/usr/local/bin/memspy-ui"
    test "$(readlink "$stage/usr/local/bin/memspy-ui")" = /opt/memspy/bin/memspy-ui
    grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/usr/share/applications/org.memspy.MemSpyUI.desktop"
    grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/etc/xdg/autostart/org.memspy.MemSpyUI.desktop"
    grep -q '^Exec=/opt/memspy/bin/memspy-ui$' "$stage/usr/share/applications/org.memspy.MemSpyUI.desktop"
    grep -q '^Exec=/opt/memspy/bin/memspy-ui --background$' "$stage/etc/xdg/autostart/org.memspy.MemSpyUI.desktop"
fi

"$build_dir/memspyd" --help | grep -q '/run/memspy/memspy.sock'
"$build_dir/memspyd" --help | grep -q '/etc/memspy/response-allowlist.conf'

grep -q '<action id="org.memspy.response.configure">' \
    "$stage/usr/share/polkit-1/actions/org.memspy.response.policy"
test "$(grep -c '<allow_.*>auth_admin_keep</allow_' \
    "$stage/usr/share/polkit-1/actions/org.memspy.response.policy")" -eq 3

if "$stage/opt/memspy/libexec/memspy/cleanup-bpf" /tmp/not-memspy >/dev/null 2>&1; then
    echo "cleanup helper accepted a path outside /sys/fs/bpf/memspy" >&2
    exit 1
fi

if [ "$profile" = desktop ]; then
    for icon in healthy medium high offline; do
        test -f "$stage/usr/share/icons/hicolor/scalable/status/memspy-$icon-symbolic.svg"
    done
fi
