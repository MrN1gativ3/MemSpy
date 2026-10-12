#!/bin/sh
set -eu

build_dir=${1:-build-package}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

DESTDIR="$stage" meson install -C "$build_dir" >/dev/null

for path in \
    usr/bin/memspyd \
    usr/bin/memspy-ui \
    usr/libexec/memspy/memspy.bpf.o \
    usr/libexec/memspy/memspy_enforce.bpf.o \
    usr/libexec/memspy/migrate-legacy \
    usr/libexec/memspy/cleanup-bpf \
    etc/memspy/allowlist.conf \
    etc/memspy/response-allowlist.conf \
    usr/lib/systemd/system/memspyd.service \
    usr/lib/tmpfiles.d/memspyd.conf \
    usr/lib/sysusers.d/memspyd.conf \
    usr/share/applications/org.memspy.MemSpyUI.desktop \
    usr/share/polkit-1/actions/org.memspy.response.policy \
    etc/xdg/autostart/org.memspy.MemSpyUI.desktop \
    usr/share/man/man8/memspyd.8 \
    usr/share/man/man1/memspy-ui.1; do
    test -e "$stage/$path" || { echo "missing installed path: $path" >&2; exit 1; }
done

test "$(stat -c %a "$stage/etc/memspy/allowlist.conf")" = 644
test "$(stat -c %a "$stage/etc/memspy/response-allowlist.conf")" = 644
test "$(stat -c %a "$stage/usr/libexec/memspy/cleanup-bpf")" = 755
grep -q '^Group=memspy-ui$' "$stage/usr/lib/systemd/system/memspyd.service"
grep -q 'RestrictAddressFamilies=AF_UNIX' "$stage/usr/lib/systemd/system/memspyd.service"
grep -q 'CapabilityBoundingSet=.*CAP_BPF' "$stage/usr/lib/systemd/system/memspyd.service"
grep -q 'CapabilityBoundingSet=.*CAP_PERFMON' "$stage/usr/lib/systemd/system/memspyd.service"
grep -q 'ReadWritePaths=.*/sys/fs/bpf/memspy' "$stage/usr/lib/systemd/system/memspyd.service"
grep -q '^d /sys/fs/bpf/memspy 0700 root root -$' "$stage/usr/lib/tmpfiles.d/memspyd.conf"
grep -q '^g memspy-ui ' "$stage/usr/lib/sysusers.d/memspyd.conf"
grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/usr/share/applications/org.memspy.MemSpyUI.desktop"
grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/etc/xdg/autostart/org.memspy.MemSpyUI.desktop"
grep -q '^Exec=memspy-ui --background$' "$stage/etc/xdg/autostart/org.memspy.MemSpyUI.desktop"

"$build_dir/memspyd" --help | grep -q '/run/memspy/memspy.sock'
"$build_dir/memspyd" --help | grep -q '/etc/memspy/response-allowlist.conf'

grep -q '<action id="org.memspy.response.configure">' \
    "$stage/usr/share/polkit-1/actions/org.memspy.response.policy"
test "$(grep -c '<allow_.*>auth_admin_keep</allow_' \
    "$stage/usr/share/polkit-1/actions/org.memspy.response.policy")" -eq 3

if "$stage/usr/libexec/memspy/cleanup-bpf" /tmp/not-memspy >/dev/null 2>&1; then
    echo "cleanup helper accepted a path outside /sys/fs/bpf/memspy" >&2
    exit 1
fi

for icon in healthy medium high offline; do
    test -f "$stage/usr/share/icons/hicolor/scalable/status/memspy-$icon-symbolic.svg"
done
