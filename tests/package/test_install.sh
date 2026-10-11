#!/bin/sh
set -eu

build_dir=${1:-build-package}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

DESTDIR="$stage" meson install -C "$build_dir" >/dev/null

for path in \
    usr/bin/filelessd \
    usr/bin/fileless-ui \
    usr/libexec/filelessd/fileless.bpf.o \
    etc/filelessd/allowlist.conf \
    usr/lib/systemd/system/filelessd.service \
    usr/lib/tmpfiles.d/filelessd.conf \
    usr/lib/sysusers.d/filelessd.conf \
    usr/share/applications/org.fileless.DetectorUI.desktop \
    etc/xdg/autostart/org.fileless.DetectorUI.desktop \
    usr/share/man/man8/filelessd.8 \
    usr/share/man/man1/fileless-ui.1; do
    test -e "$stage/$path" || { echo "missing installed path: $path" >&2; exit 1; }
done

test "$(stat -c %a "$stage/etc/filelessd/allowlist.conf")" = 644
grep -q '^Group=filelessd-ui$' "$stage/usr/lib/systemd/system/filelessd.service"
grep -q 'RestrictAddressFamilies=AF_UNIX' "$stage/usr/lib/systemd/system/filelessd.service"
grep -q '^g filelessd-ui ' "$stage/usr/lib/sysusers.d/filelessd.conf"
grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/usr/share/applications/org.fileless.DetectorUI.desktop"
grep -q '^OnlyShowIn=GNOME;KDE;' "$stage/etc/xdg/autostart/org.fileless.DetectorUI.desktop"
grep -q '^Exec=fileless-ui --background$' "$stage/etc/xdg/autostart/org.fileless.DetectorUI.desktop"

for icon in healthy medium high offline; do
    test -f "$stage/usr/share/icons/hicolor/scalable/status/fileless-$icon-symbolic.svg"
done
