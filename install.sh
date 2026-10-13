#!/bin/sh
set -eu

fail()
{
    echo "MemSpy installer: $*" >&2
    exit 2
}

usage()
{
    cat <<'EOF'
Usage: sudo ./install.sh [reader-user] [gnome|kde|headless]

Build, test, install, and start MemSpy on Ubuntu, Debian, Fedora, and Arch Linux.
The desktop profile is detected automatically; servers without GNOME/KDE use headless.
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

test "$(id -u)" -eq 0 || fail "run with sudo: sudo ./install.sh"
test "$#" -le 2 || fail "usage: sudo ./install.sh [reader-user] [gnome|kde|headless]"
test -r /etc/os-release || fail "cannot identify this operating system"
. /etc/os-release
case "${ID:-}" in
    ubuntu|debian|fedora|arch) distribution=$ID ;;
    *) fail "unsupported distribution '${ID:-unknown}'; use Ubuntu, Debian, Fedora, or Arch Linux" ;;
esac

test "$(uname -m)" = x86_64 || fail "x86_64 is required"
test -r /sys/kernel/btf/vmlinux || fail "kernel BTF is missing at /sys/kernel/btf/vmlinux"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

kernel_release=$(uname -r)
kernel_major=${kernel_release%%.*}
kernel_rest=${kernel_release#*.}
kernel_minor=${kernel_rest%%.*}
case "$kernel_major:$kernel_minor" in
    *[!0-9:]*|:*) fail "cannot parse kernel version '$kernel_release'" ;;
esac
if [ "$kernel_major" -lt 5 ] || { [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 4 ]; }; then
    fail "Linux 5.4 or newer is required"
fi

reader_supplied=false
[ "$#" -ge 1 ] && [ "${1:-}" != headless ] && reader_supplied=true
desktop_user=${1:-${SUDO_USER:-}}
desktop_environment=${2:-}
if [ "$#" -eq 1 ] && [ "${1:-}" = headless ]; then
    desktop_environment=headless
    desktop_user=
fi
case "$desktop_environment" in
    gnome|kde|headless) ;;
    "")
        current_desktop=$(printf '%s' "${XDG_CURRENT_DESKTOP:-}" | tr '[:upper:]' '[:lower:]')
        case "$current_desktop" in
            *gnome*) desktop_environment=gnome ;;
            *kde*|*plasma*) desktop_environment=kde ;;
        esac
        ;;
    *) fail "profile must be 'gnome', 'kde', or 'headless'" ;;
esac

if [ -z "$desktop_environment" ] && [ -n "$desktop_user" ]; then
    gnome_running=false
    kde_running=false
    pgrep -u "$desktop_user" -x gnome-shell >/dev/null 2>&1 && gnome_running=true
    pgrep -u "$desktop_user" -x plasmashell >/dev/null 2>&1 && kde_running=true
    if [ "$gnome_running" = true ] && [ "$kde_running" = false ]; then
        desktop_environment=gnome
    elif [ "$gnome_running" = false ] && [ "$kde_running" = true ]; then
        desktop_environment=kde
    elif [ "$gnome_running" = true ] && [ "$kde_running" = true ]; then
        fail "both GNOME and KDE sessions are running; select one explicitly"
    fi
fi

if [ -z "$desktop_environment" ]; then
    gnome_present=false
    kde_present=false
    command -v gnome-shell >/dev/null 2>&1 && gnome_present=true
    command -v plasmashell >/dev/null 2>&1 && kde_present=true
    if [ "$gnome_present" = true ] && [ "$kde_present" = false ]; then
        desktop_environment=gnome
    elif [ "$gnome_present" = false ] && [ "$kde_present" = true ]; then
        desktop_environment=kde
    elif [ "$gnome_present" = true ] && [ "$kde_present" = true ]; then
        fail "both GNOME and KDE are installed; pass 'gnome' or 'kde' as the second argument"
    else
        desktop_environment=headless
    fi
fi

if [ "$desktop_environment" = gnome ]; then
    command -v gnome-shell >/dev/null 2>&1 || fail "GNOME is not installed; no changes were made"
elif [ "$desktop_environment" = kde ]; then
    command -v plasmashell >/dev/null 2>&1 || fail "KDE Plasma is not installed; no changes were made"
fi

if [ "$desktop_environment" != headless ]; then
    test -n "$desktop_user" || fail "pass the unprivileged desktop username"
fi
if [ "$desktop_environment" = headless ] && [ "$reader_supplied" = false ]; then
    desktop_user=
fi
if [ -n "$desktop_user" ]; then
    test "$desktop_user" != root || fail "the reader must be an unprivileged user"
    getent passwd "$desktop_user" >/dev/null || fail "user '$desktop_user' does not exist"
fi

echo "Selected installation profile: $desktop_environment"

echo "Installing build dependencies for $distribution..."
case "$distribution" in
    ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            build-essential meson ninja-build clang pkg-config linux-tools-common linux-tools-generic \
            libbpf-dev libglib2.0-dev libjson-c-dev libsqlite3-dev libsystemd-dev \
            libpolkit-gobject-1-dev policykit-1
        if [ "$desktop_environment" != headless ]; then
            apt-get install -y --no-install-recommends libgtk-3-dev \
                libayatana-appindicator3-dev libnotify-dev
        fi
        if [ "$desktop_environment" = gnome ]; then
            apt-get install -y --no-install-recommends gnome-shell-extension-appindicator
        fi
        if ! bpftool version >/dev/null 2>&1; then
            apt-get install -y --no-install-recommends "linux-tools-$kernel_release" || true
        fi
        if ! bpftool version >/dev/null 2>&1; then
            bpftool_binary=$(find /usr/lib -maxdepth 4 -type f -name bpftool -perm -111 \
                -path '/usr/lib/linux-tools*' -print 2>/dev/null | sort -V | tail -n 1)
            test -n "$bpftool_binary" || fail "no usable bpftool was provided by Ubuntu"
            install -m 0755 "$bpftool_binary" /usr/local/bin/bpftool
            hash -r
        fi
        ;;
    debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            build-essential meson ninja-build clang pkg-config bpftool \
            libbpf-dev libglib2.0-dev libjson-c-dev libsqlite3-dev libsystemd-dev \
            libpolkit-gobject-1-dev policykit-1
        if [ "$desktop_environment" != headless ]; then
            apt-get install -y --no-install-recommends libgtk-3-dev \
                libayatana-appindicator3-dev libnotify-dev
        fi
        if [ "$desktop_environment" = gnome ]; then
            apt-get install -y --no-install-recommends gnome-shell-extension-appindicator
        fi
        ;;
    fedora)
        dnf install -y gcc meson ninja-build clang pkgconf-pkg-config bpftool \
            libbpf-devel glib2-devel json-c-devel sqlite-devel systemd-devel polkit-devel
        if [ "$desktop_environment" != headless ]; then
            dnf install -y gtk3-devel libayatana-appindicator-gtk3-devel libnotify-devel
        fi
        if [ "$desktop_environment" = gnome ]; then
            dnf install -y gnome-shell-extension-appindicator
        fi
        ;;
    arch)
        pacman -S --needed --noconfirm base-devel meson ninja clang pkgconf bpf \
            libbpf glib2 json-c sqlite systemd polkit
        if [ "$desktop_environment" != headless ]; then
            pacman -S --needed --noconfirm gtk3 libayatana-appindicator libnotify
        fi
        if [ "$desktop_environment" = gnome ]; then
            pacman -S --needed --noconfirm gnome-shell-extension-appindicator
        fi
        ;;
esac

bpftool version >/dev/null 2>&1 || fail "bpftool is installed but cannot run"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir="$script_dir/build-install"

if systemctl is-active --quiet filelessd.service; then
    systemctl stop filelessd.service
fi
"$script_dir/packaging/common/migrate-legacy.sh"

saved_allowlist=$(mktemp)
saved_response_allowlist=$(mktemp)
had_allowlist=false
had_response_allowlist=false
restore_allowlist()
{
    if [ "$had_allowlist" = true ]; then
        install -m 0644 -o root -g root "$saved_allowlist" /etc/memspy/allowlist.conf
        had_allowlist=false
    fi
    if [ "$had_response_allowlist" = true ]; then
        install -m 0644 -o root -g root "$saved_response_allowlist" \
            /etc/memspy/response-allowlist.conf
        had_response_allowlist=false
    fi
}
cleanup()
{
    restore_allowlist
    rm -f "$saved_allowlist" "$saved_response_allowlist"
}
trap cleanup EXIT
if [ -f /etc/memspy/allowlist.conf ]; then
    cp /etc/memspy/allowlist.conf "$saved_allowlist"
    had_allowlist=true
fi
if [ -f /etc/memspy/response-allowlist.conf ]; then
    cp /etc/memspy/response-allowlist.conf "$saved_response_allowlist"
    had_response_allowlist=true
fi

if [ "$desktop_environment" = headless ]; then
    desktop_option=disabled
else
    desktop_option=enabled
fi
if [ -f "$build_dir/meson-private/coredata.dat" ]; then
    meson setup --reconfigure "$build_dir" --prefix=/opt/memspy --buildtype=release \
        -Dintegration_tests=false -Ddesktop_ui="$desktop_option"
else
    meson setup "$build_dir" --prefix=/opt/memspy --buildtype=release \
        -Dintegration_tests=false -Ddesktop_ui="$desktop_option"
fi
meson compile -C "$build_dir"
meson test -C "$build_dir" --no-suite privileged --print-errorlogs
meson install -C "$build_dir"

restore_allowlist
reboot_required=false
response_probe=
if response_probe=$("$build_dir/memspyd" --check-response 2>&1); then
    printf '%s\n' "$response_probe"
    install -d -m 0700 -o root -g root /sys/fs/bpf/memspy
else
    probe_status=$?
    printf '%s\n' "$response_probe"
    test "$probe_status" -eq 3 || fail "response support probe failed unexpectedly"
    case "$response_probe" in
        *"BPF LSM is not active"*)
            if "$script_dir/packaging/common/enable-bpf-lsm.sh" "$distribution"; then
                reboot_required=true
            else
                boot_status=$?
                test "$boot_status" -eq 3 || fail "automatic BPF LSM setup failed unexpectedly"
                echo "MemSpy installer: BPF LSM must be enabled manually before response mode is available" >&2
            fi
            ;;
    esac
fi
systemd-sysusers /usr/lib/sysusers.d/memspyd.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/memspyd.conf || true
if [ -n "$desktop_user" ]; then
    usermod -aG memspy-ui -- "$desktop_user"
fi
systemctl daemon-reload
systemctl enable --now memspyd
systemctl restart memspyd

if ! systemctl is-active --quiet memspyd; then
    journalctl -u memspyd -n 50 --no-pager >&2 || true
    fail "memspyd did not start"
fi

systemctl disable filelessd.service >/dev/null 2>&1 || true
rm -f /run/filelessd/filelessd.sock \
    /usr/bin/filelessd \
    /usr/bin/fileless-ui \
    /usr/libexec/filelessd/fileless.bpf.o \
    /usr/lib/systemd/system/filelessd.service \
    /usr/lib/tmpfiles.d/filelessd.conf \
    /usr/lib/sysusers.d/filelessd.conf \
    /usr/share/applications/org.fileless.DetectorUI.desktop \
    /usr/share/fileless-detector/fileless-ui.css \
    /usr/share/icons/hicolor/scalable/status/fileless-healthy-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/fileless-medium-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/fileless-high-symbolic.svg \
    /usr/share/icons/hicolor/scalable/status/fileless-offline-symbolic.svg \
    /usr/share/man/man1/fileless-ui.1 \
    /usr/share/man/man1/fileless-ui.1.gz \
    /usr/share/man/man8/filelessd.8 \
    /usr/share/man/man8/filelessd.8.gz \
    /etc/xdg/autostart/org.fileless.DetectorUI.desktop
rmdir /run/filelessd /usr/libexec/filelessd /usr/share/fileless-detector 2>/dev/null || true
groupdel filelessd-ui >/dev/null 2>&1 || true

rm -f /usr/bin/memspyd \
    /usr/bin/memspyctl \
    /usr/bin/memspy-ui \
    /usr/libexec/memspy/memspy.bpf.o \
    /usr/libexec/memspy/memspy_enforce.bpf.o \
    /usr/libexec/memspy/migrate-legacy \
    /usr/libexec/memspy/cleanup-bpf \
    /usr/lib/systemd/system/memspyd.service \
    /usr/share/memspy/memspy-ui.css
rmdir /usr/libexec/memspy /usr/share/memspy 2>/dev/null || true
systemctl daemon-reload

echo
echo "MemSpy is installed and running."
echo "Application files: /opt/memspy"
echo "Installation profile: $desktop_environment"
if [ "$desktop_environment" = headless ]; then
    echo "Run: memspyctl status"
    if [ -n "$desktop_user" ]; then
        echo "Log out and back in as $desktop_user before using memspyctl without sudo."
    fi
else
    echo "Log out and back in as $desktop_user, then run: memspy-ui"
fi
if [ "$reboot_required" = true ]; then
    echo "BPF LSM was enabled in the bootloader configuration."
    echo "Reboot to activate response mode: sudo reboot"
fi
