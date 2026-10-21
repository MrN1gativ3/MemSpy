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
On Fedora GNOME, reboot after adding a desktop user to memspy-ui.
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
# Prefer the active session; an explicit profile resolves ambiguous desktops.
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

saved_allowlist=$(mktemp)
saved_response_allowlist=$(mktemp)
# Meson installs default configuration files on each install. Preserve any
# administrator edits first, then restore them even if a later step fails.
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
# Reconfigure an existing build directory when switching desktop/headless
# profiles; the chosen profile determines whether GTK is built and installed.
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

if [ "$desktop_environment" != headless ]; then
    icon=/usr/share/icons/hicolor/scalable/apps/org.memspy.MemSpyUI.svg
    test -r "$icon" || fail "the desktop icon was not installed at $icon"
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -f -q /usr/share/icons/hicolor || \
            echo "MemSpy installer: could not refresh the icon cache" >&2
    fi
fi

restore_allowlist
reboot_required=false
response_probe=
# Detection works without BPF LSM. Probe response support separately; if the
# kernel has not enabled BPF LSM, prepare its boot configuration and tell the
# operator a reboot is required before blocking can be active.
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
    id -nG "$desktop_user" | tr ' ' '\n' | grep -qx memspy-ui || \
        fail "could not add '$desktop_user' to the memspy-ui group"
fi
if [ "$desktop_environment" = gnome ]; then
    reader_uid=$(id -u "$desktop_user")
    reader_runtime=/run/user/$reader_uid
    if [ -S "$reader_runtime/bus" ] && command -v gnome-extensions >/dev/null 2>&1; then
        if ! runuser -u "$desktop_user" -- env \
            XDG_RUNTIME_DIR="$reader_runtime" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=$reader_runtime/bus" \
            gnome-extensions enable appindicatorsupport@rgcjonas.gmail.com; then
            echo "MemSpy installer: enable AppIndicator after logging in with: gnome-extensions enable appindicatorsupport@rgcjonas.gmail.com" >&2
        fi
    else
        echo "MemSpy installer: enable AppIndicator after logging in with: gnome-extensions enable appindicatorsupport@rgcjonas.gmail.com" >&2
    fi
fi
systemctl daemon-reload
systemctl enable --now memspyd
systemctl restart memspyd

if ! systemctl is-active --quiet memspyd; then
    journalctl -u memspyd -n 50 --no-pager >&2 || true
    fail "memspyd did not start"
fi

rm -f /usr/bin/memspyd \
    /usr/bin/memspyctl \
    /usr/bin/memspy-ui \
    /usr/libexec/memspy/memspy.bpf.o \
    /usr/libexec/memspy/memspy_enforce.bpf.o \
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
    if [ "$distribution" = fedora ] && [ "$desktop_environment" = gnome ]; then
        echo "Reboot so GNOME refreshes group access and desktop integration: sudo reboot"
        echo "Then log in as $desktop_user and run: memspy-ui"
    else
        echo "Log out and back in as $desktop_user, then run: memspy-ui"
    fi
fi
if [ "$reboot_required" = true ]; then
    echo "BPF LSM was enabled in the bootloader configuration."
    echo "Reboot to activate response mode: sudo reboot"
fi
