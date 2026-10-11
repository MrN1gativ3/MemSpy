#!/bin/sh
set -eu

fail()
{
    echo "filelessd installer: $*" >&2
    exit 2
}

test "$(id -u)" -eq 0 || fail "run with sudo: sudo $0 [desktop-user] [gnome|kde]"
test "$#" -le 2 || fail "usage: sudo $0 [desktop-user] [gnome|kde]"
test -r /etc/os-release || fail "cannot identify this operating system"
. /etc/os-release
test "${ID:-}" = ubuntu || fail "this installer supports Ubuntu only"
test "$(uname -m)" = x86_64 || fail "x86_64 is required"
test -r /sys/kernel/btf/vmlinux || fail "kernel BTF is missing at /sys/kernel/btf/vmlinux"

desktop_user=${1:-${SUDO_USER:-}}
test -n "$desktop_user" || fail "pass the desktop username as the first argument"
test "$desktop_user" != root || fail "the UI must run as an unprivileged desktop user"
getent passwd "$desktop_user" >/dev/null || fail "user '$desktop_user' does not exist"

desktop_environment=${2:-}
case "$desktop_environment" in
    gnome|kde) ;;
    "")
        current_desktop=$(printf '%s' "${XDG_CURRENT_DESKTOP:-}" | tr '[:upper:]' '[:lower:]')
        case "$current_desktop" in
            *gnome*) desktop_environment=gnome ;;
            *kde*|*plasma*) desktop_environment=kde ;;
        esac
        ;;
    *) fail "desktop must be 'gnome' or 'kde'" ;;
esac

if [ -z "$desktop_environment" ]; then
    gnome_running=false
    kde_running=false
    pgrep -u "$desktop_user" -x gnome-shell >/dev/null 2>&1 && gnome_running=true
    pgrep -u "$desktop_user" -x plasmashell >/dev/null 2>&1 && kde_running=true
    if [ "$gnome_running" = true ] && [ "$kde_running" = false ]; then
        desktop_environment=gnome
    elif [ "$gnome_running" = false ] && [ "$kde_running" = true ]; then
        desktop_environment=kde
    elif [ "$gnome_running" = true ] && [ "$kde_running" = true ]; then
        fail "both GNOME and KDE sessions are running for '$desktop_user'; select one explicitly"
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
        fail "neither GNOME nor KDE Plasma is installed; no changes were made"
    fi
fi

if [ "$desktop_environment" = gnome ]; then
    command -v gnome-shell >/dev/null 2>&1 || fail "GNOME is not installed; no changes were made"
else
    command -v plasmashell >/dev/null 2>&1 || fail "KDE Plasma is not installed; no changes were made"
fi

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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_dir="$project_root/build-ubuntu"
saved_allowlist=$(mktemp)
had_allowlist=false
restore_allowlist()
{
    if [ "$had_allowlist" = true ]; then
        install -m 0644 -o root -g root "$saved_allowlist" /etc/filelessd/allowlist.conf
        had_allowlist=false
    fi
}
cleanup()
{
    restore_allowlist
    rm -f "$saved_allowlist"
}
trap cleanup EXIT
if [ -f /etc/filelessd/allowlist.conf ]; then
    cp /etc/filelessd/allowlist.conf "$saved_allowlist"
    had_allowlist=true
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential meson ninja-build clang pkg-config linux-tools-common \
    libbpf-dev libglib2.0-dev libjson-c-dev libsqlite3-dev libgtk-3-dev \
    libayatana-appindicator3-dev libnotify-dev

if [ "$desktop_environment" = gnome ]; then
    apt-get install -y --no-install-recommends gnome-shell-extension-appindicator
fi

if ! bpftool version >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends "linux-tools-$kernel_release" ||
        fail "bpftool is unavailable for kernel $kernel_release"
fi
bpftool version >/dev/null 2>&1 || fail "bpftool is installed but cannot run"

if [ -f "$build_dir/meson-private/coredata.dat" ]; then
    meson setup --reconfigure "$build_dir" --prefix=/usr --buildtype=release \
        -Dintegration_tests=false
else
    meson setup "$build_dir" --prefix=/usr --buildtype=release \
        -Dintegration_tests=false
fi
meson compile -C "$build_dir"
meson test -C "$build_dir" --no-suite privileged --print-errorlogs
meson install -C "$build_dir"

restore_allowlist
systemd-sysusers /usr/lib/sysusers.d/filelessd.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/filelessd.conf
usermod -aG filelessd-ui -- "$desktop_user"
systemctl daemon-reload
systemctl enable --now filelessd
systemctl restart filelessd

if ! systemctl is-active --quiet filelessd; then
    journalctl -u filelessd -n 50 --no-pager >&2 || true
    fail "filelessd did not start"
fi

echo
echo "filelessd is installed and running."
echo "Desktop integration: $desktop_environment"
echo "Log out and back in as $desktop_user, then run: fileless-ui"
echo "To run the intentional detection fixtures later:"
echo "  sudo sh '$project_root/tests/vm/run_matrix.sh' build-vm"
