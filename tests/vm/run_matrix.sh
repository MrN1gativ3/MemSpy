#!/bin/sh
set -eu

test "$(id -u)" -eq 0 || { echo 'run as root in a disposable VM' >&2; exit 2; }
test "$(uname -m)" = x86_64 || { echo 'x86_64 is required' >&2; exit 2; }
test -r /sys/kernel/btf/vmlinux || { echo 'kernel BTF is missing' >&2; exit 2; }

. /etc/os-release
case "$ID" in
  ubuntu|debian|fedora|arch) ;;
  *) echo "unsupported matrix guest: $ID" >&2; exit 2 ;;
esac

major=$(uname -r | cut -d. -f1)
minor=$(uname -r | cut -d. -f2)
if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 4 ]; }; then
  echo 'Linux 5.4 or newer is required' >&2
  exit 2
fi

build_dir=${1:-build-vm}
meson setup "$build_dir" --buildtype=release -Dintegration_tests=true
meson compile -C "$build_dir"
meson test -C "$build_dir" --no-suite privileged --print-errorlogs
ASAN_OPTIONS=detect_leaks=0 meson test -C "$build_dir" --suite privileged --print-errorlogs

printf 'verified %s %s kernel %s x86_64\n' "$ID" "$VERSION_ID" "$(uname -r)"
