#!/bin/sh
set -eu

helper=$1
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

make_command()
{
    name=$1
    mkdir -p "$stage/bin"
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"$MEMSPY_TEST_COMMAND_LOG"\n' \
        >"$stage/bin/$name"
    chmod +x "$stage/bin/$name"
}

reset_stage()
{
    rm -rf "$stage/root" "$stage/bin" "$stage/commands.log"
    mkdir -p "$stage/root/sys/kernel/security" "$stage/root/proc" "$stage/bin"
    : >"$stage/commands.log"
}

run_helper()
{
    MEMSPY_BOOT_ROOT="$stage/root" \
    MEMSPY_TEST_COMMAND_LOG="$stage/commands.log" \
    PATH="$stage/bin:/usr/bin:/bin" \
        "$helper" "$1"
}

reset_stage
mkdir -p "$stage/root/etc/default"
printf '%s\n' 'lockdown,capability,landlock,yama,apparmor,ima,evm' \
    >"$stage/root/sys/kernel/security/lsm"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz quiet splash lsm=lockdown,apparmor' \
    >"$stage/root/proc/cmdline"
printf '%s\n' 'GRUB_TIMEOUT=5' \
    'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,apparmor"' \
    >"$stage/root/etc/default/grub"
make_command update-grub
run_helper ubuntu | grep -q 'reboot required'
grep -q '^GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,apparmor,bpf"$' \
    "$stage/root/etc/default/grub"
test "$(cat "$stage/commands.log")" = ""

reset_stage
printf '%s\n' 'lockdown,capability,apparmor,bpf' \
    >"$stage/root/sys/kernel/security/lsm"
printf '%s\n' 'quiet lsm=lockdown,apparmor,bpf' >"$stage/root/proc/cmdline"
run_helper ubuntu | grep -q 'already active'
test ! -s "$stage/commands.log"

reset_stage
printf '%s\n' 'lockdown,capability,selinux,ima,evm' \
    >"$stage/root/sys/kernel/security/lsm"
printf '%s\n' 'quiet lsm=lockdown,selinux' >"$stage/root/proc/cmdline"
make_command grubby
run_helper fedora | grep -q 'reboot required'
grep -q -- '--update-kernel=ALL --remove-args=lsm --args=lsm=lockdown,selinux,bpf' \
    "$stage/commands.log"

reset_stage
mkdir -p "$stage/root/etc/kernel"
printf '%s\n' 'lockdown,capability,landlock,yama' \
    >"$stage/root/sys/kernel/security/lsm"
printf '%s\n' 'quiet' >"$stage/root/proc/cmdline"
printf '%s\n' 'root=UUID=test rw quiet' >"$stage/root/etc/kernel/cmdline"
make_command kernel-install
run_helper arch | grep -q 'reboot required'
grep -q '^root=UUID=test rw quiet lsm=lockdown,capability,landlock,yama,bpf$' \
    "$stage/root/etc/kernel/cmdline"
grep -q '^add-all$' "$stage/commands.log"

reset_stage
printf '%s\n' 'lockdown,capability,apparmor' \
    >"$stage/root/sys/kernel/security/lsm"
printf '%s\n' 'quiet' >"$stage/root/proc/cmdline"
if run_helper debian >/dev/null 2>&1; then
    echo "helper accepted an unknown bootloader" >&2
    exit 1
else
    test "$?" -eq 3
fi
