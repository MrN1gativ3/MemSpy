#!/bin/sh
set -eu

workflow=$1
install_block=$(sed -n '/sudo apt-get install -y/,/xvfb dbus-x11/p' "$workflow")

printf '%s\n' "$install_block" | grep -qw linux-tools-generic
printf '%s\n' "$install_block" | grep -qw at-spi2-core
printf '%s\n' "$install_block" | grep -qw libpolkit-gobject-1-dev
printf '%s\n' "$install_block" | grep -qw libsystemd-dev
! printf '%s\n' "$install_block" | grep -qw bpftool
grep -q 'bpftool version' "$workflow"
grep -Fq '/usr/lib/linux-tools' "$workflow"
grep -Fq -- "-path '/usr/lib/linux-tools*'" "$workflow"
grep -Fq '/usr/local/bin/bpftool' "$workflow"
! grep -Fq 'linux-tools-$(uname -r)' "$workflow"
