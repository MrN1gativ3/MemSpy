#!/bin/sh
set -eu

meson_file=$1
store_source=$2

test "$(sed -n '1p' "$store_source")" = '#define _POSIX_C_SOURCE 200809L'
grep -Fq "host_machine.cpu_family() + '-linux-gnu'" "$meson_file"
