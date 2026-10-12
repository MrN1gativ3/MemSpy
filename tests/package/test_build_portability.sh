#!/bin/sh
set -eu

meson_file=$1
store_source=$2
enforce_source=$3
enforcer_source=$4
daemon_main=$5

test "$(sed -n '1p' "$store_source")" = '#define _POSIX_C_SOURCE 200809L'
grep -Fq "host_machine.cpu_family() + '-linux-gnu'" "$meson_file"
grep -Fq 'bpf_perf_event_output(ctx, &enforce_events' "$enforce_source"
! grep -Fq 'bpf_perf_event_output((void *)bprm, &enforce_events' "$enforce_source"
grep -Fq 'staged ? "_new" : ""' "$enforcer_source"
! grep -Fq '".new"' "$enforcer_source"
grep -Fq '"%s_probe_%ld"' "$daemon_main"
! grep -Fq '"%s.probe-%ld"' "$daemon_main"
