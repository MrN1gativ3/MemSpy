#!/bin/sh
set -eu

meson_file=$1
store_source=$2
enforce_source=$3
enforcer_source=$4
daemon_main=$5

test "$(sed -n '1p' "$store_source")" = '#define _POSIX_C_SOURCE 200809L'
grep -Fq "input: ['src/bpf/memspy.bpf.c', vmlinux_header]" "$meson_file"
grep -Fq 'bpf_perf_event_output(ctx, &enforce_events' "$enforce_source"
! grep -Fq 'bpf_perf_event_output((void *)bprm, &enforce_events' "$enforce_source"
grep -Fq 'int BPF_PROG(block_suspicious_exec' "$enforce_source"
grep -Fq 'int BPF_PROG(block_process_vm_write' "$enforce_source"
grep -Fq 'int BPF_PROG(block_ptrace_access' "$enforce_source"
grep -Fq 'int BPF_PROG(block_ptrace_traceme' "$enforce_source"
grep -Fq 'int BPF_PROG(block_proc_mem_write' "$enforce_source"
grep -Fq 'staged ? "_new" : ""' "$enforcer_source"
! grep -Fq '".new"' "$enforcer_source"
grep -Fq '"%s_probe_%ld"' "$daemon_main"
! grep -Fq '"%s.probe-%ld"' "$daemon_main"
