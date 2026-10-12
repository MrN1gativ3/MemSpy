#!/bin/sh
set -eu

pin_dir=${1:-/sys/fs/bpf/memspy}

if [ "$pin_dir" != /sys/fs/bpf/memspy ]; then
    echo "MemSpy cleanup: refusing path outside /sys/fs/bpf/memspy" >&2
    exit 2
fi
if [ -L "$pin_dir" ]; then
    echo "MemSpy cleanup: refusing symbolic-link pin directory" >&2
    exit 2
fi
if [ ! -d "$pin_dir" ]; then
    exit 0
fi

enabled_map=$pin_dir/response_enabled
if [ -e "$enabled_map" ]; then
    command -v bpftool >/dev/null 2>&1 || {
        echo "MemSpy cleanup: bpftool is required to disable response mode" >&2
        exit 2
    }
    bpftool map update pinned "$enabled_map" \
        key hex 00 00 00 00 value hex 00 00 00 00
fi

for name in \
    enter_execve enter_execveat block_memfd_exec \
    response_enabled launcher_allowlist pending_exec enforce_events \
    enforce_counters enforce_scratch; do
    rm -f -- "$pin_dir/$name" "$pin_dir/$name.new"
done
rmdir -- "$pin_dir" 2>/dev/null || true
