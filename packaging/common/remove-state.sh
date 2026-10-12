#!/bin/sh
set -eu

state_dir=${1:-/var/lib/memspy}

rm -f -- \
    "$state_dir/alerts.db" \
    "$state_dir/alerts.db-shm" \
    "$state_dir/alerts.db-wal" \
    "$state_dir/response-mode"
rmdir -- "$state_dir" 2>/dev/null || true
