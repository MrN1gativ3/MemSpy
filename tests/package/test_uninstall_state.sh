#!/bin/sh
set -eu

cleanup=$1
state=$(mktemp -d)
trap 'rm -rf "$state"' EXIT

for name in alerts.db alerts.db-shm alerts.db-wal response-mode keep-me; do
    printf '%s\n' "$name" >"$state/$name"
done

sh "$cleanup" "$state"

for name in alerts.db alerts.db-shm alerts.db-wal response-mode; do
    test ! -e "$state/$name" || {
        echo "persistent state was not removed: $name" >&2
        exit 1
    }
done
test -f "$state/keep-me"
