#!/bin/sh
set -eu

binary=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

ASAN_OPTIONS=detect_leaks=0 "$binary" version | grep -q '^memspyctl '

set +e
ASAN_OPTIONS=detect_leaks=0 "$binary" >"$tmp/out" 2>"$tmp/err"
status=$?
set -e
[ "$status" -eq 2 ]
[ ! -s "$tmp/out" ]
grep -q '^Usage:' "$tmp/err"

set +e
ASAN_OPTIONS=detect_leaks=0 "$binary" status >"$tmp/out" 2>"$tmp/err"
status=$?
set -e
case $status in
    0)
        [ -s "$tmp/out" ]
        [ ! -s "$tmp/err" ]
        ;;
    3)
        [ ! -s "$tmp/out" ]
        grep -q '^memspyctl:' "$tmp/err"
        ;;
    *)
        echo "unexpected status exit code: $status" >&2
        exit 1
        ;;
esac
