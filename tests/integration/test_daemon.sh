#!/bin/sh
set -eu

daemon=$1

"$daemon" --version | grep -qx 'memspyd 0.1.0'
"$daemon" --help | grep -q -- '--database PATH'
if "$daemon" --unknown >/dev/null 2>&1; then
    echo 'unknown option unexpectedly succeeded' >&2
    exit 1
fi
