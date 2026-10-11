#!/bin/sh
set -eu

root=${1:-}
old_config="$root/etc/filelessd/allowlist.conf"
new_config="$root/etc/memspy/allowlist.conf"
old_state="$root/var/lib/filelessd"
new_state="$root/var/lib/memspy"

fail()
{
    echo "MemSpy migration: $*" >&2
    exit 2
}

for name in alerts.db alerts.db-wal alerts.db-shm; do
    test ! -e "$old_state/$name" || test ! -e "$new_state/$name" ||
        fail "both legacy and MemSpy $name exist; resolve the conflict manually"
done
test ! -e "$old_config" || test ! -e "$new_config" ||
    fail "both legacy and MemSpy allowlists exist; resolve the conflict manually"

config_copied=false
database_moved=false
wal_moved=false
shm_moved=false
complete=false
rollback()
{
    [ "$complete" = true ] && return
    [ "$config_copied" = false ] || rm -f "$new_config"
    [ "$shm_moved" = false ] || mv "$new_state/alerts.db-shm" "$old_state/alerts.db-shm"
    [ "$wal_moved" = false ] || mv "$new_state/alerts.db-wal" "$old_state/alerts.db-wal"
    [ "$database_moved" = false ] || mv "$new_state/alerts.db" "$old_state/alerts.db"
}
trap rollback EXIT HUP INT TERM

if [ -e "$old_config" ]; then
    mkdir -p "$root/etc/memspy"
    temporary=$(mktemp "$root/etc/memspy/.allowlist.XXXXXX")
    cp -p "$old_config" "$temporary"
    sed -i \
        -e 's/^\([[:space:]]*\)FL-MEMFD-EXEC\([[:space:]]\)/\1MEMFD_EXEC\2/' \
        -e 's/^\([[:space:]]*\)FL-DELETED-EXEC\([[:space:]]\)/\1DELETED_EXEC\2/' \
        -e 's/^\([[:space:]]*\)FL-PROCESS-VM-WRITE\([[:space:]]\)/\1PROCESS_VM_WRITE\2/' \
        -e 's/^\([[:space:]]*\)FL-PTRACE-WRITE\([[:space:]]\)/\1PTRACE_WRITE\2/' \
        -e 's/^\([[:space:]]*\)FL-INJECTION-CHAIN\([[:space:]]\)/\1INJECTION_CHAIN\2/' \
        "$temporary"
    mv "$temporary" "$new_config"
    config_copied=true
fi

if [ -e "$old_state/alerts.db" ] || [ -e "$old_state/alerts.db-wal" ] ||
   [ -e "$old_state/alerts.db-shm" ]; then
    mkdir -p "$new_state"
fi
if [ -e "$old_state/alerts.db" ]; then
    mv "$old_state/alerts.db" "$new_state/alerts.db"
    database_moved=true
fi
if [ -e "$old_state/alerts.db-wal" ]; then
    mv "$old_state/alerts.db-wal" "$new_state/alerts.db-wal"
    wal_moved=true
fi
if [ -e "$old_state/alerts.db-shm" ]; then
    mv "$old_state/alerts.db-shm" "$new_state/alerts.db-shm"
    shm_moved=true
fi

for name in alerts.db alerts.db-wal alerts.db-shm; do
    [ ! -e "$new_state/$name" ] || chmod 0600 "$new_state/$name"
done
if [ "$config_copied" = true ]; then
    chmod 0644 "$new_config"
    if [ -z "$root" ]; then
        chown root:root "$new_config"
    fi
    rm "$old_config"
fi
if [ -z "$root" ] && [ -d "$new_state" ]; then
    chown root:root "$new_state" "$new_state"/alerts.db* 2>/dev/null || true
fi

complete=true
trap - EXIT HUP INT TERM
rmdir "$root/etc/filelessd" 2>/dev/null || true
rmdir "$old_state" 2>/dev/null || true
