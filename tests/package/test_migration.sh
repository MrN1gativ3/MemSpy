#!/bin/sh
set -eu

migrator=$1
root=$(mktemp -d)
conflict=$(mktemp -d)
trap 'rm -rf "$root" "$conflict"' EXIT

mkdir -p "$root/etc/filelessd" "$root/var/lib/filelessd"
cat >"$root/etc/filelessd/allowlist.conf" <<'EOF'
# keep this comment
FL-MEMFD-EXEC /opt/runtime
FL-DELETED-EXEC /opt/deleted
EOF
printf 'database' >"$root/var/lib/filelessd/alerts.db"
printf 'wal' >"$root/var/lib/filelessd/alerts.db-wal"
chmod 0600 "$root/var/lib/filelessd/alerts.db" "$root/var/lib/filelessd/alerts.db-wal"

"$migrator" "$root"
test -f "$root/etc/memspy/allowlist.conf"
test -f "$root/var/lib/memspy/alerts.db"
test -f "$root/var/lib/memspy/alerts.db-wal"
grep -q '^MEMFD_EXEC /opt/runtime$' "$root/etc/memspy/allowlist.conf"
grep -q '^DELETED_EXEC /opt/deleted$' "$root/etc/memspy/allowlist.conf"
grep -q '^# keep this comment$' "$root/etc/memspy/allowlist.conf"
test "$(cat "$root/var/lib/memspy/alerts.db")" = database
test "$(stat -c %a "$root/var/lib/memspy/alerts.db")" = 600
test ! -e "$root/etc/filelessd/allowlist.conf"
test ! -e "$root/var/lib/filelessd/alerts.db"
"$migrator" "$root"

mkdir -p "$conflict/etc/filelessd" "$conflict/etc/memspy"
printf 'old\n' >"$conflict/etc/filelessd/allowlist.conf"
printf 'new\n' >"$conflict/etc/memspy/allowlist.conf"
if "$migrator" "$conflict" >/dev/null 2>&1; then
    echo "migration accepted conflicting configuration" >&2
    exit 1
fi
test "$(cat "$conflict/etc/filelessd/allowlist.conf")" = old
test "$(cat "$conflict/etc/memspy/allowlist.conf")" = new
