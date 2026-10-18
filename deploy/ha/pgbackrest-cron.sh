#!/usr/bin/env bash
# Run a pgBackRest backup, but ONLY on the node that is currently the PostgreSQL primary.
# Install on all 3 nodes and call it from cron / a systemd timer on all 3: exactly one of them
# acts, whichever holds the primary role at that moment, so a failover needs no change.
#
#   /etc/cron.d/pgbackrest:
#     30 1 * * 0     postgres  /usr/local/bin/pgbackrest-cron.sh full
#     30 1 * * 1-6   postgres  /usr/local/bin/pgbackrest-cron.sh diff
#
# Usage: pgbackrest-cron.sh full|diff|incr
set -euo pipefail

TYPE="${1:?usage: $0 full|diff|incr}"
STANZA="${PGBACKREST_STANZA:-acmeeh}"
PATRONI_URL="${PATRONI_URL:-https://localhost:8008}"
CA="${PATRONI_CA:-/etc/patroni/tls/ca.pem}"

# Patroni answers 200 on /primary only on the leader.
code=$(curl -s -m 3 --cacert "$CA" -o /dev/null -w '%{http_code}' "$PATRONI_URL/primary" || true)
if [ "$code" != "200" ]; then
  echo "not the primary (HTTP $code): nothing to do"
  exit 0
fi

# `check` verifies that WAL archiving works end to end before relying on it.
pgbackrest --stanza="$STANZA" check
pgbackrest --stanza="$STANZA" --type="$TYPE" backup
pgbackrest --stanza="$STANZA" info
