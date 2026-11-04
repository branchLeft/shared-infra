#!/bin/sh
# Makes the running control-plane database read the pg_hba.conf on disk, and reports
# success only once the server has reloaded it. Run INSIDE the db container, as
# `docker exec -i <db> sh -s` with this file on standard input, by the control_plane
# role and by hetzner/provision/test_control_plane_hba_server.py.
#
# The order of the checks, and why each one is there, is in ../README.md under "How a
# changed pg_hba.conf reaches the running database" (step 3). The password comes from
# the container's POSTGRES_PASSWORD.
set -eu

PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set in the db container}"
export PGPASSWORD

# psql reads no standard input (it is given --command and </dev/null), because `sh -s`
# is reading this very script from it.
sql() {
    psql --username=postgres --dbname=postgres --no-password --no-psqlrc \
        --set=ON_ERROR_STOP=1 --tuples-only --no-align --command="$1" </dev/null
}

rules_with_errors() {
    sql "select count(*) from pg_hba_file_rules where error is not null"
}

load_time() {
    sql "select extract(epoch from pg_conf_load_time())"
}

if [ "$(rules_with_errors)" != "0" ]; then
    echo "reload_hba: the pg_hba.conf on disk does not parse; the server keeps the rules it holds" >&2
    sql "select line_number, error from pg_hba_file_rules where error is not null" >&2
    exit 1
fi

before="$(load_time)"
sql "select pg_reload_conf()" >/dev/null

tries=0
while [ "$(load_time)" = "$before" ]; do
    tries=$((tries + 1))
    if [ "$tries" -ge 20 ]; then
        echo "reload_hba: the server did not report a configuration reload within 10 seconds" >&2
        exit 1
    fi
    sleep 0.5
done

if [ "$(rules_with_errors)" != "0" ]; then
    echo "reload_hba: the pg_hba.conf on disk does not parse after the reload" >&2
    exit 1
fi

echo "reload_hba: the server reloaded its configuration and the pg_hba.conf parses"
