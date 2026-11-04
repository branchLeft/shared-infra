#!/bin/sh
# Make the running control-plane database use the pg_hba.conf it can now see, and
# say so only when it does. Run INSIDE the db container, as `docker exec -i <db> sh -s`
# with this file on standard input, by the control_plane role after the deploy wrapper
# and by hetzner/provision/test_control_plane_hba_server.py (one script, two callers).
#
# The administrator's password is taken from the container's own environment
# (POSTGRES_PASSWORD, set by the stack's compose file), so the role handles no secret
# and no value is in an argument or in the output. The file is mounted as a directory,
# so a replaced file is visible at once; PostgreSQL still reads it only when told to.
#
# Order, and why:
#   1. The file on disk must parse. pg_hba_file_rules reads the file as it is now, one
#      row per line, with `error` set on a line the server cannot parse. A file with an
#      error is refused BEFORE the reload, so the server keeps the rules it holds (it
#      would keep them anyway: PostgreSQL does not replace its rules with a file that
#      fails to parse). The run fails, loudly, with the old rules in force.
#   2. pg_reload_conf() sends the reload. A reload is not a restart: no connection is
#      dropped.
#   3. pg_conf_load_time() must move. The reload is asynchronous, so a script that sent
#      it and went on would report success on a server that had not read the file yet.
#      Bounded: about 10 seconds, then the run fails.
#   4. The file must still parse, read once more after the reload.
#
# psql reads no standard input here (it is given --command and </dev/null), because
# `sh -s` is reading this very script from it.
set -eu

PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set in the db container}"
export PGPASSWORD

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
