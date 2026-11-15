#!/bin/sh
# Asks the running control-plane database whether it has loaded the access rules file as it
# stands now. Run INSIDE the db container, as `docker exec -i <db> sh -s -- <rules file>` with
# this file on standard input, by tasks/_hba.yml. It changes nothing: it only reads.
#
# Why the server is asked. The stack mounts the rules file's directory, so the container
# sees a delivered file at once, whether or not the server has read it. Comparing the
# container's copy with the delivered one therefore proves only that the container sees the
# file. What the server enforces is what its postmaster loaded at its last reload, and
# pg_hba_file_rules does not show that: it reads the file on disk each time it is queried.
# So three things are read, and all three must hold:
#   1. the server's hba_file setting is the path it was given, so the file is the one the
#      server reads;
#   2. pg_hba_file_rules shows no error, so the file as it stands parses, and a reload of it
#      has put its rules in force rather than kept the old ones; and
#   3. the server's last configuration load (pg_conf_load_time) is later than the later of the
#      file's modification and change times, so a reload came after the last delivery.
# Whole seconds are compared and the load must be strictly later, so a reload in the same
# second as the delivery is refused, not guessed at. That fails closed, and the next apply
# reloads again.
#
# The password is the container's own POSTGRES_PASSWORD, as reload_hba.sh uses. It stays in
# this process and is never printed.
set -eu

file="${1:?server_loaded_hba: give the path of the rules file as the first argument}"
PGPASSWORD="${POSTGRES_PASSWORD:?server_loaded_hba: POSTGRES_PASSWORD is not set in the db container}"
export PGPASSWORD

# psql reads no standard input (it is given --command and </dev/null), because `sh -s`
# is reading this very script from it.
sql() {
    psql --username=postgres --dbname=postgres --no-password --no-psqlrc \
        --set=ON_ERROR_STOP=1 --tuples-only --no-align --command="$1" </dev/null
}

server_file="$(sql "select setting from pg_settings where name = 'hba_file'")"
if [ "$server_file" != "$file" ]; then
    echo "server_loaded_hba: the server reads another file ($server_file) than the one delivered ($file)" >&2
    exit 1
fi

errors="$(sql "select count(*) from pg_hba_file_rules where error is not null")"
if [ "$errors" != "0" ]; then
    echo "server_loaded_hba: the rules file does not parse ($errors rule(s) with an error); the server keeps the rules it last loaded" >&2
    exit 1
fi

loaded="$(sql "select floor(extract(epoch from pg_conf_load_time()))::bigint")"
modified="$(stat -c %Y "$file")"
changed="$(stat -c %Z "$file")"
latest="$modified"
if [ "$changed" -gt "$latest" ]; then
    latest="$changed"
fi

if [ "$loaded" -le "$latest" ]; then
    echo "server_loaded_hba: the server has not reloaded since the rules file last changed (loaded at $loaded, file changed at $latest, in epoch seconds)" >&2
    exit 1
fi

echo "server_loaded_hba: the server reloaded at $loaded, after the rules file last changed at $latest, and the file parses"
