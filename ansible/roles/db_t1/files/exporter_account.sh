#!/bin/sh
# The program of the exporter-account service of the dbt1 stack (see the role README, "The
# exporter's account"). It runs inside the database image, as the exporter's own user, with the
# exporter's credentials file mounted read-only and the database's socket directory shared.
#
# serve   wait for the database, make the account the credentials file names, then idle so the
#         container stays up and its health check can read the account back. The default.
# apply   the same, without the idle. Used by the unit tests.
# check   the container's health check: connect as the exporter with the credentials file alone
#         and read back that its two grants are there. Writes nothing.
#
# The value of the exporter's credential is read from the file and written only to the
# database client's standard input. It is never an argument, never in the environment of a
# program, never printed, and no line of this file is traced. Every message below names the
# rule that failed and never a line of the file.
#
# The account is made with the database's own root credential, which this container gets
# from the same environment the database does. The statements are idempotent and are not
# written to the binary log: a replica must not carry a transaction of its own.

set -eu

cnf=${EXPORTER_ACCOUNT_CNF:-/etc/mysqld-exporter/.my.cnf}
sock=${EXPORTER_ACCOUNT_SOCKET:-/var/run/mysqld/mysqld.sock}
mode=${1:-serve}
account_user=exporter
# How long the database may take to answer, in two-second steps. The container is started
# after the database's health check passes, but Docker also starts it by itself after a
# restart of the daemon, with no such order.
wait_steps=${EXPORTER_ACCOUNT_WAIT_STEPS:-90}

fail() {
    echo "exporter-account: $1" >&2
    exit 1
}

root_client() {
    MYSQL_PWD=${MYSQL_ROOT_PASSWORD:?the root credential is not in the environment} \
        mysql --protocol=socket --socket="$sock" -uroot "$@"
}

if [ "$mode" = check ]; then
    grants=$(mysql --defaults-file="$cnf" --protocol=socket --socket="$sock" -N -B -e 'SHOW GRANTS') ||
        fail "the exporter cannot connect with its credentials file"
    case $grants in
        *'GRANT PROCESS, REPLICATION CLIENT ON *.*'*) ;;
        *) fail "the exporter lacks its global grants" ;;
    esac
    case $grants in
        *'GRANT SELECT ON '?performance_schema?'.*'*) ;;
        *) fail "the exporter lacks its performance_schema grant" ;;
    esac
    exit 0
fi

case $mode in
    serve | apply) ;;
    *) fail "unknown mode" ;;
esac

# The file is checked before the database is touched, so a file that names another account
# or holds a value the statements cannot carry changes nothing.
file_user=$(sed -n 's/^user[[:space:]]*=[[:space:]]*//p' "$cnf")
secret=$(sed -n 's/^password[[:space:]]*=[[:space:]]*//p' "$cnf")
[ "$file_user" = "$account_user" ] || fail "the credentials file must name the user $account_user"
case $secret in
    '' | *[!A-Za-z0-9._~-]*) fail "the credentials file has no value of the allowed alphabet" ;;
esac
[ "${#secret}" -ge 20 ] || fail "the credentials file value is shorter than 20 characters"

steps=0
until root_client -e 'SELECT 1' >/dev/null 2>&1; do
    steps=$((steps + 1))
    [ "$steps" -le "$wait_steps" ] || fail "the database did not answer on its socket"
    sleep 2
done

root_client <<SQL
SET @@SESSION.SQL_LOG_BIN=0;
CREATE USER IF NOT EXISTS '$account_user'@'localhost' IDENTIFIED BY '$secret' WITH MAX_USER_CONNECTIONS 3;
ALTER USER '$account_user'@'localhost' IDENTIFIED BY '$secret' WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT ON *.* TO '$account_user'@'localhost';
GRANT SELECT ON performance_schema.* TO '$account_user'@'localhost';
SQL

echo "exporter-account: the $account_user account is in place"
[ "$mode" = apply ] || exec sleep infinity
