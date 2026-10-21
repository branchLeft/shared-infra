#!/usr/bin/env python3
"""A fake mysql client, for the db1_grants test only; NOT a MySQL server.

Installed as /usr/local/bin/mysql in the test container and nowhere else. It records
each call and keeps a small account table, and it refuses any statement it does not
know or any login that is not the test's. The README ("The fake client") says what it
proves and what it does not; the read statements it answers are listed in
fake_mysql_reads.txt, installed beside its state.
"""

import hashlib
import json
import os
import re
import sys

STATE = "/var/lib/fake-mysql/state.json"
CALLS = "/var/lib/fake-mysql/calls.log"
ADMIN = "/var/lib/fake-mysql/admin.sha256"
READS = "/var/lib/fake-mysql/fake_mysql_reads.txt"
SOCKET = "/opt/branchleft/db/run/mysqld/mysqld.sock"
DYNAMIC = {"BACKUP_ADMIN", "CLONE_ADMIN", "SYSTEM_VARIABLES_ADMIN"}
STATIC_ORDER = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "RELOAD", "SHUTDOWN", "PROCESS", "FILE",
    "REFERENCES", "INDEX", "ALTER", "SHOW DATABASES", "SUPER", "CREATE TEMPORARY TABLES", "LOCK TABLES",
    "EXECUTE", "REPLICATION SLAVE", "REPLICATION CLIENT", "CREATE VIEW", "SHOW VIEW", "CREATE ROUTINE",
    "ALTER ROUTINE", "CREATE USER", "EVENT", "TRIGGER",
]  # fmt: skip


class Refused(Exception):
    def __init__(self, text):
        super().__init__(text)
        self.text = text


def account(user, host):
    return f"{user}@{host}"


def load():
    with open(STATE, encoding="utf-8") as handle:
        return json.load(handle)


def save(state):
    with open(STATE, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)


def redact(statement):
    return re.sub(r"(IDENTIFIED BY ')[^']*(')", r"\1***\2", statement)


def split_privileges(text):
    return [part.strip() for part in text.split(",") if part.strip()]


def lookup(state, user, host):
    entry = state["users"].get(account(user, host))
    if entry is None:
        raise Refused(f"ERROR 1396 (HY000): Operation failed for '{user}'@'{host}'")
    return entry


def grant_lines(user, host, entry):
    tail = f"TO `{user}`@`{host}`"
    option = " WITH GRANT OPTION" if entry.get("grant_option") else ""
    static = sorted(
        [p for p in entry.get("static", [])],
        key=lambda p: STATIC_ORDER.index(p) if p in STATIC_ORDER else len(STATIC_ORDER),
    )
    lines = [f"GRANT {', '.join(static) if static else 'USAGE'} ON *.* {tail}{option}"]
    if entry.get("dynamic"):
        lines.append(f"GRANT {', '.join(sorted(entry['dynamic']))} ON *.* {tail}")
    for database in sorted(entry.get("db", {})):
        lines.append(f"GRANT {', '.join(entry['db'][database])} ON `{database}`.* {tail}")
    return lines


def add_privileges(entry, privileges, target):
    if target == "*.*":
        for name in privileges:
            if name == "GRANT OPTION":
                entry["grant_option"] = True
            elif name in DYNAMIC:
                if name not in entry.setdefault("dynamic", []):
                    entry["dynamic"].append(name)
            elif name not in entry.setdefault("static", []):
                entry["static"].append(name)
        return
    database = target[1:-3]
    held = entry.setdefault("db", {}).setdefault(database, [])
    for name in privileges:
        if name not in held:
            held.append(name)


def remove_privileges(entry, privileges, target):
    if target != "*.*":
        raise Refused("ERROR 1064 (42000): the fake revokes global privileges only")
    for name in privileges:
        if name == "GRANT OPTION":
            entry["grant_option"] = False
        elif name in DYNAMIC:
            entry["dynamic"] = [p for p in entry.get("dynamic", []) if p != name]
        else:
            entry["static"] = [p for p in entry.get("static", []) if p != name]


def read_ssl_and_limit(state, match, out):
    entry = state["users"].get(account(match.group(1), match.group(2)))
    if entry is not None:
        out.append(f"{entry.get('ssl_type', '')}\t{entry.get('muc', 0)}")


def read_other_hosts(state, match, out):
    for key in sorted(state["users"]):
        user, host = key.split("@", 1)
        if user == match.group(1) and host != match.group(2):
            out.append(host)


def read_clone_plugin(state, match, out):
    out.extend(state.get("plugins", []))


def read_account_count(state, match, out):
    present = account(match.group(1), match.group(2)) in state["users"]
    if match.group(1) in state.get("race", []):
        present = False
    out.append("1" if present else "0")


# The read statements the fake answers are a table beside its state, one name and one
# pattern per line (fake_mysql_reads.txt); each name is answered by the function here.
READERS = {
    "connection_limit": read_ssl_and_limit,
    "other_host": read_other_hosts,
    "clone_plugin": read_clone_plugin,
    "account_count": read_account_count,
}


def read_patterns():
    with open(READS, encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t", 1) for line in handle if line.strip()]
    if sorted(name for name, _ in rows) != sorted(READERS):
        raise Refused("ERROR 1064 (42000): the fake's table of read statements does not match its readers")
    return [(name, re.compile(pattern)) for name, pattern in rows]


def run_statement(state, statement, out):
    text = re.sub(r"\s+", " ", statement).strip()
    if not text:
        return
    # A test switch: with it on, every statement that changes an account fails, as a
    # server in read-only mode would refuse it, and nothing is changed.
    if state.get("refuse_writes") and re.match(r"(GRANT|REVOKE|CREATE USER|ALTER USER) ", text):
        raise Refused("ERROR 1290 (HY000): The MySQL server is running with the --read-only option")
    for name, pattern in read_patterns():
        match = pattern.fullmatch(text)
        if match:
            READERS[name](state, match, out)
            return
    match = re.fullmatch(r"SHOW GRANTS FOR '([^']*)'@'([^']*)'", text)
    if match:
        entry = state["users"].get(account(match.group(1), match.group(2)))
        if entry is None:
            raise Refused(f"ERROR 1141 (42000): There is no such grant defined for user '{match.group(1)}'")
        out.extend(grant_lines(match.group(1), match.group(2), entry))
        return
    match = re.fullmatch(r"GRANT (.+) ON (\*\.\*|`.+`\.\*) TO '([^']*)'@'([^']*)'", text)
    if match:
        if account(match.group(3), match.group(4)) not in state["users"]:
            raise Refused("ERROR 1410 (42000): You are not allowed to create a user with GRANT")
        entry = lookup(state, match.group(3), match.group(4))
        add_privileges(entry, split_privileges(match.group(1)), match.group(2))
        return
    match = re.fullmatch(r"REVOKE (.+) ON (\*\.\*|`.+`\.\*) FROM '([^']*)'@'([^']*)'", text)
    if match:
        entry = lookup(state, match.group(3), match.group(4))
        remove_privileges(entry, split_privileges(match.group(1)), match.group(2))
        return
    match = re.fullmatch(r"CREATE USER '([^']*)'@'([^']*)' IDENTIFIED BY '([^']*)'( REQUIRE SSL)?", text)
    if match:
        key = account(match.group(1), match.group(2))
        if key in state["users"] and match.group(1) not in state.get("race", []):
            raise Refused(f"ERROR 1396 (HY000): Operation CREATE USER failed for '{match.group(1)}'@'{match.group(2)}'")
        state["users"][key] = {
            "auth": hashlib.sha256(match.group(3).encode()).hexdigest(),
            "ssl_type": "ANY" if match.group(4) else "",
            "muc": 0,
            "static": [],
            "dynamic": [],
            "db": {},
        }
        return
    match = re.fullmatch(r"ALTER USER '([^']*)'@'([^']*)' IDENTIFIED BY '([^']*)'", text)
    if match:
        lookup(state, match.group(1), match.group(2))["auth"] = hashlib.sha256(match.group(3).encode()).hexdigest()
        return
    match = re.fullmatch(r"ALTER USER '([^']*)'@'([^']*)' REQUIRE SSL", text)
    if match:
        lookup(state, match.group(1), match.group(2))["ssl_type"] = "ANY"
        return
    match = re.fullmatch(r"ALTER USER '([^']*)'@'([^']*)' WITH MAX_USER_CONNECTIONS (\d+)", text)
    if match:
        entry = lookup(state, match.group(1), match.group(2))
        # A test switch: with it on, the statement fails, as a server would refuse it.
        if state.get("refuse_connection_limit"):
            raise Refused("ERROR 1227 (42000): Access denied; you need the SYSTEM_USER privilege for this operation")
        # A test switch: with it on, the limit is accepted and not applied, as a
        # server that ignored the statement would, so the role's readback after
        # its changes has a difference to find.
        if not state.get("ignore_connection_limit"):
            entry["muc"] = int(match.group(3))
        return
    match = re.fullmatch(r"CREATE DATABASE IF NOT EXISTS `([^`]*)` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", text)
    if match:
        if match.group(1) not in state.setdefault("databases", []):
            state["databases"].append(match.group(1))
        return
    if text == "FLUSH PRIVILEGES":
        return
    raise Refused(f"ERROR 1064 (42000): the fake does not know this statement: {redact(text)}")


def parse(argv):
    options = {"socket": None, "user": None, "sql": None, "version": False}
    flags = {"-N", "-B", "-r", "--batch", "--raw", "--skip-column-names"}
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--version":
            options["version"] = True
        elif arg in flags:
            pass
        elif arg.startswith("--socket="):
            options["socket"] = arg.split("=", 1)[1]
        elif arg == "--socket":
            index += 1
            options["socket"] = argv[index]
        elif arg.startswith("--user="):
            options["user"] = arg.split("=", 1)[1]
        elif arg in ("--user", "-u"):
            index += 1
            options["user"] = argv[index]
        elif arg in ("-e", "--execute"):
            index += 1
            options["sql"] = argv[index]
        else:
            raise Refused(f"ERROR 2000 (HY000): the fake does not know the option {arg}")
        index += 1
    return options


def main(argv):
    record = {"argv": argv, "via": None, "statements": [], "ok": False}
    try:
        options = parse(argv)
        if options["version"]:
            print("mysql  Ver 8.0.99 for Linux on x86_64 (FAKE FOR THE TEST)")
            record["ok"] = True
            return 0
        with open(ADMIN, encoding="utf-8") as handle:
            expected = handle.read().strip()
        given = hashlib.sha256(os.environ.get("MYSQL_PWD", "").encode()).hexdigest()
        if given != expected or options["socket"] != SOCKET or options["user"] != "root":
            raise Refused("ERROR 1045 (28000): Access denied for user 'root'@'localhost'")
        if options["sql"] is not None:
            record["via"] = "argv"
            sql = options["sql"]
        else:
            record["via"] = "stdin"
            sql = sys.stdin.read()
        state = load()
        out = []
        for statement in sql.split(";"):
            if statement.strip():
                record["statements"].append(redact(re.sub(r"\s+", " ", statement).strip()))
            try:
                run_statement(state, statement, out)
            finally:
                save(state)
        if out:
            print("\n".join(out))
        record["ok"] = True
        return 0
    except Refused as error:
        print(error.text, file=sys.stderr)
        return 1
    finally:
        with open(CALLS, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
