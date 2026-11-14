#!/usr/bin/python3
"""A stand-in for the docker command, for the role's container test only.

It records every call as one JSON line, with the state of each file the call mounts
at the moment of the call, and it answers the way the applications image's programs
do: the lines the real ones print, read from the files they are told about. The mode
file picks a behaviour: ok, fail, leak, drift, no-flag, no-network, stale-hba, not-reloaded or no-db. It never
starts a container and never opens a network connection.
"""

import json
import os
import sys
from pathlib import Path

STATE = Path("/var/tmp/fake-docker")  # noqa: S108 - the test container's own scratch directory
LOG = STATE / "calls.jsonl"
MODE = STATE / "mode"
# The file the stack delivered, which the stand-in database "holds" as its access rules.
DELIVERED_HBA = Path("/opt/branchleft/control-plane/postgres/pg_hba.conf")
MIGRATE_LINES = [
    "pre-check passed: no difference from the manifest",
    "applied migration 0003_versioned_documents",
    "post-check passed: the server matches the manifest",
    "portal database migrated",
]
VALUE_FLAGS = frozenset(
    {
        "--label",
        "--network",
        "--user",
        "--memory",
        "--cap-drop",
        "--security-opt",
        "-w",
        "--add-host",
    }
)
PROVISION_LINES = [
    "pre-check passed: no difference from the manifest",
    "created role portal_owner",
    "post-check passed: the server matches the manifest",
    "boundary verified",
    "portal database provisioned",
]


def mode() -> str:
    """Return the behaviour the scenario asked for, ok when it asked for none."""
    try:
        return MODE.read_text(encoding="utf-8").strip() or "ok"
    except OSError:
        return "ok"


def snapshot(path: str) -> dict[str, object]:
    """Describe a mounted host path as it is when the call is made."""
    try:
        info = os.lstat(path)
    except OSError:
        return {"exists": False}
    return {
        "exists": True,
        "mode": f"{info.st_mode & 0o7777:04o}",
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


def record(argv: list[str], mounts: dict[str, str]) -> None:
    """Append the call to the log."""
    STATE.mkdir(parents=True, exist_ok=True)
    entry = {
        "argv": argv,
        "mounts": {host: snapshot(host) for host in mounts.values()},
        "config": {
            host: (Path(host) / "config.json").read_text(encoding="utf-8")
            for host in mounts.values()
            if (Path(host) / "config.json").is_file()
        },
    }
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def parse_run(args: list[str]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Split a run call into container paths to host paths, the environment and the command."""
    mounts: dict[str, str] = {}
    env: dict[str, str] = {}
    index = 0
    while index < len(args):
        item = args[index]
        if "@sha256:" in item:
            return mounts, env, args[index + 1 :]
        if item == "-v":
            host, container = args[index + 1].split(":")[:2]
            mounts[container] = host
            index += 1
        elif item == "-e":
            name, _, value = args[index + 1].partition("=")
            env[name] = value
            index += 1
        elif item in VALUE_FLAGS:
            index += 1
        index += 1
    return mounts, env, []


def read_input(mounts: dict[str, str], env: dict[str, str], name: str) -> str | None:
    """Read the file an environment variable names, through the mounts, as the program does."""
    container = env.get(name)
    host = mounts.get(container or "")
    if host is None:
        return None
    try:
        return Path(host).read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        return None


def run_program(command: list[str], mounts: dict[str, str], env: dict[str, str]) -> int:
    """Answer the programs of the applications image."""
    behaviour = mode()
    if command[:2] == ["node", "-e"]:
        print("false" if behaviour == "no-flag" else "true")
        return 0
    provisioning = command[:2] == ["node", "dist/provision/provisionMain.js"]
    if provisioning:
        migrating = command[2:] == ["--migrate-only"]
        # As the real program does: --migrate-only connects as the migrator and reads its URL
        # alone, and the full provision reads the administrator's URL and the four passwords.
        # The administrator's URL is never read by a migrate, whatever it was given.
        required = (
            ("PORTAL_MIGRATOR_URL_FILE",)
            if migrating
            else ("PORTAL_ADMIN_URL_FILE", "PORTAL_MIGRATOR_PASSWORD_FILE")
        )
        for name in required:
            if read_input(mounts, env, name) is None:
                print(f"provision failed: {name}: cannot read the file", file=sys.stderr)
                return 1
        lines = MIGRATE_LINES if migrating else PROVISION_LINES
        if behaviour == "fail":
            print("pre-check passed: no difference from the manifest")
            print("provision failed: refused: 1 difference(s) from the manifest", file=sys.stderr)
            return 1
        if behaviour == "leak":
            secret = read_input(mounts, env, "PORTAL_TENANT_PASSWORD_FILE")
            secret = secret or read_input(mounts, env, "PORTAL_MIGRATOR_URL_FILE")
            print(f"debug: connecting with {secret}")
            print("provision failed: refused: 1 difference(s) from the manifest", file=sys.stderr)
            return 1
        print("\n".join(lines))
        return 0
    if command[:2] == ["node", "dist/cli.js"]:
        if behaviour == "fail":
            print("reconcile failed: the service answered 404", file=sys.stderr)
            return 1
        work = mounts.get("/work")
        if work is None or not (Path(work) / "config.json").is_file():
            print("reconcile failed: no configuration", file=sys.stderr)
            return 1
        (Path(work) / "outputs.json").write_text('{"ids":"EXAMPLE_ID"}\n', encoding="utf-8")
        print("drift: project settings differ" if behaviour == "drift" else "created organisation")
        return 0
    print(f"fake docker: unknown program {command}", file=sys.stderr)
    return 2


def run_server_check(args: list[str]) -> int:
    """Answer the exec that asks the server what it has loaded: `-i <db> sh -s -- <rules file>`.

    The script arrives on standard input, as it does to the real container, and is read to
    the end. It must be the role's check, which names the load time it compares. The
    not-reloaded mode answers as a server that has not reloaded since the file was delivered,
    which the container's own copy of the file cannot show.
    """
    script = sys.stdin.read()
    if args[1:] != ["sh", "-s", "--", "/etc/postgresql-hba/pg_hba.conf"]:
        print(f"fake docker: unknown exec {args}", file=sys.stderr)
        return 2
    if "pg_conf_load_time" not in script:
        print("fake docker: the server check was not given on standard input", file=sys.stderr)
        return 2
    if mode() == "not-reloaded":
        print(
            "server_loaded_hba: the server has not reloaded since the rules file last changed",
            file=sys.stderr,
        )
        return 1
    print("server_loaded_hba: the server reloaded after the rules file last changed, and the file parses")
    return 0


def run_exec(args: list[str]) -> int:
    """Answer the two execs the role makes: cat the access rules the running database holds, and ask it.

    The database is stood in for by the file the stack delivered, so the rules it "holds"
    are that file's content exactly, with no line break added. The stale-hba mode serves
    that content without the migrator login's rule, as a container that was started
    before the file was replaced would, and the no-db mode answers as a missing container.
    """
    asking = args[:1] == ["-i"]
    if asking:
        args = args[1:]
    if mode() == "no-db":
        print(f"Error response from daemon: No such container: {args[0]}", file=sys.stderr)
        return 1
    if asking:
        return run_server_check(args)
    if args[1:] != ["cat", "/etc/postgresql-hba/pg_hba.conf"]:
        print(f"fake docker: unknown exec {args}", file=sys.stderr)
        return 2
    try:
        text = DELIVERED_HBA.read_text(encoding="utf-8")
    except OSError:
        print("cat: /etc/postgresql-hba/pg_hba.conf: No such file or directory", file=sys.stderr)
        return 1
    if mode() == "stale-hba":
        text = "".join(line for line in text.splitlines(keepends=True) if "portal_migrator_login" not in line)
    sys.stdout.write(text)
    return 0


def main() -> int:
    """Handle one docker call."""
    argv = sys.argv[1:]
    if argv[:1] == ["pull"]:
        record(argv, {})
        print("Digest: sha256:EXAMPLE")
        return 0
    if argv[:2] == ["network", "inspect"]:
        record(argv, {})
        if mode() == "no-network":
            print("Error: No such network", file=sys.stderr)
            return 1
        print("[]")
        return 0
    if argv[:1] == ["exec"]:
        record(argv, {})
        return run_exec(argv[1:])
    if argv[:1] == ["run"]:
        mounts, env, command = parse_run(argv[1:])
        record(argv, mounts)
        return run_program(command, mounts, env)
    record(argv, {})
    print(f"fake docker: unknown call {argv}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
