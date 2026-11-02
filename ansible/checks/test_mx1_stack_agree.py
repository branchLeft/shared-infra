"""The mx1_stack role, the hand scripts it replaces and the two compose files agree.

The role places the mail host's resolver drop-in, its DNSBL cron entry, the shim's environment
file and the two Compose projects. Each of those is also written by a hand script under
mail/provision until the role is applied, so every copy stays and this test holds the two in step
(the cross-role references are not allowed, ANS-12, but a role may not drift from the script that
it replaces either). It also holds the audit: every host file a container reads, in either
compose file, has a row in mx1_stack_container_inputs that says what a change to it must do, and
every row names something a compose file holds. A compose file that gains a bind mount, an
env_file or a ${VAR} without a row fails here, so a new input cannot be added without deciding it
(the Caddyfile that never restarted Caddy was exactly such an input).
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import NoReturn, cast

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
ROLE = "mx1_stack"
PROVISION = ROOT / "mail" / "provision"
# The directories of a role that run on a host (the scenarios and the README name paths to test
# them or explain them, which writes nothing).
HOST_DIRS = ("defaults", "vars", "tasks", "handlers", "templates", "files", "meta")
HOST_SUFFIXES = (".yml", ".yaml", ".j2", ".service", ".sh", ".py", ".conf", ".timer")
# The paths no other role may name: the role is their only owner. The shared stamp directory and
# /etc/resolv.conf are left out, because other roles legitimately read or share them.
OWNED = (
    "mx1_stack_stalwart_compose_file",
    "mx1_stack_stalwart_env_file",
    "mx1_stack_shim_compose_file",
    "mx1_stack_shim_caddyfile",
    "mx1_stack_shim_env_file",
    "mx1_stack_shim_throttle_file",
    "mx1_stack_stalwart_stamp",
    "mx1_stack_shim_stamp",
    "mx1_stack_resolver_stamp",
    "mx1_stack_resolver_dropin",
    "mx1_stack_dnsbl_cron",
)
# project name -> (name of the variable holding its compose file, its directory variable)
PROJECTS = {
    "stalwart": ("mx1_stack_stalwart_compose_file", "mx1_stack_stalwart_dir"),
    "mailgun-shim": ("mx1_stack_shim_compose_file", "mx1_stack_shim_dir"),
}
COMPOSE_FILES = {"stalwart": "docker-compose.yml", "mailgun-shim": "shim-compose.yml"}
INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")
BIND_KINDS = ("bind_file", "bind_dir")


class Mx1AgreeError(Exception):
    """A file the check reads is missing, unparseable or not in the shape it needs."""


def refuse(message: str) -> NoReturn:
    """Stop the check with a message.

    Raises:
        Mx1AgreeError: always, carrying the message.
    """
    raise Mx1AgreeError(message)


def yaml_of(path: Path) -> object:
    """Return the parsed YAML of a file.

    Raises:
        Mx1AgreeError: when the file cannot be read as YAML.
    """
    document, problem = load_yaml(path)
    if problem is not None:
        raise Mx1AgreeError(problem)
    return document


def mapping_of(value: object) -> dict[str, object]:
    """Return a YAML mapping.

    Raises:
        Mx1AgreeError: when the value is not a mapping.
    """
    if not isinstance(value, dict):
        refuse("expected a YAML mapping")
    return cast("dict[str, object]", value)


def list_of(value: object) -> list[object]:
    """Return a YAML list.

    Raises:
        Mx1AgreeError: when the value is not a list.
    """
    if not isinstance(value, list):
        refuse("expected a YAML list")
    return cast("list[object]", value)


def load_module(name: str, path: Path) -> types.ModuleType:
    """Import a Python file by its path, standing in for Ansible's module base when absent.

    Raises:
        Mx1AgreeError: when the file cannot be imported.
    """
    if "ansible.module_utils.basic" not in sys.modules:
        try:
            __import__("ansible.module_utils.basic")
        except ImportError:
            for part in ("ansible", "ansible.module_utils", "ansible.module_utils.basic"):
                sys.modules.setdefault(part, types.ModuleType(part))
            sys.modules["ansible.module_utils.basic"].__dict__["AnsibleModule"] = object
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        refuse(f"{path.name} cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def host_text(role: Path) -> str:
    """Return the text of every file of a role that runs on a host, in a fixed order."""
    parts: list[str] = []
    for name in HOST_DIRS:
        base = role / name
        if base.is_dir():
            parts.extend(
                path.read_text(encoding="utf-8")
                for path in sorted(base.rglob("*"))
                if path.is_file() and path.suffix in HOST_SUFFIXES and not path.is_symlink()
            )
    return "\n".join(parts)


def heredoc(script: str, opener: str) -> str:
    """Return the body of the heredoc that a script opens with the given line.

    Raises:
        Mx1AgreeError: when the script has no such heredoc.
    """
    found = re.search(rf"^{re.escape(opener)}\n(.*?)^EOF$", script, re.DOTALL | re.MULTILINE)
    if found is None:
        refuse(f"no heredoc opened by {opener!r}")
    return found.group(1)


def script_assignment(script: str, name: str) -> str:
    """Return the value of a plain NAME=value line of a shell script.

    Raises:
        Mx1AgreeError: when the script has no such line.
    """
    found = re.search(rf"^{name}=(\S+)$", script, re.MULTILINE)
    if found is None:
        refuse(f"no assignment of {name}")
    return found.group(1)


def without_comments(text: str) -> list[str]:
    """Return the lines of a text that are not comments or blank."""
    return [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def audit_inputs(
    composes: dict[str, tuple[object, str]],
    rows: list[dict[str, str]],
    project_dirs: dict[str, str],
    compose_paths: dict[str, str],
) -> list[str]:
    """Return one line for each way the compose files and the audit table disagree.

    ``composes`` maps a project to its parsed compose file and its text.
    """
    needed: set[tuple[str, str, str, str]] = set()
    found: list[str] = []
    for project, (document, text) in composes.items():
        needed.add((project, "*", compose_paths[project], "compose_file"))
        services = mapping_of(mapping_of(document).get("services"))
        for service, body in services.items():
            spec = mapping_of(body)
            env_files = spec.get("env_file", [])
            for env_file in env_files if isinstance(env_files, list) else [env_files]:
                needed.add((project, service, str(env_file), "create_env"))
            if INTERPOLATION.search(repr(spec)):
                needed.add((project, service, f"{project_dirs[project]}/.env", "create_env"))
            for volume in cast("list[object]", spec.get("volumes", [])):
                source = (
                    str(volume.get("source", ""))
                    if isinstance(volume, dict)
                    else str(volume).split(":", 1)[0]
                )
                if source.startswith(("/", "./", "../", "~")):
                    needed.add((project, service, source, "bind"))
        found.extend(
            f"{project}: {match} is interpolated outside any service"
            for match in sorted(set(INTERPOLATION.findall(text)))
            if f"${{{match}" not in repr(services)
        )
    held = {
        (
            row["project"],
            row["service"],
            row["path"],
            "bind" if row["kind"] in BIND_KINDS else row["kind"],
        )
        for row in rows
    }
    found.extend(
        f"{project} {service}: {path} ({kind}) is an input of a container with no row in "
        "mx1_stack_container_inputs"
        for project, service, path, kind in sorted(needed - held)
    )
    found.extend(
        f"mx1_stack_container_inputs names {path} ({kind}) of {project} {service}, "
        "which no compose file holds"
        for project, service, path, kind in sorted(held - needed)
    )
    return found


def row_mismatches(
    composes: dict[str, tuple[object, str]], rows: list[dict[str, str]]
) -> list[str]:
    """Return one line for each bind row whose container path or container name is wrong."""
    found: list[str] = []
    for row in rows:
        if row["kind"] not in BIND_KINDS:
            continue
        document = composes[row["project"]][0]
        services = mapping_of(mapping_of(document).get("services"))
        spec = mapping_of(services.get(row["service"]))
        targets = {
            str(volume.get("target", "")) if isinstance(volume, dict) else str(volume).split(":")[1]
            for volume in cast("list[object]", spec.get("volumes", []))
            if (
                str(volume.get("source", ""))
                if isinstance(volume, dict)
                else str(volume).split(":")[0]
            )
            == row["path"]
        }
        if row["container_path"] not in targets:
            found.append(
                f"{row['name']}: container_path {row['container_path']!r} is not where "
                f"{row['path']} is mounted ({sorted(targets)})"
            )
        name = str(spec.get("container_name", row["service"]))
        if row["container"] != name:
            found.append(
                f"{row['name']}: container {row['container']!r} but the compose file names {name!r}"
            )
    return found


# The module keys that create a host path as a directory, and that write one as a file.
DIRECTORY_MAKERS = ("ansible.builtin.file", "file")
FILE_WRITERS = ("ansible.builtin.copy", "ansible.builtin.template", "copy", "template")


def placed_kinds(role: Path, role_vars: dict[str, object]) -> dict[str, str]:
    """Return each host path the role's tasks create or write, as "dir" or "file".

    Compose says nothing about whether a bind mount is a file or a directory, so the row's kind is
    the only statement of it. The role's own tasks are the other statement: a path a task makes
    with state: directory is a directory, and a path a copy or template writes is a file. A path no
    task names is left out, and the audit makes no claim about it.
    """
    kinds: dict[str, str] = {}

    def resolved(value: object) -> str:
        match = re.fullmatch(r"\{\{\s*(\w+)\s*\}\}", str(value).strip())
        if match is not None and match.group(1) in role_vars:
            return str(role_vars[match.group(1)])
        return str(value).strip()

    def walk(tasks: object) -> None:
        if not isinstance(tasks, list):
            return
        for task in cast("list[object]", tasks):
            if not isinstance(task, dict):
                continue
            body = cast("dict[str, object]", task)
            for block in ("block", "rescue", "always"):
                walk(body.get(block))
            for module, args in body.items():
                if not isinstance(args, dict):
                    continue
                options = cast("dict[str, object]", args)
                if module in DIRECTORY_MAKERS and options.get("state") == "directory":
                    kinds[resolved(options.get("path", ""))] = "dir"
                elif module in FILE_WRITERS:
                    kinds[resolved(options.get("dest", ""))] = "file"

    for task_file in sorted((role / "tasks").rglob("*.yml")):
        walk(yaml_of(task_file))
    return kinds


def kind_mismatches(rows: list[dict[str, str]], placed: dict[str, str]) -> list[str]:
    """Return one line for each bind row whose kind names the wrong type of host path.

    A bind_file must be a file the role writes and a bind_dir a directory the role makes. A single
    file mounted under a bind_dir label is therefore red, as is a directory under a bind_file label.
    """
    found: list[str] = []
    for row in rows:
        kind = placed.get(row["path"])
        if row["kind"] == "bind_file" and kind == "dir":
            found.append(
                f"{row['name']}: labelled bind_file, but the role makes {row['path']} a directory"
            )
        if row["kind"] == "bind_dir" and kind == "file":
            found.append(
                f"{row['name']}: labelled bind_dir, but the role writes {row['path']} as a file"
            )
    return found


def facts(root: Path = ROOT) -> dict[str, object]:
    """Read every fact the role, the hand scripts and the compose files state."""
    role = root / "ansible" / "roles" / ROLE
    provision = root / "mail" / "provision"
    role_vars = mapping_of(yaml_of(role / "vars" / "main.yml"))
    resolver = (provision / "65-install-local-resolver.sh").read_text(encoding="utf-8")
    cron = (provision / "70-schedule-dnsbl-check.sh").read_text(encoding="utf-8")
    packages = re.search(r"^for pkg in ([a-z0-9\s.-]+); do$", resolver, re.MULTILINE)
    if packages is None:
        refuse("65-install-local-resolver.sh has no package loop")
    composes: dict[str, tuple[object, str]] = {}
    for project, name in COMPOSE_FILES.items():
        text = (provision / name).read_text(encoding="utf-8")
        composes[project] = (yaml_of(provision / name), text)
    others = {
        path.name: host_text(path)
        for path in sorted((root / "ansible" / "roles").iterdir())
        if path.is_dir() and path.name != ROLE
    }
    return {
        "vars": role_vars,
        "role_dropin": (role / "files" / "10-branchleft-local-recursive.conf").read_text(
            encoding="utf-8"
        ),
        "script_dropin": heredoc(resolver, "cat > \"$TMP\" <<'EOF'"),
        "script_conf": script_assignment(resolver, "CONF"),
        "script_packages": packages.group(1).split(),
        "script_cron": heredoc(cron, 'cat > "$TMP" <<EOF'),
        "script_cron_path": script_assignment(cron, "DROPIN"),
        "shim_env_role": load_module("mx1_envfile", role / "library" / "mx1_stack_envfile.py"),
        "shim_env_script": load_module("render_shim_env", provision / "render_shim_env.py"),
        "composes": composes,
        "rows": [
            {key: str(value) for key, value in mapping_of(row).items()}
            for row in list_of(role_vars["mx1_stack_container_inputs"])
        ],
        "others": others,
        "placed": placed_kinds(role, role_vars),
    }


def disagreements(f: dict[str, object]) -> list[str]:
    """Return one line for each way the role and the hand scripts disagree."""
    found: list[str] = []
    role_vars = cast("dict[str, object]", f["vars"])
    if f["role_dropin"] != f["script_dropin"]:
        found.append(
            "the role's resolver drop-in is not the heredoc of 65-install-local-resolver.sh"
        )
    if str(role_vars["mx1_stack_resolver_dropin"]) != f["script_conf"]:
        found.append("the resolver drop-in path is not CONF of 65-install-local-resolver.sh")
    if sorted(cast("list[str]", role_vars["mx1_stack_resolver_packages"])) != sorted(
        cast("list[str]", f["script_packages"])
    ):
        found.append(
            "the resolver packages are not the package loop of 65-install-local-resolver.sh"
        )
    script_cron = str(f["script_cron"]).replace(
        "$SCRIPT_DIR", str(role_vars["mx1_stack_dnsbl_dir"])
    )
    if without_comments(script_cron) != without_comments(
        str(role_vars["mx1_stack_dnsbl_cron_text"])
    ):
        found.append("the DNSBL cron line is not the line 70-schedule-dnsbl-check.sh writes")
    if str(role_vars["mx1_stack_dnsbl_cron"]) != f["script_cron_path"]:
        found.append("the DNSBL cron path is not DROPIN of 70-schedule-dnsbl-check.sh")
    token = "T" * 43
    role_env = cast("types.ModuleType", f["shim_env_role"]).render_shim_env(token)
    script_env = cast("types.ModuleType", f["shim_env_script"]).render_env_file(token)
    if role_env != script_env:
        found.append("the shim environment file is not what render_shim_env.py renders")
    others = cast("dict[str, str]", f["others"])
    for role, text in others.items():
        found.extend(
            f"{role} names {role_vars[key]!r}, which {ROLE} owns ({key})"
            for key in OWNED
            if str(role_vars[key]) in text
        )
    composes = cast("dict[str, tuple[object, str]]", f["composes"])
    rows = cast("list[dict[str, str]]", f["rows"])
    project_dirs = {project: str(role_vars[dir_var]) for project, (_, dir_var) in PROJECTS.items()}
    compose_paths = {project: str(role_vars[var]) for project, (var, _) in PROJECTS.items()}
    found.extend(audit_inputs(composes, rows, project_dirs, compose_paths))
    found.extend(row_mismatches(composes, rows))
    found.extend(kind_mismatches(rows, cast("dict[str, str]", f["placed"])))
    return found


class Mx1AgreeTest(unittest.TestCase):
    def test_the_real_tree_agrees(self) -> None:
        self.assertEqual([], disagreements(facts()))

    def test_a_single_file_labelled_bind_dir_is_named(self) -> None:
        base = facts()
        rows = [
            dict(row, kind="bind_dir") if row["name"] == "shim_caddyfile" else row
            for row in cast("list[dict[str, str]]", base["rows"])
        ]
        found = disagreements(dict(base, rows=rows))
        self.assertTrue(
            any("shim_caddyfile" in line and "labelled bind_dir" in line for line in found), found
        )

    def test_a_directory_labelled_bind_file_is_named(self) -> None:
        base = facts()
        rows = [
            dict(row, kind="bind_file") if row["name"] == "shim_data" else row
            for row in cast("list[dict[str, str]]", base["rows"])
        ]
        found = disagreements(dict(base, rows=rows))
        self.assertTrue(
            any("shim_data" in line and "labelled bind_file" in line for line in found), found
        )

    def test_a_drifted_dropin_is_named(self) -> None:
        found = disagreements(dict(facts(), role_dropin="server:\n    port: 5353\n"))
        self.assertTrue(any("drop-in" in line for line in found), found)

    def test_a_drifted_package_list_is_named(self) -> None:
        found = disagreements(dict(facts(), script_packages=["unbound", "dig"]))
        self.assertTrue(any("packages" in line for line in found), found)

    def test_a_drifted_cron_line_is_named(self) -> None:
        found = disagreements(
            dict(facts(), script_cron="5 * * * * root python3 $SCRIPT_DIR/x.py\n")
        )
        self.assertTrue(any("cron line" in line for line in found), found)

    def test_a_cron_comment_is_not_a_disagreement(self) -> None:
        base = facts()
        text = "# another comment\n" + str(base["script_cron"])
        self.assertEqual([], disagreements(dict(base, script_cron=text)))

    def test_a_drifted_shim_env_is_named(self) -> None:
        class Drifted:
            @staticmethod
            def render_env_file(token: str) -> str:
                return f"PORT=9090\nSHIM_DRAIN_TOKEN={token}\n"

        found = disagreements(dict(facts(), shim_env_script=Drifted))
        self.assertTrue(any("environment file" in line for line in found), found)

    def test_a_path_named_by_a_second_role_is_named(self) -> None:
        base = facts()
        role_vars = cast("dict[str, object]", base["vars"])
        for key in OWNED:
            with self.subTest(key=key):
                others = dict(
                    cast("dict[str, str]", base["others"]),
                    host_baseline=f"dest: {role_vars[key]}\n",
                )
                found = disagreements(dict(base, others=others))
                self.assertTrue(
                    any(key in line and "host_baseline" in line for line in found), found
                )

    def test_a_symlinked_file_is_not_the_roles_own_statement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = Path(tmp)
            (role / "files").mkdir()
            (role / "target.yml").write_text("dest: /etc/mailgun-shim/env\n")
            (role / "files" / "link.yml").symlink_to(role / "target.yml")
            self.assertNotIn("/etc/mailgun-shim/env", host_text(role))


def fixture_compose(volumes: list[object], extra: str = "") -> tuple[object, str]:
    """Return a parsed compose file with one service, and its text."""
    lines = ["services:", "  web:", "    image: example@sha256:" + "0" * 64]
    if extra:
        lines.append(f"    {extra}")
    lines.append("    volumes:")
    lines.extend(f"      - {volume}" for volume in volumes)
    text = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "compose.yml"
        path.write_text(text, encoding="utf-8")
        return yaml_of(path), text


class AuditTest(unittest.TestCase):
    PROJECT_DIRS = {"p": "/opt/p"}
    PATHS = {"p": "/opt/p/compose.yml"}
    COMPOSE_ROW = {
        "name": "compose",
        "project": "p",
        "service": "*",
        "container": "",
        "path": "/opt/p/compose.yml",
        "kind": "compose_file",
        "container_path": "",
    }

    def audit(self, compose: tuple[object, str], rows: list[dict[str, str]]) -> list[str]:
        return audit_inputs(
            {"p": compose}, [self.COMPOSE_ROW, *rows], self.PROJECT_DIRS, self.PATHS
        )

    def test_a_named_volume_needs_no_row(self) -> None:
        self.assertEqual([], self.audit(fixture_compose(["data:/var/lib/data"]), []))

    def test_a_bind_mount_without_a_row_is_red(self) -> None:
        found = self.audit(fixture_compose(["/etc/p/Caddyfile:/etc/caddy/Caddyfile:ro"]), [])
        self.assertTrue(
            any("/etc/p/Caddyfile" in line and "no row" in line for line in found), found
        )

    def test_a_bind_mount_with_a_row_is_green(self) -> None:
        row = {
            "name": "caddyfile",
            "project": "p",
            "service": "web",
            "container": "web",
            "path": "/etc/p/Caddyfile",
            "kind": "bind_file",
            "container_path": "/etc/caddy/Caddyfile",
        }
        compose = fixture_compose(["/etc/p/Caddyfile:/etc/caddy/Caddyfile:ro"])
        self.assertEqual([], self.audit(compose, [row]))
        self.assertEqual([], row_mismatches({"p": compose}, [row]))

    def test_a_row_with_the_wrong_container_path_is_red(self) -> None:
        row = {
            "name": "caddyfile",
            "project": "p",
            "service": "web",
            "container": "web",
            "path": "/etc/p/Caddyfile",
            "kind": "bind_file",
            "container_path": "/somewhere/else",
        }
        compose = fixture_compose(["/etc/p/Caddyfile:/etc/caddy/Caddyfile:ro"])
        found = row_mismatches({"p": compose}, [row])
        self.assertTrue(any("container_path" in line for line in found), found)

    def test_an_env_file_without_a_row_is_red(self) -> None:
        compose = fixture_compose(["data:/d"], "env_file: /etc/p/env")
        found = self.audit(compose, [])
        self.assertTrue(any("/etc/p/env" in line and "no row" in line for line in found), found)

    def test_an_interpolated_variable_without_a_row_is_red(self) -> None:
        compose = fixture_compose(["data:/d"], "environment: { KEY: '${SECRET:?set it}' }")
        found = self.audit(compose, [])
        self.assertTrue(any("/opt/p/.env" in line and "no row" in line for line in found), found)

    def test_a_row_for_nothing_is_red(self) -> None:
        row = {
            "name": "ghost",
            "project": "p",
            "service": "web",
            "container": "web",
            "path": "/etc/p/gone",
            "kind": "bind_file",
            "container_path": "/gone",
        }
        found = self.audit(fixture_compose(["data:/d"]), [row])
        self.assertTrue(
            any("/etc/p/gone" in line and "no compose file holds" in line for line in found), found
        )

    def test_a_compose_file_without_its_row_is_red(self) -> None:
        found = audit_inputs({"p": fixture_compose(["data:/d"])}, [], self.PROJECT_DIRS, self.PATHS)
        self.assertTrue(any("compose.yml" in line for line in found), found)

    def test_the_audit_table_holds_the_six_known_inputs(self) -> None:
        base = facts()
        rows = cast("list[dict[str, str]]", base["rows"])
        kinds = sorted(row["name"] for row in rows)
        self.assertEqual(
            [
                "shim_caddyfile",
                "shim_compose",
                "shim_data",
                "shim_env",
                "stalwart_compose",
                "stalwart_env",
            ],
            kinds,
        )


if __name__ == "__main__":
    unittest.main()
