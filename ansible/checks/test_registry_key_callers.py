"""Hold every task and program that pulls or runs an image to the one registry read key directory.

A private image needs the host's read key, which docker finds through DOCKER_CONFIG. The directory
is one constant, `deploy_verifier_registry_docker_dir` in the deploy_verifier role's vars. A role
may not import another role (ANS-12), and deploy_verifier is applied after some of the roles that
pull on a host and is not in a role's Molecule scenario, so each caller keeps a pinned copy in its
own vars (the way the ci_login copies are kept) and this test holds the copies to the constant:

  * the callers are found by scanning the role and pattern tasks, not named by hand. A caller is
    a task that runs `docker pull`, `docker run`, `docker create`, `docker compose` with
    `up`, `run`, `pull` or `create`, a community.docker module that pulls or starts, or a script
    from the role's files that does one of those;
  * each caller sets `DOCKER_CONFIG` in its `environment` (its own, or its block's) to
    `{{ <role>_registry_docker_config }}`, never to a literal;
  * that variable sits in the role's vars, where no inventory can move it, and equals the constant;
  * no task file holds the path as a literal;
  * every program under hetzner/provision that pulls or runs an image names DOCKER_CONFIG.

Each rule is shown red on a synthetic tree with the fault in it and green once it is put right.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
CONSTANT_FILE = Path("ansible/roles/deploy_verifier/vars/main.yml")
CONSTANT_NAME = "deploy_verifier_registry_docker_dir"
ENV_KEY = "DOCKER_CONFIG"
TREES = ("roles", "patterns")
TASK_DIRECTORIES = ("tasks", "handlers")
PROVISION = Path("hetzner/provision")
# The hand installer is frozen and gets no new caller; nothing in it pulls an image.
PROVISION_SKIPPED = frozenset({"30-install-deploy-tooling.sh"})
PROVISION_SUFFIXES = frozenset({".py", ".sh", ".service"})

BLOCK_KEYS = ("block", "rescue", "always")
COMMAND_MODULES = frozenset({"command", "shell", "raw"})
DOCKER_MODULES = frozenset(
    {
        "docker_compose",
        "docker_compose_v2",
        "docker_compose_v2_pull",
        "docker_compose_v2_run",
        "docker_container",
        "docker_image",
        "docker_image_pull",
        "docker_stack",
    }
)
PULLING = frozenset({"pull", "run", "create"})
COMPOSE_PULLING = frozenset({"up", "run", "pull", "create"})
IMAGE_LINE = re.compile(r"^[A-Z][A-Z0-9_]*_IMAGE=", re.MULTILINE)
SCRIPT_LOOKUP = re.compile(r"lookup\(\s*'(?:ansible\.builtin\.)?file'\s*,\s*'([^']+)'")
SCRIPT_PULLS = re.compile(
    r"\bdocker\s+(?:(?:image|container)\s+)?(?:pull|run|create)\b"
    r"|\bdocker\s+compose\b[^\n]*\b(?:up|run|pull|create)\b"
)


def _short(key: object) -> str:
    """Return a module key without its collection prefix, so every spelling matches."""
    return str(key).rsplit(".", 1)[-1]


def _load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _variables(path: Path) -> dict[str, object]:
    """Return a vars file as a mapping, empty when the file is missing or empty."""
    if not path.is_file():
        return {}
    document = _load(path)
    return {str(k): v for k, v in document.items()} if isinstance(document, dict) else {}


def constant_value(root: Path) -> str:
    """Return the registry key directory, as the deploy_verifier role defines it.

    Raises:
        AssertionError: when the role does not define it as an absolute path.
    """
    value = _variables(root / CONSTANT_FILE).get(CONSTANT_NAME)
    if not isinstance(value, str) or not value.startswith("/"):
        message = f"{CONSTANT_NAME} is not an absolute path in {CONSTANT_FILE}"
        raise AssertionError(message)
    return value


def _tokens(args: object) -> list[str]:
    """Return the words of a command task's arguments, an argv list or a templated string."""
    parts = args.get("argv", args.get("cmd", "")) if isinstance(args, dict) else args
    if isinstance(parts, list):
        return [str(item) for item in parts]
    return re.findall(r"[^\s'\",\[\]{}()]+", str(parts))


def command_pulls(args: object) -> bool:
    """Whether a command's words run docker in a way that pulls an image or starts a container."""
    words = _tokens(args)
    for index, word in enumerate(words):
        if word.rsplit("/", 1)[-1] != "docker":
            continue
        rest = [item for item in words[index + 1 :] if not item.startswith("-")]
        if not rest:
            return False
        if rest[0] in PULLING:
            return True
        if rest[0] in {"image", "container"}:
            return len(rest) > 1 and rest[1] in PULLING
        # A flag's value stands where a subcommand would: compose and its verb are matched anywhere.
        return rest[0] == "compose" and any(item in COMPOSE_PULLING for item in rest[1:])
    return False


def _code(text: str) -> str:
    """Return a script's text without its comment lines, which may name a command in prose."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _script_pulls(task: dict[str, object], files_dir: Path) -> bool:
    """Whether the task hands a shell script from the role's files to a shell and it pulls."""
    for name in SCRIPT_LOOKUP.findall(json.dumps(task, default=str)):
        script = files_dir / name
        if name.endswith(".sh") and script.is_file():
            if SCRIPT_PULLS.search(_code(script.read_text(encoding="utf-8"))):
                return True
    return False


def task_pulls(task: dict[str, object], files_dir: Path) -> bool:
    """Whether a task pulls an image or starts a container directly."""
    for key, value in task.items():
        name = _short(key)
        if name in DOCKER_MODULES or (name in COMMAND_MODULES and command_pulls(value)):
            return True
    return _script_pulls(task, files_dir)


def _walk(
    tasks: object, inherited: dict[str, object]
) -> Iterator[tuple[dict[str, object], dict[str, object]]]:
    """Yield each task with the environment it runs under: its own over its blocks'."""
    if not isinstance(tasks, list):
        return
    for task in tasks:
        if not isinstance(task, dict):
            continue
        own = task.get("environment")
        env = {**inherited, **own} if isinstance(own, dict) else dict(inherited)
        if any(key in task for key in BLOCK_KEYS):
            for key in BLOCK_KEYS:
                yield from _walk(task.get(key), env)
        else:
            yield task, env


def _role_dirs(root: Path) -> Iterator[Path]:
    for tree in TREES:
        base = root / "ansible" / tree
        if base.is_dir():
            yield from sorted(path for path in base.iterdir() if path.is_dir())


def role_variable(role: Path) -> str:
    """Return the name of the variable a caller in this role takes the directory from."""
    return f"{role.name}_registry_docker_config"


def role_callers(role: Path) -> list[tuple[str, str, dict[str, object]]]:
    """Return (file, task name, environment) for each task in a role that pulls an image."""
    found = []
    for directory in TASK_DIRECTORIES:
        for path in sorted((role / directory).rglob("*.y*ml")):
            for task, env in _walk(_load(path), {}):
                if task_pulls(task, role / "files"):
                    where = path.relative_to(role).as_posix()
                    found.append((where, str(task.get("name", "(unnamed)")), env))
    return found


def hands_images_to_a_program(role: Path) -> bool:
    """Whether a template of the role names images for a program to run, in an env file.

    A program from a release pulls and runs them where no task of the role does, so the role must
    hand it the directory itself, in a unit drop-in.
    """
    templates = role / "templates"
    paths = sorted(templates.glob("*")) if templates.is_dir() else []
    return any(IMAGE_LINE.search(path.read_text(encoding="utf-8")) for path in paths)


def has_dropin(role: Path, variable: str) -> bool:
    """Whether a template of the role sets the directory in a unit's Environment line."""
    line = f"\nEnvironment={ENV_KEY}={{{{ {variable} }}}}\n"
    templates = role / "templates"
    paths = sorted(templates.glob("*")) if templates.is_dir() else []
    return any(line in path.read_text(encoding="utf-8") for path in paths)


def role_findings(root: Path, role: Path, value: str) -> list[str]:
    """Return one finding per way a role's callers stray from the constant."""
    findings: list[str] = []
    callers = role_callers(role)
    handoff = hands_images_to_a_program(role)
    if not callers and not handoff:
        return findings
    variable = role_variable(role)
    expected = "{{ " + variable + " }}"
    for where, name, env in callers:
        if env.get(ENV_KEY) != expected:
            findings.append(
                f"{role.name}/{where}: '{name}' pulls or runs an image and does not set "
                f"{ENV_KEY} to {expected}"
            )
    if handoff and not has_dropin(role, variable):
        findings.append(
            f"{role.name}/templates: names images for a program to run and has no unit drop-in "
            f"with Environment={ENV_KEY}={expected}"
        )
    own = _variables(role / "vars" / "main.yml").get(variable)
    if own != value:
        findings.append(
            f"{role.name}/vars/main.yml: {variable} must equal {CONSTANT_NAME} ({value}) "
            "and sit in vars, not defaults"
        )
    for path in sorted(role.rglob("*.y*ml")):
        parts = path.relative_to(role).parts
        if parts[0] in TASK_DIRECTORIES and value in path.read_text(encoding="utf-8"):
            findings.append(f"{role.name}/{'/'.join(parts)}: holds the key directory as a literal")
    return findings


def _program_pulls(path: Path, text: str) -> bool:
    """Whether a program under hetzner/provision pulls an image or starts a container."""
    if path.suffix == ".service":
        return bool(re.search(r"^Exec\w*=\S*docker compose (?:up|pull)", text, re.MULTILINE))
    if path.suffix == ".sh":
        return bool(SCRIPT_PULLS.search(_code(text)))
    return bool(re.search(r'"docker",\s*"(?:pull|run|create|compose)"', text))


def program_findings(root: Path, value: str) -> list[str]:
    """Return one finding per program under hetzner/provision that pulls and lacks the key."""
    found = []
    for path in sorted((root / PROVISION).glob("*")):
        if path.suffix not in PROVISION_SUFFIXES or path.name in PROVISION_SKIPPED:
            continue
        if path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8")
        if not _program_pulls(path, text):
            continue
        # A unit sets it in an Environment line; a program names it in code, not in prose.
        line = f"\nEnvironment={ENV_KEY}={value}\n"
        named = line in text if path.suffix == ".service" else ENV_KEY in _code(text)
        if not named:
            found.append(f"{PROVISION / path.name}: pulls or runs an image without {ENV_KEY}")
    return found


def findings(root: Path) -> list[str]:
    """Return every finding for the tree under ``root``."""
    value = constant_value(root)
    out: list[str] = []
    for role in _role_dirs(root):
        out.extend(role_findings(root, role, value))
    out.extend(program_findings(root, value))
    return out


def callers(root: Path) -> list[str]:
    """Return the name of each role or pattern that has a caller, for the tests to name."""
    return [
        role.name
        for role in _role_dirs(root)
        if role_callers(role) or hands_images_to_a_program(role)
    ]


# A tree that follows every rule: one role with a pulling task and its pinned copy.
GOOD_TASKS = """\
- name: Pull the image
  ansible.builtin.command:
    argv: [docker, pull, 'registry.example/x@sha256:0']
  environment:
    DOCKER_CONFIG: '{{ probe_registry_docker_config }}'
"""
GOOD_VARS = "probe_registry_docker_config: /etc/branchleft/registry/docker\n"
CONSTANT_VARS = "deploy_verifier_registry_docker_dir: /etc/branchleft/registry/docker\n"


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _tree(base: Path, tasks: str = GOOD_TASKS, role_vars: str = GOOD_VARS) -> Path:
    _write(base, str(CONSTANT_FILE), CONSTANT_VARS)
    _write(base, "ansible/roles/probe/tasks/main.yml", tasks)
    _write(base, "ansible/roles/probe/vars/main.yml", role_vars)
    return base


class RealTreeTests(unittest.TestCase):
    maxDiff = None

    def test_the_constant_is_the_one_the_wrapper_and_the_unit_use(self) -> None:
        value = constant_value(ROOT)
        unit = (ROOT / PROVISION / "branchleft-compose@.service").read_text(encoding="utf-8")
        self.assertIn(f"\nEnvironment={ENV_KEY}={value}\n", unit)

    def test_every_caller_takes_the_directory_from_the_constant(self) -> None:
        self.assertEqual(findings(ROOT), [])

    def test_the_callers_are_found_by_scanning_and_are_not_none(self) -> None:
        # A scan that finds nothing proves nothing: the roles that pull or run an image today.
        found = set(callers(ROOT))
        self.assertTrue(
            {"control_plane", "control_plane_db", "backup_restore"} <= found, sorted(found)
        )

    def test_the_programs_that_pull_are_found(self) -> None:
        text = (ROOT / PROVISION / "branchleft-compose@.service").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^ExecStartPre=\S*docker compose pull")


class SabotageTests(unittest.TestCase):
    def tree(self, **kwargs: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return _tree(Path(directory.name), **kwargs)

    def test_a_tree_that_follows_the_rules_is_clean(self) -> None:
        self.assertEqual(findings(self.tree()), [])
        self.assertEqual(callers(self.tree()), ["probe"])

    def test_a_pulling_task_without_the_directory_is_a_finding(self) -> None:
        bare = GOOD_TASKS.replace(
            "  environment:\n    DOCKER_CONFIG: '{{ probe_registry_docker_config }}'\n", ""
        )
        out = findings(self.tree(tasks=bare))
        self.assertEqual(len(out), 1, out)
        self.assertIn("does not set DOCKER_CONFIG", out[0])

    def test_a_task_that_runs_an_image_is_a_caller_in_every_spelling(self) -> None:
        spellings = [
            "ansible.builtin.command: docker run --rm x@sha256:0",
            "ansible.builtin.command:\n    argv: [/usr/bin/docker, compose, up, -d]",
            "ansible.builtin.command:\n    argv: \"{{ ['docker', 'run', '--rm'] + limits }}\"",
            "community.docker.docker_compose_v2:\n    project_src: /srv/x",
            "ansible.builtin.command:\n    argv: [docker, image, pull, x]",
        ]
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                tasks = f"- name: Run it\n  {spelling}\n"
                out = findings(self.tree(tasks=tasks))
                self.assertTrue(any("does not set DOCKER_CONFIG" in line for line in out), out)

    def test_a_task_that_only_reads_docker_is_not_a_caller(self) -> None:
        reads = [
            "ansible.builtin.command:\n    argv: [docker, ps, --all]",
            "ansible.builtin.command:\n    argv: [docker, exec, --interactive, db, sh]",
            "ansible.builtin.command:\n    argv: [docker, network, inspect, net]",
            "ansible.builtin.command:\n    argv: [docker, compose, ps]",
        ]
        for read in reads:
            with self.subTest(read=read):
                tasks = f"- name: Look\n  {read}\n"
                self.assertEqual(findings(self.tree(tasks=tasks, role_vars="")), [])

    def test_the_directory_on_a_block_covers_the_tasks_in_it(self) -> None:
        tasks = (
            "- name: Group\n"
            "  environment:\n"
            "    DOCKER_CONFIG: '{{ probe_registry_docker_config }}'\n"
            "  block:\n"
            "    - name: Pull\n"
            "      ansible.builtin.command:\n"
            "        argv: [docker, pull, x]\n"
        )
        self.assertEqual(findings(self.tree(tasks=tasks)), [])

    def test_a_literal_path_in_the_task_is_a_finding(self) -> None:
        literal = GOOD_TASKS.replace(
            "'{{ probe_registry_docker_config }}'", "/etc/branchleft/registry/docker"
        )
        out = findings(self.tree(tasks=literal))
        self.assertTrue(any("does not set DOCKER_CONFIG" in line for line in out), out)
        self.assertTrue(any("as a literal" in line for line in out), out)

    def test_a_copy_that_differs_from_the_constant_is_a_finding(self) -> None:
        out = findings(self.tree(role_vars="probe_registry_docker_config: /root/.docker\n"))
        self.assertEqual(len(out), 1, out)
        self.assertIn("must equal", out[0])

    def test_a_copy_that_sits_in_defaults_is_a_finding(self) -> None:
        base = self.tree(role_vars="")
        _write(base, "ansible/roles/probe/defaults/main.yml", GOOD_VARS)
        out = findings(base)
        self.assertEqual(len(out), 1, out)
        self.assertIn("not defaults", out[0])

    def test_a_script_from_the_role_files_that_runs_an_image_is_a_caller(self) -> None:
        base = self.tree(
            tasks="- name: Apply\n  ansible.builtin.command:\n    cmd: sh -s\n"
            "    stdin: \"{{ lookup('ansible.builtin.file', 'apply.sh') }}\"\n"
        )
        _write(base, "ansible/roles/probe/files/apply.sh", 'docker run --rm "$image" true\n')
        out = findings(base)
        self.assertTrue(any("does not set DOCKER_CONFIG" in line for line in out), out)

    def test_a_role_that_names_images_for_a_program_needs_the_unit_drop_in(self) -> None:
        base = self.tree(tasks="- name: Nothing\n  ansible.builtin.debug:\n    msg: hi\n")
        _write(
            base, "ansible/roles/probe/templates/drill.env.j2", "DRILL_MYSQL_IMAGE={{ image }}\n"
        )
        out = findings(base)
        self.assertEqual(len(out), 1, out)
        self.assertIn("no unit drop-in", out[0])
        dropin = "[Service]\nEnvironment=DOCKER_CONFIG={{ probe_registry_docker_config }}\n"
        _write(base, "ansible/roles/probe/templates/key.conf.j2", dropin)
        self.assertEqual(findings(base), [])
        self.assertEqual(callers(base), ["probe"])

    def test_a_pattern_is_scanned_as_a_role_is(self) -> None:
        base = self.tree()
        _write(
            base,
            "ansible/patterns/stack/tasks/main.yml",
            "- name: Up\n  community.docker.docker_compose_v2:\n    project_src: /x\n",
        )
        out = findings(base)
        self.assertEqual(len(out), 2, out)
        self.assertTrue(all(line.startswith("stack/") for line in out), out)

    def test_a_program_that_pulls_and_never_names_the_directory_is_a_finding(self) -> None:
        base = self.tree()
        _write(
            base,
            "hetzner/provision/pull.service",
            "[Service]\nExecStartPre=/usr/bin/docker compose pull --quiet\n",
        )
        out = findings(base)
        self.assertEqual(len(out), 1, out)
        self.assertIn("hetzner/provision/pull.service", out[0])
        wrong = (
            "[Service]\nEnvironment=DOCKER_CONFIG=/x\nExecStartPre=/usr/bin/docker compose pull\n"
        )
        _write(base, "hetzner/provision/pull.service", wrong)
        self.assertEqual(len(findings(base)), 1)
        right = wrong.replace("/x", "/etc/branchleft/registry/docker")
        _write(base, "hetzner/provision/pull.service", right)
        self.assertEqual(findings(base), [])


if __name__ == "__main__":
    unittest.main()
