"""demo1's roles reach neither GitHub nor its container registry, and hold their vendored files.

demo1's egress allowlist holds the package mirrors only. Its files arrive in the signed commit
the host checks out, so a role that applies to it must fetch nothing from
raw.githubusercontent.com or ghcr.io, and must not pull an image. Three properties, each read
from the tree:

* no task, handler, default, variable, argument spec or template of a role the demo1 playbook
  applies names either host, or uses a module or command that fetches (get_url, a uri to an
  address that is not the host's own, git, a Docker image or login module, docker pull,
  compose pull, docker login);
* every file under files/ghost-platform of demo1_build and demo1_egress_spool is listed in the
  role's pins, every pin has its file, and each file has its pinned sha256;
* each of the two roles checks its vendored files right after its inputs, before any other step.

Not covered, and named: the vendored files themselves are not scanned (they are upstream's text,
held to their pins, and the host runs them), and nothing here compares them with
branchLeft/ghost-platform. The README of each role says so.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import NoReturn

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = Path("ansible/playbooks/demo1.yml")
ROLES = Path("ansible/roles")
# The parts of a role that run on a host or say what it does. files/ is left out on purpose.
AREAS = ("tasks", "handlers", "defaults", "vars", "meta", "templates")
VENDORED = Path("files/ghost-platform")
# The roles that carry upstream files, and the variable that pins them.
PINS = {
    "demo1_build": "demo1_build_release_files",
    "demo1_egress_spool": "demo1_egress_spool_files",
}

BANNED_HOSTS = re.compile(r"raw\.githubusercontent\.com|ghcr\.io", re.IGNORECASE)
# Modules that fetch from a network place. uri is allowed to the host's own loopback only.
FETCH_MODULES = frozenset(
    {
        "get_url",
        "git",
        "subversion",
        "docker_image",
        "docker_image_pull",
        "docker_login",
        "docker_compose_v2",
        "docker_compose_v2_pull",
        "docker_container",
    }
)
COMMAND_MODULES = frozenset({"command", "shell", "raw", "script"})
# docker pull, docker image pull, docker login, compose pull. The program may be a variable.
DOCKER_PROGRAM = r"(?:\bdocker\b|\{\{[^}]*docker[^}]*\}\})"
BANNED_COMMANDS = (
    re.compile(DOCKER_PROGRAM + r".*\b(?:pull|login)\b"),
    re.compile(r"\bcompose\b.*\bpull\b"),
)
LOOPBACK_URL = re.compile(r"^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?:[:/]|$)")
MODULE_LINE = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<name>[A-Za-z_][\w.]*)\s*:(?P<rest>.*)$")
COMMENT = re.compile(r"(^|\s)#.*$")
INCLUDE = "ansible.builtin.include_tasks"
LABEL = "ansible/roles/demo1_build/tasks/_release.yml"


class DemoFetchError(Exception):
    """A file the check reads is missing or is not in the shape it needs."""


def refuse(message: str) -> NoReturn:
    """Stop the check with a message.

    Raises:
        DemoFetchError: always, carrying the message.
    """
    raise DemoFetchError(message)


def strip_comment(line: str) -> str:
    """Return a line without its comment: a comment names things without doing them."""
    return COMMENT.sub("", line)


def short_name(module: str) -> str:
    """Return a module's name without its collection, ansible.builtin.get_url -> get_url."""
    return module.rsplit(".", 1)[-1]


def indent_of(line: str) -> int:
    """Return how many spaces a line is indented."""
    return len(line) - len(line.lstrip(" "))


def argument_text(lines: list[str], index: int, rest: str) -> str:
    """Return a module's arguments as one string: what follows its key and its indented block."""
    base = indent_of(lines[index])
    parts = [rest]
    for line in lines[index + 1 :]:
        if line.strip() and indent_of(line) <= base:
            break
        parts.append(line)
    return re.sub(r"[\[\]'\",]+", " ", " ".join(parts))


def url_of(text: str) -> str:
    """Return the value of the url argument in a module's arguments, empty when it has none."""
    found = re.search(r"\burl\s*:\s*(\S+)", text)
    return found.group(1) if found else ""


def file_findings(path: Path, label: str) -> list[str]:
    """Return one finding, with file and line, for each fetch a YAML file of a role makes."""
    findings: list[str] = []
    lines = [strip_comment(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for number, line in enumerate(lines, start=1):
        findings.extend(f"{label}:{number}: names {host}" for host in BANNED_HOSTS.findall(line))
        matched = MODULE_LINE.match(line)
        if matched is None:
            continue
        module = short_name(matched.group("name"))
        text = argument_text(lines, number - 1, matched.group("rest"))
        if module in FETCH_MODULES:
            findings.append(f"{label}:{number}: uses the {module} module, which fetches")
        elif module == "uri":
            url = url_of(text)
            if not LOOPBACK_URL.match(url):
                where = url or "an address that is not given"
                findings.append(
                    f"{label}:{number}: uri to {where}, which is not the host's own loopback"
                )
        elif module in COMMAND_MODULES:
            findings.extend(
                f"{label}:{number}: runs a command that pulls or logs in"
                for pattern in BANNED_COMMANDS
                if pattern.search(text)
            )
    return findings


def role_findings(root: Path, role: str) -> list[str]:
    """Return every fetch the areas of a role make, each as 'path:line: what'."""
    base = root / ROLES / role
    findings: list[str] = []
    for area in AREAS:
        directory = base / area
        paths = sorted(directory.rglob("*")) if directory.is_dir() else []
        for path in paths:
            if path.is_file() and path.suffix in (".yml", ".yaml", ".j2"):
                findings.extend(file_findings(path, path.relative_to(root).as_posix()))
    return findings


def playbook_roles(root: Path) -> list[str]:
    """Return the names of the roles the demo1 playbook applies.

    Raises:
        DemoFetchError: when the playbook is not one play with a role list.
    """
    document, problem = load_yaml(root / PLAYBOOK)
    if problem is not None:
        refuse(problem)
    plays = document if isinstance(document, list) else []
    if len(plays) != 1 or not isinstance(plays[0], dict) or "roles" not in plays[0]:
        refuse("demo1.yml must hold exactly one play with a role list")
    names: list[str] = []
    for entry in plays[0]["roles"]:
        if not isinstance(entry, dict) or "role" not in entry:
            refuse("every role of demo1.yml must be written as 'role: <path>'")
        names.append(Path(str(entry["role"])).name)
    return names


def fetch_findings(root: Path) -> list[str]:
    """Return every fetch in every role the demo1 playbook applies."""
    found: list[str] = []
    for role in playbook_roles(root):
        found.extend(role_findings(root, role))
    return found


def pinned_files(root: Path, role: str) -> dict[str, str]:
    """Return the path and sha256 of each file the role pins.

    Raises:
        DemoFetchError: when the role's defaults do not hold a list of path and sha256 pairs.
    """
    document, problem = load_yaml(root / ROLES / role / "defaults" / "main.yml")
    if problem is not None:
        refuse(problem)
    entries = document.get(PINS[role]) if isinstance(document, dict) else None
    if not isinstance(entries, list):
        refuse(f"{role} defaults must hold {PINS[role]} as a list")
    pins: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or "path" not in entry or "sha256" not in entry:
            refuse(f"every entry of {PINS[role]} needs a path and a sha256")
        pins[str(entry["path"])] = str(entry["sha256"])
    return pins


def vendored_findings(root: Path, role: str) -> list[str]:
    """Return a finding for each vendored file with no pin, each pin with no file, each mismatch."""
    base = root / ROLES / role / VENDORED
    on_disk = {
        path.relative_to(base).as_posix(): path for path in base.rglob("*") if path.is_file()
    }
    pins = pinned_files(root, role)
    findings = [
        f"{role}: {name} is vendored and has no pin"
        for name in sorted(on_disk.keys() - pins.keys())
    ]
    findings.extend(
        f"{role}: {name} is pinned and has no vendored file"
        for name in sorted(pins.keys() - on_disk.keys())
    )
    for name in sorted(on_disk.keys() & pins.keys()):
        digest = hashlib.sha256(on_disk[name].read_bytes()).hexdigest()
        if digest != pins[name]:
            findings.append(f"{role}: {name} is {digest}, and its pin is {pins[name]}")
    return findings


def include_order(root: Path, role: str) -> list[str]:
    """Return the tasks files a role's main.yml includes, in order.

    Raises:
        DemoFetchError: when main.yml is not a list of tasks.
    """
    document, problem = load_yaml(root / ROLES / role / "tasks" / "main.yml")
    if problem is not None:
        refuse(problem)
    if not isinstance(document, list):
        refuse(f"{role} tasks/main.yml must be a list of tasks")
    return [str(task[INCLUDE]) for task in document if isinstance(task, dict) and INCLUDE in task]


def order_findings(root: Path, role: str) -> list[str]:
    """Return a finding when the vendored check is not the second step, right after the inputs."""
    first = include_order(root, role)[:2]
    if first != ["_inputs.yml", "_vendored.yml"]:
        return [f"{role}: main.yml includes {first} first, not _inputs.yml then _vendored.yml"]
    return []


def doc(*lines: str) -> str:
    """Return a YAML document made of the given lines."""
    return "\n".join(["---", *lines]) + "\n"


def copy_role(tree: Path, role: str) -> Path:
    """Copy a role of the real tree into a temporary tree and return the copy's path."""
    target = tree / ROLES / role
    shutil.copytree(ROOT / ROLES / role, target)
    return target


class NoGithubFetchTest(unittest.TestCase):
    def test_the_real_tree_fetches_nothing(self) -> None:
        self.assertEqual([], fetch_findings(ROOT))

    def test_the_playbook_applies_the_four_roles_the_check_reads(self) -> None:
        self.assertEqual(
            ["ansible_runtime", "pull_trigger", "demo1_build", "demo1_egress_spool"],
            playbook_roles(ROOT),
        )

    def test_the_old_download_is_named_by_file_and_line(self) -> None:
        old = doc(
            "- name: Download each program and hold it to its checksum",
            "  ansible.builtin.get_url:",
            "    url: 'https://raw.githubusercontent.com/branchLeft/ghost-platform/{{ sha }}/x.py'",
            "    dest: /opt/x.py",
            "    checksum: 'sha256:{{ item.sha256 }}'",
        )
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp)
            tasks = tree / ROLES / "demo1_build" / "tasks"
            tasks.mkdir(parents=True)
            (tasks / "_release.yml").write_text(old, encoding="utf-8")
            found = role_findings(tree, "demo1_build")
        self.assertIn(f"{LABEL}:3: uses the get_url module, which fetches", found)
        self.assertIn(f"{LABEL}:4: names raw.githubusercontent.com", found)

    def test_each_way_to_fetch_is_named(self) -> None:
        cases = {
            "get_url": doc("- ansible.builtin.get_url:", "    url: https://example.org/x"),
            "git": doc("- ansible.builtin.git:", "    repo: https://example.org/x.git"),
            "uri": doc("- ansible.builtin.uri:", "    url: https://example.org/x"),
            "docker_image": doc("- community.docker.docker_image:", "    source: pull"),
            "docker_login": doc("- community.docker.docker_login:", "    username: x"),
            "ghcr": doc("- ansible.builtin.debug:", "    msg: ghcr.io/branchleft/x"),
            "raw": doc("- ansible.builtin.debug:", "    msg: https://raw.githubusercontent.com/x"),
            "docker pull": doc("- ansible.builtin.command:", "    argv: [docker, pull, x]"),
            "docker pull listed": doc(
                "- ansible.builtin.command:",
                "    argv:",
                "      - docker",
                "      - pull",
            ),
            "docker pull by variable": doc(
                "- ansible.builtin.command:", "    argv: ['{{ docker }}', image, pull, x]"
            ),
            "compose pull": doc(
                "- ansible.builtin.shell:", "    cmd: docker compose -f x pull --quiet"
            ),
            "docker login": doc("- ansible.builtin.command:", "    cmd: docker login a.example"),
        }
        for name, text in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "tasks.yml"
                path.write_text(text, encoding="utf-8")
                self.assertTrue(file_findings(path, "tasks.yml"), name)

    def test_what_is_not_a_fetch_is_not_named(self) -> None:
        cases = {
            "loopback uri": doc("- ansible.builtin.uri:", "    url: 'http://127.0.0.1:{{ p }}/x'"),
            "docker inspect": doc(
                "- ansible.builtin.command:", "    argv: ['{{ docker }}', image, inspect, x]"
            ),
            "docker volume": doc(
                "- ansible.builtin.command:", "    argv: [docker, volume, create, x]"
            ),
            "a comment": doc(
                "# get_url from raw.githubusercontent.com is gone",
                "- ansible.builtin.copy:",
                "    src: x",
            ),
            "copy": doc("- ansible.builtin.copy:", "    src: x", "    dest: /y"),
        }
        for name, text in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "tasks.yml"
                path.write_text(text, encoding="utf-8")
                self.assertEqual([], file_findings(path, "tasks.yml"), name)

    def test_the_vendored_files_are_the_pinned_files(self) -> None:
        for role in PINS:
            with self.subTest(role=role):
                self.assertEqual([], vendored_findings(ROOT, role))

    def test_a_vendored_file_that_is_not_its_pin_is_named(self) -> None:
        for role in PINS:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                tree = Path(tmp)
                vendored = copy_role(tree, role) / VENDORED
                victim = next(path for path in sorted(vendored.rglob("*")) if path.is_file())
                victim.write_bytes(victim.read_bytes() + b"\n")
                found = vendored_findings(tree, role)
                self.assertEqual(1, len(found), found)
                self.assertIn(victim.relative_to(vendored).as_posix(), found[0])

    def test_a_vendored_file_with_no_pin_and_a_pin_with_no_file_are_named(self) -> None:
        for role in PINS:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                tree = Path(tmp)
                vendored = copy_role(tree, role) / VENDORED
                (vendored / "extra.py").write_text("x\n", encoding="utf-8")
                found = vendored_findings(tree, role)
                self.assertIn(f"{role}: extra.py is vendored and has no pin", found)
                victim = next(
                    path
                    for path in sorted(vendored.rglob("*"))
                    if path.is_file() and path.name != "extra.py"
                )
                victim.unlink()
                found = vendored_findings(tree, role)
                self.assertTrue(any("is pinned and has no vendored file" in line for line in found))

    def test_the_vendored_check_comes_right_after_the_inputs(self) -> None:
        for role in PINS:
            with self.subTest(role=role):
                self.assertEqual([], order_findings(ROOT, role))

    def test_a_vendored_check_that_moved_is_named(self) -> None:
        for role in PINS:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                main = copy_role(Path(tmp), role) / "tasks" / "main.yml"
                text = main.read_text(encoding="utf-8")
                main.write_text(text.replace("_vendored.yml", "_preconditions.yml", 1))
                self.assertTrue(order_findings(Path(tmp), role))


if __name__ == "__main__":
    unittest.main()
