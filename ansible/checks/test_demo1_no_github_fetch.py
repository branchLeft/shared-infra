"""demo1's roles reach neither GitHub nor its container registry, and hold their vendored files.

demo1's egress allowlist holds the package mirrors, and one more host: nodejs.org, for the
broker's Node runtime, pinned by its sha256. Its files arrive in the signed commit
the host checks out, so a role that applies to it must fetch nothing from
raw.githubusercontent.com or ghcr.io, and must not pull an image. Three properties, each read
from the tree:

* no task, handler, default, variable, argument spec or template of a role the demo1 playbook
  applies names either host, or uses a module or command that fetches (get_url, a uri to an
  address that is not the host's own, git, a Docker image or login module, docker pull,
  compose pull, docker login), except the one download below;
* every file under files/ghost-platform of demo1_build and demo1_egress_spool is listed in the
  role's pins, every pin has its file, and each file has its pinned sha256;
* each of the two roles checks its vendored files right after its inputs, before any other step.

The one download is broker_deploy's Node runtime, read from the parsed YAML: see
download_problems for what must hold. A get_url with no checksum, on another host, on GitHub, in
another role or in another file of the role is still a finding.

Not covered, and named: the vendored files themselves are not scanned (they are upstream's text,
held to their pins, and the host runs them), and nothing here compares them with
branchLeft/ghost-platform. The README of each role says so. This test holds the roles' text to
the allowlist; it does not read the host's own firewall, and a variable passed at run time
could still move the base url (the pull route passes none, and the checksum still has to match).
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NoReturn, cast

from check_pins import load_yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

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

# The one host a role on demo1 may download from, and only for the broker runtime, which the
# role holds to a sha256 pin. https, the default port, no other host and no suffix of it.
ALLOWED_DOWNLOAD_BASE = "https://nodejs.org/dist"
DOWNLOAD_ROLE = "broker_deploy"
DOWNLOAD_TASKS = ROLES / DOWNLOAD_ROLE / "tasks" / "main.yml"
DOWNLOAD_DEFAULTS = ROLES / DOWNLOAD_ROLE / "defaults" / "main.yml"
DOWNLOAD_MODULES = ("get_url", "ansible.builtin.get_url")
DOWNLOAD_URL = (
    "{{ broker_deploy_node_base_url }}/{{ broker_deploy_node_version }}"
    "/node-{{ broker_deploy_node_version }}-linux-{{ broker_deploy_node_arch }}.tar.xz"
)
DOWNLOAD_CHECKSUM = "{{ broker_deploy_node_checksums[broker_deploy_node_arch] }}"
DOWNLOAD_ARGUMENTS = frozenset({"url", "dest", "checksum", "owner", "group", "mode"})
SHA256_PIN = re.compile(r"sha256:[0-9a-f]{64}")
BASE_URL_VARIABLE = "broker_deploy_node_base_url"
FETCH_FINDING = "{label}:{line}: uses the get_url module, which fetches"


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


def mappings_in(node: object) -> Iterator[dict[str, object]]:
    """Yield every mapping inside a parsed YAML value, blocks and their sections included."""
    if isinstance(node, dict):
        yield cast("dict[str, object]", node)
        for value in node.values():
            yield from mappings_in(value)
    elif isinstance(node, list):
        for item in node:
            yield from mappings_in(item)


def download_problems(root: Path, arguments: dict[str, object]) -> list[str]:
    """Return one line for each way the broker's Node download is not the one permitted.

    The download is permitted only when its arguments are the url, dest, checksum, owner, group
    and mode and no others, its url is the exact shape under the role's base url, its checksum
    is the role's table of pins, the role's default base url is exactly ALLOWED_DOWNLOAD_BASE,
    every pin in the table is a sha256, and no file of the role other than its defaults sets
    the base url. An empty list means permitted.
    """
    found = [
        f"the download has an argument that is not allowed: {name}"
        for name in sorted(arguments.keys() - DOWNLOAD_ARGUMENTS)
    ]
    if arguments.get("url") != DOWNLOAD_URL:
        found.append("the download url is not the pinned shape under the role's base url")
    if arguments.get("checksum") != DOWNLOAD_CHECKSUM:
        found.append("the download does not carry the role's table of sha256 pins as its checksum")
    defaults, problem = load_yaml(root / DOWNLOAD_DEFAULTS)
    if problem is not None or not isinstance(defaults, dict):
        return [*found, "the role's defaults cannot be read"]
    if defaults.get(BASE_URL_VARIABLE) != ALLOWED_DOWNLOAD_BASE:
        found.append(f"the role's base url is not exactly {ALLOWED_DOWNLOAD_BASE}")
    pins = defaults.get("broker_deploy_node_checksums")
    if not isinstance(pins, dict) or not pins:
        found.append("the role has no table of sha256 pins")
    elif not all(isinstance(pin, str) and SHA256_PIN.fullmatch(pin) for pin in pins.values()):
        found.append("a pin in the role's table is not a sha256")
    found.extend(f"{name} sets the base url" for name in base_url_setters(root))
    return found


def base_url_setters(root: Path) -> list[str]:
    """Return the files of the role, other than its defaults, that name the base url.

    A use of the variable as a template, with nothing around it, is not a setting.
    """
    base = root / ROLES / DOWNLOAD_ROLE
    use = "{{ " + BASE_URL_VARIABLE + " }}"
    names: list[str] = []
    for area in AREAS:
        directory = base / area
        for path in sorted(directory.rglob("*")) if directory.is_dir() else []:
            if path.is_file() and path != root / DOWNLOAD_DEFAULTS:
                text = path.read_text(encoding="utf-8")
                if BASE_URL_VARIABLE in text.replace(use, ""):
                    names.append(path.relative_to(root).as_posix())
    return names


def permitted_download_lines(root: Path, path: Path) -> set[int]:
    """Return the line of the one download a file may make, empty when none is permitted.

    Only broker_deploy's tasks/main.yml is looked at, and only when it holds exactly one
    get_url (of any collection) and that one is permitted by download_problems.
    """
    if path.relative_to(root) != DOWNLOAD_TASKS:
        return set()
    try:
        document = YAML(typ="rt").load(path.read_text(encoding="utf-8"))
    except (OSError, YAMLError):
        return set()
    fetches = [
        (task, key)
        for task in mappings_in(document)
        for key in task
        if short_name(str(key)) == "get_url" and isinstance(task[key], dict)
    ]
    if len(fetches) != 1:
        return set()
    task, key = fetches[0]
    arguments = cast("dict[str, object]", task[key])
    if key not in DOWNLOAD_MODULES or download_problems(root, arguments):
        return set()
    lines = cast("CommentedMap", task).lc.data
    return {int(lines[key][0]) + 1}


def role_findings(root: Path, role: str) -> list[str]:
    """Return every fetch the areas of a role make, each as 'path:line: what'."""
    base = root / ROLES / role
    findings: list[str] = []
    for area in AREAS:
        directory = base / area
        paths = sorted(directory.rglob("*")) if directory.is_dir() else []
        for path in paths:
            if path.is_file() and path.suffix in (".yml", ".yaml", ".j2"):
                label = path.relative_to(root).as_posix()
                permitted = {
                    FETCH_FINDING.format(label=label, line=line)
                    for line in permitted_download_lines(root, path)
                }
                findings.extend(
                    finding for finding in file_findings(path, label) if finding not in permitted
                )
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


def node_task_text() -> str:
    """Return the text of broker_deploy's Node download task, from its name to the next task."""
    text = (ROOT / DOWNLOAD_TASKS).read_text(encoding="utf-8")
    start = text.index("- name: Download the Node tarball")
    return text[start : text.index("\n\n", start)] + "\n"


def replacing(old: str, new: str) -> Callable[[str], str]:
    """Return an edit that puts a new text for the first occurrence of an old one."""

    def edit(text: str) -> str:
        return text.replace(old, new, 1)

    return edit


def get_url_findings_after(relative: str, edit: Callable[[str], str]) -> list[str]:
    """Edit one file of a copy of broker_deploy and return the get_url findings that result.

    Raises:
        DemoFetchError: when the edit changes nothing, so the case would prove nothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        path = copy_role(tree, DOWNLOAD_ROLE) / relative
        before = path.read_text(encoding="utf-8") if path.exists() else ""
        after = edit(before)
        if after == before:
            refuse(f"the edit changed nothing in {relative}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(after, encoding="utf-8")
        return [line for line in role_findings(tree, DOWNLOAD_ROLE) if "get_url" in line]


class NoGithubFetchTest(unittest.TestCase):
    def test_the_real_tree_fetches_nothing(self) -> None:
        self.assertEqual([], fetch_findings(ROOT))

    def test_the_one_node_download_is_what_is_let_through(self) -> None:
        self.assertEqual(1, len(permitted_download_lines(ROOT, ROOT / DOWNLOAD_TASKS)))
        text = node_task_text()
        self.assertIn("ansible.builtin.get_url:", text)
        self.assertIn("checksum:", text)

    def test_a_download_with_no_checksum_or_the_wrong_one_is_named(self) -> None:
        pins = "{{ broker_deploy_node_checksums[broker_deploy_node_arch] }}"
        cases = {
            "no checksum": lambda text: text.replace(f"    checksum: '{pins}'\n", "", 1),
            "a checksum of its own": lambda text: text.replace(pins, "sha256:{{ sha }}", 1),
            "validation off": lambda text: text.replace(
                "    mode: '0644'\n  when: broker_deploy_node_needed\n\n# Skipped",
                "    mode: '0644'\n    validate_certs: false\n  when: broker_deploy_node_needed"
                "\n\n# Skipped",
                1,
            ),
            "another url": lambda text: text.replace(
                "url: '{{ broker_deploy_node_base_url }}/", "url: 'https://nodejs.org/x/", 1
            ),
        }
        for name, edit in cases.items():
            with self.subTest(name=name):
                self.assertTrue(get_url_findings_after("tasks/main.yml", edit), name)

    def test_a_download_from_any_other_host_is_named(self) -> None:
        hosts = (
            "https://github.com/nodejs/node/releases/download",
            "https://raw.githubusercontent.com/nodejs/node/main",
            "https://example.org/dist",
            "https://nodejs.org.example.org/dist",
            "https://evilnodejs.org/dist",
            "https://www.nodejs.org/dist",
            "https://nodejs.org:8443/dist",
            "http://nodejs.org/dist",
            "https://nodejs.org/dist/",
            "",
        )
        old = f"{BASE_URL_VARIABLE}: {ALLOWED_DOWNLOAD_BASE}"
        for host in hosts:
            with self.subTest(host=host):
                found = get_url_findings_after(
                    "defaults/main.yml", replacing(old, f"{BASE_URL_VARIABLE}: '{host}'")
                )
                self.assertTrue(found, host)

    def test_a_pin_that_is_not_a_sha256_is_named(self) -> None:
        arm = "036df0b49662ebb350eb56f1cac603699b1e9ed1e2603ee129fefda473479030"
        for name, new in {
            "a short digest": "sha256:036df0b49662",
            "another algorithm": f"sha1:{arm[:40]}",
            "an empty pin": "",
            "upper case": f"sha256:{arm.upper()}",
        }.items():
            with self.subTest(name=name):
                found = get_url_findings_after("defaults/main.yml", replacing(f"sha256:{arm}", new))
                self.assertTrue(found, name)

    def test_a_second_download_is_named_and_so_is_the_first(self) -> None:
        found = get_url_findings_after(
            "tasks/main.yml", lambda text: text + "\n" + node_task_text()
        )
        self.assertEqual(2, len(found), found)

    def test_the_same_download_in_another_file_of_the_role_is_named(self) -> None:
        found = get_url_findings_after("tasks/_other.yml", lambda _: node_task_text())
        self.assertEqual(1, len(found), found)

    def test_the_same_download_in_another_role_is_named(self) -> None:
        for role in ("demo1_build", "demo1_egress_spool", "pull_trigger", "ansible_runtime"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                tree = Path(tmp)
                copy_role(tree, DOWNLOAD_ROLE)
                tasks = tree / ROLES / role / "tasks"
                tasks.mkdir(parents=True)
                (tasks / "main.yml").write_text(node_task_text(), encoding="utf-8")
                found = [line for line in role_findings(tree, role) if "get_url" in line]
                self.assertEqual(1, len(found), found)

    def test_a_second_place_that_sets_the_base_url_is_named(self) -> None:
        text = doc(f"{BASE_URL_VARIABLE}: https://example.org/dist")
        found = get_url_findings_after("vars/main.yml", lambda _: text)
        self.assertEqual(1, len(found), found)

    def test_the_playbook_applies_the_five_roles_the_check_reads(self) -> None:
        self.assertEqual(
            [
                "ansible_runtime",
                "pull_trigger",
                "broker_deploy",
                "demo1_build",
                "demo1_egress_spool",
            ],
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
