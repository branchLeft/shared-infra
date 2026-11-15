"""Pins on the ci_step_login role: the step account can run one command and hold one key, and
the owner's values for ops1 are the key and the step list the sender expects.

The role carries its own copy of the ed25519 key shape (the sudoers_and_keys pattern is not
called, so the role imports no pattern) and of the trigger program's path (pull_trigger owns it).
Each pin is shown red on a sabotaged copy of the files it reads, and green again once the file is
put back. Nothing here runs ssh or sudo: the sudo half runs in the role's container scenario.

The sender is ansible-gated-step.yml in the workflows repository. It sends
`ssh -- USER@HOST "SHA STEP WORD"` as a step account named `[a-z_][a-z0-9_-]{0,31}`, and judges the
step against the `pull_trigger_steps` list of the host's inventory file. The shapes it enforces are
copied below, so the step list of ops1 cannot hold an entry the sender would refuse to send.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[2]
ROLE = "ansible/roles/ci_step_login"
OWNER_FILE = "ansible/owner_vars/ops1.yml"
HOMES = (
    "ansible/patterns/sudoers_and_keys/vars/main.yml",
    "ansible/roles/pull_trigger/vars/main.yml",
    OWNER_FILE,
)
# The role files that carry the role's behaviour. The README and molecule/ are prose and tests.
CODE_DIRECTORIES = ("tasks", "templates", "vars", "meta")

# The public half of the step key the owner holds the private half of, and the one line the
# role must write for it. A change to either is a decision of the owner, so it is pinned here.
STEP_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF7LL0AnUqZIbGs312C8/jx7NR92q+Zs3LbSinLUh6JO "
    "control-plane-step"
)
STEP_FROM = ["10.20.1.10"]
KEY_LINE = (
    'restrict,from="10.20.1.10",command="sudo /usr/local/sbin/pull-trigger --mode step" ' + STEP_KEY
)
SUDOERS_LINES = [
    'Defaults!/usr/local/sbin/pull-trigger env_keep += "SSH_ORIGINAL_COMMAND"',
    "control-plane-step ALL=(root) NOPASSWD: /usr/local/sbin/pull-trigger --mode step",
]
# The sender's own shapes (ansible-gated-step.yml): a step id, a word, and the user part of the
# destination it connects to.
SENDER_STEP = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
SENDER_WORD = re.compile(r"[A-Z0-9-]{4,32}\Z")
SENDER_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
STEP_IDS = {"migrate", "identity", "provision"}

GOOD_ADDRESSES = ("10.20.1.10", "192.0.2.0/24", "198.51.100.7/32", "203.0.113.128/25")
BAD_ADDRESSES = (
    "*",
    "?",
    "0.0.0.0/0",
    "10.0.0.0/8",
    "10.20.0.0/16",
    "10.20.1.10/23",
    "10.20.1.10/33",
    "10.20.1.256",
    "10.20.1",
    "01.2.3.4",
    "example.invalid",
    "!10.20.1.10",
    "10.20.1.10,10.20.1.11",
    '10.20.1.10",command="/bin/EXAMPLE_COMMAND',
    "10.20.1.10\n",
    "",
)
BAD_KEYS = (
    "",
    "ssh-rsa " + STEP_KEY.split(" ")[1],
    "ssh-ed25519 " + STEP_KEY.split(" ")[1][:40],
    "ssh-ed25518 " + STEP_KEY.split(" ")[1],
    'command="/bin/EXAMPLE_COMMAND" ' + STEP_KEY,
    STEP_KEY + "\n",
    STEP_KEY + '\ncommand="/bin/EXAMPLE_COMMAND" ' + STEP_KEY,
    STEP_KEY + " PLACEHOLDER_é",
)


def _variables(path: Path) -> dict[str, object]:
    document: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    return (
        {str(key): value for key, value in document.items()} if isinstance(document, dict) else {}
    )


def _render(variables: dict[str, object], name: str, **extra: object) -> str:
    """One variable of the role's vars, with the names it holds filled in from the same file.

    Every name a value refers to is plain text, so one pass of the template engine is the whole
    of what Ansible would do.

    Raises:
        TypeError: the variable is not text.
    """
    value = variables[name]
    if not isinstance(value, str):
        message = f"{name} is not text"
        raise TypeError(message)
    context: dict[str, object] = {**variables, **extra}
    return Environment(autoescape=False).from_string(value).render(context)  # noqa: S701


def _option_names(node: object) -> list[str]:
    """Every key under an `options` mapping of an argument spec, however deep."""
    names: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "options" and isinstance(value, dict):
                names.extend(str(name) for name in value)
            names.extend(_option_names(value))
    elif isinstance(node, list):
        for item in node:
            names.extend(_option_names(item))
    return names


def _sudoers_task_findings(role: Path) -> list[str]:
    """The sudoers task must show its content in the gated plan and must be checked by visudo."""
    tasks = yaml.safe_load((role / "tasks" / "_sudoers.yml").read_text(encoding="utf-8"))
    copies = [
        task
        for task in (tasks if isinstance(tasks, list) else [])
        if isinstance(task, dict) and "ansible.builtin.copy" in task
    ]
    if len(copies) != 1:
        return [f"tasks/_sudoers.yml: expected one copy task, found {len(copies)}"]
    task = copies[0]
    found: list[str] = []
    if task.get("no_log") not in (None, False):
        found.append("tasks/_sudoers.yml: the sudoers task sets no_log (hidden from the plan)")
    if task.get("diff") is False:
        found.append("tasks/_sudoers.yml: the sudoers task sets diff: false (hidden from the plan)")
    arguments = task["ansible.builtin.copy"]
    validate = arguments.get("validate") if isinstance(arguments, dict) else None
    if not (isinstance(validate, str) and re.fullmatch(r"/usr/sbin/visudo -c\w*f %s", validate)):
        found.append("tasks/_sudoers.yml: the sudoers task has no visudo validate")
    return found


def _key_task_findings(role: Path) -> list[str]:
    """The key task writes the whole file (exclusive) and hides the key from log and plan."""
    tasks = yaml.safe_load((role / "tasks" / "_keys.yml").read_text(encoding="utf-8"))
    writes = [
        task
        for task in (tasks if isinstance(tasks, list) else [])
        if isinstance(task, dict) and "ansible.posix.authorized_key" in task
    ]
    if len(writes) != 1:
        return [f"tasks/_keys.yml: expected one authorized_key task, found {len(writes)}"]
    task = writes[0]
    found: list[str] = []
    arguments = task["ansible.posix.authorized_key"]
    if not (isinstance(arguments, dict) and arguments.get("exclusive") is True):
        found.append("tasks/_keys.yml: the key task is not exclusive, so a second key would stay")
    if task.get("no_log") is not True or task.get("diff") is not False:
        found.append("tasks/_keys.yml: the key task must set no_log: true and diff: false")
    return found


def _step_list_findings(root: Path) -> list[str]:
    """ops1's step list is the three steps, in the shapes the sender enforces."""
    owner = _variables(root / OWNER_FILE)
    steps = owner.get("pull_trigger_steps")
    if not isinstance(steps, list):
        return [f"{OWNER_FILE}: pull_trigger_steps is not a list"]
    found: list[str] = []
    seen: set[str] = set()
    for entry in steps:
        step = str(entry.get("id")) if isinstance(entry, dict) else ""
        word = str(entry.get("word")) if isinstance(entry, dict) else ""
        seen.add(step)
        if not SENDER_STEP.match(step) or step not in STEP_IDS:
            found.append(f"{OWNER_FILE}: step id {step!r} is not one the sender can send")
        if not SENDER_WORD.match(word):
            found.append(f"{OWNER_FILE}: the word of step {step!r} is not one the sender accepts")
    if seen != STEP_IDS:
        found.append(f"{OWNER_FILE}: the step ids are {sorted(seen)}, not {sorted(STEP_IDS)}")
    return found


def problems(root: Path) -> list[str]:  # noqa: C901, PLR0912
    """Return one finding per broken pin in the tree under ``root``."""
    found: list[str] = []
    role = root / ROLE
    mine = _variables(role / "vars" / "main.yml")
    pattern = _variables(root / HOMES[0])
    trigger = _variables(root / HOMES[1])
    owner = _variables(root / OWNER_FILE)

    shapes = pattern.get("sudoers_and_keys_key_shapes")
    if not (isinstance(shapes, list) and mine.get("ci_step_login_key_shape") in shapes):
        found.append("ci_step_login_key_shape is not a key shape of sudoers_and_keys")
    if not str(mine.get("ci_step_login_key_shape", "")).startswith("ssh-ed25519 "):
        found.append("ci_step_login_key_shape is not the ed25519 shape")
    if mine.get("ci_step_login_program") != trigger.get("pull_trigger_program_path"):
        found.append("ci_step_login_program differs from pull_trigger_program_path")
    if mine.get("ci_step_login_mode") != "step":
        found.append("ci_step_login_mode is not step")
    if mine.get("ci_step_login_key_options") != "restrict":
        found.append("ci_step_login_key_options is not restrict")
    user = str(mine.get("ci_step_login_user", ""))
    if not SENDER_USER.match(user) or user != mine.get("ci_step_login_sudoers_name"):
        found.append("ci_step_login_user is not a name the sender can log in as, or differs")

    lines: list[str] = []
    raw_lines = mine.get("ci_step_login_sudoers_lines")
    if isinstance(raw_lines, list) and all(isinstance(item, str) for item in raw_lines):
        lines = [
            Environment(autoescape=False).from_string(item).render(mine)  # noqa: S701
            for item in raw_lines
        ]
    if lines != SUDOERS_LINES:
        found.append("ci_step_login_sudoers_lines must be the env_keep line and the one grant")

    found.extend(_sudoers_task_findings(role))
    found.extend(_key_task_findings(role))
    found.extend(_step_list_findings(root))

    key_pattern = re.compile(_render(mine, "ci_step_login_key_pattern"))
    address_pattern = re.compile(_render(mine, "ci_step_login_address_pattern"))
    if not key_pattern.search(STEP_KEY):
        found.append("the key pattern refuses the owner's step key")
    found.extend(f"the key pattern accepts {bad!r}" for bad in BAD_KEYS if key_pattern.search(bad))
    found.extend(
        f"the address pattern refuses {good!r}"
        for good in GOOD_ADDRESSES
        if not address_pattern.search(good)
    )
    found.extend(
        f"the address pattern accepts {bad!r}"
        for bad in BAD_ADDRESSES
        if address_pattern.search(bad)
    )

    if owner.get("ci_step_login_key") != STEP_KEY:
        found.append(f"{OWNER_FILE}: ci_step_login_key is not the owner's step key")
    if owner.get("ci_step_login_from") != STEP_FROM:
        found.append(f"{OWNER_FILE}: ci_step_login_from is not {STEP_FROM}")

    template = (role / "templates" / "authorized_keys.j2").read_text(encoding="utf-8")
    written = (
        Environment(autoescape=False)  # noqa: S701
        .from_string(template)
        .render(
            {
                **mine,
                "ci_step_login_key": owner.get("ci_step_login_key"),
                "ci_step_login_from": owner.get("ci_step_login_from"),
            }
        )
        .splitlines()
    )
    if written != [KEY_LINE]:
        found.append("the key template does not write the one restricted, forced-command line")

    # The step id and its word travel in the request and are judged by the program: none of the
    # two files may name one, and nothing may be a wildcard.
    for name in ("vars/main.yml", "templates/authorized_keys.j2"):
        text = (role / name).read_text(encoding="utf-8")
        if re.search(r"migrate|identity|provision|MIGRATE|IDENTITY|PROVISION", text):
            found.append(f"{name}: names a step id or a word (they belong to the allow-list)")
    if "*" in "".join(SUDOERS_LINES) or any("*" in line for line in lines):
        found.append("a sudoers line holds a wildcard")

    for directory in CODE_DIRECTORIES:
        for path in sorted((role / directory).rglob("*")):
            if path.is_file() and re.search(r"ALL=\(ALL", path.read_text(encoding="utf-8")):
                found.append(f"{path.relative_to(root).as_posix()}: grants more than root")
    spec = yaml.safe_load((role / "meta" / "argument_specs.yml").read_text(encoding="utf-8"))
    if sorted(_option_names(spec)) != ["ci_step_login_from", "ci_step_login_key"]:
        found.append("meta/argument_specs.yml: the interface is not the key and the addresses")
    return found


class RealTree(unittest.TestCase):
    def test_the_pins_hold_on_the_real_tree(self) -> None:
        self.assertEqual(problems(ROOT), [])

    def test_the_key_template_has_restrict_a_source_and_the_forced_command(self) -> None:
        template = (ROOT / ROLE / "templates" / "authorized_keys.j2").read_text(encoding="utf-8")
        self.assertTrue(template.startswith("{{ ci_step_login_key_options }},from="))
        self.assertIn(
            'command="sudo {{ ci_step_login_program }} --mode {{ ci_step_login_mode }}"', template
        )


class Sabotage(unittest.TestCase):
    """Break one file of a copy of the tree, require the named finding, put the file back and
    require none, so a pin that is always red cannot pass for one that is switched on."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(ROOT / ROLE, self.root / ROLE)
        for home in HOMES:
            (self.root / home).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / home, self.root / home)

    def _red_then_green(self, relative: str, old: str, new: str, expected: str) -> None:
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        self.assertIn(old, original, f"the sabotage matched nothing in {relative}")
        path.write_text(original.replace(old, new, 1), encoding="utf-8")
        red = problems(self.root)
        self.assertTrue(any(expected in finding for finding in red), f"{expected!r} not in {red}")
        path.write_text(original, encoding="utf-8")
        self.assertEqual(problems(self.root), [])

    # The sudoers boundary: one command, no wildcard.
    def test_a_wildcard_in_the_grant_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "--mode {{ ci_step_login_mode }}'",
            "--mode *'",
            "ci_step_login_sudoers_lines must be",
        )

    def test_a_second_command_in_the_grant_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "--mode {{ ci_step_login_mode }}'",
            "--mode {{ ci_step_login_mode }}, /bin/sh'",
            "ci_step_login_sudoers_lines must be",
        )

    def test_a_third_sudoers_line_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "--mode {{ ci_step_login_mode }}'\n",
            "--mode {{ ci_step_login_mode }}'\n  - 'control-plane-step ALL=(ALL) NOPASSWD: ALL'\n",
            "ci_step_login_sudoers_lines must be",
        )

    def test_the_apply_mode_in_the_grant_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_step_login_mode: step",
            "ci_step_login_mode: apply",
            "ci_step_login_mode is not step",
        )

    def test_a_step_id_in_the_grant_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "--mode {{ ci_step_login_mode }}'",
            "--mode {{ ci_step_login_mode }} migrate'",
            "names a step id or a word",
        )

    def test_no_log_on_the_sudoers_task_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_sudoers.yml",
            "    validate: /usr/sbin/visudo -csf %s\n",
            "    validate: /usr/sbin/visudo -csf %s\n  no_log: true\n",
            "the sudoers task sets no_log",
        )

    def test_diff_false_on_the_sudoers_task_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_sudoers.yml",
            "    validate: /usr/sbin/visudo -csf %s\n",
            "    validate: /usr/sbin/visudo -csf %s\n  diff: false\n",
            "the sudoers task sets diff: false",
        )

    def test_a_sudoers_task_without_visudo_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_sudoers.yml",
            "    validate: /usr/sbin/visudo -csf %s\n",
            "",
            "the sudoers task has no visudo validate",
        )

    # The key line: restrict, a source, the forced command, one key.
    def test_a_key_without_restrict_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "{{ ci_step_login_key_options }},",
            "",
            "the key template does not write the one restricted",
        )

    def test_a_key_options_variable_without_restrict_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_step_login_key_options: restrict",
            "ci_step_login_key_options: no-pty",
            "ci_step_login_key_options is not restrict",
        )

    def test_a_key_without_a_source_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "from=\"{{ ci_step_login_from | join(',') }}\",",
            "",
            "the key template does not write the one restricted",
        )

    def test_a_key_with_another_forced_command_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            "--mode {{ ci_step_login_mode }}",
            "--mode apply",
            "the key template does not write the one restricted",
        )

    def test_a_key_without_a_forced_command_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/templates/authorized_keys.j2",
            'command="sudo {{ ci_step_login_program }} --mode {{ ci_step_login_mode }}" ',
            "",
            "the key template does not write the one restricted",
        )

    def test_a_non_exclusive_key_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_keys.yml",
            "    exclusive: true\n",
            "    exclusive: false\n",
            "the key task is not exclusive",
        )

    def test_a_visible_key_write_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/tasks/_keys.yml",
            "  no_log: true\n  diff: false\n  when:",
            "  diff: false\n  when:",
            "the key task must set no_log: true and diff: false",
        )

    def test_a_widened_address_pattern_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "(/(2[4-9]|3[0-2]))?",
            "(/[0-9]{1,2})?",
            "the address pattern accepts '0.0.0.0/0'",
        )

    def test_an_address_pattern_that_accepts_a_wildcard_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_step_login_address_pattern: '^",
            "ci_step_login_address_pattern: '^[*]|^",
            "the address pattern accepts '*'",
        )

    def test_a_key_pattern_without_the_end_anchor_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "( [ -~]*)?\\Z'",
            "( [ -~]*)?'",
            "the key pattern accepts",
        )

    def test_drifted_key_shapes_are_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ssh-ed25519 [A-Za-z0-9+/]{68}",
            "ssh-ed25519 [A-Za-z0-9+/]{60,}",
            "ci_step_login_key_shape is not a key shape",
        )

    def test_a_changed_key_shape_in_the_home_is_red(self) -> None:
        self._red_then_green(
            HOMES[0],
            "ssh-ed25519 [A-Za-z0-9+/]{68}",
            "ssh-ed25519 [A-Za-z0-9+/]{67}",
            "ci_step_login_key_shape is not a key shape",
        )

    def test_a_drifted_program_path_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/vars/main.yml",
            "ci_step_login_program: /usr/local/sbin/pull-trigger",
            "ci_step_login_program: /usr/local/sbin/pull-trigger2",
            "ci_step_login_program differs",
        )

    def test_a_moved_program_in_the_home_is_red(self) -> None:
        self._red_then_green(
            HOMES[1],
            "pull_trigger_program_path: /usr/local/sbin/pull-trigger",
            "pull_trigger_program_path: /usr/local/sbin/pull-trigger2",
            "ci_step_login_program differs",
        )

    def test_a_second_input_in_the_interface_is_red(self) -> None:
        self._red_then_green(
            f"{ROLE}/meta/argument_specs.yml",
            "      ci_step_login_from:\n",
            "      ci_step_login_mode:\n        type: str\n      ci_step_login_from:\n",
            "the interface is not the key and the addresses",
        )

    # The owner's values.
    def test_another_key_in_the_owner_file_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "AAAAC3NzaC1lZDI1NTE5AAAAIF7LL0AnUqZIbGs312C8",
            "AAAAC3NzaC1lZDI1NTE5AAAAIF7LL0AnUqZIbGs312C9",
            "ci_step_login_key is not the owner's step key",
        )

    def test_another_source_in_the_owner_file_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "  - '10.20.1.10'\n",
            "  - '10.20.1.0/24'\n",
            "ci_step_login_from is not",
        )

    # The step list the sender reads: a step outside the three, or a word it would refuse.
    def test_a_step_outside_the_allow_list_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "  - id: provision\n",
            "  - id: break_glass\n    tag: control_plane_db_break_glass\n    word: BREAK-GLASS\n"
            "  - id: provision\n",
            "step id 'break_glass' is not one the sender can send",
        )

    def test_a_dropped_step_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "  - id: identity\n    tag: control_plane_db_identity\n    word: IDENTITY-OPS1\n",
            "",
            "the step ids are",
        )

    def test_a_lower_case_word_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "word: MIGRATE-OPS1",
            "word: migrate-ops1",
            "the word of step 'migrate' is not one the sender accepts",
        )

    def test_an_upper_case_step_id_is_red(self) -> None:
        self._red_then_green(
            OWNER_FILE,
            "  - id: migrate\n",
            "  - id: Migrate\n",
            "step id 'Migrate' is not one the sender can send",
        )


if __name__ == "__main__":
    unittest.main()
