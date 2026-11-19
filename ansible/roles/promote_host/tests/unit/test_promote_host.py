"""Unit tests that hold the promote_host role to the applier it installs.

The tests read the real files and run the real program, never a copy: the applier is loaded from
hetzner/provision/, the deploy wrapper beside it supplies the stack grammar, and the host's own
`ssh-keygen` signs and verifies. A control that a test names was run red on a sabotaged copy and
green on the file as shipped (the pull request records both).

Placeholders only: the keys here are made for each test in a scratch directory and are never kept.
The README gives the command.
"""

import dataclasses
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, cast
from unittest import mock

import jinja2
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ruamel.yaml import YAML

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

ROLE = Path(__file__).resolve().parents[2]
REPO = ROLE.parents[2]
PROVISION = REPO / "hetzner" / "provision"
SERVICE = ROLE / "files" / "branchleft-promote.service"
TIMER = ROLE / "files" / "branchleft-promote.timer"

SSH_KEYGEN = "/usr/bin/ssh-keygen"
LEDGER_URL = "https://example.invalid/ledger/current.json"
# The only two inputs the role takes, and the only name its environment file holds.
INPUTS = ["promote_host_ledger_url", "promote_host_signer_key"]
ENV_NAMES = ["PROMOTE_LEDGER_URL"]
# Where the role may put a file: its own directories, the program and its two units.
ALLOWED_PREFIXES = (
    "/etc/branchleft/promote",
    "/var/lib/branchleft/promote",
    "/usr/local/sbin/branchleft-promote",
    "/etc/systemd/system/branchleft-promote.",
)
WRITING_MODULES = {"copy", "template", "file"}
FORBIDDEN_MODULES = {"shell", "command", "script", "raw", "slurp", "pipe", "fetch", "lineinfile"}
# Words that would put a model, an agent or a push route in a unit of this role.
FORBIDDEN_UNIT_WORDS = ("ANTHROPIC", "_API_KEY", "claude", "ssh ", "git ")


def load_module(name: str, path: Path) -> ModuleType:
    """Load a program by path, the way the host runs it, under the name the tests use.

    Raises:
        AssertionError: when the file cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        message = f"cannot load {path}"
        raise AssertionError(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BP = load_module("branchleft_promote", PROVISION / "branchleft_promote.py")


def load(path: Path) -> object:
    """Load a YAML file with the safe loader."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def role_vars() -> dict[str, object]:
    """Return the role's vars/main.yml."""
    return cast("dict[str, object]", load(ROLE / "vars" / "main.yml"))


def role_defaults() -> dict[str, object]:
    """Return the role's defaults/main.yml."""
    return cast("dict[str, object]", load(ROLE / "defaults" / "main.yml"))


def tasks() -> list[dict[str, object]]:
    """Return the role's tasks."""
    return cast("list[dict[str, object]]", load(ROLE / "tasks" / "main.yml"))


def render(text: str, variables: Mapping[str, object] | None = None) -> str:
    """Render a Jinja text with the role's vars, defaults and any extra values.

    The role's own variables hold templates of each other, so they are resolved a few passes deep.
    """
    merged: dict[str, object] = {
        "role_path": str(ROLE),
        **role_defaults(),
        **role_vars(),
        **(variables or {}),
    }
    # Ansible text and unit files, never HTML, so there is nothing to escape.
    environment = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["to_nice_json"] = _to_nice_json
    for _ in range(5):
        merged = {key: _render_value(environment, value, merged) for key, value in merged.items()}
    return environment.from_string(text).render(**merged)


def _to_nice_json(value: object, indent: int = 4) -> str:
    """Stand in for Ansible's filter of the same name: sorted keys, the given indent."""
    import json  # noqa: PLC0415 - used by this one stand-in

    return json.dumps(value, indent=indent, sort_keys=True)


def _render_value(
    environment: jinja2.Environment, value: object, scope: dict[str, object]
) -> object:
    """Render a string, or each string of a list, against the scope."""
    if isinstance(value, str) and "{{" in value:
        return environment.from_string(value).render(**scope)
    if isinstance(value, list):
        return [_render_value(environment, item, scope) for item in value]
    return value


def resolved_list(template: str) -> list[str]:
    """Return the items of a loop that is `{{ some_role_list }}`, each rendered as a string."""
    name = template.strip().removeprefix("{{").removesuffix("}}").strip()
    merged = {**role_defaults(), **role_vars()}
    return [render(str(item)) for item in cast("list[object]", merged[name])]


def unit_keys(text: str) -> list[tuple[str, str]]:
    """Return each Key=value line of a unit file as a pair, in file order."""
    return [
        (line.split("=", 1)[0], line.split("=", 1)[1])
        for line in text.splitlines()
        if "=" in line and not line.lstrip().startswith("#") and not line.startswith("[")
    ]


def module_of(task: dict[str, object]) -> str | None:
    """Return the short name of the module a task calls, or None for a block."""
    keywords = {
        "name", "when", "loop", "loop_control", "register", "notify", "no_log", "diff",
        "failed_when", "changed_when", "check_mode", "tags", "vars", "block", "rescue",
        "always", "become", "environment", "delegate_to", "until", "retries", "delay",
    }  # fmt: skip
    for key in task:
        if key not in keywords:
            return str(key).rsplit(".", 1)[-1]
    return None


def named(name_start: str) -> dict[str, object]:
    """Return the one task whose name starts with the text.

    Raises:
        AssertionError: when no task, or more than one, matches.
    """
    found = [t for t in tasks() if str(t.get("name", "")).startswith(name_start)]
    if len(found) != 1:
        message = f"{len(found)} tasks start with {name_start!r}"
        raise AssertionError(message)
    return found[0]


def make_key(directory: Path, name: str) -> tuple[Path, str]:
    """Make an ed25519 key pair with the host's ssh-keygen; return the private path and the
    public key line without its comment."""
    private = directory / name
    subprocess.run(  # noqa: S603 - the host's own tool, over a scratch directory
        [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(private)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    fields = (directory / f"{name}.pub").read_text(encoding="utf-8").split()
    return private, f"{fields[0]} {fields[1]}"


def sign(private: Path, namespace: str, body: bytes) -> bytes:
    """Sign a body the way the ledger's writer does; return the signature."""
    body_path = private.parent / f"{private.name}.body"
    body_path.write_bytes(body)
    subprocess.run(  # noqa: S603 - the host's own tool, over a scratch directory
        [SSH_KEYGEN, "-Y", "sign", "-q", "-f", str(private), "-n", namespace, str(body_path)],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    return Path(f"{body_path}.sig").read_bytes()


class InputTests(unittest.TestCase):
    def test_the_spec_names_exactly_the_two_inputs_and_both_default_to_empty(self) -> None:
        spec = cast(
            "dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]",
            load(ROLE / "meta" / "argument_specs.yml"),
        )
        options = spec["argument_specs"]["main"]["options"]
        self.assertEqual(sorted(options), sorted(INPUTS))
        defaults = role_defaults()
        for name in INPUTS:
            with self.subTest(name=name):
                self.assertEqual(options[name]["default"], "")
                self.assertEqual(defaults[name], "")
                self.assertEqual(options[name]["type"], "str")
                self.assertNotIn("no_log", options[name], "both inputs are public data")

    def test_the_spec_accepts_the_defaults_and_refuses_an_unknown_input(self) -> None:
        spec = cast(
            "dict[str, dict[str, dict[str, object]]]", load(ROLE / "meta" / "argument_specs.yml")
        )
        options = spec["argument_specs"]["main"]["options"]
        validator = ArgumentSpecValidator(options)
        self.assertFalse(validator.validate({}).error_messages)
        self.assertTrue(validator.validate({"promote_host_push_remote": "x"}).error_messages)

    def test_a_signer_key_pattern_takes_one_ed25519_line_and_nothing_else(self) -> None:
        pattern = cast("str", role_vars()["promote_host_key_pattern"])
        with tempfile.TemporaryDirectory() as scratch:
            _, good = make_key(Path(scratch), "signer")
        self.assertTrue(re.match(pattern, good), "a real ed25519 public key must be accepted")
        bad = {
            "a trailing newline": good + "\n",
            "a comment": good + " someone@host",
            "a leading option": 'command="x" ' + good,
            "another key type": good.replace("ssh-ed25519", "ssh-rsa", 1),
            "a second line": good + "\n" + good,
            "a truncated key": good[:-4],
            "a longer key": good + "AAAA",
            "an empty line": "",
            "a space before": " " + good,
        }
        for label, value in bad.items():
            with self.subTest(label):
                self.assertFalse(re.match(pattern, value), f"{label} must be refused")

    def test_a_ledger_url_pattern_takes_one_plain_https_address_and_nothing_else(self) -> None:
        pattern = cast("str", role_vars()["promote_host_url_pattern"])
        self.assertTrue(re.match(pattern, LEDGER_URL))
        self.assertTrue(re.match(pattern, "https://ledger.example.invalid:8443/a/b.json"))
        bad = {
            "plain http": "http://example.invalid/ledger.json",
            "a user name": "https://user@example.invalid/ledger.json",
            "a query": "https://example.invalid/ledger.json?x=1",
            "a fragment": "https://example.invalid/ledger.json#x",
            "a space": "https://example.invalid/a b",
            "a quote": 'https://example.invalid/a"b',
            "a dollar": "https://example.invalid/a$b",
            "a hash": "https://example.invalid/a#b",
            "a backslash": "https://example.invalid/a\\b",
            "a trailing newline": LEDGER_URL + "\n",
            "a file URL": "file:///etc/passwd",
        }
        for label, value in bad.items():
            with self.subTest(label):
                self.assertFalse(re.match(pattern, value), f"{label} must be refused")

    def test_each_input_has_its_own_refusal_and_the_pair_is_both_or_neither(self) -> None:
        by_name = {str(t.get("name")): t for t in tasks()}
        url = by_name["Refuse a ledger URL that is set and is not an https URL with no credential"]
        key = by_name["Refuse a signer key that is set and is not one ed25519 public key line"]
        for task, variable, pattern in (
            (url, "promote_host_ledger_url", "promote_host_url_pattern"),
            (key, "promote_host_signer_key", "promote_host_key_pattern"),
        ):
            with self.subTest(variable):
                body = cast("dict[str, list[str]]", task["ansible.builtin.assert"])["that"]
                joined = " ".join(body)
                self.assertIn(f"{variable} is string", joined)
                self.assertIn(f"is match({pattern})", joined)
        url_alone = named("Refuse a ledger URL with no signer key")
        key_alone = named("Refuse a signer key with no ledger URL")
        self.assertIn("promote_host_signer_key | length > 0", str(url_alone))
        self.assertIn("promote_host_ledger_url | length > 0", str(key_alone))
        for task in (url, key, url_alone, key_alone):
            message = str(cast("dict[str, object]", task["ansible.builtin.assert"])["fail_msg"])
            for value in (LEDGER_URL, "ssh-ed25519"):
                self.assertNotIn(value, message, "a refusal names the input, never a value")
            self.assertEqual(
                cast("dict[str, object]", task["ansible.builtin.assert"])["quiet"], True
            )


class ProgramAgreementTests(unittest.TestCase):
    """The role and the applier name one set of paths, one signer and one namespace."""

    def test_every_path_the_role_fixes_is_the_one_the_program_defaults_to(self) -> None:
        variables = role_vars()
        self.assertEqual(variables["promote_host_allowed_signers_path"], BP.ALLOWED_SIGNERS)
        self.assertEqual(variables["promote_host_slots_path"], BP.SLOT_MAP)
        self.assertEqual(variables["promote_host_state_dir"], BP.STATE_DIR)
        self.assertEqual(variables["promote_host_wrapper_path"], BP.WRAPPER)
        self.assertEqual(variables["promote_host_config_dir"], BP.CONFIG_DIR)

    def test_the_signer_name_and_the_namespace_are_the_programs(self) -> None:
        variables = role_vars()
        self.assertEqual(variables["promote_host_signer_principal"], BP.SIGNER_IDENTITY)
        self.assertEqual(variables["promote_host_ledger_namespace"], BP.NAMESPACE)

    def test_the_unit_runs_the_program_with_the_ledger_url_and_nothing_that_moves_a_path(
        self,
    ) -> None:
        keys = dict(unit_keys(SERVICE.read_text(encoding="utf-8")))
        argv = shlex.split(keys["ExecStart"].replace("${PROMOTE_LEDGER_URL}", LEDGER_URL))
        self.assertEqual(argv[0], role_vars()["promote_host_program_path"])
        captured: list[dict[str, object]] = []

        def run_once_stub(config: object, **_: object) -> int:
            captured.append(dataclasses.asdict(cast("DataclassInstance", config)))
            return 0

        with mock.patch.object(BP, "run_once", side_effect=run_once_stub):
            self.assertEqual(BP.main(argv), 0)
        config = captured[0]
        # Every option other than the URL keeps the program's own default, so the trust anchors
        # the unit reads are the ones the role placed and the unit can name no other.
        self.assertEqual(config["ledger_url"], LEDGER_URL)
        self.assertEqual(config["allowed_signers"], BP.ALLOWED_SIGNERS)
        self.assertEqual(config["slot_map"], BP.SLOT_MAP)
        self.assertEqual(config["state_dir"], BP.STATE_DIR)
        self.assertEqual(config["wrapper"], BP.WRAPPER)
        self.assertEqual(argv[1:], ["--ledger-url", LEDGER_URL], "the unit passes the URL only")

    def test_the_installed_program_is_the_one_in_hetzner_provision(self) -> None:
        variables = role_vars()
        directory = Path(render("{{ promote_host_programs_dir }}")).resolve()
        self.assertEqual(directory, PROVISION.resolve())
        source = directory / str(variables["promote_host_program_source"])
        self.assertTrue(source.is_file())
        self.assertEqual(source.read_bytes()[:25], b'#!/usr/bin/python3 -I\n"""')
        install = named("Install the applier")
        copy = cast("dict[str, str]", install["ansible.builtin.copy"])
        self.assertEqual(
            copy["src"], "{{ promote_host_programs_dir }}/{{ promote_host_program_source }}"
        )
        self.assertEqual(copy["dest"], "{{ promote_host_program_path }}")
        self.assertEqual((copy["owner"], copy["group"]), ("root", "root"))
        self.assertEqual(role_vars()["promote_host_program_mode"], "0755")

    def test_the_website_slot_is_a_row_the_applier_accepts_for_the_real_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            wrapper_path = Path(scratch) / "branchleft-deploy"
            shutil.copyfile(PROVISION / "branchleft_deploy.py", wrapper_path)
            wrapper_path.chmod(0o644)
            wrapper = BP.load_wrapper(str(wrapper_path), trusted_uid=os.getuid())
            slots_path = Path(scratch) / "slots.json"
            template = (ROLE / "templates" / "slots.json.j2").read_text(encoding="utf-8")
            slots_path.write_text(render(template), encoding="utf-8")
            slots_path.chmod(0o644)
            slot_map = BP.load_slot_map(str(slots_path), wrapper, trusted_uid=os.getuid())
        self.assertEqual(slot_map, {30999: "website"})
        self.assertIn(30999, BP.SLOT_UIDS)
        self.assertEqual(max(BP.SLOT_UIDS), 30999, "the website holds the top of the range")


class SignerTests(unittest.TestCase):
    """The signer file the role writes is a trust anchor the program's own check accepts."""

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="promote-host-test-"))
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        self.private, self.public = make_key(self.scratch, "ledger-signer")
        template = (ROLE / "templates" / "allowed_signers.j2").read_text(encoding="utf-8")
        self.signers = self.scratch / "allowed_signers"
        self.signers.write_text(render(template, {"promote_host_signer_key": self.public}))

    def verify(self, body: bytes, signature: bytes) -> str | None:
        """Return the program's refusal, or None when it accepts the signature."""
        try:
            BP.verify_signature(body, signature, str(self.signers))
        except BP.LedgerRefused as error:
            return str(error)
        return None

    def test_the_signer_file_is_one_line_naming_one_principal_one_namespace_and_one_key(
        self,
    ) -> None:
        lines = self.signers.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(
            lines[0],
            f'{BP.SIGNER_IDENTITY} namespaces="{BP.NAMESPACE}" {self.public}',
        )

    def test_a_ledger_signed_by_the_placed_key_in_the_ledger_namespace_is_accepted(self) -> None:
        body = b'{"v":1}'
        self.assertIsNone(self.verify(body, sign(self.private, BP.NAMESPACE, body)))

    def test_a_ledger_signed_by_another_key_is_refused(self) -> None:
        other, _ = make_key(self.scratch, "someone-else")
        body = b'{"v":1}'
        self.assertIsNotNone(self.verify(body, sign(other, BP.NAMESPACE, body)))

    def test_the_placed_key_cannot_sign_for_another_namespace(self) -> None:
        # The namespace restriction in the signer file is what stops a signature the key made for
        # another purpose (git, a file, a certificate) from passing as a ledger.
        body = b'{"v":1}'
        self.assertIsNotNone(self.verify(body, sign(self.private, "git", body)))
        self.assertIsNotNone(self.verify(body, sign(self.private, "file", body)))

    def test_a_body_changed_after_signing_is_refused(self) -> None:
        signature = sign(self.private, BP.NAMESPACE, b'{"v":1}')
        self.assertIsNotNone(self.verify(b'{"v":2}', signature))


class UnitTests(unittest.TestCase):
    def test_the_timer_is_inert_by_default_and_its_state_follows_the_ledger_url(self) -> None:
        task = named("Hold the timer to the state the inputs ask for")
        service = cast("dict[str, str]", task["ansible.builtin.systemd_service"])
        self.assertEqual(service["enabled"], "{{ promote_host_ledger_url | length > 0 }}")
        self.assertIn(
            "'started' if promote_host_ledger_url | length > 0 else 'stopped'", service["state"]
        )
        self.assertEqual(task["when"], "promote_host_timer_stat.stat.exists")
        self.assertEqual(role_defaults()["promote_host_ledger_url"], "")

    def test_the_service_names_the_files_the_role_writes_and_runs_only_on_a_trusted_host(
        self,
    ) -> None:
        text = SERVICE.read_text(encoding="utf-8")
        pairs = unit_keys(text)
        values: dict[str, list[str]] = {}
        for key, value in pairs:
            values.setdefault(key, []).append(value)
        self.assertEqual(values["EnvironmentFile"], [role_vars()["promote_host_env_path"]])
        self.assertEqual(
            sorted(values["ConditionPathExists"]),
            sorted(
                [
                    str(role_vars()["promote_host_allowed_signers_path"]),
                    str(role_vars()["promote_host_wrapper_path"]),
                ]
            ),
        )
        self.assertEqual(values["Type"], ["oneshot"])
        self.assertIn("NoNewPrivileges", values)
        self.assertNotIn("User", values, "the applier runs as root, as the wrapper does")

    def test_the_timer_runs_the_service_and_is_wanted_by_timers(self) -> None:
        pairs = dict(unit_keys(TIMER.read_text(encoding="utf-8")))
        self.assertEqual(pairs["Unit"], role_vars()["promote_host_service_unit"])
        self.assertEqual(pairs["WantedBy"], "timers.target")
        self.assertIn("OnUnitInactiveSec", pairs)

    def test_the_units_name_no_model_key_agent_program_or_push_route(self) -> None:
        for path in (SERVICE, TIMER):
            text = "\n".join(
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("#")
            )
            for word in FORBIDDEN_UNIT_WORDS:
                with self.subTest(path=path.name, word=word):
                    self.assertNotIn(word, text)

    def test_the_environment_file_holds_the_ledger_url_and_nothing_else(self) -> None:
        template = (ROLE / "templates" / "promote.env.j2").read_text(encoding="utf-8")
        text = render(template, {"promote_host_ledger_url": LEDGER_URL})
        names = [
            line.split("=", 1)[0]
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(names, ENV_NAMES)
        self.assertIn(f"PROMOTE_LEDGER_URL={LEDGER_URL}\n", text)
        self.assertIn("${PROMOTE_LEDGER_URL}", SERVICE.read_text(encoding="utf-8"))

    def test_the_unit_files_carry_nothing_the_plan_scan_reads_as_a_credential(self) -> None:
        # The plan's diff is withheld from the approver when a line looks like a credential
        # assignment; none of this role's files should trip it, so the diff is always shown.
        scan = re.compile(
            r"(passw(or)?d|passphrase|secret|token|api key|private key|credential)\s*[:=]\s*\S",
            re.IGNORECASE,
        )
        for path in sorted(ROLE.glob("files/*")) + sorted(ROLE.glob("templates/*")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                with self.subTest(path=path.name, line=number):
                    self.assertIsNone(scan.search(line), line)


class TaskTests(unittest.TestCase):
    def test_the_role_uses_no_shell_command_or_reader_of_other_files(self) -> None:
        for task in tasks():
            with self.subTest(task=task.get("name")):
                self.assertNotIn(module_of(task), FORBIDDEN_MODULES)

    def test_every_path_the_role_writes_is_its_own(self) -> None:
        written = 0
        for task in tasks():
            module = module_of(task)
            if module not in WRITING_MODULES:
                continue
            arguments = cast("dict[str, str]", task[next(k for k in task if k.endswith(module))])
            template = arguments.get("dest", arguments.get("path", ""))
            # A loop over one of the role's own lists writes one path for each item.
            items = resolved_list(str(task["loop"])) if "loop" in task else [""]
            for item in items:
                destination = render(template, {"item": item})
                written += 1
                with self.subTest(task=task.get("name"), path=destination):
                    self.assertTrue(destination.startswith(ALLOWED_PREFIXES), destination)
        self.assertGreaterEqual(written, 7)

    def test_the_signer_file_is_removed_when_no_signer_is_set_and_written_when_one_is(self) -> None:
        write = named("Write the signer file")
        remove = named("Remove the signer file when no signer is set")
        self.assertEqual(write["when"], "promote_host_signer_key | length > 0")
        self.assertEqual(remove["when"], "promote_host_signer_key | length == 0")
        removal = cast("dict[str, str]", remove["ansible.builtin.file"])
        self.assertEqual(removal["state"], "absent")
        self.assertEqual(removal["path"], "{{ promote_host_allowed_signers_path }}")

    def test_the_state_directory_is_root_only_and_the_signer_file_is_not_writable_by_others(
        self,
    ) -> None:
        state = cast("dict[str, str]", named("Make the state directory")["ansible.builtin.file"])
        self.assertEqual((state["owner"], state["mode"]), ("root", "0700"))
        signer = cast("dict[str, str]", named("Write the signer file")["ansible.builtin.template"])
        self.assertEqual(
            (signer["owner"], signer["group"], signer["mode"]), ("root", "root", "0644")
        )
        slots = cast("dict[str, str]", named("Write the slot map")["ansible.builtin.template"])
        self.assertEqual((slots["owner"], slots["group"], slots["mode"]), ("root", "root", "0644"))

    def test_the_role_asserts_its_parents_and_never_makes_them(self) -> None:
        parents = cast("list[str]", role_vars()["promote_host_parents"])
        self.assertEqual(parents, ["/etc/branchleft", "/var/lib/branchleft"])
        made = [
            render(cast("dict[str, str]", t["ansible.builtin.file"])["path"])
            for t in tasks()
            if module_of(t) == "file"
        ]
        for parent in parents:
            self.assertNotIn(parent, made)

    def test_the_role_imports_no_other_role(self) -> None:
        text = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertNotIn("include_role", text)
        self.assertNotIn("import_role", text)
        self.assertFalse(
            (ROLE / "meta" / "main.yml").read_text(encoding="utf-8").count("dependencies")
        )


if __name__ == "__main__":
    unittest.main()
