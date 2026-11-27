"""The role's contract for the restricted export account.

What the key line, the sudoers rule and the sshd settings say, and that they and the program name
the same thing and nothing else. The program's own behaviour is `test_export_entry.py`, and the
forced command as a real sshd serves it is the Molecule `entry` scenario's. This file holds what
joins them: the three layers (the key's options, the sudoers rule, the program) each name the one
program; the values the program copies from other places still match them; every task that handles
the key hides it; and the key goes in last.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import export_entry as entry
import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "B" * 43


def as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"not a mapping: {value!r}")
    return {str(key): item for key, item in value.items()}


def as_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AssertionError(f"not a list: {value!r}")
    return value


def load(path: Path) -> dict[str, object]:
    return as_dict(yaml.safe_load(path.read_text(encoding="utf-8")))


CONSTANTS = load(ROLE / "vars" / "main.yml")


def render(name: str) -> str:
    # Text files, not HTML: escaping would change the line under test.
    env = jinja2.Environment(  # noqa: S701
        undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    template = env.from_string((ROLE / "templates" / name).read_text(encoding="utf-8"))
    values: dict[str, object] = {
        key: value for key, value in CONSTANTS.items() if key.startswith("export_bundler_entry_")
    }
    values["export_bundler_controller_key"] = SSH_KEY
    return template.render(values)


def entry_tasks() -> list[dict[str, object]]:
    """Every task of _entry.yml, blocks and rescues flattened, in file order."""
    flat: list[dict[str, object]] = []

    def walk(items: list[object]) -> None:
        for item in items:
            task = as_dict(item)
            for section in ("block", "rescue", "always"):
                if section in task:
                    walk(as_list(task[section]))
            flat.append(task)

    walk(as_list(yaml.safe_load((ROLE / "tasks" / "_entry.yml").read_text(encoding="utf-8"))))
    return flat


class ThreeLayersNameOneProgram(unittest.TestCase):
    program = str(CONSTANTS["export_bundler_entry_program_path"])
    sudo = str(CONSTANTS["export_bundler_entry_sudo_path"])

    def test_the_key_line_is_one_restricted_forced_command_and_the_key(self) -> None:
        self.assertEqual(
            f'restrict,command="{self.sudo} -n {self.program}" {SSH_KEY}\n',
            render("authorized_keys.j2"),
        )

    def test_the_key_line_carries_no_option_that_widens_it(self) -> None:
        line = render("authorized_keys.j2")
        for widening in ("permitopen", "port-forwarding", "pty", "agent-forwarding", "environment"):
            self.assertNotIn(widening, line)

    def test_the_sudoers_rule_is_the_one_program_with_no_argument(self) -> None:
        rules = [
            line for line in render("sudoers.j2").splitlines() if line and not line.startswith("#")
        ]
        account = str(CONSTANTS["export_bundler_entry_account"])
        self.assertEqual(
            [
                f'Defaults:{account} env_keep += "SSH_ORIGINAL_COMMAND"',
                f'{account} ALL=(root) NOPASSWD: {self.program} ""',
            ],
            rules,
        )

    def test_the_sshd_settings_force_the_same_command_and_turn_everything_else_off(self) -> None:
        text = render("sshd-drop-in.conf.j2")
        self.assertIn(f"ForceCommand {self.sudo} -n {self.program}\n", text)
        for line in (
            "AuthenticationMethods publickey",
            "AllowTcpForwarding no",
            "AllowAgentForwarding no",
            "AllowStreamLocalForwarding no",
            "GatewayPorts no",
            "X11Forwarding no",
            "PermitTTY no",
            "PermitTunnel no",
            "PermitUserRC no",
        ):
            self.assertIn(f"    {line}\n", text)
        self.assertTrue(text.rstrip().endswith("Match all"))

    def test_the_program_is_installed_at_the_path_the_rule_and_the_key_name(self) -> None:
        installs = [
            task
            for task in entry_tasks()
            if "ansible.builtin.copy" in task
            and as_dict(task["ansible.builtin.copy"]).get("src")
            == "{{ export_bundler_entry_program_source }}"
        ]
        self.assertEqual(1, len(installs))
        copy = as_dict(installs[0]["ansible.builtin.copy"])
        self.assertEqual("{{ export_bundler_entry_program_path }}", copy["dest"])
        self.assertEqual("0755", copy["mode"])
        self.assertTrue(
            (ROLE / "files" / str(CONSTANTS["export_bundler_entry_program_source"])).is_file()
        )

    def test_the_sudoers_file_is_checked_strictly_and_is_not_writable(self) -> None:
        sudoers = [
            as_dict(task["ansible.builtin.template"])
            for task in entry_tasks()
            if "ansible.builtin.template" in task
            and as_dict(task["ansible.builtin.template"]).get("src") == "sudoers.j2"
        ]
        self.assertEqual(1, len(sudoers))
        self.assertEqual("/usr/sbin/visudo -csf %s", sudoers[0]["validate"])
        self.assertEqual("0440", sudoers[0]["mode"])
        # sudo ignores a file name with a dot or ending in a tilde.
        self.assertRegex(
            Path(str(CONSTANTS["export_bundler_entry_sudoers_path"])).name, r"^[A-Za-z0-9_-]+$"
        )

    def test_the_key_file_and_its_directory_are_root_s_and_closed_to_the_account(self) -> None:
        for task in entry_tasks():
            copy = task.get("ansible.builtin.template")
            if isinstance(copy, dict) and copy.get("src") in (
                "authorized_keys.j2",
                "sshd-drop-in.conf.j2",
            ):
                self.assertEqual("root", copy["owner"])
                self.assertEqual("root", copy["group"])
                self.assertEqual("0644", copy["mode"])
        keys_dir = str(CONSTANTS["export_bundler_entry_keys_dir"])
        self.assertEqual(
            keys_dir + "/authorized_keys", CONSTANTS["export_bundler_entry_authorized_keys_path"]
        )
        self.assertFalse(
            str(CONSTANTS["export_bundler_entry_authorized_keys_path"]).startswith(
                str(CONSTANTS["export_bundler_entry_home"])
            )
        )


class WhatTheRoleHandles(unittest.TestCase):
    def test_every_task_that_handles_the_key_hides_it(self) -> None:
        for task in entry_tasks():
            text = yaml.safe_dump(task)
            handles = "export_bundler_controller_key" in text or "authorized_keys.j2" in text
            if handles and "when" not in task and "block" not in task:
                self.assertIs(True, task.get("no_log"), task.get("name"))
        key_file = [
            task
            for task in entry_tasks()
            if as_dict(task.get("ansible.builtin.template", {})).get("src") == "authorized_keys.j2"
        ]
        self.assertEqual(1, len(key_file))
        self.assertIs(False, key_file[0]["diff"])

    def test_the_key_and_the_sshd_settings_go_in_after_the_account_the_program_and_the_rule(
        self,
    ) -> None:
        names = [str(task.get("name")) for task in entry_tasks()]

        def at(fragment: str) -> int:
            hits = [i for i, name in enumerate(names) if fragment in name]
            self.assertEqual(1, len(hits), fragment)
            return hits[0]

        key = at("Write the account's key with its restrictions")
        for earlier in (
            "Make the account the controller",
            "Install the forced-command program",
            "Let the account run",
        ):
            self.assertLess(at(earlier), key, earlier)
        self.assertLess(
            at("Ask Docker which server version"), at("Make the account the controller")
        )
        self.assertLess(at("Refuse a Docker older than 28"), at("Make the account the controller"))
        self.assertLess(at("Refuse a controller key that is not"), at("Ask Docker"))

    def test_a_refused_sshd_check_takes_the_key_and_the_settings_back_out(self) -> None:
        text = (ROLE / "tasks" / "_entry.yml").read_text(encoding="utf-8")
        self.assertIn("rescue:", text)
        rescue = text[text.index("rescue:") :]
        self.assertIn("export_bundler_entry_authorized_keys_path", rescue)
        self.assertIn("export_bundler_entry_sshd_dropin", rescue)
        self.assertIn("state: absent", rescue)

    def test_docker_28_is_the_floor_and_the_check_reads_the_server(self) -> None:
        self.assertEqual(28, CONSTANTS["export_bundler_entry_docker_min_major"])
        self.assertIn(
            "Server.Version", str(CONSTANTS["export_bundler_entry_docker_version_format"])
        )
        self.assertEqual("/usr/bin/docker", CONSTANTS["export_bundler_entry_docker"])

    def test_an_unset_key_is_the_off_state_and_changes_nothing_but_the_two_files(self) -> None:
        off = [t for t in entry_tasks() if t.get("when") == "not export_bundler_entry_on"]
        self.assertEqual(1, len(off))
        self.assertEqual("absent", as_dict(off[0]["ansible.builtin.file"])["state"])
        on = [t for t in entry_tasks() if t.get("when") == "export_bundler_entry_on"]
        self.assertEqual(1, len(on), "everything that writes sits in the one block that is on")

    def test_the_input_is_declared_optional_secret_and_without_a_default(self) -> None:
        specs = load(ROLE / "meta" / "argument_specs.yml")
        options = as_dict(as_dict(as_dict(specs["argument_specs"])["main"])["options"])
        spec = as_dict(options["export_bundler_controller_key"])
        self.assertIs(True, spec["no_log"])
        self.assertNotIn("required", spec)
        self.assertNotIn("default", spec)
        self.assertNotIn("export_bundler_controller_key", load(ROLE / "defaults" / "main.yml"))

    def test_the_key_pattern_is_the_estates_one_line_ed25519_shape(self) -> None:
        pattern = str(CONSTANTS["export_bundler_entry_key_pattern"])
        self.assertTrue(re.match(pattern, SSH_KEY))
        for bad in (
            SSH_KEY + " comment",
            "no-pty " + SSH_KEY,
            SSH_KEY + "\n",
            SSH_KEY + "\n" + SSH_KEY,
        ):
            self.assertIsNone(re.match(pattern, bad), bad)


class ValuesCopiedFromElsewhere(unittest.TestCase):
    def test_the_node_path_is_the_one_broker_deploy_installs(self) -> None:
        broker = load(ROLES / "broker_deploy" / "defaults" / "main.yml")
        self.assertEqual(f"{broker['broker_deploy_node_dir']}/bin/node", entry.NODE)
        self.assertEqual(entry.NODE, CONSTANTS["export_bundler_entry_node"])

    def test_the_program_s_directories_are_the_roles_own(self) -> None:
        defaults = load(ROLE / "defaults" / "main.yml")
        self.assertEqual(defaults["export_bundler_dir"], entry.BUNDLER_DIR)
        self.assertEqual(defaults["export_bundler_state_dir"], entry.STATE_DIR)

    def test_the_state_subdirectories_the_program_names_are_the_ones_the_role_makes(self) -> None:
        subdirectories = [str(path) for path in as_list(CONSTANTS["export_bundler_state_subdirs"])]
        self.assertEqual(
            [f"{{{{ export_bundler_state_dir }}}}/{name}" for name in ("flags", "out")],
            subdirectories,
        )

    def test_the_lock_is_in_a_directory_only_root_writes(self) -> None:
        self.assertEqual("/run/lock", str(Path(entry.LOCK_PATH).parent))

    def test_the_program_is_a_forced_command_for_this_one_account_and_installs_under_sbin(
        self,
    ) -> None:
        self.assertEqual(
            "/usr/local/sbin/branchleft-export-entry",
            CONSTANTS["export_bundler_entry_program_path"],
        )
        self.assertEqual("promoexport", CONSTANTS["export_bundler_entry_account"])


if __name__ == "__main__":
    unittest.main()
