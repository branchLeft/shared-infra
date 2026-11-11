"""Tests that hold the drain list to what the role writes: one descriptor for each listed host.

The collector drains exactly the hosts its descriptor directory names, and nothing else names a
host. So the directory is the drain list, and these tests judge the role by what it leaves there.
They run the role's own tasks (the host checks and the descriptor writes and removals, taken from
`tasks/main.yml` as shipped) with Ansible on this machine, against a scratch directory. They touch
no host. The directory is then read the way the collector reads it.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast

import jinja2
from ansible.plugins.filter.core import FilterModule
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
TEMPLATE = ROLE / "templates" / "descriptor.json.j2"
SUFFIX = ".json"
# The tasks that handle the drain list, by the start of their names. The play runs these and no
# others, so the account, the unit and the other directories are not part of what is judged here.
TASK_STARTS = (
    "Refuse a demo mail domain",
    "Refuse a host list",
    "Refuse a host entry",
    "Refuse two hosts",
    "Refuse a demo host",
    "Make the descriptor directory",
    "Write each listed host",
    "Look for descriptor files",
    "Remove every descriptor",
)
DEMO = {"slug": "demo1", "kind": "demo", "app_host_ip": "10.20.1.100"}
APP = {"slug": "app1", "kind": "tenant", "app_host_ip": "10.20.1.101"}
DEMO_DOMAIN = "demo.example"
# The keys the collector's reader needs of a descriptor, and the only keys the role writes.
DESCRIPTOR_KEYS = ["appHostIp", "expiresAt", "kind", "slug"]
RUN_SECONDS = 120


def ansible_playbook() -> str:
    """Return the path of the ansible-playbook that belongs to the interpreter running the tests.

    Raises:
        AssertionError: when there is none, which is a failure and never a skip.
    """
    beside = Path(sys.executable).parent / "ansible-playbook"
    found = str(beside) if beside.is_file() else shutil.which("ansible-playbook")
    if found is None:
        message = "no ansible-playbook beside the interpreter or on the path"
        raise AssertionError(message)
    return found


def role_tasks() -> list[dict[str, object]]:
    """Return the role's tasks."""
    return cast("list[dict[str, object]]", YAML(typ="safe").load(TASKS.read_text(encoding="utf-8")))


def play_tasks() -> list[dict[str, object]]:
    """Return the drain-list tasks as shipped, without the root owner a scratch run cannot set.

    Dropping the owner and group is the one change. The scratch directory belongs to whoever runs
    the test; the real run sets root, and the Molecule scenario checks that on a host.
    """
    picked = [t for t in role_tasks() if str(t.get("name", "")).startswith(TASK_STARTS)]
    for task in picked:
        for value in task.values():
            if isinstance(value, dict):
                value.pop("owner", None)
                value.pop("group", None)
        template = task.get("ansible.builtin.template")
        if isinstance(template, dict):
            template["src"] = str(TEMPLATE)
    return picked


class Result:
    """What one run of the play did."""

    def __init__(self, returncode: int, output: str) -> None:
        self.returncode = returncode
        self.output = output

    @property
    def failed(self) -> bool:
        """Whether the run stopped."""
        return self.returncode != 0

    def recap(self, name: str) -> int:
        """Return the number in the recap line for the name, such as changed."""
        recap = [line for line in self.output.splitlines() if line.startswith("localhost ")][-1]
        return int(recap.split(f"{name}=", 1)[1].split()[0])


class Scratch:
    """A scratch descriptor directory and the play that runs the role's tasks against it."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="mail-collector-descriptors-"))
        test.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.directory = self.home / "descriptors"
        self.play = self.home / "play.yml"
        writer = YAML()
        writer.default_flow_style = False
        play = [
            {
                "name": "Drain list",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                "vars_files": [
                    str(ROLE / "vars" / "main.yml"),
                    str(ROLE / "defaults" / "main.yml"),
                ],
                "tasks": play_tasks(),
            }
        ]
        with self.play.open("w", encoding="utf-8") as handle:
            writer.dump(play, handle)

    def run(self, hosts: object, domain: str = "", *, check: bool = False) -> Result:
        """Run the play with a host list and a demo mail domain."""
        values = self.home / "values.json"
        values.write_text(
            json.dumps(
                {
                    "mail_collector_descriptor_dir": str(self.directory),
                    "mail_collector_hosts": hosts,
                    "mail_collector_demo_mail_domain": domain,
                    "ansible_python_interpreter": sys.executable,
                }
            ),
            encoding="utf-8",
        )
        command = [ansible_playbook(), "-i", "localhost,", str(self.play), "-e", f"@{values}"]
        if check:
            command.append("--check")
        environment = {
            **os.environ,
            "ANSIBLE_HOME": str(self.home / "home"),
            "ANSIBLE_LOCAL_TEMP": str(self.home / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOST_KEY_CHECKING": "false",
        }
        run = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
            timeout=RUN_SECONDS,
        )
        return Result(run.returncode, run.stdout + run.stderr)

    def files(self) -> list[str]:
        """Return the names in the descriptor directory, or none if it is not there."""
        if not self.directory.is_dir():
            return []
        return sorted(path.name for path in self.directory.iterdir())

    def put(self, name: str, text: str) -> None:
        """Put a file in the descriptor directory, as a stale or foreign one."""
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / name).write_text(text, encoding="utf-8")

    def drain_list(self) -> list[str]:
        """Return the hosts the collector would drain from the directory, as it reads it.

        This is the collector's shape check (`hasValidShapeForDraining` in its descriptor store):
        a .json file, a kind of demo or tenant, a non-empty slug and address, and an expiry that
        is null or text. A file that fails it names no host.
        """
        named: list[str] = []
        for name in self.files():
            if not name.endswith(SUFFIX):
                continue
            try:
                value = json.loads((self.directory / name).read_text(encoding="utf-8"))
            except ValueError:
                continue
            if not isinstance(value, dict):
                continue
            slug, address = value.get("slug"), value.get("appHostIp")
            expires = value.get("expiresAt")
            if (
                value.get("kind") in {"demo", "tenant"}
                and isinstance(slug, str)
                and slug
                and isinstance(address, str)
                and address
                and (expires is None or isinstance(expires, str))
            ):
                named.append(f"{slug}={address}")
        return sorted(named)


class DrainListTests(unittest.TestCase):
    """The directory the collector reads is the list the role was given, and no more."""

    def setUp(self) -> None:
        self.scratch = Scratch(self)

    def test_a_host_is_missing_from_the_drain_list_until_it_is_in_the_list_and_written(
        self,
    ) -> None:
        # Red, then green. With only the tenant listed the collector would never drain the demo
        # host; the check below is the one that goes red if a host the estate needs is not named.
        first = self.scratch.run([APP])
        self.assertFalse(first.failed, first.output)
        self.assertEqual(self.scratch.drain_list(), ["app1=10.20.1.101"])
        self.assertNotIn("demo1=10.20.1.100", self.scratch.drain_list())
        second = self.scratch.run([DEMO, APP], DEMO_DOMAIN)
        self.assertFalse(second.failed, second.output)
        self.assertEqual(self.scratch.drain_list(), ["app1=10.20.1.101", "demo1=10.20.1.100"])

    def test_a_second_run_changes_nothing(self) -> None:
        self.assertFalse(self.scratch.run([DEMO, APP], DEMO_DOMAIN).failed)
        again = self.scratch.run([DEMO, APP], DEMO_DOMAIN)
        self.assertFalse(again.failed, again.output)
        self.assertEqual(again.recap("changed"), 0)

    def test_a_host_that_leaves_the_list_leaves_the_drain_list_on_the_next_run(self) -> None:
        # The collector re-reads the directory every refresh period and drains only what it finds,
        # so a file removed by the apply is a host dropped within one period of it.
        self.assertFalse(self.scratch.run([DEMO, APP], DEMO_DOMAIN).failed)
        self.assertIn("demo1.json", self.scratch.files())
        gone = self.scratch.run([APP])
        self.assertFalse(gone.failed, gone.output)
        self.assertEqual(self.scratch.files(), ["app1.json"])
        self.assertEqual(self.scratch.drain_list(), ["app1=10.20.1.101"])
        empty = self.scratch.run([])
        self.assertFalse(empty.failed, empty.output)
        self.assertEqual(self.scratch.files(), [])
        self.assertEqual(self.scratch.drain_list(), [])

    def test_a_descriptor_nobody_listed_is_removed_and_a_file_that_is_not_one_is_left(self) -> None:
        self.scratch.put("hand-placed.json", "{}")
        self.scratch.put("notes.txt", "kept")
        self.assertFalse(self.scratch.run([APP]).failed)
        self.assertEqual(self.scratch.files(), ["app1.json", "notes.txt"])

    def test_a_link_named_like_a_descriptor_is_removed_and_its_target_is_not(self) -> None:
        outside = self.scratch.home / "outside.json"
        outside.write_text("target", encoding="utf-8")
        self.scratch.directory.mkdir(parents=True)
        (self.scratch.directory / "link.json").symlink_to(outside)
        self.assertFalse(self.scratch.run([]).failed)
        self.assertEqual(self.scratch.files(), [])
        self.assertEqual(outside.read_text(encoding="utf-8"), "target")

    def test_a_plan_on_a_fresh_host_runs_and_writes_nothing(self) -> None:
        result = self.scratch.run([DEMO, APP], DEMO_DOMAIN, check=True)
        self.assertFalse(result.failed, result.output)
        self.assertEqual(self.scratch.files(), [])

    def test_each_descriptor_holds_exactly_the_four_public_keys(self) -> None:
        self.assertFalse(self.scratch.run([DEMO, APP], DEMO_DOMAIN).failed)
        for name, entry in (("demo1.json", DEMO), ("app1.json", APP)):
            with self.subTest(name=name):
                text = (self.scratch.directory / name).read_text(encoding="utf-8")
                value = json.loads(text)
                self.assertEqual(sorted(value), DESCRIPTOR_KEYS)
                self.assertEqual(
                    value,
                    {
                        "slug": entry["slug"],
                        "kind": entry["kind"],
                        "appHostIp": entry["app_host_ip"],
                        "expiresAt": None,
                    },
                )

    def test_a_refused_list_leaves_the_directory_as_it_was(self) -> None:
        # Refused before anything is written or removed: the stale file survives the refusal.
        self.scratch.put("stale.json", "{}")
        refused = self.scratch.run([DEMO], "")
        self.assertTrue(refused.failed)
        self.assertEqual(self.scratch.files(), ["stale.json"])


class RefusalTests(unittest.TestCase):
    """A list that names a host wrongly, or a demo host without its mail domain, stops the run."""

    def setUp(self) -> None:
        self.scratch = Scratch(self)

    def refused(self, hosts: object, domain: str = "") -> Result:
        result = self.scratch.run(hosts, domain)
        self.assertTrue(result.failed, result.output)
        self.assertEqual(self.scratch.files(), [], "a refused run wrote a descriptor")
        return result

    def test_a_demo_host_with_no_demo_mail_domain_stops_the_run(self) -> None:
        # The collector holds demo mail while the domain is empty, so a demo host named with none
        # set would look live and send nothing. Red while the demo host is listed and the domain is
        # empty; green once it is set.
        result = self.refused([DEMO], "")
        self.assertIn("mail_collector_demo_mail_domain must be set", result.output)
        green = self.scratch.run([DEMO], DEMO_DOMAIN)
        self.assertFalse(green.failed, green.output)

    def test_a_list_without_a_demo_host_needs_no_demo_mail_domain(self) -> None:
        result = self.scratch.run([APP], "")
        self.assertFalse(result.failed, result.output)

    def test_a_demo_host_with_a_domain_that_is_not_bare_stops_the_run(self) -> None:
        self.refused([DEMO], "https://demo.example")

    def test_an_entry_with_a_key_besides_the_three_is_refused(self) -> None:
        # No secret can reach a descriptor: the entry holds three public keys and the template
        # names four, so there is nowhere for a fourth to go.
        self.refused([{**APP, "token": "x"}])

    def test_an_entry_with_a_key_missing_is_refused(self) -> None:
        self.refused([{k: v for k, v in APP.items() if k != "app_host_ip"}])

    def test_an_address_that_is_not_private_ipv4_is_refused(self) -> None:
        self.refused([{**APP, "app_host_ip": "8.8.8.8"}])

    def test_a_private_address_is_accepted(self) -> None:
        result = self.scratch.run([{**APP, "app_host_ip": "192.168.1.1"}])
        self.assertFalse(result.failed, result.output)

    def test_a_slug_that_would_climb_out_of_the_directory_is_refused(self) -> None:
        self.refused([{**APP, "slug": "../x"}])

    def test_two_hosts_with_one_slug_are_refused(self) -> None:
        self.refused([APP, {**APP, "app_host_ip": "10.20.1.102"}])

    def test_a_kind_that_is_not_demo_or_tenant_is_refused(self) -> None:
        self.refused([{**APP, "kind": "other"}])

    def test_a_list_that_is_not_a_list_of_mappings_is_refused(self) -> None:
        for bad in ({"slug": "a"}, ["app1"]):
            with self.subTest(value=str(bad)[:20]):
                self.refused(bad)


class InterfaceTests(unittest.TestCase):
    """The spec, the template and the constants agree on the three keys and the four fields."""

    def test_the_spec_names_the_same_three_keys_the_run_checks_for(self) -> None:
        spec = cast(
            "dict[str, dict[str, dict[str, dict[str, dict[str, object]]]]]",
            YAML(typ="safe").load((ROLE / "meta" / "argument_specs.yml").read_text("utf-8")),
        )["argument_specs"]["main"]["options"]["mail_collector_hosts"]
        self.assertEqual(spec["elements"], "dict")
        self.assertEqual(spec["default"], [])
        suboptions = cast("dict[str, dict[str, object]]", spec["options"])
        constants = cast(
            "dict[str, object]",
            YAML(typ="safe").load((ROLE / "vars" / "main.yml").read_text("utf-8")),
        )
        self.assertEqual(sorted(suboptions), constants["mail_collector_host_keys"])
        self.assertEqual(sorted(suboptions), ["app_host_ip", "kind", "slug"])
        for name, option in suboptions.items():
            with self.subTest(name=name):
                self.assertIs(option["required"], True)
                self.assertNotIn("no_log", option)
        self.assertEqual(suboptions["kind"]["choices"], ["demo", "tenant"])

    def test_the_template_names_the_four_fields_and_nothing_else(self) -> None:
        environment = jinja2.Environment(  # noqa: S701 - JSON text, never HTML
            undefined=jinja2.StrictUndefined, keep_trailing_newline=True
        )
        environment.filters.update(FilterModule().filters())
        text = environment.from_string(TEMPLATE.read_text(encoding="utf-8")).render(item=APP)
        self.assertEqual(sorted(json.loads(text)), DESCRIPTOR_KEYS)
        # An entry that carried more would still render these four and no more: the template reads
        # each field by name and never iterates the entry.
        wider = {**APP, "token": "sentinel-value"}
        text = environment.from_string(TEMPLATE.read_text(encoding="utf-8")).render(item=wider)
        self.assertNotIn("sentinel-value", text)
        self.assertNotIn("token", text)

    def test_the_descriptor_tasks_write_only_inside_the_descriptor_directory(self) -> None:
        directory = "{{ mail_collector_descriptor_dir }}/"
        seen = 0
        for task in play_tasks():
            for module in ("ansible.builtin.template", "ansible.builtin.file"):
                args = task.get(module)
                if not isinstance(args, dict) or str(task["name"]).startswith("Make the"):
                    continue
                seen += 1
                self.assertTrue(str(args.get("dest", args.get("path"))).startswith(directory))
        self.assertEqual(seen, 2)


if __name__ == "__main__":
    unittest.main()
