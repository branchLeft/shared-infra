"""Unit tests for which Prometheus config the monitoring_stack role delivers.

The stack holds two renderings of prometheus.yml (hetzner/monitoring/render.ts): the one that
names no TLS file, and prometheus.demo1.yml, which scrapes demo1 and names the three files of
/etc/branchleft/demo1-metrics-tls. Prometheus reads each named file when it loads its
configuration and a missing one stops it, and the pin among them (ca.crt) is written by the
host_tls_identity role only once host_tls_identity_peer_cert is non-empty. So the role may put
the second rendering on a host only while that value is set, and these tests read the role's own
vars and task and run them through Ansible's templating to hold that:

- the delivery's source is the variant for a non-empty value, and the plain file for an empty,
  blank or absent one;
- the choice is made from the same variable, and the same test of it, that host_tls_identity uses
  to decide whether to write the pin;
- prometheus.yml is delivered by the task that chooses, and the variant is not a delivered name;
- the committed plain rendering names no file, so a host with no value gets a config that loads.

Sabotage, the red and then green for the change that made them: make the task's `src` always
the variant (or the plain file), or drop the trim from monitoring_stack_demo1_scrape, and these
tests fail; put it back and they pass.
"""

import re
import unittest
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
STACK = ROLE.parents[2] / "hetzner" / "monitoring" / "stack"
PLAIN = "prometheus/prometheus.yml"
VARIANT = "prometheus/prometheus.demo1.yml"
FLAG = "host_tls_identity_peer_cert"
TLS_FILE = re.compile(r"^\s*(ca_file|cert_file|key_file):", re.MULTILINE)
CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def _mapping(path: Path) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        message = f"{path} is not a mapping"
        raise TypeError(message)
    return cast("dict[str, object]", loaded)


def _task(name: str) -> dict[str, object]:
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    for task in tasks:
        if task.get("name") == name:
            return cast("dict[str, object]", task)
    message = f"no task named {name}"
    raise LookupError(message)


def _render(template: str, variables: dict[str, object]) -> str:
    """Template one string the way Ansible does, with its own variables trusted as templates.

    Ansible trusts what it loads from a role's files; a bare dict of strings is not, and would
    come back unexpanded, so each string value is marked here.
    """
    trusted = {
        key: trust_as_template(value) if isinstance(value, str) else value
        for key, value in variables.items()
    }
    templar = Templar(loader=DataLoader(), variables=trusted)
    return str(templar.template(trust_as_template(template)))


def _source(owner: object, item: str = PLAIN) -> str:
    """The `src` the delivery task resolves for one item, with the owner's value as given.

    `owner` is left out of the variables when it is None, which is how a host that has no
    owner_vars row for the value looks to the role.
    """
    variables = dict(_mapping(ROLE / "vars" / "main.yml"))
    if owner is not None:
        variables[FLAG] = owner
    variables["item"] = item
    task = _task("Deliver the stack's files whose diff is not shown")
    copy = cast("dict[str, object]", task["ansible.builtin.copy"])
    return _render(str(copy["src"]), variables)


class Demo1VariantTest(unittest.TestCase):
    def test_a_set_value_delivers_the_variant_as_prometheus_yml(self) -> None:
        self.assertEqual(f"stack/{VARIANT}", _source(CERT))

    def test_an_empty_blank_or_absent_value_delivers_the_plain_file(self) -> None:
        for owner in ("", "   ", "\n", None):
            with self.subTest(owner=owner):
                self.assertEqual(f"stack/{PLAIN}", _source(owner))

    def test_no_other_file_is_ever_swapped_for_the_variant(self) -> None:
        files = _mapping(ROLE / "vars" / "main.yml")["monitoring_stack_files"]
        for item in cast("list[str]", files):
            if item == PLAIN:
                continue
            with self.subTest(item=item):
                self.assertEqual(f"stack/{item}", _source(CERT, item))

    def test_the_choice_reads_the_value_the_pin_role_reads_and_tests_it_the_same_way(self) -> None:
        # host_tls_identity writes the pin when the value, trimmed, is not empty. This role's flag
        # must be that same test of that same variable, or the config can name a file the role
        # did not write.
        pin_tasks = (ROLES / "host_tls_identity" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn(f"{FLAG} | trim != ''", pin_tasks)
        flag = str(_mapping(ROLE / "vars" / "main.yml")["monitoring_stack_demo1_scrape"])
        self.assertIn(FLAG, flag)
        self.assertIn("trim", flag)
        self.assertIn("!= ''", flag)

    def test_the_plain_file_is_delivered_by_the_task_that_chooses_and_the_variant_is_not_a_name(
        self,
    ) -> None:
        role_vars = _mapping(ROLE / "vars" / "main.yml")
        files = cast("list[str]", role_vars["monitoring_stack_files"])
        hidden = cast("list[str]", role_vars["monitoring_stack_files_hidden"])
        self.assertIn(PLAIN, files)
        self.assertIn(PLAIN, hidden)
        self.assertNotIn(VARIANT, files)
        self.assertEqual(PLAIN, role_vars["monitoring_stack_prometheus_config"])
        self.assertEqual(VARIANT, role_vars["monitoring_stack_prometheus_demo1_variant"])
        task = _task("Deliver the stack's files whose diff is not shown")
        self.assertEqual(
            "{{ monitoring_stack_files | intersect(monitoring_stack_files_hidden) }}",
            task["loop"],
        )
        # The destination is the item, never the variant: one file on the host either way.
        copy = cast("dict[str, object]", task["ansible.builtin.copy"])
        self.assertEqual("{{ monitoring_stack_project_dir }}/{{ item }}", copy["dest"])

    def test_the_other_delivery_task_does_not_carry_the_config(self) -> None:
        # The task that shows its diff is the one the plain choice does not pass through.
        role_vars = _mapping(ROLE / "vars" / "main.yml")
        files = cast("list[str]", role_vars["monitoring_stack_files"])
        hidden = cast("list[str]", role_vars["monitoring_stack_files_hidden"])
        self.assertNotIn(PLAIN, [name for name in files if name not in hidden])

    def test_the_plain_rendering_names_no_file_and_the_variant_names_the_three(self) -> None:
        plain = (STACK / PLAIN).read_text(encoding="utf-8")
        variant = (STACK / VARIANT).read_text(encoding="utf-8")
        self.assertEqual([], TLS_FILE.findall(plain))
        self.assertEqual(["ca_file", "cert_file", "key_file"], TLS_FILE.findall(variant))


if __name__ == "__main__":
    unittest.main()
