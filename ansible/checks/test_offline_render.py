"""Fast tests of offline_render.py and its data files: no Ansible runs here.

The proof that the tool catches a planted defect (red, then green) runs Ansible and lives in
sabotage_offline_render.py. These tests pin the pieces around it: the typed dummies, the
classification, the environment scrub, the fixtures against the roles and the image, and the
data files against the roles they describe.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import offline_render as o
from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
PULUMI = ROOT / "hetzner" / "estate" / "Pulumi.production.yaml"
CODENAMES = {"debian-12": "bookworm", "debian-13": "trixie"}


def spec(**fields: object) -> dict[str, object]:
    """Return an argument_specs option."""
    return dict(fields)


class TypedDummies(unittest.TestCase):
    """A dummy has the type the role's argument_specs declares."""

    def test_each_declared_type_gets_a_value_of_that_type(self) -> None:
        for kind in ("str", "path", "int", "bool", "list", "dict", "float", "raw"):
            value = o.dummy_value("some_option", spec(type=kind))
            self.assertTrue(o.type_matches(kind, value), kind)

    def test_a_choice_is_used_first(self) -> None:
        self.assertEqual("x64", o.dummy_value("arch", spec(type="str", choices=["x64", "arm64"])))

    def test_a_dummy_names_its_option_and_holds_no_secret(self) -> None:
        self.assertEqual("DUMMY_the_password", o.dummy_value("the_password", spec(type="str")))
        self.assertEqual("/dummy/the_dir", o.dummy_value("the_dir", spec(type="path")))

    def test_a_dict_carries_its_required_suboptions(self) -> None:
        sub = {
            "a": spec(type="str", required=True),
            "b": spec(type="str"),
            "c": spec(type="int", required=True, default=3),
        }
        self.assertEqual({"a": "DUMMY_a"}, o.dummy_value("d", spec(type="dict", options=sub)))

    def test_type_matches_rejects_the_wrong_type(self) -> None:
        self.assertFalse(o.type_matches("int", True))
        self.assertFalse(o.type_matches("str", 3))
        self.assertFalse(o.type_matches("list", {}))
        self.assertFalse(o.type_matches("bool", "false"))

    def test_only_required_options_without_a_default_need_a_dummy(self) -> None:
        options = {
            "a": spec(type="str", required=True),
            "b": spec(type="str", required=True, default="x"),
            "c": spec(type="str"),
        }
        self.assertEqual(["a"], list(o.required_without_default(options)))

    def test_every_role_has_an_argument_spec_with_typed_options(self) -> None:
        roles = [path for path in ROLES.iterdir() if path.is_dir()]
        self.assertTrue(roles)
        for role in roles:
            self.assertTrue(o.role_specs(role), f"{role.name} has no argument_specs")
            for name, option in o.role_options(role).items():
                self.assertIn("type", option, f"{role.name} {name} declares no type")

    def test_host_input_keys_are_options_of_some_role(self) -> None:
        known = {n for role in ROLES.iterdir() for n in o.role_options(role)}
        table = o.mapping(o.load_mapping(ROLES / "host_inputs" / "vars" / "main.yml"))
        for host, keys in o.mapping(table["host_inputs_required_by_host"]).items():
            for key in o.sequence(keys):
                self.assertIn(key, known, f"{host} input {key} is no role option")

    def test_the_environment_of_each_host_holds_a_typed_dummy_for_each_required_option(
        self,
    ) -> None:
        data = o.load_data(ROOT)
        for plan in o.host_plans(ROOT):
            env = o.build_env(ROOT, plan, o.mapping(data.facts.get(plan.name)))
            for use in plan.roles:
                needed = o.required_without_default(o.role_options(ROLES / use.name))
                for name, option in needed.items():
                    self.assertIn(name, env, f"{plan.name} {use.name}")
                    self.assertTrue(
                        o.type_matches(str(option.get("type", "str")), env[name]),
                        f"{plan.name} {use.name} {name}",
                    )


class Classification(unittest.TestCase):
    """The summary's extracts become one class, and a reason made of names only."""

    def classify(self, **item: object) -> tuple[str, str]:
        return o.classify(
            item,
            {"registered_later"},
            {"architecture": "x86_64"},
            {"architecture", "distribution_release"},
        )

    def test_a_clean_item_is_ok(self) -> None:
        self.assertEqual(("ok", ""), self.classify(failed=False))

    def test_a_syntax_error_is_red(self) -> None:
        self.assertEqual(("red", "syntax"), self.classify(failed=True, syntax=True))

    def test_a_variable_defined_nowhere_is_red_and_named(self) -> None:
        status, reason = self.classify(failed=True, undefined="never_set")
        self.assertEqual("red", status)
        self.assertIn("never_set", reason)

    def test_a_variable_a_task_assigns_is_unresolved(self) -> None:
        self.assertEqual("unresolved", self.classify(failed=True, undefined="registered_later")[0])

    def test_a_fact_the_roles_read_and_the_fixture_lacks_is_red(self) -> None:
        status, reason = self.classify(failed=True, attr="distribution_release")
        self.assertEqual("red", status)
        self.assertIn("distribution_release", reason)

    def test_an_attribute_of_a_dummy_is_unresolved_not_red(self) -> None:
        self.assertEqual("unresolved", self.classify(failed=True, attr="some_key")[0])

    def test_a_refused_validate_is_red_with_its_exit_code(self) -> None:
        status, reason = self.classify(failed=True, validate=True, rc="1")
        self.assertEqual("red", status)
        self.assertIn("1", reason)

    def test_the_reason_holds_only_what_was_extracted(self) -> None:
        for item in (
            {"failed": True, "undefined": "x"},
            {"failed": True, "validate": True, "rc": "2"},
        ):
            self.assertLess(len(self.classify(**item)[1]), 80)


class Ratchet(unittest.TestCase):
    """Unresolved is allowed only for a listed pair, and a listed pair that renders is red."""

    def test_an_unlisted_unresolved_pair_is_red(self) -> None:
        results = [o.Result("db1", "r", "t.j2", "unresolved", "why")]
        out = o.apply_ratchet(results, frozenset(), whole=True)
        self.assertEqual("red", out[0].status)

    def test_a_listed_unresolved_pair_stays_unresolved(self) -> None:
        results = [o.Result("db1", "r", "t.j2", "unresolved", "why")]
        out = o.apply_ratchet(results, frozenset({("r", "t.j2")}), whole=True)
        self.assertEqual(["unresolved"], [r.status for r in out])

    def test_a_stale_entry_is_red_on_a_whole_run_only(self) -> None:
        allowed = frozenset({("r", "t.j2")})
        self.assertEqual("red", o.apply_ratchet([], allowed, whole=True)[0].status)
        self.assertEqual([], o.apply_ratchet([], allowed, whole=False))


class Environment(unittest.TestCase):
    """What the Ansible child can see."""

    def test_secret_looking_variables_do_not_reach_the_child(self) -> None:
        leaking = {
            "GITHUB_TOKEN": "t",
            "ANSIBLE_VAULT_PASSWORD": "p",
            "AWS_SECRET_ACCESS_KEY": "k",
            "SSH_AUTH_SOCK": "/s",
            "PATH": "/usr/bin",
        }
        with tempfile.TemporaryDirectory() as scratch, mock.patch.dict(os.environ, leaking):
            child = o.scrubbed_env(Path(scratch))
            self.assertEqual({"PATH", "HOME", "TMPDIR"}, {"PATH", "HOME", "TMPDIR"} & set(child))
            for name in (
                "GITHUB_TOKEN",
                "ANSIBLE_VAULT_PASSWORD",
                "AWS_SECRET_ACCESS_KEY",
                "SSH_AUTH_SOCK",
            ):
                self.assertNotIn(name, child)
            self.assertTrue(child["HOME"].startswith(scratch))
            self.assertTrue(child["ANSIBLE_CONFIG"].startswith(scratch))
            self.assertEqual("", Path(child["ANSIBLE_CONFIG"]).read_text(encoding="utf-8"))

    def test_the_child_environment_names_are_an_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            names = set(o.scrubbed_env(Path(scratch)))
        for name in names:
            self.assertTrue(
                name in o.ENV_ALLOWED or name in {"HOME", "TMPDIR"} or name.startswith("ANSIBLE_"),
                name,
            )

    def test_both_layers_that_keep_a_rendered_line_out_of_the_logs_are_on(self) -> None:
        self.assertTrue(o.NO_LOG)
        self.assertEqual(subprocess.DEVNULL, o.ANSIBLE_STDIO)


class Replay(unittest.TestCase):
    """A template task is replayed into the throwaway tree and nowhere else."""

    def replay(self, task: dict[str, object], arguments: dict[str, object]) -> o.Replay:
        return o._replay("role", "tasks/main.yml", "x.j2", 3, task, arguments, Path("/work/out"))

    def test_the_destination_is_rewritten_and_the_attributes_dropped(self) -> None:
        arguments: dict[str, object] = {
            "src": "x.j2",
            "dest": "/etc/real",
            "owner": "root",
            "group": "root",
            "mode": "0440",
            "backup": True,
        }
        replayed = self.replay({"name": "t", "when": "false", "notify": "h"}, arguments).task
        args = o.mapping(replayed["ansible.builtin.template"])
        self.assertEqual({"src", "dest"}, set(args))
        self.assertTrue(str(args["dest"]).startswith("/work/out/3/"))
        self.assertNotIn("when", replayed)
        self.assertNotIn("notify", replayed)

    def test_the_task_is_hidden_and_never_fatal(self) -> None:
        replayed = self.replay({"name": "t"}, {"src": "x.j2"}).task
        self.assertIs(True, replayed["no_log"])
        self.assertIs(True, replayed["ignore_errors"])
        self.assertIs(False, replayed["diff"])

    def test_vars_validate_and_loop_are_kept(self) -> None:
        task: dict[str, object] = {
            "vars": {"a": 1},
            "loop": ["x", "y"],
            "loop_control": {"loop_var": "unit"},
        }
        replay = self.replay(task, {"src": "x.j2", "validate": f"{sys.executable} %s"})
        self.assertEqual({"a": 1}, replay.task["vars"])
        self.assertEqual(["x", "y"], replay.task["loop"])
        self.assertEqual("unit", o.mapping(replay.task["loop_control"])["loop_var"])
        self.assertIn("_or_n", str(o.mapping(replay.task["ansible.builtin.template"])["dest"]))
        self.assertEqual(f"{sys.executable} %s", replay.validate)
        self.assertIsNone(replay.uncovered)

    def test_a_validator_that_is_not_installed_is_not_covered_and_not_run(self) -> None:
        replay = self.replay({}, {"src": "x.j2", "validate": "/nonexistent/tool -c %s"})
        self.assertEqual("/nonexistent/tool", replay.uncovered)
        self.assertNotIn("validate", o.mapping(replay.task["ansible.builtin.template"]))

    def test_names_a_task_assigns_are_collected(self) -> None:
        document = [
            {
                "register": "got",
                "vars": {"local_a": 1},
                "loop_control": {"loop_var": "unit", "index_var": "n"},
            },
            {"block": [{"ansible.builtin.set_fact": {"made": 1, "cacheable": True}}]},
        ]
        found: set[str] = set()
        o._collect(document, found)
        self.assertTrue({"got", "local_a", "unit", "n", "made"} <= found)
        self.assertNotIn("cacheable", found)


class Fixtures(unittest.TestCase):
    """The per-host fact fixtures stay true to the roles and to the image."""

    def test_each_host_has_a_fixture_and_each_fixture_a_host(self) -> None:
        data = o.load_data(ROOT)
        self.assertEqual({p.name for p in o.host_plans(ROOT)}, set(data.facts))

    def test_every_fact_a_hosts_roles_read_is_in_its_fixture(self) -> None:
        data = o.load_data(ROOT)
        for plan in o.host_plans(ROOT):
            missing = o.fact_keys_read(ROOT, plan) - set(data.facts[plan.name])
            self.assertEqual(set(), missing, f"{plan.name} fixture lacks facts its roles read")

    def test_the_release_is_the_codename_of_the_image_the_estate_builds(self) -> None:
        image = re.search(r"image: (debian-\d+)", PULUMI.read_text(encoding="utf-8"))
        self.assertIsNotNone(image)
        codename = CODENAMES[image[1]] if image else ""
        data = o.load_data(ROOT)
        for host, facts in data.facts.items():
            if "distribution_release" in facts:
                self.assertEqual(codename, facts["distribution_release"], host)

    def test_a_fixture_holds_facts_and_no_other_value(self) -> None:
        for host, facts in o.load_data(ROOT).facts.items():
            for key in facts:
                self.assertRegex(key, r"^[a-z][a-z0-9_]*$", host)


class DataFiles(unittest.TestCase):
    """The files under offline/ describe things that exist."""

    def test_each_override_declares_the_type_it_has_and_the_role_gives_it(self) -> None:
        options = {
            name: opt for role in ROLES.iterdir() for name, opt in o.role_options(role).items()
        }
        overrides = o.declared_overrides(ROOT)
        self.assertTrue(overrides)
        for name, entry in overrides.items():
            kind = str(entry.get("type"))
            self.assertTrue(o.type_matches(kind, entry.get("value")), f"{name} is not a {kind}")
            if name in options:
                self.assertEqual(
                    options[name].get("type", "str"),
                    kind,
                    f"{name} differs from its argument_specs type",
                )

    def test_each_override_is_used_by_a_role(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in ROLES.rglob("*")
            if path.is_file()
            and "molecule" not in path.parts
            and path.suffix in {".yml", ".j2", ".yaml"}
        )
        for name in o.declared_overrides(ROOT):
            self.assertRegex(text, rf"\b{re.escape(name)}\b", f"override {name} is used by no role")

    def test_each_validator_names_its_binary_and_the_file(self) -> None:
        data = o.load_data(ROOT)
        self.assertTrue(data.validators)
        for template, entry in data.validators.items():
            argv = [str(part) for part in o.sequence(entry.get("argv"))]
            self.assertEqual(entry.get("binary"), argv[0], template)
            self.assertIn("{file}", argv, template)
            self.assertTrue((ROOT / "ansible").rglob(f"templates/{template}"), template)

    def test_each_ratchet_entry_names_a_template_that_exists(self) -> None:
        document, problem = load_yaml(ROOT / o.DATA / "unresolved.yml")
        self.assertIsNone(problem)
        for item in o.sequence(o.mapping(document).get("allowed")):
            entry = o.mapping(item)
            path = ROLES / str(entry.get("role")) / "templates" / str(entry.get("template"))
            self.assertTrue(path.is_file(), str(entry))

    def test_the_summary_lists_what_is_not_ok_and_no_content(self) -> None:
        results = [o.Result("h", "r", "a.j2", "ok"), o.Result("h", "r", "b.j2", "red", "syntax")]
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "summary.md"
            o.write_summary(target, results, "hosts=1")
            text = target.read_text(encoding="utf-8")
        self.assertIn("b.j2", text)
        self.assertNotIn("a.j2", text)


if __name__ == "__main__":
    unittest.main()
