"""Unit tests for the role's tenant profile: its class lists against the tenant stack directory.

The role delivers one of two stacks, chosen by `edge_stack_profile` (README, "Profiles"). The
estate's is `hetzner/edge/stack`; the tenant's is `hetzner/edge-t/stack`, which has no
verified-session parser and no Nextcloud profile and names no hostname. The tenant lists
are constants in vars/main.yml, and the stack directory is where the files are, so these tests
hold the two equal: a file added to the tenant stack and left out of a class, or a class
that names a file the stack does not hold, fails here and not on the host.

They also hold the profile switch to its shape: the estate profile sets nothing, so a caller's
`edge_stack_source_dir` still reaches it, and the tenant profile swaps the three names the
tasks read (the stack directory, the CrowdSec files and the directories).

Sabotage, the red and then green for the change that made them: add a file to
`hetzner/edge-t/stack` that no class names, or add `crowdsec/parsers/nextcloud-profile.yaml` to
the tenant list, or make `edge_stack_profile` default to `tenant`, and these tests fail; put it
back and they pass.
"""

import unittest
from pathlib import Path

import edge_stack_apply
import yaml

ROLE = Path(__file__).resolve().parents[2]
TENANT_STACK = ROLE.parents[2] / "hetzner" / "edge-t" / "stack"
ESTATE_STACK = ROLE.parents[2] / "hetzner" / "edge" / "stack"


def load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def mapping(path: Path) -> dict[str, object]:
    document = load(path)
    if not isinstance(document, dict):
        message = f"{path} is not a mapping"
        raise TypeError(message)
    return {str(key): value for key, value in document.items()}


def names(value: object) -> list[str]:
    if not isinstance(value, list):
        message = f"{value!r} is not a list"
        raise TypeError(message)
    return [str(item) for item in value]


VARS = mapping(ROLE / "vars" / "main.yml")
DEFAULTS = mapping(ROLE / "defaults" / "main.yml")


def files_of(stack: Path) -> list[str]:
    return sorted(p.relative_to(stack).as_posix() for p in stack.rglob("*") if p.is_file())


def tenant_classes() -> tuple[set[str], str]:
    """The files the tenant profile names one by one, and the directory it takes whole."""
    named = {str(VARS["edge_stack_caddy_file"]), str(VARS["edge_stack_compose_file"])}
    named |= set(names(VARS["edge_stack_tenant_crowdsec_files"]))
    return named, f"{VARS['edge_stack_acquis_dir']}/"


class TenantStackIsClassified(unittest.TestCase):
    def test_every_file_of_the_tenant_stack_is_in_a_class(self) -> None:
        named, acquis = tenant_classes()
        stack = files_of(TENANT_STACK)
        self.assertNotEqual([], stack)
        self.assertEqual([], [f for f in stack if f not in named and not f.startswith(acquis)])

    def test_every_file_a_class_names_is_in_the_tenant_stack(self) -> None:
        named, _acquis = tenant_classes()
        self.assertEqual([], sorted(named - set(files_of(TENANT_STACK))))

    def test_the_tenant_stack_has_no_acquisition_file_in_a_subdirectory(self) -> None:
        _named, acquis = tenant_classes()
        for file in files_of(TENANT_STACK):
            if file.startswith(acquis):
                self.assertNotIn("/", file[len(acquis) :], file)

    def test_the_tenant_files_are_estate_files_and_the_difference_is_the_two_parsers(self) -> None:
        tenant = set(names(VARS["edge_stack_tenant_crowdsec_files"]))
        estate = set(names(VARS["edge_stack_crowdsec_files"]))
        self.assertLessEqual(tenant, estate, "the tenant profile adds no class of file of its own")
        self.assertEqual(
            {
                "crowdsec/parsers/edge-trusted-session.yaml",
                "crowdsec/parsers/nextcloud-profile.yaml",
            },
            estate - tenant,
        )

    def test_the_directories_cover_every_directory_the_tenant_files_are_in(self) -> None:
        directories = set(names(VARS["edge_stack_tenant_dirs"]))
        needed = {
            parent.as_posix()
            for file in files_of(TENANT_STACK)
            for parent in Path(file).parents
            if parent.as_posix() != "."
        }
        self.assertEqual(set(), needed - directories)
        self.assertNotIn("crowdsec/parsers", directories)

    def test_the_module_can_read_back_every_tenant_file(self) -> None:
        for name in names(VARS["edge_stack_tenant_crowdsec_files"]):
            relative = name.removeprefix("crowdsec/")
            self.assertIn(relative, edge_stack_apply.CROWDSEC_FILES_INSIDE, name)


class ProfileSwitch(unittest.TestCase):
    def tasks(self) -> list[dict[str, object]]:
        document = load(ROLE / "tasks" / "main.yml")
        if not isinstance(document, list):
            message = "tasks/main.yml is not a list"
            raise TypeError(message)
        return [task for task in document if isinstance(task, dict)]

    def test_the_default_is_the_estate_and_the_tenant_source_is_the_tenant_link(self) -> None:
        self.assertEqual("estate", DEFAULTS["edge_stack_profile"])
        self.assertEqual(
            "{{ role_path }}/files/stack-tenant", DEFAULTS["edge_stack_tenant_source_dir"]
        )
        self.assertEqual("{{ role_path }}/files/stack", DEFAULTS["edge_stack_source_dir"])

    def test_the_links_point_at_the_two_stack_directories(self) -> None:
        files = ROLE / "files"
        self.assertEqual(TENANT_STACK.resolve(), (files / "stack-tenant").resolve())
        self.assertEqual(ESTATE_STACK.resolve(), (files / "stack").resolve())

    def test_only_the_tenant_profile_swaps_the_three_names(self) -> None:
        includes = [
            task for task in self.tasks() if task.get("ansible.builtin.include_tasks") == "_run.yml"
        ]
        self.assertEqual(2, len(includes), "one include per profile, and both run _run.yml")
        tenant, estate = includes
        self.assertEqual("edge_stack_profile == 'tenant'", tenant["when"])
        self.assertEqual("edge_stack_profile != 'tenant'", estate["when"])
        self.assertNotIn("vars", estate, "the estate profile sets nothing")
        facts = tenant["vars"]
        if not isinstance(facts, dict):
            message = "the tenant include's vars are not a mapping"
            raise TypeError(message)
        self.assertEqual(
            {"edge_stack_source_dir", "edge_stack_crowdsec_files", "edge_stack_dirs"}, set(facts)
        )

    def test_nothing_in_the_role_leaves_a_profile_fact_on_the_host(self) -> None:
        # A set_fact of one of the three names would stay on the host and reach the next run
        # of the role, whatever its profile, so none may exist.
        names_swapped = {"edge_stack_source_dir", "edge_stack_crowdsec_files", "edge_stack_dirs"}

        def set_facts(node: object) -> list[set[str]]:
            found: list[set[str]] = []
            if isinstance(node, list):
                for item in node:
                    found += set_facts(item)
            elif isinstance(node, dict):
                facts = node.get("ansible.builtin.set_fact")
                if isinstance(facts, dict):
                    found.append({str(key) for key in facts})
                for value in node.values():
                    found += set_facts(value)
            return found

        for task_file in sorted((ROLE / "tasks").glob("*.yml")):
            for facts in set_facts(load(task_file)):
                self.assertEqual(set(), facts & names_swapped, task_file.name)

    def test_the_profile_is_chosen_before_anything_reads_the_stack(self) -> None:
        main = [t for t in self.tasks() if "ansible.builtin.include_tasks" in t]
        self.assertEqual(
            ["_run.yml", "_run.yml"], [t["ansible.builtin.include_tasks"] for t in main]
        )
        run = load(ROLE / "tasks" / "_run.yml")
        if not isinstance(run, list):
            message = "tasks/_run.yml is not a list"
            raise TypeError(message)
        self.assertEqual(
            ["_assert.yml", "_classify.yml", "_decide.yml", "_deliver.yml"],
            [t["ansible.builtin.include_tasks"] for t in run if isinstance(t, dict)],
        )

    def test_the_spec_offers_exactly_the_two_profiles(self) -> None:
        spec = mapping(ROLE / "meta" / "argument_specs.yml")
        options = spec["argument_specs"]
        if not isinstance(options, dict):
            message = "argument_specs is not a mapping"
            raise TypeError(message)
        profile = options["main"]["options"]["edge_stack_profile"]
        self.assertEqual(["estate", "tenant"], profile["choices"])
        self.assertEqual("estate", profile["default"])


if __name__ == "__main__":
    unittest.main()
