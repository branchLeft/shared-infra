"""Tests for the pin check: a valid tree passes and each way of breaking a pin is found."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

import check_pins

TOOLS = (
    "ansible-core==2.21.5\nansible-lint==26.10.1\nmolecule==26.10.0\n"
    "molecule-plugins[docker]==26.10.12\nyamllint==1.38.0\nmypy==2.4.0\nruff==0.17.0\n"
)
COLLECTIONS: tuple[tuple[str, str, str, Mapping[str, str]], ...] = (
    ("ansible", "posix", "2.2.2", {}),
    ("community", "docker", "5.4.0", {"community.library_inventory_filtering_v1": ">=1.0.0"}),
    ("community", "library_inventory_filtering_v1", "1.1.5", {}),
)
CONFIG = "[defaults]\ncollections_path = .ansible/collections\n"
LINT_HOOK = (
    "repos:\n  - repo: https://github.com/ansible/ansible-lint\n    rev: {rev}\n"
    "    hooks:\n      - id: ansible-lint\n"
)
LOCAL_ONLY = "repos:\n  - repo: local\n    hooks:\n      - id: ansible-lint\n"


def artifact_name(namespace: str, name: str, version: str) -> str:
    """Return the file name Galaxy gives a collection artifact."""
    return f"{namespace}-{name}-{version}.tar.gz"


def build_artifact(
    path: Path, namespace: str, name: str, version: str, dependencies: object
) -> None:
    """Write a minimal collection artifact whose MANIFEST.json says what is given."""
    manifest = {
        "collection_info": {
            "namespace": namespace,
            "name": name,
            "version": version,
            "dependencies": dependencies,
        }
    }
    source = path.parent / "MANIFEST.json"
    source.write_text(json.dumps(manifest), encoding="utf-8")
    with tarfile.open(path, "w:gz") as archive:
        archive.add(source, arcname="MANIFEST.json")
    source.unlink()


class PinCase(unittest.TestCase):
    """A test case that builds a repository holding a valid set of pins."""

    def setUp(self) -> None:
        """Create the tree and remember where its parts are."""
        self.root = Path(tempfile.mkdtemp(prefix="pins-test-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ansible = self.root / "ansible"
        self.vendor = self.ansible / "vendor" / "collections"
        self.vendor.mkdir(parents=True)
        (self.ansible / "requirements.txt").write_text(TOOLS, encoding="utf-8")
        (self.root / "ansible.cfg").write_text(CONFIG, encoding="utf-8")
        (self.root / ".pre-commit-config.yaml").write_text(LOCAL_ONLY, encoding="utf-8")
        for namespace, name, version, dependencies in COLLECTIONS:
            build_artifact(
                self.vendor / artifact_name(namespace, name, version),
                namespace,
                name,
                version,
                dependencies,
            )
        self.write_requirements_yml()
        self.write_sums()

    def write_requirements_yml(self, versions: Mapping[str, str] | None = None) -> None:
        """Write requirements.yml naming every artifact, with optional version overrides."""
        lines = ["---", "collections:"]
        for namespace, name, version, _ in COLLECTIONS:
            pin = (versions or {}).get(name, version)
            lines.append(f"  - name: vendor/collections/{artifact_name(namespace, name, version)}")
            lines.append(f"    version: {pin}")
        (self.ansible / "requirements.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_sums(self) -> None:
        """Record the hash of every artifact now in the vendor directory."""
        lines = [
            f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}"
            for item in sorted(self.vendor.glob("*.tar.gz"))
        ]
        (self.vendor / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def findings(self) -> list[str]:
        """Return every finding for the tree as it now stands."""
        return check_pins.run_checks(self.root)[0]

    def assert_found(self, fragment: str) -> None:
        """Assert some finding contains ``fragment``."""
        found = self.findings()
        self.assertTrue(any(fragment in line for line in found), f"{fragment!r} not in {found}")


class ValidTreeTests(PinCase):
    """A tree that follows the rules has no findings, so a finding below is the cause."""

    def test_valid_tree_has_no_findings(self) -> None:
        """The control case: every sabotage below starts from this tree."""
        self.assertEqual(self.findings(), [])

    def test_missing_hook_is_noted_not_failed(self) -> None:
        """With no ansible-lint hook there is nothing to compare, and the run says so."""
        findings, notes = check_pins.run_checks(self.root)
        self.assertEqual(findings, [])
        self.assertTrue(any("no ansible-lint hook" in note for note in notes))

    def test_main_prints_a_clean_summary_and_exits_zero(self) -> None:
        """The command line reports zero findings with status 0."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = check_pins.main(["--root", str(self.root)])
        self.assertEqual(status, 0)
        self.assertIn("check_pins: 0 finding(s)", out.getvalue())

    def test_main_exits_one_on_a_finding(self) -> None:
        """A single finding makes the command fail and print it."""
        (self.ansible / "requirements.txt").write_text(TOOLS + "extra>=1\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = check_pins.main(["--root", str(self.root)])
        self.assertEqual(status, 1)
        self.assertIn("FAIL requirements.txt line 8", out.getvalue())


class ToolPinTests(PinCase):
    """Every line of requirements.txt is an exact pin and the named tools are present."""

    def put(self, text: str) -> None:
        """Replace requirements.txt."""
        (self.ansible / "requirements.txt").write_text(text, encoding="utf-8")

    def test_range_operators_are_refused(self) -> None:
        """A range, a compatible release, a wildcard and a bare name are not exact."""
        for loose in (
            "ansible-core>=2.21.5",
            "ansible-core~=2.21",
            "ansible-core==2.*",
            "ansible-core",
        ):
            with self.subTest(line=loose):
                self.put(TOOLS.replace("ansible-core==2.21.5", loose))
                self.assert_found("is not name==version")

    def test_other_requirement_forms_are_refused(self) -> None:
        """An include, an editable install, a URL and a marker are not exact pins."""
        for odd in (
            "-r other.txt",
            "-e .",
            "git+https://example.invalid/x.git",
            "ruff==0.17.0; python_version>'3'",
        ):
            with self.subTest(line=odd):
                self.put(TOOLS + odd + "\n")
                self.assert_found("is not name==version")

    def test_missing_tool_is_refused(self) -> None:
        """Dropping a named tool leaves it unpinned, which is a finding."""
        self.put(TOOLS.replace("mypy==2.4.0\n", ""))
        self.assert_found("does not pin mypy")

    def test_duplicate_pin_is_refused(self) -> None:
        """A tool pinned twice would let the later line win."""
        self.put(TOOLS + "ruff==0.16.0\n")
        self.assert_found("pins ruff a second time")

    def test_comments_and_blank_lines_are_allowed(self) -> None:
        """A full-line comment and a blank line carry no pin and are not findings."""
        self.put("# the tools\n\n" + TOOLS)
        self.assertEqual(self.findings(), [])

    def test_name_spelling_is_normalised(self) -> None:
        """An underscore or capital in the name still counts as the tool."""
        self.put(TOOLS.replace("molecule-plugins", "Molecule_Plugins"))
        self.assertEqual(self.findings(), [])


class CollectionPinTests(PinCase):
    """requirements.yml, the vendored artifacts and their hashes agree, or a finding names why."""

    def test_range_version_is_refused(self) -> None:
        """A version range would let the artifact drift from the pin."""
        for loose in (">=2.2.2", "2.2", "2.2.*", "latest"):
            with self.subTest(version=loose):
                self.write_requirements_yml({"posix": f"'{loose}'"})
                self.assert_found("is not an exact x.y.z")

    def test_galaxy_name_form_is_refused(self) -> None:
        """An entry that names a collection rather than a vendored path reaches the network."""
        text = (self.ansible / "requirements.yml").read_text(encoding="utf-8")
        (self.ansible / "requirements.yml").write_text(
            text.replace("vendor/collections/ansible-posix-2.2.2.tar.gz", "ansible.posix"),
            encoding="utf-8",
        )
        self.assert_found("is not a path under vendor/collections/")

    def test_extra_keys_are_refused(self) -> None:
        """A source, type or signature key could send the install elsewhere."""
        text = (self.ansible / "requirements.yml").read_text(encoding="utf-8")
        (self.ansible / "requirements.yml").write_text(
            text.replace(
                "    version: 2.2.2\n", "    version: 2.2.2\n    source: https://example.invalid\n"
            ),
            encoding="utf-8",
        )
        self.assert_found("an entry has only name and version")

    def test_roles_key_is_refused(self) -> None:
        """Roles are not vendored, so a roles list is an unpinned source."""
        text = (self.ansible / "requirements.yml").read_text(encoding="utf-8")
        (self.ansible / "requirements.yml").write_text(
            text + "roles:\n  - name: some.role\n", encoding="utf-8"
        )
        self.assert_found("requirements.yml sets roles")

    def test_pin_that_differs_from_the_file_name_is_refused(self) -> None:
        """Bumping the version key without replacing the artifact is caught."""
        self.write_requirements_yml({"posix": "2.2.3"})
        self.assert_found("names version 2.2.2 but the pin is 2.2.3")

    def test_missing_artifact_is_refused(self) -> None:
        """A pin whose artifact was deleted would fall back to the network."""
        (self.vendor / artifact_name("ansible", "posix", "2.2.2")).unlink()
        self.write_sums()
        self.assert_found("is not vendored")

    def test_changed_byte_is_refused(self) -> None:
        """An artifact that differs from the recorded hash is not the pinned copy."""
        target = self.vendor / artifact_name("ansible", "posix", "2.2.2")
        target.write_bytes(target.read_bytes() + b"x")
        self.assert_found("does not match SHA256SUMS")

    def test_missing_hash_line_is_refused(self) -> None:
        """An artifact with no recorded hash cannot be checked."""
        sums = self.vendor / "SHA256SUMS"
        lines = [
            line for line in sums.read_text(encoding="utf-8").splitlines() if "posix" not in line
        ]
        sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assert_found("has no line in SHA256SUMS")

    def test_missing_checksum_file_is_refused(self) -> None:
        """Without the manifest nothing can vouch for the artifacts."""
        (self.vendor / "SHA256SUMS").unlink()
        self.assert_found("SHA256SUMS is missing")

    def test_malformed_and_duplicate_hash_lines_are_refused(self) -> None:
        """A line that is not '<sha256>  <file>' or a repeated file is a finding."""
        sums = self.vendor / "SHA256SUMS"
        first = sums.read_text(encoding="utf-8").splitlines()[0]
        sums.write_text(
            sums.read_text(encoding="utf-8") + "not a hash\n" + first + "\n", encoding="utf-8"
        )
        self.assert_found("is not '<sha256>  <file>'")
        self.assert_found("a second time")

    def test_artifact_holding_another_version_is_refused(self) -> None:
        """A tarball renamed to look like the pin, with another version inside, is caught."""
        target = self.vendor / artifact_name("ansible", "posix", "2.2.2")
        build_artifact(target, "ansible", "posix", "9.9.9", {})
        self.write_sums()
        self.assert_found("holds ansible.posix 9.9.9, not ansible.posix 2.2.2")

    def test_artifact_holding_another_collection_is_refused(self) -> None:
        """A tarball renamed to look like the pin, with another collection inside, is caught."""
        target = self.vendor / artifact_name("ansible", "posix", "2.2.2")
        build_artifact(target, "evil", "posix", "2.2.2", {})
        self.write_sums()
        self.assert_found("holds evil.posix 2.2.2")

    def test_unreadable_artifact_is_refused(self) -> None:
        """A file that is not a collection tarball has no manifest to read."""
        target = self.vendor / artifact_name("ansible", "posix", "2.2.2")
        target.write_bytes(b"not a tarball")
        self.write_sums()
        self.assert_found("has no readable MANIFEST.json")

    def test_unpinned_dependency_is_refused(self) -> None:
        """A dependency missing from requirements.yml would be fetched at install time."""
        text = (self.ansible / "requirements.yml").read_text(encoding="utf-8")
        kept = text.split("  - name: vendor/collections/community-library")[0]
        (self.ansible / "requirements.yml").write_text(kept, encoding="utf-8")
        self.assert_found("depends on community.library_inventory_filtering_v1")

    def test_dependency_pinned_below_its_floor_is_refused(self) -> None:
        """A pinned dependency that does not meet the range the dependent asks for is a finding."""
        build_artifact(
            self.vendor / artifact_name("community", "docker", "5.4.0"),
            "community",
            "docker",
            "5.4.0",
            {"community.library_inventory_filtering_v1": ">=2.0.0"},
        )
        self.write_sums()
        self.assert_found(
            "needs community.library_inventory_filtering_v1 >=2.0.0, the pin is 1.1.5"
        )

    def test_unreadable_dependency_range_is_refused(self) -> None:
        """A range the check cannot read is not assumed satisfied."""
        build_artifact(
            self.vendor / artifact_name("community", "docker", "5.4.0"),
            "community",
            "docker",
            "5.4.0",
            {"community.library_inventory_filtering_v1": "~1.0"},
        )
        self.write_sums()
        self.assert_found("needs community.library_inventory_filtering_v1 ~1.0")

    def test_stray_artifact_is_refused(self) -> None:
        """An artifact nothing names, and a stray file beside them, are findings."""
        stray = self.vendor / artifact_name("other", "thing", "1.0.0")
        build_artifact(stray, "other", "thing", "1.0.0", {})
        (self.vendor / "notes.txt").write_text("x", encoding="utf-8")
        self.write_sums()
        self.assert_found("other-thing-1.0.0.tar.gz is not named by requirements.yml")
        self.assert_found("notes.txt is not named by requirements.yml")

    def test_hash_line_for_nothing_is_refused(self) -> None:
        """A recorded hash whose artifact is not pinned is stale."""
        sums = self.vendor / "SHA256SUMS"
        sums.write_text(
            sums.read_text(encoding="utf-8") + "a" * 64 + "  gone-1.0.0.tar.gz\n", encoding="utf-8"
        )
        self.assert_found("lists gone-1.0.0.tar.gz")

    def test_collection_pinned_twice_is_refused(self) -> None:
        """The same collection named by two entries would install either."""
        text = (self.ansible / "requirements.yml").read_text(encoding="utf-8")
        (self.ansible / "requirements.yml").write_text(
            text
            + text.split("collections:\n")[1].split(
                "  - name: vendor/collections/community-docker"
            )[0],
            encoding="utf-8",
        )
        self.assert_found("ansible.posix a second time")

    def test_version_that_only_looks_exact_is_refused(self) -> None:
        """A trailing newline or digits from another script are not an exact version."""
        for odd in ('"2.2.2\\n"', '"\\uff12.\\uff12.\\uff12"'):
            with self.subTest(version=odd):
                self.write_requirements_yml({"posix": odd})
                self.assert_found("is not an exact x.y.z")

    def test_requirements_yml_that_is_not_yaml_is_refused(self) -> None:
        """A file that does not parse is a finding, not a crash."""
        (self.ansible / "requirements.yml").write_text("collections: [", encoding="utf-8")
        self.assert_found("cannot be read as YAML")

    def test_empty_collections_are_refused(self) -> None:
        """An empty list would pass every per-entry rule and pin nothing."""
        (self.ansible / "requirements.yml").write_text("---\ncollections: []\n", encoding="utf-8")
        self.assert_found("no collections list")


class VersionRangeTests(unittest.TestCase):
    """The dependency range reader accepts what Galaxy writes and nothing it cannot read."""

    def test_ranges(self) -> None:
        """Each operator, a comma list and the wildcard."""
        cases = [
            ("1.1.5", ">=1.0.0", True),
            ("1.1.5", ">=1.2.0", False),
            ("1.1.5", ">=1.0.0,<2.0.0", True),
            ("2.0.0", ">=1.0.0,<2.0.0", False),
            ("1.1.5", "*", True),
            ("1.1.5", "==1.1.5", True),
            ("1.1.5", "!=1.1.5", False),
            ("1.1.5", ">1.1.4", True),
            ("1.1.5", "<=1.1.5", True),
            ("1.1.10", ">1.1.9", True),
            ("1.1.5", "~1.0", None),
        ]
        for version, constraint, expected in cases:
            with self.subTest(version=version, constraint=constraint):
                self.assertIs(check_pins.meets(version, constraint), expected)


class ScenarioTests(PinCase):
    """Every Molecule scenario switches off the dependency step, so none can reach Galaxy."""

    OFF = "dependency:\n  name: galaxy\n  enabled: false\ndriver:\n  name: docker\n"

    def put(self, where: str, text: str) -> Path:
        """Write a scenario file under ansible/ and return it."""
        scenario = self.ansible / where / "molecule" / "default" / "molecule.yml"
        scenario.parent.mkdir(parents=True)
        scenario.write_text(text, encoding="utf-8")
        return scenario

    def test_disabled_dependency_passes_everywhere(self) -> None:
        """The control case, for a role, a pattern and the skeleton."""
        for where in ("roles/demo", "patterns/demo", "role_skeleton"):
            self.put(where, self.OFF)
        findings, notes = check_pins.run_checks(self.root)
        self.assertEqual(findings, [])
        self.assertTrue(any("3 scenario(s)" in note for note in notes))

    def test_default_dependency_is_refused(self) -> None:
        """A scenario that says nothing leaves Molecule's default, which is on."""
        self.put("roles/demo", "driver:\n  name: docker\n")
        self.assert_found(
            "roles/demo/molecule/default/molecule.yml does not set dependency.enabled"
        )

    def test_enabled_dependency_is_refused(self) -> None:
        """A scenario that turns the step on, or names a string, is refused."""
        for value in ("true", "'false'", "null"):
            with self.subTest(enabled=value):
                scenario = self.put("patterns/demo", self.OFF.replace("false", value))
                self.assert_found("patterns/demo/molecule/default/molecule.yml does not set")
                scenario.unlink()
                scenario.parent.rmdir()
                scenario.parent.parent.rmdir()

    def test_skeleton_is_covered(self) -> None:
        """The skeleton is what every new role copies, so a lapse there spreads."""
        self.put("role_skeleton", "driver:\n  name: docker\n")
        self.assert_found("role_skeleton/molecule/default/molecule.yml does not set")

    def test_unreadable_scenario_is_refused(self) -> None:
        """A scenario that does not parse is a finding, not a crash."""
        self.put("roles/demo", "dependency: [")
        self.assert_found("cannot be read as YAML")


class AnsibleConfigTests(PinCase):
    """ansible.cfg holds the install directory and no other setting."""

    def put(self, text: str) -> None:
        """Replace ansible.cfg."""
        (self.root / "ansible.cfg").write_text(text, encoding="utf-8")

    def test_other_path_is_refused(self) -> None:
        """Pointing Ansible at another directory bypasses the vendored set."""
        self.put("[defaults]\ncollections_path = /elsewhere\n")
        self.assert_found("ansible.cfg must hold only")

    def test_extra_setting_is_refused(self) -> None:
        """Any other setting is a way to change what a run does."""
        self.put(CONFIG + "host_key_checking = False\n")
        self.assert_found("ansible.cfg must hold only")

    def test_galaxy_server_section_is_refused(self) -> None:
        """A galaxy section names a server, which is a network path beyond the pins."""
        self.put(CONFIG + "[galaxy]\nserver_list = other\n")
        self.assert_found("ansible.cfg must hold only")

    def test_missing_file_is_refused(self) -> None:
        """Without the file Ansible would look in its default places."""
        (self.root / "ansible.cfg").unlink()
        self.assert_found("ansible.cfg cannot be read")


class LintRevTests(PinCase):
    """The pre-commit hook for ansible-lint runs the version the requirements file pins."""

    def put(self, text: str) -> None:
        """Replace the pre-commit configuration."""
        (self.root / ".pre-commit-config.yaml").write_text(text, encoding="utf-8")

    def test_equal_rev_passes(self) -> None:
        """The control case: a hook at v26.10.1 beside the pin 26.10.1."""
        self.put(LINT_HOOK.format(rev="v26.10.1"))
        findings, notes = check_pins.run_checks(self.root)
        self.assertEqual(findings, [])
        self.assertFalse(any("no ansible-lint hook" in note for note in notes))

    def test_other_rev_is_refused(self) -> None:
        """A hook one release behind the pin is the drift ANS-4 names."""
        self.put(LINT_HOOK.format(rev="v26.10.0"))
        self.assert_found("runs ansible-lint at v26.10.0, the requirements pin is v26.10.1")

    def test_branch_or_hash_rev_is_refused(self) -> None:
        """A rev that is not the release tag is not the pinned version."""
        for rev in ("main", "9bce2bfb8f4a984e6b13767bc0d6bf0a49492164", "26.10.1"):
            with self.subTest(rev=rev):
                self.put(LINT_HOOK.format(rev=rev))
                self.assert_found("runs ansible-lint at")

    def test_hook_from_another_repository_is_refused(self) -> None:
        """A fork's ansible-lint at the right tag is still not the pinned tool."""
        self.put(
            LINT_HOOK.format(rev="v26.10.1").replace("github.com/ansible/", "github.com/other/")
        )
        self.assert_found("takes ansible-lint from")

    def test_lint_pin_is_read_from_the_requirements_file(self) -> None:
        """Moving the requirements pin alone makes the hook stale."""
        self.put(LINT_HOOK.format(rev="v26.10.1"))
        (self.ansible / "requirements.txt").write_text(
            TOOLS.replace("26.10.1", "26.11.0"), encoding="utf-8"
        )
        self.assert_found("the requirements pin is v26.11.0")

    def test_unreadable_configuration_is_refused(self) -> None:
        """A configuration that does not parse is a finding."""
        self.put("repos: [")
        self.assert_found("cannot be read as YAML")


if __name__ == "__main__":
    unittest.main()
