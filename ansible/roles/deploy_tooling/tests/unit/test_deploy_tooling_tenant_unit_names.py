"""Unit tests for deploy_tooling_tenant_unit_names: which tenant instances the role enables.

The module turns the host's tenant list into unit names, and it is the control on that step:
a name that is not one of the host's tenants, or is not a tenant name at all, must be refused
before anything is enabled. A refusal names a position, never a name, because the plan log
is public and a tenant's name is not for it.
"""

import re
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import deploy_tooling_tenant_unit_names as names

ROLE = Path(__file__).resolve().parents[2]
TENANT_CHECK = ROLE.parent / "tenant_compose" / "library" / "tenant_compose_check.py"

PREFIX = "branchleft-compose"
KNOWN = ["tenant-a", "tenant-b"]


def units(known: Sequence[str], requested: Sequence[str] = ()) -> list[str]:
    return names.unit_names(known, requested, PREFIX)


class UnitNameTests(unittest.TestCase):
    def test_every_tenant_of_the_host_gets_its_instance_when_none_is_requested(self) -> None:
        self.assertEqual([f"{PREFIX}@tenant-a.service", f"{PREFIX}@tenant-b.service"], units(KNOWN))

    def test_a_host_with_no_tenants_enables_nothing(self) -> None:
        self.assertEqual([], units([]))

    def test_a_request_narrows_the_set_to_tenants_of_the_host(self) -> None:
        self.assertEqual([f"{PREFIX}@tenant-b.service"], units(KNOWN, ["tenant-b"]))

    def test_a_unit_for_a_tenant_not_in_the_host_list_is_refused(self) -> None:
        with self.assertRaises(names.TenantUnitError) as caught:
            units(KNOWN, ["tenant-a", "tenant-c"])
        self.assertIn("requested unit 2", str(caught.exception))

    def test_a_request_on_a_host_with_no_tenants_is_refused(self) -> None:
        with self.assertRaises(names.TenantUnitError):
            units([], ["tenant-a"])

    def test_a_refusal_never_names_a_tenant(self) -> None:
        for known, requested in (
            (KNOWN, ["tenant-zzz"]),
            (["Bad-Name"], []),
            (["tenant-a", "tenant-a"], []),
            (KNOWN, ["tenant-a", "tenant-a"]),
        ):
            with self.subTest(known=known, requested=requested):
                with self.assertRaises(names.TenantUnitError) as caught:
                    units(known, requested)
                for name in [*known, *requested]:
                    self.assertNotIn(name, str(caught.exception))

    def test_a_name_that_is_not_a_tenant_name_is_refused_in_the_host_list(self) -> None:
        bad = (
            "",
            "Tenant",
            "tenant_a",
            "-tenant",
            "tenant-",
            "1tenant",
            "tenant a",
            "../etc",
            "a/b",
            "tenant@x",
            "tenant\n",
            "a" * 27,
            names.SPOOL_SLUG,
        )
        for slug in bad:
            with self.subTest(slug=slug):
                with self.assertRaises(names.TenantUnitError):
                    units([slug])

    def test_the_longest_name_is_accepted(self) -> None:
        longest = "a" * names.SLUG_MAX_LENGTH
        self.assertEqual([f"{PREFIX}@{longest}.service"], units([longest]))

    def test_a_repeated_tenant_is_refused(self) -> None:
        with self.assertRaises(names.TenantUnitError):
            units(["tenant-a", "tenant-a"])

    def test_a_repeated_request_is_refused(self) -> None:
        with self.assertRaises(names.TenantUnitError):
            units(KNOWN, ["tenant-a", "tenant-a"])

    def test_a_prefix_that_is_not_a_unit_prefix_is_refused(self) -> None:
        for prefix in ("", "Branch", "a@b", "a/b", "a b", "-a"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(names.TenantUnitError):
                    names.unit_names(KNOWN, [], prefix)


class PinTests(unittest.TestCase):
    """The tenant name rules are copied from tenant_compose (ANS-12), and held to it here."""

    def assignment(self, name: str) -> str:
        text = TENANT_CHECK.read_text(encoding="utf-8")
        found = re.findall(rf"^{name} = (.+)$", text, flags=re.MULTILINE)
        self.assertEqual(1, len(found), name)
        return str(found[0])

    def test_the_slug_pattern_is_the_one_tenant_compose_applies(self) -> None:
        self.assertEqual(
            f're.compile(r"{names.SLUG_PATTERN.pattern}")', self.assignment("SLUG_PATTERN")
        )

    def test_the_slug_length_is_the_one_tenant_compose_applies(self) -> None:
        self.assertEqual(str(names.SLUG_MAX_LENGTH), self.assignment("SLUG_MAX_LENGTH"))

    def test_the_spool_name_is_the_one_tenant_compose_reserves(self) -> None:
        self.assertEqual(f'"{names.SPOOL_SLUG}"', self.assignment("SPOOL_SLUG"))


class ModuleTests(unittest.TestCase):
    def run_module(self, params: dict[str, object]) -> mock.Mock:
        module = mock.Mock()
        module.params = params
        module.fail_json.side_effect = SystemExit
        with mock.patch.object(names, "AnsibleModule", return_value=module):
            try:
                names.main()
            except SystemExit:
                pass
        return module

    def test_the_module_returns_the_names_as_a_fact_and_changes_nothing(self) -> None:
        module = self.run_module({"known": KNOWN, "requested": [], "unit_prefix": PREFIX})
        module.exit_json.assert_called_once_with(
            changed=False,
            count=2,
            ansible_facts={
                "deploy_tooling_tenant_unit_list": [
                    f"{PREFIX}@tenant-a.service",
                    f"{PREFIX}@tenant-b.service",
                ]
            },
        )

    def test_the_module_fails_with_the_refusal_and_returns_no_fact(self) -> None:
        module = self.run_module({"known": KNOWN, "requested": ["tenant-c"], "unit_prefix": PREFIX})
        module.exit_json.assert_not_called()
        self.assertIn("requested unit 1", module.fail_json.call_args.kwargs["msg"])


if __name__ == "__main__":
    unittest.main()
