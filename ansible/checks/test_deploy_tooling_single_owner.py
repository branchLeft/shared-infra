"""Check that the deploy_tooling role is the single owner of the programs it installs.

The CI deploy wrapper, the compose template unit, the Docker user policy program and its unit
each have one home in `hetzner/provision/` and one role that installs them. A second role that
links to, or holds a byte copy of, any of the four would be a second writer of the same host
files: the two would flap or one would silently stop converging. One role is allowed for now,
because it is retired by its own follow-up after this role has run on the host that has it.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

OWNER = "deploy_tooling"
ALLOWED_SECOND_OWNERS = frozenset({"control_plane"})
PROGRAMS = (
    "branchleft_deploy.py",
    "branchleft-compose@.service",
    "branchleft_docker_user_policy.sh",
    "branchleft-docker-user-policy.service",
)


def second_owner_problems(
    roles: Path, provision: Path, allowed: frozenset[str] = ALLOWED_SECOND_OWNERS
) -> list[str]:
    """Return each file of another role that is a link to, or a copy of, one of the programs."""
    digests = {
        hashlib.sha256((provision / name).read_bytes()).hexdigest(): name for name in PROGRAMS
    }
    home = provision.resolve()
    problems: list[str] = []
    for role in sorted(entry for entry in roles.iterdir() if entry.is_dir()):
        if role.name == OWNER or role.name in allowed:
            continue
        for path in sorted(role.rglob("*")):
            shown = path.relative_to(roles).as_posix()
            if path.is_symlink():
                target = path.resolve()
                if target.parent == home and target.name in PROGRAMS:
                    problems.append(f"{shown} is a link to {target.name}")
            elif path.is_file():
                copy = digests.get(hashlib.sha256(path.read_bytes()).hexdigest())
                if copy is not None:
                    problems.append(f"{shown} is a copy of {copy}")
    return problems


class TestSingleOwner(unittest.TestCase):
    """The real tree has one owner, and a second one is found in a copy of the tree."""

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="deploy-tooling-owner-"))
        self.addCleanup(shutil.rmtree, self.work)
        self.provision = self.work / "provision"
        self.roles = self.work / "roles"
        self.provision.mkdir()
        (self.roles / OWNER).mkdir(parents=True)
        (self.roles / "control_plane").mkdir()
        for name in PROGRAMS:
            (self.provision / name).write_bytes(f"home of {name}\n".encode())

    def test_the_real_tree_has_one_owner(self) -> None:
        roles = role_vars.REPO_ROOT / "ansible" / "roles"
        self.assertEqual(second_owner_problems(roles, role_vars.PROVISION), [])

    def test_the_allow_list_is_the_one_named_role(self) -> None:
        self.assertEqual(ALLOWED_SECOND_OWNERS, frozenset({"control_plane"}))

    def test_a_second_role_holding_a_link_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        link = self.roles / "other_role" / "files" / "wrapper"
        link.symlink_to(self.provision / "branchleft_deploy.py")
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["other_role/files/wrapper is a link to branchleft_deploy.py"],
        )

    def test_a_second_role_holding_a_copy_is_found(self) -> None:
        (self.roles / "other_role" / "files").mkdir(parents=True)
        copy = self.roles / "other_role" / "files" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["other_role/files/policy.sh is a copy of branchleft_docker_user_policy.sh"],
        )

    def test_the_allowed_role_may_hold_a_copy(self) -> None:
        copy = self.roles / "control_plane" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])

    def test_the_same_copy_under_a_role_not_on_the_list_is_found(self) -> None:
        (self.roles / "not_listed").mkdir()
        copy = self.roles / "not_listed" / "policy.sh"
        copy.write_bytes((self.provision / "branchleft_docker_user_policy.sh").read_bytes())
        self.assertEqual(
            second_owner_problems(self.roles, self.provision),
            ["not_listed/policy.sh is a copy of branchleft_docker_user_policy.sh"],
        )

    def test_a_role_with_other_content_is_not_found(self) -> None:
        (self.roles / "other_role").mkdir()
        (self.roles / "other_role" / "README.md").write_text("not a program\n", encoding="utf-8")
        self.assertEqual(second_owner_problems(self.roles, self.provision), [])


if __name__ == "__main__":
    unittest.main()
