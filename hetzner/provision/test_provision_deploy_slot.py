#!/usr/bin/env python3
"""Unit tests for provision_deploy_slot.

Every line this script writes is a line sshd reads before deciding what a
credential may do, so its input validation is the whole of the boundary
between one tenant's deploy key and every other tenant's Compose slot. The
cases below are the ones that boundary exists for: a stack name that is not a
stack name, a key comment that tries to end the line it is on, a slot whose
name is a prefix of another's, a caller reaching for a stack it was not
granted, and one key installed against two slots -- which sshd resolves to
whichever entry it reaches first, silently.
"""

import os
import stat
import tempfile
import unittest

import provision_deploy_slot as ps


# Well-formed ed25519 blobs: the 25-character type prefix OpenSSH emits plus
# 43 more, which is 68 base64 characters decoding to 51 bytes with no padding.
# The fingerprint check decodes them, so a placeholder of the wrong length
# fails for a reason unrelated to what is being tested.
ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "B" * 43
OTHER_ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "C" * 43
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "D" * 43
HOST_KEY_LINE = f"restrict {HOST_KEY} deploy@app1"

DEPLOY_UID = 1001
DEPLOY_GID = 1001


class FakeFs:
    """An in-memory filesystem recording ownership and mode, so the tests can
    assert on both without running as root.

    Unset paths default to `deploy`-owned, which is the state cloud-init
    actually leaves behind -- so a test that expects hardening has to see it
    happen rather than inheriting it from the fixture.
    """

    def __init__(self, files=None, dirs=()):
        self.files = dict(files or {})
        self.dirs = set(dirs)
        self.meta = {}

    def _default(self, path):
        return (DEPLOY_UID, DEPLOY_GID, 0o700 if path in self.dirs else 0o644)

    def exists(self, path):
        return path in self.files or path in self.dirs

    def listdir(self, path):
        if path not in self.dirs:
            return []
        prefix = path.rstrip("/") + "/"
        return [
            name[len(prefix) :]
            for name in list(self.files) + list(self.dirs)
            if name.startswith(prefix) and "/" not in name[len(prefix) :]
        ]

    def walk(self, path):
        prefix = path.rstrip("/") + "/"
        return [
            name
            for name in list(self.files) + list(self.dirs)
            if name.startswith(prefix)
        ]

    def is_symlink(self, path):
        return False

    def owner_mode(self, path):
        return self.meta.get(path, self._default(path))

    def account_gid(self, name):
        return DEPLOY_GID

    def read_text(self, path):
        return self.files.get(path, "")

    def remove(self, path):
        del self.files[path]

    def makedirs(self, path, mode):
        self.dirs.add(path)
        self.meta[path] = (0, 0, mode)

    def chown(self, path, uid, gid):
        _, _, mode = self.owner_mode(path)
        self.meta[path] = (uid, gid, mode)

    def chmod(self, path, mode):
        uid, gid, _ = self.owner_mode(path)
        self.meta[path] = (uid, gid, mode)

    def replace_text(self, path, text, mode, uid, gid):
        self.files[path] = text
        self.meta[path] = (uid, gid, mode)


def fs_with(slots=None, authorized="", stacks=(), home_files=None):
    files = {ps.AUTHORIZED_KEYS: authorized}
    for stack, key in (slots or {}).items():
        files[f"{ps.SLOT_DIR}/{stack}.pub"] = f"{key}\n"
    files.update(home_files or {})
    return FakeFs(
        files=files,
        dirs={ps.DEPLOY_HOME, ps.DEPLOY_SSH_DIR, ps.SLOT_DIR, ps.STACK_DIR}
        | {f"{ps.STACK_DIR}/{name}" for name in stacks},
    )


class StackNameTests(unittest.TestCase):
    def test_accepts_plain_names(self):
        for name in ("blog", "blog2", "ghost-tenant-one", "website"):
            self.assertEqual(ps.validate_stack_name(name), name)

    def test_rejects_path_traversal(self):
        for name in ("..", "../etc", "../../root/.ssh/authorized_keys", "a/b", "./x"):
            with self.assertRaises(ps.ProvisionError):
                ps.validate_stack_name(name)

    def test_rejects_names_that_would_break_out_of_the_forced_command(self):
        # Each of these ends or extends the `command="..."` it would be
        # interpolated into, or adds a second authorized_keys entry.
        for name in ('blog"', "blog other", "blog\nrestrict", "blog;reboot", "blog$(id)"):
            with self.assertRaises(ps.ProvisionError):
                ps.validate_stack_name(name)

    def test_rejects_empty_uppercase_and_overlong(self):
        for name in ("", "Blog", "-blog", "9blog", "a" * 33):
            with self.assertRaises(ps.ProvisionError):
                ps.validate_stack_name(name)

    def test_slot_path_stays_inside_the_register(self):
        with self.assertRaises(ps.ProvisionError):
            ps.slot_path("../../home/deploy/.ssh/authorized_keys")
        self.assertEqual(ps.slot_path("blog", "/reg"), "/reg/blog.pub")


class PublicKeyTests(unittest.TestCase):
    def test_discards_the_comment_field(self):
        self.assertEqual(ps.normalise_public_key(f"{ED25519} rob@workstation\n"), ED25519)

    def test_strips_a_comment_carrying_a_quote(self):
        # Left in place this closes the forced command and appends arguments of
        # the caller's choosing to the sudo invocation.
        self.assertNotIn('"', ps.normalise_public_key(f'{ED25519} x" ,command="/bin/sh'))

    def test_rejects_an_embedded_newline(self):
        # The injected second line has no forced command, so it is a shell on
        # the deploy account rather than a scoped deploy.
        with self.assertRaises(ps.ProvisionError):
            ps.normalise_public_key(f"{ED25519}\n{OTHER_ED25519} injected\n")

    def test_rejects_an_empty_file_and_a_non_key(self):
        for text in ("", "\n\n", "not a key", "ssh-ed25519", "ssh-dss AAAA"):
            with self.assertRaises(ps.ProvisionError):
                ps.normalise_public_key(text)

    def test_rejects_an_oversized_blob(self):
        with self.assertRaises(ps.ProvisionError):
            ps.normalise_public_key("ssh-rsa " + "A" * (ps.MAX_KEY_BLOB + 1))

    def test_fingerprint_matches_the_ssh_keygen_form(self):
        printed = ps.fingerprint(ED25519)
        self.assertTrue(printed.startswith("SHA256:"))
        self.assertNotIn("=", printed)


class KeyInLineTests(unittest.TestCase):
    """Reading the key out of a line this script does not own."""

    def test_finds_the_key_behind_options(self):
        self.assertEqual(ps.key_in_line(HOST_KEY_LINE), HOST_KEY)

    def test_finds_the_key_behind_a_quoted_forced_command(self):
        self.assertEqual(ps.key_in_line(ps.slot_line("blog", ED25519)), ED25519)

    def test_returns_none_for_a_line_with_no_key(self):
        self.assertIsNone(ps.key_in_line("# a comment"))
        self.assertIsNone(ps.key_in_line(""))


class SlotLineTests(unittest.TestCase):
    def test_line_names_exactly_the_granted_stack(self):
        line = ps.slot_line("blog", ED25519)
        self.assertEqual(
            line,
            f'restrict,command="{ps.SUDO} -n {ps.WRAPPER} --slot blog" '
            f"{ED25519} {ps.MANAGED_MARKER}blog",
        )

    def test_line_carries_restrict_and_a_forced_command(self):
        line = ps.slot_line("blog", ED25519)
        self.assertTrue(line.startswith("restrict,command="))
        self.assertIn("--slot blog", line)

    def test_refuses_to_emit_an_unvalidated_key(self):
        with self.assertRaises(ps.ProvisionError):
            ps.slot_line("blog", 'AAAA" ,command="/bin/sh')

    def test_a_prefix_stack_gets_its_own_distinct_line(self):
        # `blog` and `blog2` are separate tenants. A line for one must not be
        # readable as a line for the other, in either direction.
        self.assertEqual(ps.managed_slot(ps.slot_line("blog", ED25519)), "blog")
        self.assertEqual(ps.managed_slot(ps.slot_line("blog2", ED25519)), "blog2")
        self.assertNotIn("--slot blog2", ps.slot_line("blog", ED25519))


class ReconcileTests(unittest.TestCase):
    """The single arbiter every write path consults before touching anything."""

    def test_accepts_a_file_the_register_explains(self):
        slots = {"blog": ED25519}
        ps.reconcile(slots, HOST_KEY_LINE + "\n" + ps.slot_line("blog", ED25519) + "\n")

    def test_refuses_a_marked_line_with_no_register_entry(self):
        with self.assertRaises(ps.ProvisionError):
            ps.reconcile({}, ps.slot_line("other-tenant", ED25519) + "\n")

    def test_refuses_an_unrelated_key_whose_comment_ends_in_a_marker(self):
        # The production-outage case: the host-level key the marketing site
        # deploys through, carrying a comment that happens to look managed.
        # Dropping it silently is what a bare re-render would do.
        planted = f"restrict {HOST_KEY} ci-deploy {ps.MANAGED_MARKER}app1"
        with self.assertRaises(ps.ProvisionError):
            ps.reconcile({"blog": ED25519}, planted + "\n")

    def test_refuses_a_marked_line_edited_by_hand(self):
        edited = (
            f'restrict,command="{ps.SUDO} -n {ps.WRAPPER} --slot other-tenant" '
            f"{ED25519} {ps.MANAGED_MARKER}blog"
        )
        with self.assertRaises(ps.ProvisionError):
            ps.reconcile({"blog": ED25519}, edited + "\n")

    def test_refuses_two_lines_for_one_slot(self):
        doubled = (ps.slot_line("blog", ED25519) + "\n") * 2
        with self.assertRaises(ps.ProvisionError):
            ps.reconcile({"blog": ED25519}, doubled)


class RenderTests(unittest.TestCase):
    def test_preserves_unmanaged_lines_verbatim_and_in_order(self):
        existing = f"{HOST_KEY_LINE}\nrestrict {OTHER_ED25519} operator\n"
        rendered = ps.render_authorized_keys(existing, {"blog": ED25519})
        self.assertEqual(rendered.splitlines()[:2], existing.splitlines())

    def test_replaces_managed_lines_rather_than_appending(self):
        first = ps.render_authorized_keys(HOST_KEY_LINE + "\n", {"blog": ED25519})
        second = ps.render_authorized_keys(first, {"blog": OTHER_ED25519})
        self.assertEqual(len([l for l in second.splitlines() if ps.managed_slot(l)]), 1)
        self.assertIn(OTHER_ED25519, second)
        self.assertNotIn(ED25519, second)

    def test_is_idempotent(self):
        once = ps.render_authorized_keys(HOST_KEY_LINE + "\n", {"blog": ED25519})
        self.assertEqual(ps.render_authorized_keys(once, {"blog": ED25519}), once)

    def test_revoking_one_slot_leaves_a_prefix_named_sibling_alone(self):
        both = ps.render_authorized_keys("", {"blog": ED25519, "blog2": OTHER_ED25519})
        remaining = ps.render_authorized_keys(both, {"blog2": OTHER_ED25519})
        self.assertEqual([ps.managed_slot(l) for l in remaining.splitlines()], ["blog2"])

    def test_every_line_ends_where_it_should(self):
        rendered = ps.render_authorized_keys("", {"blog": ED25519, "blog2": OTHER_ED25519})
        self.assertTrue(rendered.endswith("\n"))
        self.assertEqual(len(rendered.splitlines()), 2)


class KeyReuseTests(unittest.TestCase):
    """One key, one slot. sshd matches the first entry and never the second."""

    def test_refuses_a_key_that_already_holds_another_slot(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        with self.assertRaises(ps.ProvisionError) as caught:
            ps.grant("blog2", ED25519, fs=fs)
        self.assertIn("already holds slot 'blog'", str(caught.exception))
        self.assertNotIn(f"{ps.SLOT_DIR}/blog2.pub", fs.files)

    def test_refuses_the_host_level_key(self):
        # The sharper form: the unmanaged entry renders first, so the slot
        # would be cosmetic and the repository would keep host-wide reach
        # while the register reported it as scoped.
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        with self.assertRaises(ps.ProvisionError) as caught:
            ps.grant("blog", HOST_KEY, fs=fs)
        self.assertIn("does not manage", str(caught.exception))

    def test_regranting_the_same_slot_its_own_key_is_still_allowed(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        actions = ps.grant("blog", ED25519, fs=fs)
        self.assertTrue(any("unchanged" in action for action in actions))

    def test_list_slots_surfaces_a_duplicate_rather_than_printing_two_rows(self):
        fs = fs_with(slots={"blog": ED25519, "blog2": ED25519})
        fs.files[ps.AUTHORIZED_KEYS] = ps.render_authorized_keys(
            "", {"blog": ED25519, "blog2": ED25519}
        )
        with self.assertRaises(ps.ProvisionError) as caught:
            ps.list_slots(fs=fs)
        self.assertIn("same key", str(caught.exception))


class ExistingStackTests(unittest.TestCase):
    """The refusal derives from the host, not from a list that can drift."""

    def test_refuses_a_slug_naming_a_stack_the_host_already_runs(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n", stacks=("website",))
        with self.assertRaises(ps.ProvisionError) as caught:
            ps.grant("website", ED25519, fs=fs)
        self.assertIn("--adopt-existing-stack", str(caught.exception))
        self.assertNotIn(f"{ps.SLOT_DIR}/website.pub", fs.files)

    def test_adopting_is_explicit_and_then_allowed(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n", stacks=("website",))
        ps.grant("website", ED25519, fs=fs, adopt_existing_stack=True)
        self.assertIn("--slot website", fs.files[ps.AUTHORIZED_KEYS])

    def test_a_new_tenant_has_no_stack_directory_so_never_sees_this(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n", stacks=("website",))
        ps.grant("blog", ED25519, fs=fs)
        self.assertIn("--slot blog", fs.files[ps.AUTHORIZED_KEYS])

    def test_rotating_an_adopted_slot_does_not_need_the_flag_again(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n", stacks=("website",))
        ps.grant("website", ED25519, fs=fs, adopt_existing_stack=True)
        ps.grant("website", OTHER_ED25519, fs=fs)
        self.assertIn(OTHER_ED25519, fs.files[ps.AUTHORIZED_KEYS])


class HardeningTests(unittest.TestCase):
    def test_takes_the_home_and_ssh_directory_to_root(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        for path in (ps.DEPLOY_HOME, ps.DEPLOY_SSH_DIR):
            self.assertEqual(fs.meta[path], (0, DEPLOY_GID, ps.DEPLOY_DIR_MODE))

    def test_takes_dotfiles_beneath_the_home_to_root(self):
        # bash sources ~/.bashrc for the non-interactive `$SHELL -c` a forced
        # command runs under, so a deploy-writable dotfile runs ahead of every
        # slot key on the host.
        fs = fs_with(home_files={f"{ps.DEPLOY_HOME}/.bashrc": "", f"{ps.DEPLOY_HOME}/.profile": ""})
        ps.grant("blog", ED25519, fs=fs)
        for name in (".bashrc", ".profile"):
            uid, _, _ = fs.meta[f"{ps.DEPLOY_HOME}/{name}"]
            self.assertEqual(uid, 0)

    def test_strips_group_and_other_write_bits_beneath_the_home(self):
        fs = fs_with(home_files={f"{ps.DEPLOY_HOME}/.bashrc": ""})
        fs.meta[f"{ps.DEPLOY_HOME}/.bashrc"] = (DEPLOY_UID, DEPLOY_GID, 0o666)
        ps.grant("blog", ED25519, fs=fs)
        _, _, mode = fs.meta[f"{ps.DEPLOY_HOME}/.bashrc"]
        self.assertEqual(mode & 0o022, 0)

    def test_authorized_keys_is_root_owned_and_not_account_writable(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        uid, gid, mode = fs.meta[ps.AUTHORIZED_KEYS]
        self.assertEqual(uid, 0)
        self.assertEqual(gid, DEPLOY_GID)
        self.assertEqual(mode & 0o022, 0)

    def test_home_is_not_world_readable(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        _, _, mode = fs.meta[ps.DEPLOY_HOME]
        self.assertEqual(mode & 0o007, 0)

    def test_register_entries_are_root_owned_0600(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(fs.meta[f"{ps.SLOT_DIR}/blog.pub"], (0, 0, ps.SLOT_FILE_MODE))

    def test_unhardened_paths_reports_an_account_owned_home(self):
        fs = fs_with(home_files={f"{ps.DEPLOY_HOME}/.bashrc": ""})
        self.assertTrue(ps.unhardened_paths(fs=fs))

    def test_unhardened_paths_is_empty_after_a_grant(self):
        fs = fs_with(home_files={f"{ps.DEPLOY_HOME}/.bashrc": ""})
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(ps.unhardened_paths(fs=fs), [])

    def test_list_slots_refuses_when_the_hardening_has_been_undone(self):
        # The documented `chown -R deploy:deploy /home/deploy` remediation
        # leaves every slot in place and every deploy working, so nothing else
        # would notice.
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        fs.meta[ps.DEPLOY_SSH_DIR] = (DEPLOY_UID, DEPLOY_GID, 0o700)
        with self.assertRaises(ps.ProvisionError) as caught:
            ps.list_slots(fs=fs)
        self.assertIn("not the restriction they appear to be", str(caught.exception))


class GrantTests(unittest.TestCase):
    def test_grant_writes_the_register_and_renders_the_file(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", f"{ED25519} rob@workstation\n", fs=fs)
        self.assertEqual(fs.files[f"{ps.SLOT_DIR}/blog.pub"], f"{ED25519}\n")
        self.assertIn("--slot blog", fs.files[ps.AUTHORIZED_KEYS])
        self.assertIn(HOST_KEY_LINE, fs.files[ps.AUTHORIZED_KEYS])

    def test_granting_twice_is_a_no_op(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        first = fs.files[ps.AUTHORIZED_KEYS]
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], first)

    def test_rotation_replaces_rather_than_adds_a_second_working_key(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        ps.grant("blog", OTHER_ED25519, fs=fs)
        self.assertNotIn(ED25519, fs.files[ps.AUTHORIZED_KEYS])
        self.assertIn(OTHER_ED25519, fs.files[ps.AUTHORIZED_KEYS])

    def test_a_slot_cannot_be_granted_a_key_naming_another_slot(self):
        # The stack name is not in the key material at all -- the only place it
        # appears is the forced command this script writes -- so a key whose
        # comment claims another tenant changes nothing about what it reaches.
        fs = fs_with()
        ps.grant("blog", f"{ED25519} branchleft-slot:other-tenant", fs=fs)
        lines = fs.files[ps.AUTHORIZED_KEYS].splitlines()
        self.assertEqual([ps.managed_slot(l) for l in lines], ["blog"])
        self.assertNotIn("other-tenant", fs.files[ps.AUTHORIZED_KEYS])

    def test_a_prefix_named_tenant_does_not_disturb_its_neighbour(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        ps.grant("blog2", OTHER_ED25519, fs=fs)
        lines = fs.files[ps.AUTHORIZED_KEYS].splitlines()
        self.assertEqual([ps.managed_slot(l) for l in lines], [None, "blog", "blog2"])

    def test_grant_refuses_a_host_with_no_deploy_account(self):
        fs = FakeFs(dirs=set())
        with self.assertRaises(ps.ProvisionError):
            ps.grant("blog", ED25519, fs=fs)

    def test_grant_refuses_a_hostile_stack_name_before_writing_anything(self):
        fs = fs_with()
        with self.assertRaises(ps.ProvisionError):
            ps.grant("../../root", ED25519, fs=fs)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], "")

    def test_grant_changes_nothing_when_reconciliation_fails(self):
        planted = f"restrict {HOST_KEY} ci-deploy {ps.MANAGED_MARKER}app1"
        fs = fs_with(authorized=planted + "\n")
        with self.assertRaises(ps.ProvisionError):
            ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], planted + "\n")
        self.assertNotIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)
        self.assertEqual(fs.meta, {})


class RevokeTests(unittest.TestCase):
    def test_revoke_removes_the_line_and_the_register_entry(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        ps.revoke("blog", fs=fs)
        self.assertNotIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], HOST_KEY_LINE + "\n")

    def test_revoke_of_an_ungranted_stack_refuses_rather_than_no_ops(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        with self.assertRaises(ps.ProvisionError):
            ps.revoke("blog2", fs=fs)
        self.assertIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)

    def test_revoke_leaves_a_prefix_named_sibling_working(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        ps.grant("blog2", OTHER_ED25519, fs=fs)
        ps.revoke("blog", fs=fs)
        self.assertIn(f"{ps.SLOT_DIR}/blog2.pub", fs.files)
        self.assertEqual(
            [ps.managed_slot(l) for l in fs.files[ps.AUTHORIZED_KEYS].splitlines()],
            [None, "blog2"],
        )

    def test_revoke_changes_nothing_when_reconciliation_fails(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        fs.files[ps.AUTHORIZED_KEYS] += ps.slot_line("ghost", OTHER_ED25519) + "\n"
        before = fs.files[ps.AUTHORIZED_KEYS]
        with self.assertRaises(ps.ProvisionError):
            ps.revoke("blog", fs=fs)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], before)
        self.assertIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)


class ReadSlotsTests(unittest.TestCase):
    def test_refuses_a_register_file_that_is_not_a_stack_name(self):
        fs = fs_with()
        fs.files[f"{ps.SLOT_DIR}/Blog.pub"] = ED25519
        with self.assertRaises(ps.ProvisionError):
            ps.read_slots(fs=fs)

    def test_refuses_a_register_file_that_is_not_a_key(self):
        fs = fs_with(slots={"blog": ED25519})
        fs.files[f"{ps.SLOT_DIR}/blog.pub"] = "garbage\n"
        with self.assertRaises(ps.ProvisionError):
            ps.read_slots(fs=fs)

    def test_refuses_a_stray_file_rather_than_skipping_it(self):
        fs = fs_with(slots={"blog": ED25519})
        fs.files[f"{ps.SLOT_DIR}/notes.txt"] = "x"
        with self.assertRaises(ps.ProvisionError):
            ps.read_slots(fs=fs)


class ListSlotsTests(unittest.TestCase):
    def test_reports_each_slot_with_its_fingerprint(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(ps.list_slots(fs=fs), [f"blog={ps.fingerprint(ED25519)}"])

    def test_detects_a_managed_line_added_by_hand(self):
        fs = fs_with(authorized=ps.slot_line("other-tenant", ED25519) + "\n")
        with self.assertRaises(ps.ProvisionError):
            ps.list_slots(fs=fs)

    def test_an_empty_host_reports_nothing_rather_than_failing(self):
        self.assertEqual(ps.list_slots(fs=fs_with()), [])


class AtomicWriteTests(unittest.TestCase):
    """The one seam that touches a real filesystem.

    Ownership is asserted as "unchanged from this process's own", because the
    suite does not run as root and chown to any other uid would fail for a
    reason unrelated to what is being tested.
    """

    def test_replaces_atomically_with_the_requested_mode(self):
        fs = ps._RealFs()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "authorized_keys")
            fs.replace_text(path, "one\n", 0o640, os.getuid(), os.getgid())
            fs.replace_text(path, "two\n", 0o640, os.getuid(), os.getgid())
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "two\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
            self.assertEqual(os.listdir(directory), ["authorized_keys"])

    def test_walk_finds_nested_paths(self):
        fs = ps._RealFs()
        with tempfile.TemporaryDirectory() as directory:
            os.makedirs(os.path.join(directory, ".ssh"))
            open(os.path.join(directory, ".bashrc"), "w").close()
            open(os.path.join(directory, ".ssh", "authorized_keys"), "w").close()
            found = {os.path.relpath(p, directory) for p in fs.walk(directory)}
            self.assertEqual(found, {".ssh", ".bashrc", os.path.join(".ssh", "authorized_keys")})


class MainTests(unittest.TestCase):
    def test_refuses_to_run_as_a_non_root_user(self):
        self.assertEqual(ps.main(["--list-slots"], geteuid=lambda: 1000, fs=fs_with()), 1)

    def test_usage_errors_exit_two(self):
        for argv in (
            ["blog"],
            ["--revoke", "--public-key-file", "k.pub", "blog"],
            ["--list-slots", "blog"],
            ["--revoke", "--adopt-existing-stack", "blog"],
            [],
        ):
            self.assertEqual(ps.main(argv, geteuid=lambda: 0, fs=fs_with()), 2, argv)

    def test_a_refusal_about_host_state_exits_one(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n", stacks=("website",))
        code = ps.main(
            ["--public-key-file", "k.pub", "website"],
            geteuid=lambda: 0,
            fs=fs,
            read_key=lambda path: ED25519,
        )
        self.assertEqual(code, 1)

    def test_grant_reports_each_action(self):
        fs = fs_with()
        lines = []
        code = ps.main(
            ["--public-key-file", "k.pub", "blog"],
            geteuid=lambda: 0,
            fs=fs,
            out=lines.append,
            read_key=lambda path: ED25519,
        )
        self.assertEqual(code, 0)
        self.assertTrue(any("granted slot blog" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
