#!/usr/bin/env python3
"""Unit tests for provision_deploy_slot.

Every line this script writes is a line sshd reads before deciding what a
credential may do, so its input validation is the whole of the boundary
between one tenant's deploy key and every other tenant's Compose slot. The
cases below are the ones that boundary exists for: a stack name that is not a
stack name, a key comment that tries to end the line it is on, a slot whose
name is a prefix of another's, and a caller reaching for a stack it was not
granted.
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
HOST_KEY_LINE = "restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "D" * 43 + " deploy@app1"


class FakeFs:
    """An in-memory filesystem recording ownership and mode, so the tests can
    assert on both without running as root."""

    def __init__(self, files=None, dirs=()):
        self.files = dict(files or {})
        self.dirs = set(dirs)
        self.meta = {}

    def exists(self, path):
        return path in self.files or path in self.dirs

    def listdir(self, path):
        if path not in self.dirs:
            return []
        prefix = path.rstrip("/") + "/"
        return [
            name[len(prefix) :]
            for name in self.files
            if name.startswith(prefix) and "/" not in name[len(prefix) :]
        ]

    def read_text(self, path):
        return self.files.get(path, "")

    def remove(self, path):
        del self.files[path]

    def makedirs(self, path, mode):
        self.dirs.add(path)
        self.meta[path] = (0, 0, mode)

    def chown(self, path, uid, gid):
        _, _, mode = self.meta.get(path, (0, 0, None))
        self.meta[path] = (uid, gid, mode)

    def chmod(self, path, mode):
        uid, gid, _ = self.meta.get(path, (0, 0, None))
        self.meta[path] = (uid, gid, mode)

    def replace_text(self, path, text, mode, uid, gid):
        self.files[path] = text
        self.meta[path] = (uid, gid, mode)


def fs_with(slots=None, authorized="", **kwargs):
    files = {ps.AUTHORIZED_KEYS: authorized}
    for stack, key in (slots or {}).items():
        files[f"{ps.SLOT_DIR}/{stack}.pub"] = f"{key}\n"
    return FakeFs(
        files=files,
        dirs={ps.DEPLOY_HOME, ps.DEPLOY_SSH_DIR, ps.SLOT_DIR},
        **kwargs,
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

    def test_rejects_a_comment_carrying_a_quote(self):
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

    def test_fingerprint_matches_the_ssh_keygen_form(self):
        printed = ps.fingerprint(ED25519)
        self.assertTrue(printed.startswith("SHA256:"))
        self.assertNotIn("=", printed)


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


class RenderTests(unittest.TestCase):
    def test_preserves_unmanaged_lines_verbatim_and_in_order(self):
        existing = f"{HOST_KEY_LINE}\nrestrict ssh-ed25519 AAAAsecond operator\n"
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


class GrantTests(unittest.TestCase):
    def test_grant_writes_the_register_and_renders_the_file(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", f"{ED25519} rob@workstation\n", fs=fs)
        self.assertEqual(fs.files[f"{ps.SLOT_DIR}/blog.pub"], f"{ED25519}\n")
        self.assertIn("--slot blog", fs.files[ps.AUTHORIZED_KEYS])
        self.assertIn(HOST_KEY_LINE, fs.files[ps.AUTHORIZED_KEYS])

    def test_grant_takes_the_deploy_home_and_ssh_directory_to_root(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        for path in (ps.DEPLOY_HOME, ps.DEPLOY_SSH_DIR):
            self.assertEqual(fs.meta[path], (0, 0, ps.DEPLOY_DIR_MODE))

    def test_authorized_keys_is_root_owned_and_not_writable_by_deploy(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        uid, gid, mode = fs.meta[ps.AUTHORIZED_KEYS]
        self.assertEqual((uid, gid), (0, 0))
        self.assertEqual(mode & 0o022, 0)

    def test_register_entries_are_root_owned_0600(self):
        fs = fs_with()
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(fs.meta[f"{ps.SLOT_DIR}/blog.pub"], (0, 0, ps.SLOT_FILE_MODE))

    def test_granting_twice_is_a_no_op(self):
        fs = fs_with(authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        first = fs.files[ps.AUTHORIZED_KEYS]
        actions = ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], first)
        self.assertTrue(any("unchanged" in action for action in actions))

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


class RevokeTests(unittest.TestCase):
    def test_revoke_removes_the_line_and_the_register_entry(self):
        fs = fs_with(slots={"blog": ED25519}, authorized=HOST_KEY_LINE + "\n")
        ps.grant("blog", ED25519, fs=fs)
        ps.revoke("blog", fs=fs)
        self.assertNotIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)
        self.assertEqual(fs.files[ps.AUTHORIZED_KEYS], HOST_KEY_LINE + "\n")

    def test_revoke_of_an_ungranted_stack_refuses_rather_than_no_ops(self):
        fs = fs_with(slots={"blog": ED25519})
        with self.assertRaises(ps.ProvisionError):
            ps.revoke("blog2", fs=fs)
        self.assertIn(f"{ps.SLOT_DIR}/blog.pub", fs.files)

    def test_revoke_leaves_a_prefix_named_sibling_working(self):
        fs = fs_with(slots={"blog": ED25519, "blog2": OTHER_ED25519})
        ps.revoke("blog", fs=fs)
        self.assertIn(f"{ps.SLOT_DIR}/blog2.pub", fs.files)
        self.assertEqual(
            [ps.managed_slot(l) for l in fs.files[ps.AUTHORIZED_KEYS].splitlines()], ["blog2"]
        )


class ReadSlotsTests(unittest.TestCase):
    def test_refuses_a_register_file_that_is_not_a_stack_name(self):
        fs = fs_with()
        fs.files[f"{ps.SLOT_DIR}/../evil.pub"] = ED25519
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
        fs = fs_with(slots={"blog": ED25519})
        ps.grant("blog", ED25519, fs=fs)
        self.assertEqual(ps.list_slots(fs=fs), [f"blog={ps.fingerprint(ED25519)}"])

    def test_detects_a_managed_line_added_by_hand(self):
        fs = fs_with(authorized=ps.slot_line("other-tenant", ED25519) + "\n")
        with self.assertRaises(ps.ProvisionError):
            ps.list_slots(fs=fs)

    def test_detects_a_managed_line_edited_by_hand(self):
        fs = fs_with(slots={"blog": ED25519})
        fs.files[ps.AUTHORIZED_KEYS] = (
            f'restrict,command="{ps.SUDO} -n {ps.WRAPPER} --slot other-tenant" '
            f"{ED25519} {ps.MANAGED_MARKER}blog\n"
        )
        with self.assertRaises(ps.ProvisionError):
            ps.list_slots(fs=fs)


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
            fs.replace_text(path, "one\n", 0o644, os.getuid(), os.getgid())
            fs.replace_text(path, "two\n", 0o644, os.getuid(), os.getgid())
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "two\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
            self.assertEqual(os.listdir(directory), ["authorized_keys"])


class MainTests(unittest.TestCase):
    def test_refuses_to_run_as_a_non_root_user(self):
        self.assertEqual(ps.main(["--list-slots"], geteuid=lambda: 1000, fs=fs_with()), 1)

    def test_grant_requires_a_key(self):
        self.assertEqual(ps.main(["blog"], geteuid=lambda: 0, fs=fs_with()), 1)

    def test_revoke_and_key_are_mutually_exclusive(self):
        code = ps.main(
            ["--revoke", "--public-key-file", "k.pub", "blog"],
            geteuid=lambda: 0,
            fs=fs_with(),
        )
        self.assertEqual(code, 1)

    def test_list_slots_takes_no_stack(self):
        self.assertEqual(
            ps.main(["--list-slots", "blog"], geteuid=lambda: 0, fs=fs_with()), 1
        )

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
