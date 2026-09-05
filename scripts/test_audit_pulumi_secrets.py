#!/usr/bin/env python3
"""Unit tests for audit-pulumi-secrets.

The audited property -- that no stack still depends on a KMS key that is about
to be destroyed -- has no second line of defence and no reversal, so the
failure that matters is this script reporting a clean sweep over a stack it
did not actually read. Every test below is aimed at that shape: a parse that
returns a wrong-but-plausible answer, a path that resolves to nothing, or a
status that is quietly treated as a pass.
"""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "audit-pulumi-secrets.py"
    spec = importlib.util.spec_from_file_location("audit_pulumi_secrets", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = _load_module()


GCPKMS_URL = (
    "gcpkms://projects/branchleft-prod/locations/europe-west1"
    "/keyRings/pulumi/cryptoKeys/pulumi-secrets"
)


class TopLevelScalarTests(unittest.TestCase):
    def test_reads_plain_pairs(self):
        parsed = audit.read_top_level_scalars("name: branchleft-mail\nruntime: nodejs\n")
        self.assertEqual(parsed, {"name": "branchleft-mail", "runtime": "nodejs"})

    def test_ignores_comments_and_blank_lines(self):
        text = "# a comment: with a colon\n\nname: edge\n"
        self.assertEqual(audit.read_top_level_scalars(text), {"name": "edge"})

    def test_ignores_nested_keys(self):
        # `config:` nests `gcp:project`, which must not be mistaken for a
        # top-level key -- it would shadow a real one of the same name.
        text = "config:\n  gcp:project: branchleft-prod\nsecretsprovider: passphrase\n"
        parsed = audit.read_top_level_scalars(text)
        self.assertEqual(parsed, {"secretsprovider": "passphrase"})

    def test_block_openers_are_not_values(self):
        text = "description: >-\n  wrapped prose\nname: x\n"
        parsed = audit.read_top_level_scalars(text)
        self.assertNotIn("description", parsed)
        self.assertEqual(parsed["name"], "x")

    def test_strips_quotes(self):
        parsed = audit.read_top_level_scalars("url: 's3://bucket?a=b'\n")
        self.assertEqual(parsed["url"], "s3://bucket?a=b")

    def test_keeps_url_scheme_colons_intact(self):
        parsed = audit.read_top_level_scalars(f"secretsprovider: {GCPKMS_URL}\n")
        self.assertEqual(parsed["secretsprovider"], GCPKMS_URL)

    def test_bom_does_not_hide_the_first_key(self):
        # An unstripped BOM makes line 1 fail `not line[0].isspace()` below --
        # the reader reads it as an indented (nested) line and silently skips
        # it, same failure mode as the sibling script's BOM bug.
        parsed = audit.read_top_level_scalars(audit.BOM + "secretsprovider: passphrase\n")
        self.assertEqual(parsed, {"secretsprovider": "passphrase"})

    def test_strips_quotes_from_the_key_too(self):
        parsed = audit.read_top_level_scalars('"secretsprovider": passphrase\n')
        self.assertEqual(parsed, {"secretsprovider": "passphrase"})


class BackendUrlTests(unittest.TestCase):
    def test_reads_pinned_backend(self):
        text = "name: x\nbackend:\n  url: 's3://b?endpoint=e&s3ForcePathStyle=true'\nruntime: nodejs\n"
        self.assertEqual(audit.read_backend_url(text), "s3://b?endpoint=e&s3ForcePathStyle=true")

    def test_absent_when_not_pinned(self):
        self.assertIsNone(audit.read_backend_url("name: x\nruntime: nodejs\n"))

    def test_stops_at_the_end_of_the_block(self):
        # A later top-level `url:` belongs to something else entirely.
        text = "backend:\n  region: nbg1\nurl: gs://wrong\n"
        self.assertIsNone(audit.read_backend_url(text))


class ClassifyTests(unittest.TestCase):
    def test_gcpkms(self):
        kind, detail = audit.classify_secrets_provider(
            f"secretsprovider: {GCPKMS_URL}\nencryptedkey: CiQAaaa=\n"
        )
        self.assertEqual(kind, "gcpkms")
        self.assertEqual(detail, GCPKMS_URL)

    def test_passphrase_explicit(self):
        kind, detail = audit.classify_secrets_provider(
            "secretsprovider: passphrase\nencryptionsalt: v1:abc:def\n"
        )
        self.assertEqual((kind, detail), ("passphrase", "v1:abc:def"))

    def test_passphrase_implied_by_salt_alone(self):
        # `pulumi stack change-secrets-provider passphrase` writes the salt and
        # no `secretsprovider` key. Reading that as "absent" would report a
        # finished migration as never started.
        kind, detail = audit.classify_secrets_provider("encryptionsalt: v1:abc:def\n")
        self.assertEqual((kind, detail), ("passphrase", "v1:abc:def"))

    def test_absent(self):
        self.assertEqual(audit.classify_secrets_provider("config:\n  a: b\n")[0], "absent")

    def test_third_provider_is_unknown_not_migrated(self):
        kind, _ = audit.classify_secrets_provider("secretsprovider: awskms://alias/x\n")
        self.assertEqual(kind, "unknown")

    def test_bom_does_not_hide_a_gcpkms_config(self):
        # Without stripping the BOM here, line 1 looks indented to
        # read_top_level_scalars and is silently skipped -- the same class of
        # bug assert-no-committed-pulumi-secrets.py was fixed for next door,
        # but in the reader this script's own gate depends on.
        kind, detail = audit.classify_secrets_provider(
            audit.BOM + f"secretsprovider: {GCPKMS_URL}\nencryptedkey: CiQAaaa=\n"
        )
        self.assertEqual(kind, "gcpkms")
        self.assertEqual(detail, GCPKMS_URL)

    def test_quoted_key_is_still_read(self):
        kind, detail = audit.classify_secrets_provider(f'"secretsprovider": {GCPKMS_URL}\n')
        self.assertEqual((kind, detail), ("gcpkms", GCPKMS_URL))

    def test_single_quoted_key_is_still_read(self):
        kind, _ = audit.classify_secrets_provider("'encryptionsalt': v1:abc:def\n")
        self.assertEqual(kind, "passphrase")

    def test_encryptedkey_alone_is_gcpkms_even_with_no_secretsprovider_line(self):
        # The realistic half-edit: RUNBOOK-existing-stack-migration.md
        # describes secretsprovider/encryptedkey moving together with
        # encryptionsalt; deleting one line by hand and not the other leaves
        # exactly this shape, and encryptedkey -- the wrapped data key
        # itself -- is the more direct evidence of the two.
        kind, detail = audit.classify_secrets_provider("encryptedkey: CiQAaaa=\n")
        self.assertEqual(kind, "gcpkms")
        self.assertEqual(detail, "CiQAaaa=")

    def test_encryptedkey_wins_over_a_contradictory_secretsprovider(self):
        kind, _ = audit.classify_secrets_provider(
            "secretsprovider: passphrase\nencryptedkey: CiQAaaa=\n"
        )
        self.assertEqual(kind, "gcpkms")


class AuditStackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def _write(self, repo, rel, text):
        path = self.root / repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def _entry(self, **over):
        entry = {
            "project": "p",
            "stack": "s",
            "repo": "website",
            "config_path": "infra/Pulumi.s.yaml",
            "terminal_state": "migrate",
        }
        entry.update(over)
        return entry

    def test_pending_when_still_on_kms(self):
        self._write("website", "infra/Pulumi.s.yaml", f"secretsprovider: {GCPKMS_URL}\n")
        self.assertEqual(audit.audit_stack(self._entry(), self.root)["status"], "pending")

    def test_migrated_when_salt_present(self):
        self._write("website", "infra/Pulumi.s.yaml", "encryptionsalt: v1:x:y\n")
        self.assertEqual(audit.audit_stack(self._entry(), self.root)["status"], "migrated")

    def test_passphrase_without_salt_is_drift(self):
        # Decrypts nothing it has committed, and every command still succeeds
        # until something needs a secret.
        self._write("website", "infra/Pulumi.s.yaml", "secretsprovider: passphrase\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "drift")

    def test_unattested_absent_file_needs_attestation_not_drift(self):
        # This is the shape of a *correctly* migrated salt-injected-at-deploy
        # stack per PUL-12 -- indistinguishable by content from one never
        # created. Reporting it `drift` (as opposed to `needs-attestation`)
        # would fail the default CI invocation, with no --require-migrated,
        # the moment a new stack is added to the inventory ahead of its
        # attestation -- and that invocation gates this repo's production
        # deploy.
        self._write("website", "infra/Pulumi.s.yaml", "config:\n  a: b\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "needs-attestation")
        self.assertNotIn("attested", finding)

    def test_missing_file_is_not_a_pass(self):
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "missing")

    def test_no_committed_config_needs_an_attestation(self):
        # Distinct from `unresolved`: a repo this run could not reach is fixed
        # by passing --root, whereas no file exists for this stack in any repo
        # and never will, so only an operator statement can close it.
        finding = audit.audit_stack(self._entry(config_path=None), self.root)
        self.assertEqual(finding["status"], "needs-attestation")

    def test_unreachable_repo_is_unresolved_rather_than_skipped(self):
        finding = audit.audit_stack(self._entry(), None)
        self.assertEqual(finding["status"], "unresolved")


def _finding(status, terminal_state="migrate", **over):
    finding = {"status": status, "terminal_state": terminal_state, "stack": "p/s", "repo": "r"}
    finding.update(over)
    return finding


class TerminalStateTests(unittest.TestCase):
    """The gate has to be able to go green.

    Demanding `migrated` of every stack made it permanently red, because two
    stacks are destroy-bound and can never report it. A gate that is red in
    the success state gets ignored rather than satisfied, so these pin the
    success state itself.
    """

    def test_destroy_bound_stack_is_satisfied_by_removal_not_migration(self):
        self.assertTrue(audit.satisfies_terminal_state(_finding("attested-removed", "destroy")))
        self.assertFalse(audit.satisfies_terminal_state(_finding("migrated", "destroy")))

    def test_migrate_bound_stack_is_not_satisfied_by_removal(self):
        self.assertFalse(audit.satisfies_terminal_state(_finding("attested-removed", "migrate")))

    def test_either_terminal_state_accepts_both(self):
        for status in ("migrated", "attested-migrated", "attested-removed"):
            self.assertTrue(
                audit.satisfies_terminal_state(_finding(status, "migrate-or-destroy")), status
            )

    def test_pending_satisfies_nothing(self):
        for terminal_state in audit.TERMINAL_STATES:
            self.assertFalse(audit.satisfies_terminal_state(_finding("pending", terminal_state)))

    def test_unknown_terminal_state_is_drift(self):
        entry = {"project": "p", "stack": "s", "terminal_state": "archive"}
        self.assertEqual(audit.audit_stack(entry, None)["status"], "drift")

    def test_shipped_inventory_uses_only_known_terminal_states(self):
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        for entry in inventory["stacks"]:
            self.assertIn(entry["terminal_state"], audit.TERMINAL_STATES, entry["project"])

    def test_never_kms_is_satisfied_without_an_attestation(self):
        # A stack born on the passphrase provider has no KMS dependency to
        # migrate away from. Demanding an attestation from it anyway is the
        # same "gate red in its own success state" failure documented above,
        # just relocated: an operator would have to type "migrated" for a
        # migration that never happened.
        self.assertTrue(audit.satisfies_terminal_state(_finding("needs-attestation", "never-kms")))

    def test_never_kms_still_fails_on_real_evidence_of_kms(self):
        # The point of accepting "needs-attestation" above is narrow -- it
        # must not become a blanket pass. If such a stack's file ever did
        # read gcpkms, or an attestation contradicted it, never-kms must not
        # paper over that.
        self.assertFalse(audit.satisfies_terminal_state(_finding("pending", "never-kms")))
        self.assertFalse(audit.satisfies_terminal_state(_finding("drift", "never-kms")))

    def test_never_kms_stack_with_no_config_path_is_satisfied_end_to_end(self):
        entry = {
            "project": "p",
            "stack": "s",
            "repo": "shared-infra",
            "config_path": None,
            "terminal_state": "never-kms",
        }
        finding = audit.audit_stack(entry, None)
        self.assertEqual(finding["status"], "needs-attestation")
        self.assertTrue(audit.satisfies_terminal_state(finding))


class AttestationTests(unittest.TestCase):
    def _entry(self, attestation):
        return {
            "project": "p",
            "stack": "s",
            "terminal_state": "destroy",
            "config_path": None,
            "attestation": attestation,
        }

    def test_complete_attestation_is_accepted(self):
        finding = audit.audit_stack(
            self._entry({"state": "removed", "date": "2026-08-16", "evidence": "stack ls: absent"}),
            None,
        )
        self.assertEqual(finding["status"], "attested-removed")

    def test_attestation_without_evidence_is_drift(self):
        # An attestation that does not say what was run is a checkbox, and a
        # checkbox on this gate is what the gate exists to replace.
        finding = audit.audit_stack(self._entry({"state": "removed", "date": "2026-08-16"}), None)
        self.assertEqual(finding["status"], "drift")

    def test_attestation_without_date_is_drift(self):
        finding = audit.audit_stack(self._entry({"state": "removed", "evidence": "x"}), None)
        self.assertEqual(finding["status"], "drift")

    def test_unknown_attested_state_is_drift(self):
        finding = audit.audit_stack(
            self._entry({"state": "probably fine", "date": "d", "evidence": "e"}), None
        )
        self.assertEqual(finding["status"], "drift")

    def test_missing_attestation_reports_that_nothing_can_check_it(self):
        finding = audit.audit_stack(self._entry(None), None)
        self.assertEqual(finding["status"], "needs-attestation")

    def test_non_iso_date_is_drift(self):
        finding = audit.audit_stack(
            self._entry({"state": "removed", "date": "last Tuesday", "evidence": "e"}), None
        )
        self.assertEqual(finding["status"], "drift")


class AttestationVersusFileTests(unittest.TestCase):
    """A committed file is a fact; an attestation is somebody's word. Where
    both exist the file decides.

    This is also what makes a rollback self-correcting. Restoring a
    KMS-wrapped checkpoint restores the `gcpkms://` line with it, so a stale
    attestation stops agreeing with the file and the gate goes red again --
    whereas an attestation that outranked the file would stay green forever
    over a stack that had been rolled back underneath it.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "website").mkdir()

    def _entry(self, terminal_state="migrate", **over):
        entry = {
            "project": "p",
            "stack": "s",
            "repo": "website",
            "config_path": "Pulumi.s.yaml",
            "terminal_state": terminal_state,
            "attestation": {"state": "migrated", "date": "2026-08-16", "evidence": "e"},
        }
        entry.update(over)
        return entry

    def _write(self, text):
        (self.root / "website" / "Pulumi.s.yaml").write_text(text)

    def test_attestation_cannot_override_a_file_that_still_says_kms(self):
        # The forged-green case: someone types "migrated" onto a stack whose
        # committed config still names the KMS key.
        self._write(f"secretsprovider: {GCPKMS_URL}\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "drift")
        self.assertIn("gcpkms", finding["detail"])

    def test_attestation_agreeing_with_the_file_is_accepted(self):
        self._write("encryptionsalt: v1:a:b\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "attested-migrated")
        self.assertTrue(finding["attested"])

    def test_attestation_agrees_with_a_salt_injected_at_deploy(self):
        # PUL-12 forbids a migrated passphrase stack from ever committing its
        # encryptionsalt again -- the mandated end state injects it at deploy
        # and never writes it back, so the file this test writes is exactly
        # what a *correctly* migrated stack looks like on disk. It reads
        # identically to a stack that was never created (`classify_secrets_
        # provider` calls both "absent"), which is why the migration can only
        # be evidenced by an attestation, never inferred from the file. Before
        # `ATTESTATION_AGREES_WITH` accepted "absent", this exact shape --
        # the shipped inventory's live shape for four stacks -- read as drift.
        self._write("config:\n  gcp:project: p\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "attested-migrated")
        self.assertTrue(finding["attested"])

    def test_attestation_cannot_override_a_rollback_to_kms_even_with_no_salt_committed(self):
        # The rollback guarantee has to survive the "absent" addition above:
        # a stack rolled back to a KMS checkpoint writes an explicit
        # `secretsprovider: gcpkms://...` line, which is a real fact in the
        # file and still outside ATTESTATION_AGREES_WITH -- a stale "migrated"
        # attestation must not paper over it.
        self._write(f"secretsprovider: {GCPKMS_URL}\nencryptedkey: CiQAaaa=\n")
        finding = audit.audit_stack(self._entry(), self.root)
        self.assertEqual(finding["status"], "drift")
        self.assertIn("gcpkms", finding["detail"])

    def test_removal_attestation_requires_the_file_to_be_gone_too(self):
        # A stack removed from its backend has its config file removed with
        # it. A file still on disk means the removal did not happen, or only
        # half did.
        self._write("encryptionsalt: v1:a:b\n")
        entry = self._entry(
            terminal_state="destroy",
            attestation={"state": "removed", "date": "2026-08-16", "evidence": "e"},
        )
        self.assertEqual(audit.audit_stack(entry, self.root)["status"], "drift")

    def test_removal_attestation_is_accepted_once_the_file_is_gone(self):
        entry = self._entry(
            terminal_state="destroy",
            attestation={"state": "removed", "date": "2026-08-16", "evidence": "e"},
        )
        self.assertEqual(audit.audit_stack(entry, self.root)["status"], "attested-removed")

    def test_migration_attestation_over_a_vanished_file_is_drift(self):
        self.assertEqual(audit.audit_stack(self._entry(), self.root)["status"], "drift")

    def test_attestation_does_not_substitute_for_an_unreachable_repo(self):
        # Without --root the file was not read, which is different from the
        # file not existing -- so the attestation must not stand in for it.
        self.assertEqual(audit.audit_stack(self._entry(), None)["status"], "unresolved")


class ProviderSelectionSiteTests(unittest.TestCase):
    """Re-wrapping every existing stack is only half the sweep: a workflow that
    selects the shared KMS key via `--secrets-provider` when it *creates* a
    stack mints a new KMS-wrapped one, in a bucket no earlier inventory could
    list."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "ghost-platform").mkdir()

    def _inventory(self, retired, text=None):
        if text is not None:
            (self.root / "ghost-platform" / "w.yml").write_text(text)
        return {
            "stacks": [{}],
            "provider_selection_sites": [
                {
                    "repo": "ghost-platform",
                    "path": "w.yml",
                    "retired": retired,
                    "must_not_contain": "gcpkms://",
                }
            ],
        }

    def test_live_site_blocks_the_precondition(self):
        sites = [{"site": "x", "status": "live", "detail": ""}]
        self.assertEqual(audit.exit_code([_finding("migrated")], None, True, sites), 1)

    def test_verified_retired_sites_do_not_block(self):
        sites = [{"site": "x", "status": "retired", "detail": ""}]
        self.assertEqual(audit.exit_code([_finding("migrated")], None, True, sites), 0)

    def test_a_forged_retired_flag_is_caught_against_the_real_file(self):
        # The whole irreversible wind-down hangs on this one gate, so a
        # hand-flipped boolean must not be able to open it. Plausibly typed
        # when the retirement PR is open but unmerged.
        inventory = self._inventory(True, text=f'--secrets-provider="{GCPKMS_URL}"\n')
        sites = audit.audit_provider_selection_sites(inventory, self.root)
        self.assertEqual(sites[0]["status"], "drift")
        self.assertEqual(audit.exit_code([_finding("migrated")], None, True, sites), 1)

    def test_genuinely_retired_site_verifies_against_the_file(self):
        inventory = self._inventory(True, text="--secrets-provider=passphrase\n")
        sites = audit.audit_provider_selection_sites(inventory, self.root)
        self.assertEqual(sites[0]["status"], "retired")

    def test_the_string_false_is_not_a_boolean(self):
        # `site.get("retired")` truthiness would read the *string* "false" as
        # retired, which is exactly what a hurried JSON edit produces.
        for value in ("false", "no", 0, None, "true"):
            inventory = self._inventory(value, text="anything\n")
            sites = audit.audit_provider_selection_sites(inventory, self.root)
            self.assertEqual(sites[0]["status"], "drift", repr(value))

    def test_unreachable_file_is_never_counted_as_retired(self):
        # Unrecoverable in one direction, merely inconvenient in the other.
        inventory = self._inventory(True)
        sites = audit.audit_provider_selection_sites(inventory, None)
        self.assertEqual(sites[0]["status"], "retired-unverified")
        self.assertEqual(audit.exit_code([_finding("migrated")], None, True, sites), 1)

    def test_a_site_retired_in_the_file_but_not_the_inventory_is_drift(self):
        inventory = self._inventory(False, text="--secrets-provider=passphrase\n")
        sites = audit.audit_provider_selection_sites(inventory, self.root)
        self.assertEqual(sites[0]["status"], "drift")

    def test_shipped_inventory_marks_exactly_the_fixed_sites_retired(self):
        # root=None deliberately, matching this repo's own CI
        # (.github/workflows/ci.yml runs the audit with no --root), so this
        # is what the gate the shipped repo actually runs sees -- not a
        # stand-in for a fuller check. With no root, `retired` claims can
        # only ever read back as "retired-unverified" or "live", never
        # "retired" -- so this asserts on the *claim* each site carries, not
        # on file content. A prior version of this test asserted
        # `all(status != "retired")`, which was true for every possible
        # inventory content under root=None and could never fail -- it
        # protected nothing. This one fails if a site's `retired` claim
        # regresses either direction: silently un-flipping a fixed site, or
        # flipping an unfixed one.
        #
        # `infra/provisioning/index.ts` is deliberately not one of these
        # sites any more: it creates a new per-tenant *state bucket*, never a
        # secrets-provider selection, and the earlier inventory carrying it
        # here was a miscategorisation. It is tracked as its own item
        # (branchLeft/workspace#105) rather than folded into this gate.
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        sites = audit.audit_provider_selection_sites(inventory, None)
        self.assertTrue(sites, "the tenant-provisioning minting sites must stay enumerated")
        statuses = [s["status"] for s in sites]
        # Two provision-tenant.yml entries: the workflow no longer creates any
        # KMS-wrapped stack, so both claim retired and (root unreachable here)
        # read back as retired-unverified.
        yml_sites = [s for s in sites if s["site"].endswith("provision-tenant.yml")]
        self.assertEqual(len(yml_sites), 2, "expected exactly two provision-tenant.yml sites")
        self.assertEqual(len(sites), 2, f"expected exactly two provider-selection sites, got {statuses}")
        self.assertTrue(
            all(s["status"] == "retired-unverified" for s in yml_sites),
            f"expected both provision-tenant.yml sites retired (unverified without --root), got {statuses}",
        )


class ExitCodeTests(unittest.TestCase):
    def test_pending_alone_passes(self):
        findings = [_finding("pending"), _finding("migrated")]
        self.assertEqual(audit.exit_code(findings, None, require_migrated=False), 0)

    def test_pending_fails_the_wind_down_precondition(self):
        self.assertEqual(audit.exit_code([_finding("pending")], None, True), 1)

    def test_unresolved_fails_the_wind_down_precondition(self):
        # Otherwise the teardown proceeds on a report that never read the file.
        self.assertEqual(audit.exit_code([_finding("unresolved")], None, True), 1)

    def test_needs_attestation_fails_the_wind_down_precondition(self):
        self.assertEqual(audit.exit_code([_finding("needs-attestation")], None, True), 1)

    def test_a_completed_sweep_exits_zero(self):
        # The test whose absence let a permanently-red gate ship.
        findings = [
            _finding("migrated", "migrate"),
            _finding("attested-migrated", "migrate"),
            _finding("attested-removed", "destroy"),
            _finding("attested-removed", "migrate-or-destroy"),
        ]
        sites = [{"site": "x", "status": "retired", "detail": ""}]
        references = {"undeclared": [], "stale": []}
        self.assertEqual(audit.exit_code(findings, references, True, sites), 0)

    def test_undeclared_provider_selection_site_fails_unconditionally(self):
        # Unconditional like the backend-reference undeclared check: a new
        # minting site is not something --require-migrated should be needed
        # to catch, since it strands the *next* stack provisioned, not one
        # already in the inventory.
        findings = [_finding("migrated")]
        self.assertEqual(
            audit.exit_code(findings, None, False, provider_selection_undeclared=["w.yml"]), 1
        )

    def test_no_undeclared_provider_selection_sites_does_not_block(self):
        findings = [_finding("migrated")]
        self.assertEqual(
            audit.exit_code(findings, None, False, provider_selection_undeclared=[]), 0
        )

    def test_drift_always_fails(self):
        self.assertEqual(audit.exit_code([_finding("drift")], None, False), 1)

    def test_missing_always_fails(self):
        self.assertEqual(audit.exit_code([_finding("missing")], None, False), 1)

    def test_undeclared_reference_fails(self):
        references = {"undeclared": [".github/workflows/new.yml"], "stale": []}
        self.assertEqual(audit.exit_code([_finding("migrated")], references, False), 1)

    def test_stale_reference_fails(self):
        references = {"undeclared": [], "stale": ["README.md"]}
        self.assertEqual(audit.exit_code([_finding("migrated")], references, False), 1)


class MainTests(unittest.TestCase):
    """Drives the real entry point. The findings above all call the internals
    directly, which is exactly how an argv the CI job actually uses stayed
    uncovered."""

    def _run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = audit.main(argv)
        return code, buffer.getvalue()

    def test_ci_invocation_passes_and_reports_every_stack(self):
        # The exact argv in .github/workflows/ci.yml and the pre-commit hook:
        # no --root, so most stacks are unresolved and that must not fail.
        code, output = self._run([])
        self.assertEqual(code, 0)
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        for entry in inventory["stacks"]:
            self.assertIn(f"{entry['project']}/{entry['stack']}", output)

    def test_without_root_the_unreachable_repos_are_named_not_silently_passed(self):
        _, output = self._run([])
        self.assertIn("pass --root", output)

    def test_require_migrated_fails_today_and_says_what_is_outstanding(self):
        code, output = self._run(["--require-migrated"])
        self.assertEqual(code, 1)
        self.assertIn("sweep incomplete", output)

    def test_json_output_is_parseable_and_carries_all_three_sections(self):
        _, output = self._run(["--json"])
        parsed = json.loads(output)
        self.assertEqual(
            {"stacks", "provider_selection_sites", "provider_selection_undeclared", "backend_references"},
            set(parsed),
        )

    def test_unreadable_inventory_exits_two_rather_than_reporting_clean(self):
        code, _ = self._run(["--inventory", "/nonexistent/inventory.json", "--skip-reference-scan"])
        self.assertEqual(code, 2)

    def test_a_completed_sweep_exits_zero_through_main(self):
        # End to end on a synthetic inventory in its finished state: proves the
        # gate is satisfiable through the real entry point, not just in
        # exit_code's unit test.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "website").mkdir()
            (root / "website" / "Pulumi.done.yaml").write_text("encryptionsalt: v1:a:b\n")
            (root / "gp").mkdir()
            (root / "gp" / "w.yml").write_text("--secrets-provider=passphrase\n")
            inventory = {
                "stacks": [
                    {
                        "project": "p",
                        "stack": "done",
                        "repo": "website",
                        "config_path": "Pulumi.done.yaml",
                        "state_backend": "shared",
                        "terminal_state": "migrate",
                    },
                    {
                        "project": "q",
                        "stack": "gone",
                        "repo": None,
                        "config_path": None,
                        "state_backend": "shared",
                        "terminal_state": "destroy",
                        "attestation": {
                            "state": "removed",
                            "date": "2026-08-16",
                            "evidence": "pulumi stack ls --all: absent",
                        },
                    },
                ],
                "state_backends": {"shared": "gs://b"},
                "provider_selection_sites": [
                    {
                        "repo": "gp",
                        "path": "w.yml",
                        "retired": True,
                        "must_not_contain": "gcpkms://",
                    }
                ],
            }
            path = root / "inventory.json"
            path.write_text(json.dumps(inventory))
            code, output = self._run(
                ["--inventory", str(path), "--root", str(root),
                 "--skip-reference-scan", "--require-migrated"]
            )
            self.assertEqual(code, 0, output)
            self.assertIn("sweep complete", output)


class ReferenceScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = pathlib.Path(self.tmp.name)

    def _write(self, rel, text):
        path = self.tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_finds_a_login_step(self):
        self._write(".github/workflows/ci.yml", "run: pulumi login gs://branchleft-pulumi-state\n")
        self.assertEqual(
            audit.scan_backend_references(self.tree), {".github/workflows/ci.yml"}
        )

    def test_finds_a_per_tenant_bucket(self):
        self._write("a.md", "state in gs://branchleft-blog-pulumi-state today\n")
        self.assertEqual(audit.scan_backend_references(self.tree), {"a.md"})

    def test_finds_a_templated_bucket_name(self):
        # The tenant workflow never writes the bucket literally, so a scan for
        # literals alone reports the site that most needs enumerating as clean.
        self._write("w.yml", 'run: pulumi login "gs://$STATE_BUCKET"\n')
        self.assertEqual(audit.scan_backend_references(self.tree), {"w.yml"})

    def test_ignores_the_media_bucket(self):
        self._write("a.md", "media in gs://branchleft-prod-ghost-platform-media\n")
        self.assertEqual(audit.scan_backend_references(self.tree), set())

    def test_skips_vendored_and_generated_trees(self):
        for skipped in ("node_modules", "graphify-out", "vendor"):
            self._write(f"{skipped}/x.md", "gs://branchleft-pulumi-state\n")
        self.assertEqual(audit.scan_backend_references(self.tree), set())

    def test_ignores_unscannable_suffixes(self):
        self._write("notes.txt", "gs://branchleft-pulumi-state\n")
        self.assertEqual(audit.scan_backend_references(self.tree), set())


class ProviderSelectionScanTests(unittest.TestCase):
    """The regression assertion hetzner/RUNBOOK-existing-stack-migration.md
    describes: not just that every *enumerated* provider-selection site
    verifies retired, but that no *unenumerated* one has grown one since."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = pathlib.Path(self.tmp.name)

    def _write(self, rel, text):
        path = self.tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_finds_a_new_minting_site(self):
        self._write(".github/workflows/w.yml", f'--secrets-provider="{GCPKMS_URL}"\n')
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), {".github/workflows/w.yml"})

    def test_ignores_a_retired_site(self):
        self._write(".github/workflows/w.yml", "--secrets-provider=passphrase\n")
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), set())

    def test_ignores_prose_mentioning_both_words_without_the_flag_shape(self):
        # Documentation describing the risk, or a historical/example command
        # in a runbook, is not itself a minting site.
        self._write("RUNBOOK.md", "the doomed key: gcpkms://... via --secrets-provider\n")
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), set())

    def test_ignores_markdown_even_with_the_exact_flag_shape(self):
        # `.md` is deliberately outside PROVIDER_SELECTION_SUFFIXES: a runbook
        # narrating a historical `pulumi stack init --secrets-provider=
        # gcpkms://...` -- exactly what this repo's own migration and
        # rehearsal runbooks do -- does not create a stack on its own.
        self._write("RUNBOOK.md", f'--secrets-provider="{GCPKMS_URL}"\n')
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), set())

    def test_finds_the_flag_shape_in_a_shell_script(self):
        self._write("provision.sh", f'pulumi stack init t --secrets-provider="{GCPKMS_URL}"\n')
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), {"provision.sh"})

    def test_skips_vendored_and_generated_trees(self):
        for skipped in ("node_modules", "graphify-out", "vendor"):
            self._write(f"{skipped}/w.yml", f'--secrets-provider="{GCPKMS_URL}"\n')
        self.assertEqual(audit.scan_provider_selection_hits(self.tree), set())


class ProviderSelectionUndeclaredTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def _inventory(self, sites):
        return {"stacks": [{}], "provider_selection_sites": sites}

    def _write_here(self, rel, text):
        # REPO_ROOT is a fixed path (this checkout), not something a test can
        # relocate -- so "here" is exercised through audit_provider_selection_
        # scan's REPO_ROOT-scanning half being proven separately, by the
        # shipped-inventory regression test below. This class exercises the
        # --root half, which the test *can* relocate.
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_undeclared_site_in_a_sibling_repo_is_reported_only_with_root(self):
        self._write_here(
            "ghost-platform/.github/workflows/new.yml", f'--secrets-provider="{GCPKMS_URL}"\n'
        )
        inventory = self._inventory([])
        self.assertEqual(audit.audit_provider_selection_scan(inventory, None), [])
        self.assertEqual(
            audit.audit_provider_selection_scan(inventory, self.root),
            ["ghost-platform/.github/workflows/new.yml"],
        )

    def test_a_declared_site_in_a_sibling_repo_is_not_reported_undeclared(self):
        self._write_here(
            "ghost-platform/.github/workflows/w.yml", f'--secrets-provider="{GCPKMS_URL}"\n'
        )
        inventory = self._inventory(
            [{"repo": "ghost-platform", "path": ".github/workflows/w.yml", "retired": False}]
        )
        self.assertEqual(audit.audit_provider_selection_scan(inventory, self.root), [])

    def test_shipped_inventory_has_no_undeclared_provider_selection_sites_in_this_repo(self):
        # Proves this repo's own tree -- what the default CI invocation with
        # no --root actually scans -- carries no self-inflicted false
        # positive from the inventory's own documentation of retired sites.
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        self.assertEqual(audit.audit_provider_selection_scan(inventory, None), [])


class InventoryTests(unittest.TestCase):
    def test_rejects_an_empty_inventory(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"stacks": []}, handle)
            path = handle.name
        with self.assertRaises(audit.InventoryError):
            audit.load_inventory(path)

    def test_rejects_an_unreadable_inventory(self):
        with self.assertRaises(audit.InventoryError):
            audit.load_inventory(pathlib.Path(self.id()) / "nope.json")

    def test_shipped_inventory_is_loadable_and_complete(self):
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        for entry in inventory["stacks"]:
            for field in ("project", "stack", "state_backend", "terminal_state"):
                self.assertIn(field, entry, f"{entry.get('project')} missing {field}")
            self.assertIn(entry["state_backend"], inventory["state_backends"])

    def test_shipped_inventory_enumerates_every_backend_reference_in_this_repo(self):
        # The check that would have caught the site nobody wrote down.
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        result = audit.audit_backend_references(inventory, audit.REPO_ROOT)
        self.assertEqual(result["undeclared"], [])
        self.assertEqual(result["stale"], [])


class ShippedInventoryLiveStateTests(unittest.TestCase):
    """Every other test above proves the audit mechanism in the abstract;
    this one pins it to the shipped inventory, run with every repo
    reachable, to prove the sweep it claims is complete actually is."""

    def test_require_migrated_reports_the_sweep_complete(self):
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            # Materialise each reachable repo's config file in the shape its
            # live checkpoint actually reports, independent of what the
            # inventory's attestations claim -- every one of these is a
            # migrated, salt-injected-at-deploy stack, so PUL-12 means its
            # committed file carries no evidence of its own and only the
            # attestation can settle it.
            live = {
                ("shared-infra", "Pulumi.production.yaml"): "config:\n  gcp:project: p\n",
                ("shared-infra", "mail/Pulumi.production.yaml"): "config:\n  a: b\n",
                ("website", "infra/Pulumi.production.yaml"): "config:\n  a: b\n",
                (
                    "ghost-platform",
                    "infra/platform/Pulumi.platform.yaml",
                ): "config:\n  a: b\n",
                ("ghost-tenant-blog", "Pulumi.blog.yaml"): "config:\n  gcp:project: p\n",
                # branchleft-ghost-provisioning/blog has no committed config
                # anywhere (its config_path is null) -- nothing to write.
                (
                    "ghost-platform",
                    "infra/hosts/Pulumi.production.yaml",
                ): "config:\n  a: b\n",
            }
            for (repo, rel), text in live.items():
                path = root / repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)

            findings = audit.audit_stacks(inventory, root)
            by_stack = {f["stack"]: f for f in findings}
            outstanding = {
                name for name, finding in by_stack.items() if not audit.satisfies_terminal_state(finding)
            }
            # The two Hetzner stacks reach never-kms via needs-attestation on
            # its own -- see SATISFIED_BY. Every other stack in the inventory
            # is now attested-migrated, so nothing should be outstanding.
            self.assertEqual(outstanding, set(), by_stack)

    def test_a_regression_to_kms_would_still_be_caught(self):
        # The property the test above cannot exercise: if a migrated stack's
        # live checkpoint ever regressed to a KMS-wrapped one, the stale
        # "migrated" attestation must not paper over it. AttestationVersus-
        # FileTests proves this in the abstract; this pins it to a real
        # entry from the shipped inventory.
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = root / "ghost-tenant-blog" / "Pulumi.blog.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"secretsprovider: {GCPKMS_URL}\n")

            findings = audit.audit_stacks(inventory, root)
            by_stack = {f["stack"]: f for f in findings}
            self.assertEqual(by_stack["blog-infra/blog"]["status"], "drift")
            self.assertFalse(audit.satisfies_terminal_state(by_stack["blog-infra/blog"]))


class WorkspaceStackDiscoveryTests(unittest.TestCase):
    """Regression guard for the failure this inventory's own `$comment`
    names: a stack that exists but was never entered here. Every check
    elsewhere in this file audits sites the inventory already knows about;
    none of them can notice a whole stack nobody wrote down, which is
    exactly how one went missing before. This walks the stack-owning repos
    for every `Pulumi.yaml` and fails if one has no matching entry.

    Only runs where those repos sit next to this one on disk -- this
    repo's own CI checks out `shared-infra` alone, so there the sibling
    repos are absent and the test skips rather than reporting a false
    pass or fail for a tree it cannot see.
    """

    STACK_OWNING_REPOS = ("website", "ghost-platform", "ghost-tenant-blog")
    SKIP_DIR_NAMES = {".git", "node_modules", "vendor", "dist", "graphify-out"}

    @classmethod
    def _is_excluded_dir(cls, name):
        return name in cls.SKIP_DIR_NAMES or name.startswith(".worktrees") or name == "worktrees"

    @classmethod
    def _find_workspace_root(cls):
        candidate = audit.REPO_ROOT
        for _ in range(8):
            if all((candidate / repo).is_dir() for repo in cls.STACK_OWNING_REPOS):
                return candidate
            parent = candidate.parent
            if parent == candidate:
                return None
            candidate = parent
        return None

    @classmethod
    def _pulumi_projects(cls, repo_dir):
        """Repo-relative paths of every `Pulumi.yaml` under `repo_dir`."""
        found = []
        for dirpath, dirnames, filenames in os.walk(repo_dir):
            dirnames[:] = [d for d in dirnames if not cls._is_excluded_dir(d)]
            if "Pulumi.yaml" in filenames:
                found.append((pathlib.Path(dirpath) / "Pulumi.yaml").relative_to(repo_dir).as_posix())
        return found

    def test_every_pulumi_project_in_a_stack_owning_repo_is_in_the_inventory(self):
        root = self._find_workspace_root()
        if root is None:
            self.skipTest(
                "sibling repos not found above this checkout -- this check "
                "only runs with the full multi-repo workspace present"
            )
        inventory = audit.load_inventory(audit.DEFAULT_INVENTORY)
        known = {(entry.get("repo"), entry.get("project_path")) for entry in inventory["stacks"]}

        missing = []
        for path in self._pulumi_projects(audit.REPO_ROOT):
            if (audit.THIS_REPO, path) not in known:
                missing.append(f"{audit.THIS_REPO}/{path}")
        for repo in self.STACK_OWNING_REPOS:
            for path in self._pulumi_projects(root / repo):
                if (repo, path) not in known:
                    missing.append(f"{repo}/{path}")

        self.assertEqual(
            missing,
            [],
            f"Pulumi.yaml with no matching entry in {audit.DEFAULT_INVENTORY.name}: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
