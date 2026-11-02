"""Unit tests for tenant_compose_check: every refusal, the verdict's purity and its secrecy.

Run from the role's directory, with the library directory on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every name is a placeholder, and every
secret is a throwaway made for the test.
"""

import builtins
import contextlib
import copy
import json
import unittest
from collections.abc import Mapping
from typing import cast
from unittest import mock

import tenant_compose_check as check
from ruamel.yaml import YAML

DIGEST = "sha256:" + "a" * 64
PIN = f"IMAGE=example.invalid/app@{DIGEST}\n"
SECRET_ONE = "THROWAWAY_SECRET_ONE_0001"  # noqa: S105
SECRET_TWO = "THROWAWAY_SECRET_TWO_0002"  # noqa: S105
SECRETS = f"GHOST_DB_PASSWORD={SECRET_ONE}\nGHOST_MAIL_PASSWORD={SECRET_TWO}\n"
SPOOL_IMAGE = f"example.invalid/spool@{DIGEST}"
Document = dict[str, object]


def tenant_document(slug: str = "tenant-a", uid: int = 30901) -> Document:
    """Return a placeholder tenant stack with the shape the renderer produces."""
    return {
        "name": slug,
        "services": {
            "app": {
                "image": "${IMAGE}",
                "user": f"{uid}:{uid}",
                "ports": ["10.20.2.30:3901:2368"],
                "environment": {
                    "db": "${GHOST_DB_PASSWORD:?set GHOST_DB_PASSWORD in the env file}",
                    "mail": "${GHOST_MAIL_PASSWORD:?set GHOST_MAIL_PASSWORD in the env file}",
                },
                "networks": ["default", f"branchleft-mail-{uid}"],
                "volumes": [f"ghost-{slug}-content:/var/lib/ghost/content"],
            }
        },
        "networks": {
            f"branchleft-mail-{uid}": {"name": f"branchleft-mail-{uid}", "external": True}
        },
        "volumes": {f"ghost-{slug}-content": {"external": True}},
    }


def spool_document() -> Document:
    """Return a placeholder mail spool with the shape the renderer produces."""
    return {
        "name": "mail-spool",
        "services": {
            "mail-spool": {
                "image": SPOOL_IMAGE,
                "user": "31000:31000",
                "ports": ["127.0.0.1:8095:8081"],
                "environment": {
                    "token": "${SHIM_DRAIN_TOKEN:?set SHIM_DRAIN_TOKEN in the env file}"
                },
                "networks": ["drain", "branchleft-mail-30901"],
                "volumes": ["spool-data:/data"],
            }
        },
        "networks": {
            "drain": {
                "name": "drain",
                "driver": "bridge",
                "driver_opts": {"com.docker.network.bridge.name": "br-mailspool"},
            },
            "branchleft-mail-30901": {"name": "branchleft-mail-30901", "internal": True},
        },
        "volumes": {"spool-data": {"external": True}},
    }


GOOD_INPUT = (
    "-P INPUT ACCEPT\n"
    "-A INPUT -i br-mailspool -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
    "-A INPUT -i br-mailspool -j DROP\n"
)
GOOD_FORWARD = (
    "-N DOCKER-USER\n"
    "-A DOCKER-USER -i br-mailspool ! -o br-mailspool -j DROP\n"
    "-A DOCKER-USER -j RETURN\n"
)


def tenant(document: Document | None = None, **changes: object) -> check.Verdict:
    """Judge a tenant stack, with ``changes`` applied to the parameters."""
    values: dict[str, object] = {
        "slug": "tenant-a",
        "uid": 30901,
        "compose_text": json.dumps(document if document is not None else tenant_document()),
        "secrets_env_text": SECRETS,
        "image_env_text": PIN,
    }
    values.update(changes)
    return check.judge(
        check.Params(
            slug=cast("str", values["slug"]),
            uid=cast("int | None", values["uid"]),
            compose_text=cast("str", values["compose_text"]),
            secrets_env_text=cast("str", values["secrets_env_text"]),
            image_env_text=cast("str", values["image_env_text"]),
            claims_text=cast("str | None", values.get("claims_text")),
        )
    )


def spool(document: Document | None = None, **changes: object) -> check.Verdict:
    """Judge the spool, with the isolation rules present unless ``changes`` says otherwise."""
    values: dict[str, object] = {
        "compose_text": json.dumps(document if document is not None else spool_document()),
        "require_isolation": True,
        "iptables_input_text": GOOD_INPUT,
        "iptables_docker_user_text": GOOD_FORWARD,
        "secrets_env_text": "",
    }
    values.update(changes)
    return check.judge(
        check.Params(
            slug=cast("str", values.get("slug", "mail-spool")),
            profile="spool",
            compose_text=cast("str", values["compose_text"]),
            secrets_env_text=cast("str", values["secrets_env_text"]),
            require_isolation=cast("bool", values["require_isolation"]),
            iptables_input_text=cast("str | None", values["iptables_input_text"]),
            iptables_docker_user_text=cast("str | None", values["iptables_docker_user_text"]),
        )
    )


def service(document: Document) -> dict[str, object]:
    """Return the first service of a document for editing."""
    return cast("dict[str, dict[str, object]]", document["services"])[
        next(iter(cast("dict[str, object]", document["services"])))
    ]


class ArgumentSpecTests(unittest.TestCase):
    """The documentation and the argument_spec describe the same options."""

    def test_the_documentation_names_the_options_the_spec_does(self) -> None:
        documented = cast(
            "Mapping[str, Mapping[str, Mapping[str, object]]]",
            YAML(typ="safe").load(check.DOCUMENTATION),
        )["options"]
        self.assertEqual(sorted(documented), sorted(check.ARGUMENT_SPEC))
        for name, option in check.ARGUMENT_SPEC.items():
            self.assertEqual(documented[name].get("type"), option["type"], name)
            self.assertEqual(
                documented[name].get("required", False), option.get("required", False), name
            )

    def test_the_secrets_text_is_the_one_option_marked_no_log(self) -> None:
        marked = [name for name, option in check.ARGUMENT_SPEC.items() if option.get("no_log")]
        self.assertEqual(marked, ["secrets_env_text"])

    def test_the_documentation_and_return_blocks_parse(self) -> None:
        for block in (check.EXAMPLES, check.RETURN):
            self.assertTrue(YAML(typ="safe").load(block))


class TenantAcceptedTests(unittest.TestCase):
    """What a good render is judged to be."""

    def test_a_good_stack_is_accepted_and_gets_its_pin_line(self) -> None:
        verdict = tenant()
        self.assertEqual(verdict.refusals, ())
        self.assertTrue(verdict.ok)
        self.assertEqual(verdict.image_env, PIN)
        self.assertRegex(verdict.stamp, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(verdict.claim_state, "unchecked")

    def test_the_pin_line_is_normalised_to_one_line_and_a_newline(self) -> None:
        self.assertEqual(tenant(image_env_text=PIN.strip()).image_env, PIN)

    def test_a_key_the_compose_file_does_not_refer_to_is_accepted(self) -> None:
        self.assertTrue(
            tenant(secrets_env_text=SECRETS + "GHOST_OWNER_EMAIL=owner@example.invalid\n").ok
        )

    def test_comments_and_blank_lines_in_the_secrets_are_accepted(self) -> None:
        self.assertTrue(tenant(secrets_env_text="# a comment\n\n" + SECRETS).ok)

    def test_published_addresses_in_every_form_are_accepted(self) -> None:
        for entry in (
            "10.20.2.30:3901:2368",
            "10.20.2.30:3901:2368/tcp",
            "[fd00::1]:3901:2368",
            {"host_ip": "10.20.2.30", "published": 3901, "target": 2368},
        ):
            with self.subTest(entry=entry):
                document = tenant_document()
                service(document)["ports"] = [entry]
                self.assertTrue(tenant(document).ok)

    def test_the_stamp_changes_with_the_compose_text_and_with_the_secrets(self) -> None:
        base = tenant().stamp
        self.assertNotEqual(base, tenant(secrets_env_text=SECRETS.replace("ONE", "ONX")).stamp)
        document = tenant_document()
        service(document)["mem_limit"] = "1g"
        self.assertNotEqual(base, tenant(document).stamp)

    def test_the_stamp_ignores_the_pin(self) -> None:
        self.assertEqual(tenant().stamp, tenant(image_env_text=PIN.replace("a", "b")).stamp)


class TenantRefusedTests(unittest.TestCase):
    """Each rule of the delivery boundary, broken one at a time."""

    def refused(self, verdict: check.Verdict, expected: str) -> None:
        """Assert that the verdict is a refusal that mentions ``expected``."""
        self.assertFalse(verdict.ok)
        self.assertTrue(
            any(expected in refusal for refusal in verdict.refusals), (expected, verdict.refusals)
        )
        self.assertEqual(verdict.image_env, "")

    def test_an_image_that_is_not_the_pin_variable(self) -> None:
        for image in (
            "example.invalid/app:latest",
            f"example.invalid/app@{DIGEST}",
            "${IMAGE:-x}",
            None,
        ):
            with self.subTest(image=image):
                document = tenant_document()
                service(document)["image"] = image
                self.refused(tenant(document), "image is not exactly ${IMAGE}")

    def test_a_second_service_with_its_own_image(self) -> None:
        document = tenant_document()
        cast("dict[str, object]", document["services"])["side"] = {
            "image": "example.invalid/side:1"
        }
        self.refused(tenant(document), "service side image")

    def test_a_service_key_that_widens_the_container(self) -> None:
        for key, value in (
            ("build", "."),
            ("extends", {"service": "x"}),
            ("network_mode", "host"),
            ("cap_add", ["NET_ADMIN"]),
            ("devices", ["/dev/fuse"]),
        ):
            with self.subTest(key=key):
                document = tenant_document()
                service(document)[key] = value
                self.refused(tenant(document), f"service app sets {key}")

    def test_a_privileged_service(self) -> None:
        document = tenant_document()
        service(document)["privileged"] = True
        self.refused(tenant(document), "is privileged")

    def test_an_unprivileged_flag_written_out_is_accepted(self) -> None:
        document = tenant_document()
        service(document)["privileged"] = False
        self.assertTrue(tenant(document).ok)

    def test_the_docker_socket_in_any_volume_form(self) -> None:
        for volume in (
            "/var/run/docker.sock:/var/run/docker.sock",
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/s"},
        ):
            with self.subTest(volume=volume):
                document = tenant_document()
                service(document)["volumes"] = [volume]
                self.refused(tenant(document), "mounts the Docker socket")

    def test_a_port_that_binds_no_specific_address(self) -> None:
        for entry in (
            "0.0.0.0:3901:2368",
            "3901:2368",
            "2368",
            2368,
            ":3901:2368",
            "[::]:3901:2368",
            "[fd00::1]",
            {"published": 3901, "target": 2368},
            {"host_ip": "0.0.0.0", "published": 3901, "target": 2368},  # noqa: S104
            {"host_ip": "::", "published": 3901, "target": 2368},
        ):
            with self.subTest(entry=entry):
                document = tenant_document()
                service(document)["ports"] = [entry]
                self.refused(tenant(document), "publishes a port without binding one address")

    def test_ports_that_are_not_a_list(self) -> None:
        document = tenant_document()
        service(document)["ports"] = "10.20.2.30:3901:2368"
        self.refused(tenant(document), "ports is not a list")

    def test_a_network_that_is_not_external(self) -> None:
        for body in ({"name": "x"}, {"name": "x", "external": False}, {"internal": True}, None):
            with self.subTest(body=body):
                document = tenant_document()
                cast("dict[str, object]", document["networks"])["extra"] = body
                self.refused(tenant(document), "network extra")

    def test_a_volume_that_is_not_external(self) -> None:
        for body in (None, {}, {"driver": "local"}, {"external": False}):
            with self.subTest(body=body):
                document = tenant_document()
                cast("dict[str, object]", document["volumes"])["extra"] = body
                self.refused(tenant(document), "volume extra is not external")

    def test_a_top_level_key_the_renderer_does_not_produce(self) -> None:
        for key in ("include", "configs", "secrets", "x-anything"):
            with self.subTest(key=key):
                document = tenant_document()
                document[key] = {}
                self.refused(tenant(document), f"top-level key {key}")

    def test_a_compose_name_that_is_not_the_slug(self) -> None:
        document = tenant_document()
        document["name"] = "tenant-b"
        self.refused(tenant(document), "compose name is not the stack's slug")

    def test_compose_text_that_is_not_a_mapping_or_has_no_services(self) -> None:
        self.refused(tenant(compose_text="- a\n- b\n"), "not a mapping")
        document = tenant_document()
        document["services"] = {}
        self.refused(tenant(document), "no services")

    def test_compose_text_that_is_not_yaml(self) -> None:
        self.refused(tenant(compose_text="a: [unclosed"), "not valid YAML")

    def test_a_service_that_is_not_a_mapping(self) -> None:
        document = tenant_document()
        document["services"] = {"app": "x"}
        self.refused(tenant(document), "service app is not a mapping")

    def test_a_slug_that_is_not_a_slug(self) -> None:
        for slug in ("Tenant", "1tenant", "tenant-", "ten ant", "a" * 27, ""):
            with self.subTest(slug=slug):
                self.refused(tenant(tenant_document(slug), slug=slug), "slug is not")

    def test_the_spool_slug_for_a_tenant(self) -> None:
        self.refused(
            tenant(tenant_document("mail-spool"), slug="mail-spool"), "belongs to the mail spool"
        )

    def test_a_uid_outside_the_tenant_range(self) -> None:
        for uid in (None, 0, 29999, 31000):
            with self.subTest(uid=uid):
                self.refused(tenant(uid=uid), "uid is not in 30000-30999")

    def test_a_secret_key_the_compose_file_refers_to_but_the_file_lacks(self) -> None:
        self.refused(
            tenant(secrets_env_text=f"GHOST_DB_PASSWORD={SECRET_ONE}\n"),
            "no key GHOST_MAIL_PASSWORD",
        )

    def test_a_referenced_secret_with_an_empty_value(self) -> None:
        self.refused(
            tenant(secrets_env_text=f"GHOST_DB_PASSWORD=\nGHOST_MAIL_PASSWORD={SECRET_TWO}\n"),
            "key GHOST_DB_PASSWORD is empty",
        )

    def test_a_key_that_is_not_ghost_prefixed_cannot_override_the_pin(self) -> None:
        self.refused(
            tenant(secrets_env_text=SECRETS + "IMAGE=evil@sha256:b\n"),
            "key IMAGE does not start with GHOST_",
        )

    def test_a_duplicate_key(self) -> None:
        self.refused(
            tenant(secrets_env_text=SECRETS + f"GHOST_DB_PASSWORD={SECRET_TWO}\n"),
            "key GHOST_DB_PASSWORD is given twice",
        )

    def test_a_line_that_is_not_key_value(self) -> None:
        self.refused(
            tenant(secrets_env_text=SECRETS + f"{SECRET_ONE}\n"), "line 3 is not KEY=value"
        )

    def test_a_control_character_in_the_secrets(self) -> None:
        for char in ("\r", "\t", "\x00", "\x1b", "\x7f"):
            with self.subTest(char=repr(char)):
                self.refused(
                    tenant(secrets_env_text=SECRETS.replace("ONE", f"O{char}NE")),
                    "holds a control character",
                )

    def test_a_variable_the_role_does_not_supply(self) -> None:
        document = tenant_document()
        service(document)["environment"] = {"x": "${SOMETHING_ELSE}", "y": "$BARE_NAME"}
        verdict = tenant(document, secrets_env_text="")
        self.refused(verdict, "compose refers to SOMETHING_ELSE")
        self.refused(verdict, "compose refers to BARE_NAME")

    def test_a_doubled_dollar_is_not_a_reference(self) -> None:
        document = tenant_document()
        service(document)["command"] = "echo $$HOME"
        self.assertTrue(tenant(document).ok)

    def test_a_pin_that_is_not_one_digest_line(self) -> None:
        for text in (
            "",
            "IMAGE=example.invalid/app:latest\n",
            PIN + PIN,
            PIN + "OTHER=1\n",
            f"IMAGE=example.invalid/app@sha256:{'A' * 64}\n",
            f"IMAGE=example.invalid/app@sha256:{'a' * 63}\n",
            f"image=example.invalid/app@{DIGEST}\n",
            f"IMAGE=${{X}}@{DIGEST}\n",
        ):
            with self.subTest(text=text):
                self.refused(tenant(image_env_text=text), "image pin is not exactly one")

    def test_every_refusal_starts_with_the_slug(self) -> None:
        verdict = tenant(secrets_env_text="", image_env_text="")
        self.assertTrue(verdict.refusals)
        self.assertTrue(all(refusal.startswith("tenant-a: ") for refusal in verdict.refusals))

    def test_all_the_rules_a_stack_breaks_are_reported_together(self) -> None:
        document = tenant_document()
        service(document)["privileged"] = True
        service(document)["image"] = "x:latest"
        verdict = tenant(document, secrets_env_text="")
        self.assertGreaterEqual(len(verdict.refusals), 4)


class ClaimTests(unittest.TestCase):
    """The tenant's uid against what the volume program lists."""

    def test_no_claims_given_is_unchecked(self) -> None:
        self.assertEqual(tenant().claim_state, "unchecked")

    def test_an_empty_list_leaves_the_tenant_unclaimed(self) -> None:
        verdict = tenant(claims_text="")
        self.assertEqual((verdict.claim_state, verdict.ok), ("unclaimed", True))

    def test_the_same_uid_for_the_same_slug_is_the_same(self) -> None:
        verdict = tenant(claims_text="tenant-a=30901\ntenant-b=30902\n")
        self.assertEqual((verdict.claim_state, verdict.ok), ("same", True))

    def test_another_tenants_claim_does_not_stop_this_one(self) -> None:
        self.assertEqual(tenant(claims_text="tenant-b=30902\n").claim_state, "unclaimed")

    def test_the_same_slug_with_another_uid_is_a_conflict(self) -> None:
        verdict = tenant(claims_text="tenant-a=30905\n")
        self.assertEqual(verdict.claim_state, "conflict")
        self.assertIn("tenant-a: tenant-a already holds uid 30905, not 30901", verdict.refusals)

    def test_the_uid_held_by_another_slug_is_a_conflict(self) -> None:
        verdict = tenant(claims_text="tenant-b=30901\n")
        self.assertEqual(verdict.claim_state, "conflict")
        self.assertIn("tenant-a: uid 30901 is already claimed by tenant-b", verdict.refusals)

    def test_a_line_that_is_not_slug_uid_is_a_conflict(self) -> None:
        for text in ("tenant-a\n", "tenant-a=x\n", "=30901\n", "Tenant-a=30901\n"):
            with self.subTest(text=text):
                self.assertEqual(tenant(claims_text=text).claim_state, "conflict")


class SpoolTests(unittest.TestCase):
    """The mail spool's own profile."""

    def test_a_good_spool_is_accepted_and_its_pin_is_derived_from_its_digest(self) -> None:
        verdict = spool()
        self.assertEqual(verdict.refusals, ())
        self.assertEqual(verdict.image_env, f"IMAGE={SPOOL_IMAGE}\n")

    def test_the_spool_keeps_its_own_networks_unlike_a_tenant(self) -> None:
        self.assertTrue(spool().ok)
        self.assertFalse(tenant(spool_document(), slug="mail-spool", uid=30901).ok)

    def test_an_image_that_is_not_pinned_inline(self) -> None:
        for image in (
            "${IMAGE}",
            "example.invalid/spool:1",
            f"example.invalid/spool@sha256:{'a' * 10}",
        ):
            with self.subTest(image=image):
                document = spool_document()
                service(document)["image"] = image
                self.assertTrue(
                    any("not pinned inline by digest" in r for r in spool(document).refusals)
                )

    def test_a_port_that_is_not_the_single_loopback_publish(self) -> None:
        for ports in (
            ["0.0.0.0:8095:8081"],
            ["10.20.2.30:8095:8081"],
            ["8095:8081"],
            [],
            ["127.0.0.1:1:2", "127.0.0.1:3:4"],
        ):
            with self.subTest(ports=ports):
                document = spool_document()
                service(document)["ports"] = ports
                self.assertFalse(spool(document).ok)

    def test_a_network_that_is_external_or_neither_internal_nor_the_drain_bridge(self) -> None:
        for body in (
            {"name": "x", "external": True},
            {"name": "x"},
            {
                "name": "x",
                "driver": "bridge",
                "driver_opts": {"com.docker.network.bridge.name": "br-other"},
            },
            {
                "name": "x",
                "driver": "overlay",
                "driver_opts": {"com.docker.network.bridge.name": "br-mailspool"},
            },
        ):
            with self.subTest(body=body):
                document = spool_document()
                cast("dict[str, object]", document["networks"])["extra"] = body
                self.assertFalse(spool(document).ok)

    def test_a_second_service(self) -> None:
        document = spool_document()
        cast("dict[str, object]", document["services"])["other"] = copy.deepcopy(service(document))
        self.assertTrue(
            any("more or fewer than one service" in r for r in spool(document).refusals)
        )

    def test_a_variable_the_role_does_not_supply(self) -> None:
        document = spool_document()
        service(document)["environment"] = {"x": "${SOMETHING_ELSE}"}
        self.assertTrue(any("refers to SOMETHING_ELSE" in r for r in spool(document).refusals))

    def test_the_spool_takes_no_secrets_and_only_its_own_slug(self) -> None:
        self.assertTrue(
            any("takes no secrets file" in r for r in spool(secrets_env_text=SECRETS).refusals)
        )
        self.assertTrue(
            any("the spool's slug is mail-spool" in r for r in spool(slug="other").refusals)
        )

    def test_the_inherited_service_rules_apply_to_the_spool(self) -> None:
        document = spool_document()
        service(document)["privileged"] = True
        service(document)["network_mode"] = "host"
        refusals = " ".join(spool(document).refusals)
        self.assertIn("is privileged", refusals)
        self.assertIn("sets network_mode", refusals)


class IsolationTests(unittest.TestCase):
    """The drain bridge's firewall rules, read from ``iptables -S`` output."""

    def test_both_orders_of_the_conntrack_states_are_accepted(self) -> None:
        for states in ("ESTABLISHED,RELATED", "RELATED,ESTABLISHED"):
            with self.subTest(states=states):
                rules = GOOD_INPUT.replace("ESTABLISHED,RELATED", states)
                self.assertTrue(spool(iptables_input_text=rules).ok)

    def test_rules_of_other_interfaces_and_chains_do_not_matter(self) -> None:
        rules = "-A INPUT -i lo -j ACCEPT\n" + GOOD_INPUT + "-A INPUT -i docker0 -j DROP\n"
        self.assertTrue(spool(iptables_input_text=rules).ok)

    def test_no_rules_at_all(self) -> None:
        refusals = " ".join(spool(iptables_input_text="", iptables_docker_user_text="").refusals)
        self.assertIn("established-traffic accept", refusals)
        self.assertIn("INPUT does not drop what br-mailspool sends to the host", refusals)
        self.assertIn("DOCKER-USER does not drop what br-mailspool forwards out", refusals)

    def test_a_missing_host_drop(self) -> None:
        rules = GOOD_INPUT.replace("-A INPUT -i br-mailspool -j DROP\n", "")
        self.assertEqual(
            spool(iptables_input_text=rules).refusals,
            ("mail-spool: INPUT does not drop what br-mailspool sends to the host",),
        )

    def test_the_accept_must_come_first_among_the_bridges_rules(self) -> None:
        rules = (
            "-A INPUT -i br-mailspool -j DROP\n"
            "-A INPUT -i br-mailspool -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
        )
        self.assertTrue(
            any(
                "established-traffic accept" in r for r in spool(iptables_input_text=rules).refusals
            )
        )

    def test_a_broad_accept_ahead_of_the_accept_is_not_the_established_accept(self) -> None:
        rules = "-A INPUT -i br-mailspool -j ACCEPT\n" + GOOD_INPUT
        self.assertFalse(spool(iptables_input_text=rules).ok)

    def test_a_missing_forward_drop_or_one_for_another_bridge(self) -> None:
        for text in (
            "-N DOCKER-USER\n",
            GOOD_FORWARD.replace("br-mailspool", "br-other"),
            GOOD_FORWARD.replace("! -o br-mailspool", "-o br-mailspool"),
        ):
            with self.subTest(text=text):
                self.assertTrue(
                    any(
                        "DOCKER-USER does not drop" in r
                        for r in spool(iptables_docker_user_text=text).refusals
                    )
                )

    def test_rules_not_read_are_a_refusal_when_required(self) -> None:
        verdict = spool(iptables_input_text=None, iptables_docker_user_text=None)
        self.assertEqual(
            verdict.refusals, ("mail-spool: the drain bridge's firewall rules were not read",)
        )

    def test_rules_are_not_looked_at_when_not_required(self) -> None:
        self.assertTrue(
            spool(require_isolation=False, iptables_input_text="", iptables_docker_user_text="").ok
        )


class SecrecyAndPurityTests(unittest.TestCase):
    """The verdict is safe to print, and the judgement touches nothing."""

    def test_no_secret_reaches_a_refusal_or_the_params_repr(self) -> None:
        document = tenant_document()
        service(document)["privileged"] = True
        verdicts = [
            tenant(
                document,
                secrets_env_text=SECRETS
                + f"{SECRET_ONE}\nlower={SECRET_TWO}\nGHOST_X={SECRET_ONE}\x01\n",
            ),
            tenant(secrets_env_text=SECRETS.replace("GHOST_MAIL_PASSWORD", "BAD") + SECRET_TWO),
        ]
        params = check.Params(slug="s", compose_text="x", secrets_env_text=SECRETS)
        for verdict in verdicts:
            self.assertTrue(verdict.refusals)
            dumped = json.dumps([verdict.refusals, verdict.claim_state, verdict.image_env])
            for secret in (SECRET_ONE, SECRET_TWO):
                self.assertNotIn(secret, dumped)
        self.assertNotIn(SECRET_ONE, repr(params))

    def test_the_stamp_is_not_a_secret_but_is_not_the_secret(self) -> None:
        self.assertNotIn(SECRET_ONE, tenant().stamp)

    def test_judging_opens_no_file(self) -> None:
        with mock.patch.object(builtins, "open", side_effect=AssertionError("opened a file")):
            self.assertTrue(tenant().ok)
            self.assertTrue(spool().ok)

    def test_judging_leaves_its_inputs_alone(self) -> None:
        document = tenant_document()
        before = copy.deepcopy(document)
        tenant(document)
        self.assertEqual(document, before)

    def test_the_same_inputs_give_the_same_verdict(self) -> None:
        self.assertEqual(tenant(), tenant())


class ModuleTests(unittest.TestCase):
    """The module's entry point, in check mode and out of it."""

    def run_main(self, params: Mapping[str, object], *, check_mode: bool) -> mock.Mock:
        """Run main() against a stand-in AnsibleModule and return the stand-in."""
        module = mock.Mock()
        module.params = dict(params)
        module.check_mode = check_mode
        module.fail_json.side_effect = SystemExit
        with mock.patch.object(check, "AnsibleModule", return_value=module):
            with contextlib.suppress(SystemExit):
                check.main()
        return module

    def values(self) -> dict[str, object]:
        """Return module parameters as AnsibleModule hands them over, defaults filled in."""
        values: dict[str, object] = {
            name: option.get("default") for name, option in check.ARGUMENT_SPEC.items()
        }
        values.update(
            slug="tenant-a",
            uid=30901,
            compose_text=json.dumps(tenant_document()),
            secrets_env_text=SECRETS,
            image_env_text=PIN,
        )
        return values

    def test_it_reports_no_change_in_and_out_of_check_mode_with_the_same_verdict(self) -> None:
        results = []
        for check_mode in (True, False):
            module = self.run_main(self.values(), check_mode=check_mode)
            module.exit_json.assert_called_once()
            results.append(module.exit_json.call_args.kwargs)
        self.assertEqual(results[0], results[1])
        self.assertIs(results[0]["changed"], False)
        self.assertEqual(results[0]["slug"], "tenant-a")
        self.assertTrue(results[0]["ok"])

    def test_it_passes_the_spec_to_ansible_with_check_mode_supported(self) -> None:
        with mock.patch.object(check, "AnsibleModule") as module_class:
            module_class.return_value.params = self.values()
            check.main()
        module_class.assert_called_once_with(
            argument_spec=check.ARGUMENT_SPEC, supports_check_mode=True
        )

    def test_a_host_without_pyyaml_fails_the_module_with_a_clear_message(self) -> None:
        with mock.patch.object(check, "_load_yaml", side_effect=check.YamlMissingError):
            module = self.run_main(self.values(), check_mode=False)
        module.fail_json.assert_called_once()
        self.assertIn("PyYAML is not installed", module.fail_json.call_args.kwargs["msg"])

    def test_the_params_are_built_from_what_ansible_validated(self) -> None:
        params = check.params_from_mapping(self.values())
        self.assertEqual((params.slug, params.uid, params.profile), ("tenant-a", 30901, "tenant"))
        self.assertIsNone(params.claims_text)
        self.assertFalse(params.require_isolation)


if __name__ == "__main__":
    unittest.main()
