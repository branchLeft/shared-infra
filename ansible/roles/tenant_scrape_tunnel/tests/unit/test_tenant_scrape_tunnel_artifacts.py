"""Tests of the files that bound what the tenant scrape tunnel can reach.

The artifacts are the real templates and the real unit of the role, rendered or read as they
ship. The addresses are read from the address plan, the one home of them, and the port, the
account's command and the hardening are written out in tunnel_artifacts.py, so a change to a
file and to the variables beside it together still has to agree with the plan. Each validator
has a control, the real artifact with no finding, and a case for each rule it holds, broken text
with the finding that names the rule. The keys are made up for the test and have no private half.
The README gives the command, with the files directory and the library directory on PYTHONPATH.
"""

import itertools
import unittest

import jinja2
import tunnel_artifacts as artifacts

KEY = artifacts.synthetic_key("scraper")
OTHER_KEY = artifacts.synthetic_key("other")


def plan_addresses() -> list[str]:
    """The tenant hosts' addresses, from the address plan, in the order of the plan."""
    return list(artifacts.tenant_addresses().values())


def role_context() -> dict[str, artifacts.Value]:
    """The role's variables with the scraper's public key and the target's filled in."""
    variables = artifacts.role_variables()
    variables["tenant_scrape_tunnel_scraper_public_key"] = KEY
    variables["tenant_scrape_tunnel_target_host_key"] = OTHER_KEY
    variables["tenant_scrape_tunnel_target_endpoint"] = "tunnel-target.example.test"
    return variables


def wanted_line(addresses: list[str], key: str) -> str:
    """The exact line the role must write, spelled out here and not taken from the template."""
    options = ",".join(
        ["restrict", "port-forwarding"]
        + [f'permitopen="{address}:9100"' for address in sorted(addresses)]
        + ['command="/usr/sbin/nologin"']
    )
    return f"{options} {key}\n"


def unit_rules(variables: dict[str, artifacts.Value]) -> dict[str, str]:
    """The values the unit's literal copies must equal, from the role's variables."""
    text = artifacts.text_variable
    return {
        "user": text(variables, "tenant_scrape_tunnel_user"),
        "environment_file": text(variables, "tenant_scrape_tunnel_target_env_file"),
        "identity": text(variables, "tenant_scrape_tunnel_key_file"),
        "known_hosts": text(variables, "tenant_scrape_tunnel_known_hosts_file"),
        "alias": text(variables, "tenant_scrape_tunnel_host_key_alias"),
        "target_name": text(variables, "tenant_scrape_tunnel_target_env_name"),
    }


def wanted_forwards(variables: dict[str, artifacts.Value]) -> dict[int, str]:
    """Each local port to the tenant address behind it, from the role's destination list.

    Raises:
        RoleFileError: when a destination lacks an integer local port or a text address.
    """
    forwards: dict[int, str] = {}
    for entry in artifacts.destinations(variables):
        port, address = entry["local_port"], entry["address"]
        if not isinstance(port, int) or not isinstance(address, str):
            raise artifacts.RoleFileError("destination", "has no integer local_port and address")
        forwards[port] = address
    return forwards


def unit_findings_of(text: str) -> list[str]:
    """The findings on a unit text, judged against the address plan and the role's variables."""
    variables = artifacts.role_variables()
    return artifacts.unit_findings(
        text, artifacts.edge1_address(), wanted_forwards(variables), unit_rules(variables)
    )


class RenderedKeyLine(unittest.TestCase):
    def setUp(self) -> None:
        self.line = artifacts.render_template("authorized_keys.j2", role_context())

    def test_the_line_made_from_the_real_template_has_no_finding(self) -> None:
        self.assertEqual([], artifacts.key_line_findings(self.line, KEY, plan_addresses()))

    def test_the_line_is_the_one_the_contract_spells_out(self) -> None:
        self.assertEqual(wanted_line(plan_addresses(), KEY), self.line)

    def test_the_line_starts_with_the_restricting_options_for_the_three_hosts(self) -> None:
        start = "restrict,port-forwarding," + ",".join(
            f'permitopen="{address}:9100"' for address in sorted(plan_addresses())
        )
        self.assertEqual(3, len(plan_addresses()))
        self.assertTrue(self.line.startswith(start + ',command="/usr/sbin/nologin" '))

    def test_the_comment_of_the_key_is_not_carried(self) -> None:
        context = role_context()
        context["tenant_scrape_tunnel_scraper_public_key"] = f"{KEY} tenant-scrape-tunnel"
        line = artifacts.render_template("authorized_keys.j2", context)
        self.assertEqual(wanted_line(plan_addresses(), KEY), line)

    def test_a_template_name_the_variables_lack_is_an_error_and_not_an_empty_string(self) -> None:
        context = role_context()
        del context["tenant_scrape_tunnel_destinations"]
        with self.assertRaises(jinja2.UndefinedError):
            artifacts.render_template("authorized_keys.j2", context)


class KeyLineValidator(unittest.TestCase):
    """The validator that judges the real line refuses each broken line by its own finding."""

    def setUp(self) -> None:
        self.addresses = plan_addresses()
        self.good = wanted_line(self.addresses, KEY)
        self.first, self.second, self.third = sorted(self.addresses)

    def test_the_line_written_out_by_hand_is_accepted(self) -> None:
        self.assertEqual([], artifacts.key_line_findings(self.good, KEY, self.addresses))

    def _refused(self, line: str, fragment: str) -> None:
        found = artifacts.key_line_findings(line, KEY, self.addresses)
        self.assertTrue(
            any(fragment in finding for finding in found), f"{fragment!r} not in {found}"
        )

    def test_a_line_without_restrict_is_refused(self) -> None:
        self._refused(self.good.replace("restrict,", "", 1), "lacks restrict")

    def test_a_line_without_the_command_is_refused(self) -> None:
        self._refused(self.good.replace(',command="/usr/sbin/nologin"', ""), "lacks command=")

    def test_a_line_whose_command_runs_something_is_refused(self) -> None:
        self._refused(self.good.replace("/usr/sbin/nologin", "/bin/sh"), "unexpected option")

    def test_a_line_without_port_forwarding_is_refused(self) -> None:
        self._refused(
            self.good.replace("port-forwarding,", "", 1), "missing option port-forwarding"
        )

    def test_a_line_with_another_port_on_a_listed_host_is_refused(self) -> None:
        extra = f'permitopen="{self.first}:9104",'
        self._refused(self.good.replace("command=", extra + "command=", 1), "port 9104")

    def test_a_line_with_another_host_is_refused(self) -> None:
        extra = 'permitopen="192.0.2.1:9100",'
        self._refused(self.good.replace("command=", extra + "command=", 1), "destination 192.0.2.1")

    def test_a_line_that_opens_any_destination_is_refused(self) -> None:
        self._refused(self.good.replace(f'"{self.first}:9100"', '"*:9100"'), "unexpected option")

    def test_a_line_that_loses_a_listed_host_is_refused(self) -> None:
        self._refused(self.good.replace(f'permitopen="{self.third}:9100",', ""), "missing option")

    def test_a_line_that_widens_the_options_is_refused(self) -> None:
        self._refused(self.good.replace("restrict,", "restrict,pty,", 1), "unexpected option pty")
        self._refused(self.good.replace("restrict,", 'restrict,from="*",', 1), "unexpected option")

    def test_a_line_with_the_options_in_another_order_is_refused(self) -> None:
        swapped = self.good.replace("restrict,port-forwarding", "port-forwarding,restrict", 1)
        self._refused(swapped, "order")

    def test_a_line_with_a_comment_is_refused(self) -> None:
        self._refused(self.good.rstrip("\n") + " scraper\n", "found 4 space-separated fields")

    def test_a_second_line_is_refused(self) -> None:
        self._refused(self.good + self.good, "more than one line")

    def test_a_line_that_carries_another_key_is_refused(self) -> None:
        other = self.good.replace(KEY, OTHER_KEY)
        self._refused(other, "key differs")


class RenderedDropIn(unittest.TestCase):
    def setUp(self) -> None:
        self.variables = role_context()
        self.text = artifacts.render_template("sshd-drop-in.conf.j2", self.variables)
        self.addresses = plan_addresses()
        self.user = artifacts.text_variable(self.variables, "tenant_scrape_tunnel_user")

    def test_the_drop_in_made_from_the_real_template_has_no_finding(self) -> None:
        self.assertEqual([], artifacts.dropin_findings(self.text, self.user, self.addresses))

    def test_the_destinations_equal_those_of_the_key_line(self) -> None:
        line = artifacts.render_template("authorized_keys.j2", self.variables)
        permits = {
            option.removeprefix("permitopen=").strip('"')
            for option in artifacts.split_outside_quotes(line.split(" ")[0], ",")
            if option.startswith("permitopen=")
        }
        self.assertEqual(artifacts.permit_set(self.addresses), permits)
        self.assertEqual(permits, artifacts.dropin_permit_set(self.text))

    def test_the_directives_equal_the_read_back_table_of_the_role(self) -> None:
        wanted = self.variables["tenant_scrape_tunnel_expected_effective"]
        if not isinstance(wanted, dict):
            self.fail("the read-back table is not a mapping")
        written = {
            keyword.lower(): value.strip()
            for keyword, _, value in (
                line.strip().partition(" ")
                for line in self.text.splitlines()
                if line.startswith("    ")
            )
        }
        for keyword, value in wanted.items():
            self.assertEqual(value, written.get(keyword), keyword)

    def test_the_destinations_sit_in_one_line_with_a_space_between_them(self) -> None:
        line = next(item for item in self.text.splitlines() if "PermitOpen" in item)
        self.assertEqual(
            " ".join(sorted(artifacts.permit_set(self.addresses))),
            " ".join(sorted(line.split()[1:])),
        )
        self.assertEqual(3, len(line.split()[1:]))


class DropInValidator(unittest.TestCase):
    def setUp(self) -> None:
        self.addresses = plan_addresses()
        variables = role_context()
        self.good = artifacts.render_template("sshd-drop-in.conf.j2", variables)
        self.user = artifacts.text_variable(variables, "tenant_scrape_tunnel_user")
        self.first = self.addresses[0]

    def _refused(self, text: str, fragment: str) -> None:
        found = artifacts.dropin_findings(text, self.user, self.addresses)
        self.assertTrue(
            any(fragment in finding for finding in found), f"{fragment!r} not in {found}"
        )

    def _edited(self, old: str, new: str) -> str:
        self.assertIn(old, self.good, f"the case matched nothing: {old!r}")
        return self.good.replace(old, new, 1)

    def test_another_port_on_one_destination_only_in_the_drop_in_is_refused(self) -> None:
        self._refused(
            self._edited(f"{self.first}:9100", f"{self.first}:9100 {self.first}:9104"),
            "PermitOpen is",
        )

    def test_another_host_in_the_drop_in_is_refused(self) -> None:
        self._refused(self._edited("PermitOpen ", "PermitOpen 192.0.2.1:9100 "), "PermitOpen is")

    def test_a_lost_destination_is_refused(self) -> None:
        self._refused(
            self._edited(f"{self.first}:9100", "").replace("PermitOpen  ", "PermitOpen "),
            "PermitOpen is",
        )

    def test_a_second_permitopen_line_is_refused(self) -> None:
        text = self._edited(
            "    PermitListen none", f"    PermitOpen {self.first}:9104\n    PermitListen none"
        )
        self._refused(text, "exactly one PermitOpen")

    def test_forwarding_for_every_direction_is_refused(self) -> None:
        self._refused(
            self._edited("AllowTcpForwarding local", "AllowTcpForwarding yes"), "allowtcpforwarding"
        )

    def test_a_remote_listener_is_refused(self) -> None:
        self._refused(self._edited("PermitListen none", "PermitListen any"), "permitlisten")

    def test_a_public_gateway_port_is_refused(self) -> None:
        self._refused(self._edited("GatewayPorts no", "GatewayPorts yes"), "gatewayports")

    def test_a_command_that_runs_is_refused(self) -> None:
        self._refused(
            self._edited("ForceCommand /usr/sbin/nologin", "ForceCommand /bin/sh"), "forcecommand"
        )

    def test_a_password_login_is_refused(self) -> None:
        self._refused(
            self._edited("AuthenticationMethods publickey", "AuthenticationMethods any"),
            "authenticationmethods",
        )

    def test_a_block_that_is_not_closed_is_refused(self) -> None:
        self._refused(self._edited("Match all\n", ""), "does not end with Match all")

    def test_a_block_for_another_account_is_refused(self) -> None:
        self._refused(
            self._edited(f"Match User {self.user}", "Match User root"), "does not open with"
        )

    def test_a_directive_the_contract_does_not_hold_is_refused(self) -> None:
        self._refused(
            self._edited("    PermitListen none", "    PermitRootLogin yes\n    PermitListen none"),
            "unexpected directive",
        )


class RealUnit(unittest.TestCase):
    def test_the_real_unit_has_no_finding(self) -> None:
        self.assertEqual([], unit_findings_of(artifacts.unit_text()))

    def test_the_unit_holds_exactly_the_three_forwards_of_the_tenant_hosts_on_the_private_address(
        self,
    ) -> None:
        text = artifacts.unit_text()
        command = artifacts.unit_ssh_command(text)
        bind = artifacts.edge1_address()
        found = {
            tuple(forward.split(":")[:1] + forward.split(":")[2:]) for forward in command.forwards
        }
        self.assertEqual(3, len(command.forwards))
        self.assertEqual({(bind, address, "9100") for address in plan_addresses()}, found)
        for forward in command.forwards:
            self.assertTrue(forward.startswith(f"{bind}:"), forward)

    def test_the_unit_names_no_all_addresses_bind_and_no_forward_but_local(self) -> None:
        text = artifacts.unit_text()
        self.assertNotIn(artifacts.ALL_INTERFACES, text)
        command = artifacts.unit_ssh_command(text)
        self.assertEqual([], command.refused_flags)
        self.assertEqual(3, command.flags.count("-L"))

    def test_the_unit_bytes_equal_the_pin_in_the_role_variables(self) -> None:
        pin = artifacts.text_variable(
            artifacts.role_variables(), "tenant_scrape_tunnel_unit_sha256"
        )
        self.assertEqual(pin, artifacts.unit_sha256())

    def test_the_flags_the_role_allows_are_the_ones_these_tests_allow(self) -> None:
        listed = artifacts.role_variables()["tenant_scrape_tunnel_unit_allowed_flags"]
        self.assertEqual(
            sorted(artifacts.ALLOWED_SSH_FLAGS), sorted(listed if isinstance(listed, list) else [])
        )


class UnitValidator(unittest.TestCase):
    def setUp(self) -> None:
        self.good = artifacts.unit_text()
        self.first = plan_addresses()[0]

    def _refused(self, old: str, new: str, fragment: str) -> None:
        self.assertIn(old, self.good, f"the case matched nothing: {old!r}")
        found = unit_findings_of(self.good.replace(old, new, 1))
        self.assertTrue(
            any(fragment in finding for finding in found), f"{fragment!r} not in {found}"
        )

    def test_binding_every_address_is_refused(self) -> None:
        bind = artifacts.edge1_address()
        self._refused(
            f"-L {bind}:19100",
            f"-L {artifacts.ALL_INTERFACES}:19100",
            f"binds {artifacts.ALL_INTERFACES}",
        )

    def test_a_forward_with_no_bind_address_is_refused(self) -> None:
        bind = artifacts.edge1_address()
        self._refused(f"-L {bind}:19100", "-L 19100", "is not bind:port:host:port")

    def test_another_port_of_a_listed_host_is_refused(self) -> None:
        self._refused(f"{self.first}:9100", f"{self.first}:9104", "reaches port 9104")

    def test_another_host_is_refused(self) -> None:
        self._refused(f"{self.first}:9100", "192.0.2.1:9100", "not one of the contract's forwards")

    def test_a_fourth_forward_is_refused(self) -> None:
        bind = artifacts.edge1_address()
        self._refused(
            "    scrapetunnel@",
            f"    -L {bind}:19103:{self.first}:9100 \\\n    scrapetunnel@",
            "holds 4 -L",
        )

    def test_a_remote_forward_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -R 9100:10.20.1.10:9100", "flag -R")

    def test_a_dynamic_forward_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -D 1080", "flag -D")

    def test_a_stdio_forward_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -W 10.20.1.200:9100", "flag -W")

    def test_a_gateway_port_flag_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -g", "flag -g")

    def test_a_jump_host_flag_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -J other", "flag -J")

    def test_an_option_in_the_attached_form_is_refused(self) -> None:
        self._refused("-N -T", "-N -T -oProxyCommand=/bin/sh", "flag -oProxyCommand")

    def test_a_host_key_check_turned_off_is_refused(self) -> None:
        self._refused(
            "StrictHostKeyChecking=yes", "StrictHostKeyChecking=no", "stricthostkeychecking"
        )

    def test_a_missing_exit_on_forward_failure_is_refused(self) -> None:
        self._refused("-o ExitOnForwardFailure=yes ", "", "exitonforwardfailure")

    def test_a_missing_batch_mode_is_refused(self) -> None:
        self._refused("-o BatchMode=yes", "", "batchmode")

    def test_a_missing_identities_only_is_refused(self) -> None:
        self._refused("-o IdentitiesOnly=yes ", "", "identitiesonly")

    def test_a_second_setting_of_an_option_is_refused(self) -> None:
        self._refused("-o BatchMode=yes", "-o BatchMode=yes -o BatchMode=no", "given twice")

    def test_an_option_the_unit_does_not_hold_is_refused(self) -> None:
        self._refused(
            "-o ControlMaster=no",
            "-o ControlMaster=no -o ProxyCommand=/bin/sh",
            "proxycommand is not allowed",
        )

    def test_a_remote_command_is_refused(self) -> None:
        self._refused(
            "${TENANT_SCRAPE_EDGET_ENDPOINT}",
            "${TENANT_SCRAPE_EDGET_ENDPOINT} /bin/sh",
            "the ssh words are",
        )

    def test_a_second_command_is_refused(self) -> None:
        self._refused(
            "Restart=always", "Restart=always\nExecStartPost=/bin/sh", "runs a second command"
        )

    def test_a_dropped_hardening_option_is_refused(self) -> None:
        self._refused("ProtectSystem=strict\n", "", "ProtectSystem")

    def test_a_widened_address_family_set_is_refused(self) -> None:
        self._refused("AF_UNIX", "AF_UNIX AF_PACKET", "RestrictAddressFamilies")

    def test_a_restored_capability_is_refused(self) -> None:
        self._refused(
            "CapabilityBoundingSet=\n",
            "CapabilityBoundingSet=CAP_NET_ADMIN\n",
            "CapabilityBoundingSet",
        )

    def test_another_account_is_refused(self) -> None:
        self._refused("User=scrapetunnel", "User=root", "Service.User")

    def test_another_identity_file_is_refused(self) -> None:
        self._refused(
            "-i /etc/branchleft/tenant-scrape/id_ed25519", "-i /root/.ssh/id_ed25519", "-i is"
        )


class OtherRenderedFiles(unittest.TestCase):
    def setUp(self) -> None:
        self.variables = role_context()
        self.rules = unit_rules(self.variables)

    def test_the_known_hosts_line_names_the_alias_the_unit_dials_with(self) -> None:
        line = artifacts.render_template("known_hosts.j2", self.variables)
        self.assertEqual(f"{self.rules['alias']} {OTHER_KEY}\n", line)
        entries = artifacts.unit_entries(artifacts.unit_text())["Service.ExecStart"][0]
        self.assertIn(f"HostKeyAlias={self.rules['alias']} ", entries)

    def test_the_target_file_sets_the_variable_the_unit_reads(self) -> None:
        line = artifacts.render_template("target.env.j2", self.variables)
        self.assertEqual(f"{self.rules['target_name']}=tunnel-target.example.test\n", line)
        self.assertIn("${" + self.rules["target_name"] + "}", artifacts.unit_text())


def trigger(name: str, **observed: artifacts.Value) -> bool:
    """The value of one of the role's boolean variables, with the named values replacing the defaults."""
    rendered = artifacts.role_variables(observed)[name]
    if rendered not in ("True", "False"):
        raise artifacts.RoleFileError(name, f"rendered as {rendered!r}, not a boolean")
    return rendered == "True"


def scraper_teardown(host_key: str, endpoint: str, *, unit_installed: bool) -> bool:
    """Whether the scraper host removes its tunnel, given its two inputs and what is installed."""
    return trigger(
        "tenant_scrape_tunnel_is_scraper_teardown",
        tenant_scrape_tunnel_target_host_key=host_key,
        tenant_scrape_tunnel_target_endpoint=endpoint,
        tenant_scrape_tunnel_is_unit_installed=unit_installed,
    )


def target_teardown(scraper_key: str, *, installed: bool) -> bool:
    """Whether the target host removes its half, given its input and what is installed."""
    return trigger(
        "tenant_scrape_tunnel_is_target_teardown",
        tenant_scrape_tunnel_scraper_public_key=scraper_key,
        tenant_scrape_tunnel_is_target_installed=installed,
    )


class ScraperTeardownTrigger(unittest.TestCase):
    def test_the_first_apply_with_empty_data_removes_nothing_and_so_makes_the_key(self) -> None:
        self.assertFalse(scraper_teardown("", "", unit_installed=False))

    def test_emptying_both_values_once_the_unit_is_installed_removes_the_tunnel(self) -> None:
        self.assertTrue(scraper_teardown("", "", unit_installed=True))

    def test_emptying_only_one_value_removes_nothing(self) -> None:
        self.assertFalse(scraper_teardown(KEY, "", unit_installed=True))
        self.assertFalse(scraper_teardown("", "tunnel-target.example.test", unit_installed=True))

    def test_filled_data_removes_nothing_whether_or_not_the_unit_is_there(self) -> None:
        for installed in (False, True):
            self.assertFalse(
                scraper_teardown(KEY, "tunnel-target.example.test", unit_installed=installed)
            )

    def test_the_tunnel_is_never_both_enabled_and_removed(self) -> None:
        for host_key, endpoint, installed in itertools.product(("", KEY), ("", "host.test"), (False, True)):
            enabled = trigger(
                "tenant_scrape_tunnel_is_scraper_enabled",
                tenant_scrape_tunnel_target_host_key=host_key,
                tenant_scrape_tunnel_target_endpoint=endpoint,
            )
            removed = scraper_teardown(host_key, endpoint, unit_installed=installed)
            self.assertFalse(enabled and removed, (host_key, endpoint, installed))


class TargetTeardownTrigger(unittest.TestCase):
    def test_a_host_with_nothing_installed_removes_nothing(self) -> None:
        self.assertFalse(target_teardown("", installed=False))

    def test_emptying_the_key_once_any_part_is_installed_removes_the_half(self) -> None:
        self.assertTrue(target_teardown("", installed=True))

    def test_a_filled_key_removes_nothing(self) -> None:
        for installed in (False, True):
            self.assertFalse(target_teardown(KEY, installed=installed))

    def test_the_half_is_never_both_enabled_and_removed(self) -> None:
        for scraper_key, installed in itertools.product(("", KEY), (False, True)):
            enabled = trigger(
                "tenant_scrape_tunnel_is_target_enabled",
                tenant_scrape_tunnel_scraper_public_key=scraper_key,
            )
            self.assertFalse(enabled and target_teardown(scraper_key, installed=installed))


class ScraperTeardownFiles(unittest.TestCase):
    def test_the_files_removed_are_the_unit_its_files_and_the_key_pair_and_no_directory(self) -> None:
        listed = artifacts.role_variables()["tenant_scrape_tunnel_scraper_files"]
        self.assertEqual(
            [
                "/etc/systemd/system/branchleft-tenant-scrape.service",
                "/etc/branchleft/tenant-scrape/target.env",
                "/etc/branchleft/tenant-scrape/known_hosts",
                "/etc/branchleft/tenant-scrape/id_ed25519",
                "/etc/branchleft/tenant-scrape/id_ed25519.pub",
            ],
            listed,
        )


if __name__ == "__main__":
    unittest.main()
