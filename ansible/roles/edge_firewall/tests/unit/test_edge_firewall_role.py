"""Unit tests for the edge_firewall role: the contracts of its files, which need no container.

The Molecule scenario proves what the role does to a host. These tests prove, from the files
alone, the parts of the role that must not change by accident, so that a change to one of them
fails in seconds and names the control it broke. Each class names the control it holds. The
sabotage for a control is the edit that makes its test red; the README lists them.
"""

import re
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

ROLE = Path(__file__).resolve().parents[2]

# Where a flush could hide: every file the role ships or renders.
SHIPPED = (
    "tasks/main.yml",
    "tasks/_preconditions.yml",
    "tasks/_read_loaded.yml",
    "handlers/main.yml",
    "templates/rules.nft.j2",
    "files/branchleft-firewall.service",
    "vars/main.yml",
    "defaults/main.yml",
)

SHELL_MODULES = ("ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script")
SERVICE_MODULES = (
    "ansible.builtin.systemd_service",
    "ansible.builtin.systemd",
    "ansible.builtin.service",
)

TASK_KEYWORDS = {
    "name",
    "when",
    "register",
    "notify",
    "failed_when",
    "changed_when",
    "vars",
    "loop",
    "loop_control",
    "check_mode",
    "block",
    "rescue",
    "always",
    "delegate_to",
    "no_log",
}


def load(relative: str) -> object:
    """Parse one YAML file of the role."""
    parsed: object = yaml.safe_load((ROLE / relative).read_text(encoding="utf-8"))
    return parsed


def as_dict(value: object) -> dict[str, object]:
    """Narrow a parsed value to a mapping, failing the test if it is not one."""
    if not isinstance(value, dict):
        raise AssertionError(f"expected a mapping, got {type(value).__name__}")
    return {str(key): item for key, item in value.items()}


def as_list(value: object) -> list[object]:
    """Narrow a parsed value to a list, failing the test if it is not one."""
    if not isinstance(value, list):
        raise AssertionError(f"expected a list, got {type(value).__name__}")
    return list(value)


def module_of(task: dict[str, object]) -> str:
    """The module a task calls: its one key that is not a task keyword."""
    modules = [key for key in task if key not in TASK_KEYWORDS]
    if len(modules) != 1:
        raise AssertionError(f"cannot tell the module of {task.get('name')}: {modules}")
    return modules[0]


def strings_in(value: object) -> list[str]:
    """Every string anywhere inside a parsed value, keys included."""
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            found.extend(strings_in(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(strings_in(item))
    return found


def has_flush_word(value: object) -> bool:
    """Whether a parsed value holds `flush ruleset|table|chain` in a string, or a list with
    `flush` as an element (an argv for nft). Prose that says "flush the whole ruleset" is not it."""
    if isinstance(value, str):
        return re.search(r"\bflush\s+(ruleset|table|chain)\b", value) is not None
    if isinstance(value, list):
        return "flush" in value or any(has_flush_word(item) for item in value)
    if isinstance(value, dict):
        return any(has_flush_word(item) for item in value.values())
    return False


def code_lines(relative: str) -> list[str]:
    """The lines of a non-YAML file that are not comments."""
    text = (ROLE / relative).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def main_tasks() -> list[dict[str, object]]:
    """The top-level tasks of tasks/main.yml, in order."""
    return [as_dict(task) for task in as_list(load("tasks/main.yml"))]


def named(tasks: list[dict[str, object]], start: str) -> dict[str, object]:
    """The one task whose name starts with the text."""
    found = [task for task in tasks if str(task.get("name", "")).startswith(start)]
    if len(found) != 1:
        raise AssertionError(f"expected one task named '{start}...', found {len(found)}")
    return found[0]


def position(tasks: list[dict[str, object]], start: str) -> int:
    """The index of the one task whose name starts with the text."""
    return tasks.index(named(tasks, start))


def guard() -> dict[str, object]:
    """The guard: the one top-level block, with its block and its rescue."""
    blocks = [task for task in main_tasks() if "block" in task]
    if len(blocks) != 1:
        raise AssertionError("expected exactly one guard block in tasks/main.yml")
    return blocks[0]


def guard_block() -> list[dict[str, object]]:
    return [as_dict(task) for task in as_list(guard()["block"])]


def guard_rescue() -> list[dict[str, object]]:
    return [as_dict(task) for task in as_list(guard()["rescue"])]


def rendered(*, enforce: bool, nat_source: str = "10.20.1.0/24", uplink: str = "eth0") -> str:
    """The rules file for a set of inputs, rendered the way the role renders it."""
    constants = as_dict(load("vars/main.yml"))
    env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)  # noqa: S701
    env.filters["bool"] = bool
    template = env.from_string((ROLE / "templates" / "rules.nft.j2").read_text(encoding="utf-8"))
    return template.render(
        **constants,
        edge_firewall_enforce=enforce,
        edge_firewall_nat_source=nat_source,
        edge_firewall_uplink=uplink,
    )


def rules_of(text: str, table_start: str) -> list[str]:
    """The trimmed non-comment lines of one table of a rendered file."""
    lines = [line.strip() for line in text.splitlines()]
    start = lines.index(table_start)
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith(("add table", "delete table", "table ")):
            break
        if line and not line.startswith("#"):
            body.append(line)
    return body


class NeverFlushNeverRestartTests(unittest.TestCase):
    """Control: the role never flushes the ruleset and never starts, stops or restarts
    nftables.service. Sabotage: add `flush ruleset` to the template or a task that restarts
    nftables.service, and these go red. Docker's tables live in the same netfilter, and a flush
    removes them; a package upgrade restarts nftables.service on its own, which is why the
    role masks it and never touches it."""

    def test_no_shipped_file_contains_a_flush(self) -> None:
        for relative in SHIPPED:
            with self.subTest(file=relative):
                if relative.endswith((".yml", ".yaml")):
                    self.assertFalse(has_flush_word(load(relative)))
                else:
                    self.assertNotRegex(
                        "\n".join(code_lines(relative)), r"\bflush\s+(ruleset|table|chain)\b"
                    )

    def test_no_task_starts_stops_restarts_or_reloads_nftables_service(self) -> None:
        for relative in ("tasks/main.yml", "tasks/_preconditions.yml", "tasks/_read_loaded.yml"):
            for task in self._all_tasks(load(relative)):
                module = module_of(task)
                if module in SERVICE_MODULES:
                    with self.subTest(file=relative, task=task.get("name")):
                        self.assertNotIn("nftables", str(task[module]))
                with self.subTest(file=relative, task=task.get("name"), what="command"):
                    if module == "ansible.builtin.command":
                        argv = " ".join(strings_in(task[module]) + strings_in(task.get("loop")))
                        self.assertNotRegex(
                            argv, r"systemctl\s+(start|stop|restart|reload|enable)\s+nftables"
                        )

    def test_the_only_use_of_the_nftables_unit_is_to_mask_it_or_read_whether_it_is_masked(
        self,
    ) -> None:
        for relative in ("tasks/main.yml", "tasks/_preconditions.yml", "tasks/_read_loaded.yml"):
            for task in self._all_tasks(load(relative)):
                if "nftables.service" in str(task):
                    with self.subTest(file=relative, task=task.get("name")):
                        name = str(task.get("name"))
                        self.assertTrue(
                            name.startswith(
                                ("Mask nftables.service", "Read whether nftables.service")
                            )
                            or name.startswith("Refuse to go on unless nftables.service"),
                            name,
                        )

    def test_the_etc_nftables_conf_is_never_written(self) -> None:
        for relative in SHIPPED:
            text = (ROLE / relative).read_text(encoding="utf-8")
            code = "\n".join(
                line for line in text.splitlines() if not line.lstrip().startswith("#")
            )
            with self.subTest(file=relative):
                self.assertNotIn("/etc/nftables.conf", code)

    def test_the_boot_unit_has_no_stop_command_and_no_tie_to_nftables_service(self) -> None:
        lines = code_lines("files/branchleft-firewall.service")
        joined = "\n".join(lines)
        self.assertNotRegex(
            joined, r"^ExecStop", msg="a stop command would run when the unit stops"
        )
        self.assertNotRegex(
            joined, r"^ExecStopPost", msg="a stop command would run when the unit stops"
        )
        self.assertNotRegex(
            joined, r"(?m)^(Requires|Wants|After|Before|BindsTo|PartOf|Conflicts)=.*nftables"
        )
        self.assertIn("Type=oneshot", lines)
        self.assertIn("RemainAfterExit=yes", lines)
        self.assertIn("DefaultDependencies=no", lines)
        self.assertIn("Before=network-pre.target", lines)
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/branchleft-firewall/active.nft", lines)

    def test_the_rendered_rules_have_no_forward_or_output_chain(self) -> None:
        # Docker's FORWARD policy and DOCKER-USER stay in charge. A forward chain here cannot
        # rescue a packet Docker's iptables policy drops, and one that accepts would shadow it.
        for enforce in (True, False):
            text = rendered(enforce=enforce)
            with self.subTest(enforce=enforce):
                self.assertNotIn("hook forward", text)
                self.assertNotIn("hook output", text)
                self.assertEqual(
                    re.findall(r"^table (\w+) (\w+) \{", text, re.MULTILINE),
                    [
                        ("inet", "branchleft_edge"),
                        ("ip", "branchleft_edge_nat"),
                    ],
                )

    @staticmethod
    def _all_tasks(parsed: object) -> list[dict[str, object]]:
        """Every task in a parsed task file, blocks and rescues flattened."""
        found: list[dict[str, object]] = []
        for item in as_list(parsed):
            task = as_dict(item)
            if "block" in task:
                for part in ("block", "rescue", "always"):
                    found.extend(NeverFlushNeverRestartTests._all_tasks(task.get(part, [])))
            else:
                found.append(task)
        return found


class MaskBeforeInstallTests(unittest.TestCase):
    """Control: nftables.service is masked, and systemd has read the mask, before the package is
    installed. Sabotage: move the install above the mask. The package's postinst can start the
    unit, and starting it loads /etc/nftables.conf after a flush."""

    def test_the_mask_comes_before_the_install_with_a_reload_between(self) -> None:
        tasks = main_tasks()
        mask = position(tasks, "Mask nftables.service before the package is installed")
        read = position(tasks, "Make systemd read the mask before the package is installed")
        install = position(tasks, "Install the nftables package")
        self.assertLess(mask, read)
        self.assertLess(read, install)
        self.assertEqual(module_of(tasks[read]), "ansible.builtin.meta")
        self.assertEqual(tasks[read]["ansible.builtin.meta"], "flush_handlers")

    def test_the_mask_is_a_link_to_dev_null_at_the_unit_path(self) -> None:
        task = named(main_tasks(), "Mask nftables.service before the package is installed")
        options = as_dict(task["ansible.builtin.file"])
        self.assertEqual(options["src"], "/dev/null")
        self.assertEqual(options["state"], "link")
        self.assertEqual(options["dest"], "{{ edge_firewall_nftables_mask_path }}")
        self.assertEqual(
            as_dict(load("vars/main.yml"))["edge_firewall_nftables_mask_path"],
            "/etc/systemd/system/nftables.service",
        )
        self.assertEqual(task["notify"], "Reload systemd manager")

    def test_the_role_refuses_to_go_on_unless_the_mask_reads_masked(self) -> None:
        tasks = main_tasks()
        refuse = named(tasks, "Refuse to go on unless nftables.service is masked")
        self.assertIn("== 'masked'", str(as_dict(refuse["ansible.builtin.assert"])["that"]))
        self.assertLess(
            position(tasks, "Install the nftables package"),
            position(tasks, "Refuse to go on unless nftables.service is masked"),
        )
        self.assertLess(
            position(tasks, "Refuse to go on unless nftables.service is masked"),
            position(tasks, "Load the desired ruleset behind a revert guard"),
        )


class GuardTests(unittest.TestCase):
    """Control: a set that closes the control port is rolled back. Sabotage: delete the rescue,
    or point the connection check at 127.0.0.1 (a set that keeps loopback open would then pass)."""

    def test_the_guard_has_a_rescue_that_restores_and_fails(self) -> None:
        rescue = guard_rescue()
        names = [str(task.get("name")) for task in rescue]
        self.assertIn("Restore the previous ruleset", names)
        self.assertIn("Remove the tables when there was no previous set", names)
        self.assertEqual(rescue[-1]["ansible.builtin.fail"] is not None, True)
        self.assertLess(
            names.index("Restore the previous ruleset"),
            names.index("Record that the rollback completed"),
        )

    def test_the_connection_check_targets_the_hosts_own_private_address_not_loopback(self) -> None:
        check = named(
            guard_block(),
            "Connect to the host's own private address on the control port after the load",
        )
        options = as_dict(check["ansible.builtin.wait_for"])
        self.assertEqual(options["host"], "{{ edge_firewall_private_address }}")
        self.assertEqual(options["port"], "{{ edge_firewall_control_port }}")
        self.assertNotRegex(str(options["host"]), r"127\.|localhost|::1")
        self.assertEqual(options["state"], "started")

    def test_the_check_comes_after_the_load_and_before_the_set_is_promoted(self) -> None:
        names = [str(task.get("name")) for task in guard_block()]
        load_at = names.index("Load the desired ruleset")
        check_at = names.index(
            "Connect to the host's own private address on the control port after the load"
        )
        promote_at = names.index("Promote the desired rules to the active rules file")
        record_at = names.index("Record the listing the kernel gave for the confirmed set")
        self.assertLess(load_at, check_at)
        self.assertLess(check_at, promote_at)
        self.assertLess(promote_at, record_at)

    def test_the_previous_set_is_kept_before_the_load(self) -> None:
        names = [str(task.get("name")) for task in guard_block()]
        self.assertLess(
            names.index("Keep the active rules file as the previous set"),
            names.index("Load the desired ruleset"),
        )

    def test_the_load_is_one_nft_transaction_from_a_file_on_stdin(self) -> None:
        load_task = named(guard_block(), "Load the desired ruleset")
        options = as_dict(load_task["ansible.builtin.command"])
        self.assertEqual(options["argv"], ["{{ edge_firewall_nft_binary }}", "-f", "-"])
        self.assertEqual(options["stdin"], "{{ edge_firewall_rules }}")

    def test_the_guard_does_not_run_in_a_plan(self) -> None:
        conditions = str(guard()["when"])
        self.assertIn("not edge_firewall_plan", conditions)
        self.assertIn("edge_firewall_drift | length > 0", conditions)

    def test_the_rendered_set_adds_deletes_and_defines_each_table_in_that_order(self) -> None:
        text = rendered(enforce=True)
        for family, table in (("inet", "branchleft_edge"), ("ip", "branchleft_edge_nat")):
            add = text.index(f"add table {family} {table}\n")
            delete = text.index(f"delete table {family} {table}\n")
            define = text.index(f"table {family} {table} {{")
            self.assertLess(add, delete)
            self.assertLess(delete, define)


class LegacyMasqueradeOrderTests(unittest.TestCase):
    """Control: the legacy iptables masquerade rule is removed only after the guard has confirmed
    the role's own NAT table. Sabotage: move the removal above the guard; a failed load then leaves
    the estate with no masquerade at all."""

    def test_the_removal_follows_the_guard(self) -> None:
        tasks = main_tasks()
        self.assertLess(
            position(tasks, "Load the desired ruleset behind a revert guard"),
            position(tasks, "Remove the legacy iptables masquerade rule"),
        )
        self.assertLess(
            position(tasks, "Read whether the legacy iptables masquerade rule is still present"),
            position(tasks, "Remove the legacy iptables masquerade rule"),
        )

    def test_no_task_before_the_guard_touches_the_nat_table_of_iptables(self) -> None:
        tasks = main_tasks()
        before = tasks[: position(tasks, "Load the desired ruleset behind a revert guard")]
        for task in before:
            with self.subTest(task=task.get("name")):
                self.assertNotIn("MASQUERADE", str(task))

    def test_the_removal_waits_for_the_masquerade_to_be_in_the_loaded_listing(self) -> None:
        task = named(main_tasks(), "Remove the legacy iptables masquerade rule")
        conditions = str(task["when"])
        self.assertIn("'masquerade' in edge_firewall_listing", conditions)
        self.assertIn("not edge_firewall_plan", conditions)
        argv = as_list(as_dict(task["ansible.builtin.command"])["argv"])
        self.assertEqual(argv[:5], ["iptables", "-t", "nat", "-D", "POSTROUTING"])


class RenderedRulesTests(unittest.TestCase):
    """Control: the input chain is the plan's, in the plan's order, in both modes. Sabotage: delete
    the tcp/22 accept, move it after a drop, or invert the mode flag."""

    def test_enforce_mode_drops_by_policy_and_monitor_mode_accepts(self) -> None:
        enforce = rules_of(rendered(enforce=True), "table inet branchleft_edge {")
        monitor = rules_of(rendered(enforce=False), "table inet branchleft_edge {")
        self.assertIn("type filter hook input priority 0; policy drop;", enforce)
        self.assertNotIn("policy accept;", " ".join(enforce))
        self.assertIn("type filter hook input priority 0; policy accept;", monitor)
        self.assertNotIn("policy drop", " ".join(monitor))

    def test_monitor_mode_drops_nothing_by_rule_either(self) -> None:
        monitor = rules_of(rendered(enforce=False), "table inet branchleft_edge {")
        self.assertEqual([rule for rule in monitor if re.search(r"(^|\s)(drop|reject)$", rule)], [])

    def test_enforce_mode_has_the_one_drop_rule_before_the_accepts(self) -> None:
        enforce = rules_of(rendered(enforce=True), "table inet branchleft_edge {")
        drops = [rule for rule in enforce if re.search(r"(^|\s)(drop|reject)$", rule)]
        self.assertEqual(drops, ["ct state invalid drop"])
        self.assertLess(
            enforce.index("ct state invalid drop"),
            enforce.index("ct state established,related accept"),
        )

    def test_the_control_port_accept_has_no_restriction_and_precedes_every_log_rule(self) -> None:
        for enforce in (True, False):
            rules = rules_of(rendered(enforce=enforce), "table inet branchleft_edge {")
            with self.subTest(enforce=enforce):
                self.assertEqual(
                    [rule for rule in rules if "dport 22" in rule], ["tcp dport 22 accept"]
                )
                logs = [rule for rule in rules if 'log prefix "branchleft-fw would-drop: "' in rule]
                self.assertEqual(len(logs), 4)
                self.assertLess(rules.index("tcp dport 22 accept"), rules.index(logs[0]))

    def test_loopback_is_accepted_by_address_never_as_a_whole_interface(self) -> None:
        # The guard's connection arrives on lo from the host's own private address. A blanket
        # `iif "lo" accept` would let a set that closes tcp/22 pass the check.
        for enforce in (True, False):
            rules = rules_of(rendered(enforce=enforce), "table inet branchleft_edge {")
            with self.subTest(enforce=enforce):
                self.assertNotIn('iif "lo" accept', rules)
                self.assertNotIn('iifname "lo" accept', rules)
                self.assertIn('iif "lo" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept', rules)
                self.assertIn('iif "lo" ip6 saddr ::1 ip6 daddr ::1 accept', rules)

    def test_the_bridge_ports_are_the_four_the_plan_names(self) -> None:
        rules = rules_of(rendered(enforce=True), "table inet branchleft_edge {")
        for line in (
            'iifname "br-*" tcp dport { 2586, 3000, 6060, 9091 } accept',
            'iifname "docker0" tcp dport { 2586, 3000, 6060, 9091 } accept',
            'iif "lo" tcp dport { 2586, 3000, 6060, 9091 } accept',
            "tcp dport { 80, 443 } accept",
        ):
            with self.subTest(line=line):
                self.assertIn(line, rules)

    def test_one_masquerade_scoped_to_the_estate_source_and_the_derived_uplink(self) -> None:
        text = rendered(enforce=True, nat_source="10.20.1.0/24", uplink="ens3")
        nat = rules_of(text, "table ip branchleft_edge_nat {")
        masquerades = [rule for rule in nat if rule.endswith("masquerade")]
        self.assertEqual(masquerades, ['ip saddr 10.20.1.0/24 oifname "ens3" masquerade'])

    def test_the_uplink_is_never_a_literal_in_the_template(self) -> None:
        template = (ROLE / "templates" / "rules.nft.j2").read_text(encoding="utf-8")
        self.assertNotRegex(template, r'oifname "(?!\{\{)')
        self.assertIn('oifname "{{ edge_firewall_uplink }}"', template)


class InterfaceTests(unittest.TestCase):
    """The interface the spec declares is the interface the role reads (ANS-7)."""

    def test_enforce_is_off_by_default_in_the_defaults_and_in_the_spec(self) -> None:
        # Control: monitor mode is the default, so a play that forgets the variable cannot drop.
        # Sabotage: invert the default.
        defaults = as_dict(load("defaults/main.yml"))
        self.assertIs(defaults["edge_firewall_enforce"], False)
        spec = as_dict(as_dict(as_dict(load("meta/argument_specs.yml"))["argument_specs"])["main"])
        options = as_dict(spec["options"])
        self.assertIs(as_dict(options["edge_firewall_enforce"])["default"], False)

    def test_the_nat_source_has_no_default_and_is_required(self) -> None:
        defaults = as_dict(load("defaults/main.yml"))
        self.assertNotIn("edge_firewall_nat_source", defaults)
        spec = as_dict(as_dict(as_dict(load("meta/argument_specs.yml"))["argument_specs"])["main"])
        options = as_dict(spec["options"])
        self.assertIs(as_dict(options["edge_firewall_nat_source"])["required"], True)

    def test_every_variable_carries_the_role_name(self) -> None:
        for relative in ("defaults/main.yml", "vars/main.yml"):
            for key in as_dict(load(relative)):
                with self.subTest(file=relative, key=key):
                    self.assertTrue(key.startswith("edge_firewall_"))

    def test_the_source_pattern_refuses_a_trailing_newline_and_a_second_token(self) -> None:
        pattern = str(as_dict(load("vars/main.yml"))["edge_firewall_source_pattern"])
        # Ansible's `match` is re.match, so the pattern is used the way re.match uses it.
        self.assertIsNotNone(re.match(pattern, "10.20.1.0/24"))
        for bad in (
            "10.20.1.0/24\n",
            "10.20.1.0/24 counter",
            "10.20.1.0/24\nip saddr 203.0.113.0/24 masquerade",
            "10.20.0.0/16",
            "10.20.1.5/24",
            "",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(re.match(pattern, bad))

    def test_the_forwarding_drop_in_has_one_writer_and_it_is_this_role(self) -> None:
        sysctl = named(main_tasks(), "Persist IPv4 forwarding")
        options = as_dict(sysctl["ansible.posix.sysctl"])
        self.assertEqual(options["sysctl_file"], "{{ edge_firewall_sysctl_file }}")
        self.assertEqual(options["sysctl_set"], True)
        self.assertEqual(
            as_dict(load("vars/main.yml"))["edge_firewall_sysctl_file"],
            "/etc/sysctl.d/99-branchleft-nat.conf",
        )


class NoShellTests(unittest.TestCase):
    """The role calls no shell module: every command is an argv list, so a value in a variable
    cannot become shell syntax."""

    def test_no_task_calls_a_shell_module(self) -> None:
        for relative in ("tasks/main.yml", "tasks/_preconditions.yml", "tasks/_read_loaded.yml"):
            text = (ROLE / relative).read_text(encoding="utf-8")
            code = "\n".join(
                line for line in text.splitlines() if not line.lstrip().startswith("#")
            )
            for module in SHELL_MODULES:
                with self.subTest(file=relative, module=module):
                    self.assertNotIn(module, code)


if __name__ == "__main__":
    unittest.main()
