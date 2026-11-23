"""Unit tests for the delivery of the 90-day uptime collector to the host.

Gatus keeps its history for 32 days, so `branchleft_status_uptime.py` records the probe samples
itself. A program that is in the repository but never copied to the host or scheduled records
nothing, and that is how issue 2103 sat for four days with its first merge in place. These tests
read the role's tasks and render its two unit templates, and fail when the program is not
installed, the timer is not installed and enabled, or the units do not run `collect` against the
address the page is published on and write the report the figure is read from.
"""

import re
import unittest
from pathlib import Path
from typing import Any

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]
MAX_MINUTES_BETWEEN_COLLECTIONS = 100  # the page keeps the last 100 results, one a minute
INSTALL_TASKS = "_uptime.yml"


def _tasks(name: str) -> list[dict[str, Any]]:
    """Return the parsed tasks of one task file of the role."""
    return list(yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8")))


def _vars(listen_address: str) -> dict[str, str]:
    """Return the role's constants with every reference to another constant filled in."""
    values: dict[str, Any] = yaml.safe_load(
        (ROLE / "vars" / "main.yml").read_text(encoding="utf-8")
    )
    values["status_page_listen_address"] = listen_address
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    for _ in range(4):
        values = {
            key: environment.from_string(value).render(**values)
            if isinstance(value, str)
            else value
            for key, value in values.items()
        }
    return {key: str(value) for key, value in values.items()}


def _render(template: str, listen_address: str) -> str:
    """Render one of the role's unit templates with the role's own constants."""
    source = (ROLE / "templates" / template).read_text(encoding="utf-8")
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    return environment.from_string(source).render(**_vars(listen_address))


def _line(pattern: str, text: str) -> str:
    """Return the first group of the one line that matches, or fail with the text."""
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"no line matches {pattern} in:\n{text}")
    return match.group(1)


def _task(tasks: list[dict[str, Any]], module: str, **match: object) -> dict[str, Any]:
    """Return the one task that uses `module` with these argument values, or fail."""
    found = [
        task
        for task in tasks
        if module in task and all(task[module].get(key) == value for key, value in match.items())
    ]
    if len(found) != 1:
        raise AssertionError(f"expected one {module} task with {match}, found {len(found)}")
    return found[0]


class UptimeTimerInstalledTest(unittest.TestCase):
    """The collector reaches the host and runs on a schedule."""

    def test_the_role_runs_the_install_tasks_last(self) -> None:
        main = _tasks("main.yml")
        self.assertEqual(main[-1].get("ansible.builtin.include_tasks"), INSTALL_TASKS)
        recorded = [
            index for index, task in enumerate(main) if "status_page_stamp_file" in str(task)
        ]
        self.assertTrue(recorded)
        self.assertLess(max(recorded), len(main) - 1, "the collector follows the healthy stamp")

    def test_the_program_is_copied_to_the_host_byte_for_byte(self) -> None:
        values = _vars("127.0.0.1")
        task = _task(
            _tasks(INSTALL_TASKS), "ansible.builtin.copy", src="{{ status_page_uptime_program }}"
        )
        self.assertEqual(
            task["ansible.builtin.copy"]["dest"],
            "{{ status_page_uptime_program_dir }}/{{ status_page_uptime_program }}",
        )
        self.assertEqual(task["ansible.builtin.copy"]["mode"], "0755")
        self.assertNotIn("content", task["ansible.builtin.copy"])
        self.assertTrue((ROLE / "files" / values["status_page_uptime_program"]).is_file())

    def test_both_units_are_installed_into_the_systemd_directory(self) -> None:
        tasks = _tasks(INSTALL_TASKS)
        for unit, template in (
            ("status_page_uptime_service", "uptime-collect.service.j2"),
            ("status_page_uptime_timer", "uptime-collect.timer.j2"),
        ):
            task = _task(tasks, "ansible.builtin.template", src=template)
            self.assertEqual(
                task["ansible.builtin.template"]["dest"],
                "{{ status_page_uptime_unit_dir }}/{{ " + unit + " }}",
            )
            self.assertIn("Reload systemd manager", task["notify"])
        self.assertEqual(_vars("127.0.0.1")["status_page_uptime_unit_dir"], "/etc/systemd/system")

    # The control for issue 2103: remove the task that enables the timer, or the include in
    # main.yml, and this fails. The program on disk with no timer records nothing.
    def test_the_timer_is_enabled_and_started(self) -> None:
        task = _task(
            _tasks(INSTALL_TASKS),
            "ansible.builtin.systemd_service",
            name="{{ status_page_uptime_timer }}",
            enabled=True,
        )
        self.assertEqual(task["ansible.builtin.systemd_service"]["state"], "started")
        self.assertTrue(_vars("127.0.0.1")["status_page_uptime_timer"].endswith(".timer"))

    def test_the_handlers_exist_that_the_unit_tasks_notify(self) -> None:
        handlers = {
            str(handler["name"])
            for handler in yaml.safe_load(
                (ROLE / "handlers" / "main.yml").read_text(encoding="utf-8")
            )
        }
        for task in _tasks(INSTALL_TASKS):
            notified = task.get("notify", [])
            for name in [notified] if isinstance(notified, str) else notified:
                self.assertIn(name, handlers)


class UptimeUnitsTest(unittest.TestCase):
    """What the two unit files say, as rendered."""

    def test_the_timer_runs_often_enough_to_miss_no_probe(self) -> None:
        timer = _render("uptime-collect.timer.j2", "127.0.0.1")
        match = _line(r"^OnCalendar=\*:0/(\d+)$", timer)
        self.assertLessEqual(int(match), MAX_MINUTES_BETWEEN_COLLECTIONS)
        self.assertIn("WantedBy=timers.target", timer)
        self.assertIn("Persistent=true", timer)

    def test_the_service_collects_from_the_address_the_page_is_published_on(self) -> None:
        for address in ("10.20.1.50", "127.0.0.1"):
            service = _render("uptime-collect.service.j2", address)
            self.assertIn("Type=oneshot", service)
            self.assertIn(
                f"collect --url http://{address}:8303/api/v1/endpoints/statuses "
                "--dir /var/lib/branchleft/status-uptime/samples",
                service,
            )

    def test_the_service_writes_the_report_after_a_collection(self) -> None:
        service = _render("uptime-collect.service.j2", "10.20.1.50")
        post = _line(r"^ExecStartPost=(.*)$", service)
        self.assertIn(
            "/opt/branchleft/status-uptime/branchleft_status_uptime.py report "
            "--dir /var/lib/branchleft/status-uptime/samples "
            "--out /var/lib/branchleft/status-uptime/report.json",
            post,
        )
        self.assertIn("ReadWritePaths=/var/lib/branchleft/status-uptime", service)


if __name__ == "__main__":
    unittest.main()
