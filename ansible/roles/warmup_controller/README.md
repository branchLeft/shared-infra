# warmup_controller

Installs the IP2 warm-up controller's host side on ops1: the `warmup-controller` service account, its
state directory `/var/lib/branchleft/warmup-controller` (mode 0700), and the service and timer units.
It starts nothing. The timer is held off until `warmup_controller_timer_enabled` is true.

The program is the package `services/warmup-controller` in ghost-platform, installed as
`/opt/branchleft/warmup-controller/current`. The service runs `python3 -m warmup_controller` once a
day at 01:15 UTC, reads the day's evidence file and the owner's cards file, and writes the controller
state, the published state file and one ledger row. It refuses unreadable input and writes nothing.

## Not wired yet (the owner's)

- The playbook entry and the `checks/host_roles/ops1.yml` line. Both are the owner's merge: the check
  (R9) reads the host list, and `ansible/checks/` is owner-owned.
- The evidence file's producers (the readers), and the cards file's writer.
- The package install into `/opt/branchleft/warmup-controller/current`.
- Pointing the mail collector's `COLLECTOR_IP2_STATE_PATH` at the published file, which is the
  collector's own mount and is not set here.
- Turning the timer on, by changing the default in `defaults/main.yml` in a reviewed change.

## Tests

`python3 -m unittest discover -s tests/unit -p 'test_*.py'` checks the units against the role's
variables. The molecule scenario in `molecule/default` runs in the ANS-15 harness.
