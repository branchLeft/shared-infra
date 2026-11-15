# test_ci_jump_pins.py: the ci_jump copies, its output and its task order

The `ci_jump` role carries its own copy of the constants its module also pins (the port, the fixed
options, the forced command and the paths of the key file and the sshd drop-in; the module is the
read-back oracle, so the two must be held equal), and a literal list of the accounts other roles
own, because a role may not call another or load its variables (ANS-12, R6). The test fails when a
constant differs, when the account names differ from `ci_login_user` in
`roles/ci_login/vars/main.yml` and `tunnel_account_user` in `roles/tunnel_account/vars/main.yml`
(read by variable name), when either template writes other text than the module expects, when the
key template and the drop-in template do not read their destinations from the one variable
`ci_jump_destinations`, when the module stops requiring `AllowTcpForwarding local` for the jump
account (a key line with `port-forwarding` also lets its holder open a port on the jump host with
`ssh -R` under any other value), when the argument spec and the defaults name different variables,
when the role's own defaults are not inert (the flag false, and no address, destination or key), when
an `owner_vars` file of a host the owner has not turned the role on for (the flag anything but the
bool true) does not ship those defaults, when a file that turns the role on (the flag true, as edge1
does after the owner's data change) lacks an address, a list of destinations or a list of keys,
when an `owner_vars` file carries the account's name, when a host lists the role without its variables or
without `ci_jump_user` in its `host_inputs` row, when a path the role writes or the module pins is made
from the account's name (each is rendered with a realistic name and must not hold it; only the paths
of the earlier hand-made layout, which the role removes, are), when a task that handles the name or
one of those paths does not hide its result and its diff, and when the order or hiding of the role's tasks changes
(the report runs whatever the flag is; the guards and the write are behind it, in that order; the
two files are written as `root:root` at `0644` by hidden template tasks, never by `authorized_key`;
the whole configuration is checked with `sshd -t`; a rescue puts the previous files back; the
read-back is inside the rolled-back block and skipped in check mode).

It also keeps the role's output out of the gated apply's plan scan, which withholds a host's whole
plan on one line that reads like a credential assignment, and keeps the jump account's name out of
the report and the plan. The module holds a copy of the scan's credential-assignment pattern
(`SCAN_PATTERN`, from `branchLeft/github-workflows/.github/actions/ssh-check-hosts/action.yml`
line 434 at tag v1.0.19). The test runs the module's report and plan over hostile values (option
values that read like credentials, an account whose name must appear nowhere) and fails when a line
matches, when the module's last-resort guard had to withhold one, or when the name is printed, and
it scans every variable name, task name and message of the role. **Drift of the copy from the
original is not checked here**: no test holds the two equal yet. Each pin runs red on a sabotaged
copy of its files and green once the file is put back.
