# deploy_tooling

This role installs the one program the CI deploy account may run as root and the
template unit it restarts, checks (and never writes) the sudoers drop-in that grants
the account that one program, and, on a host that runs tenants' containers, installs
and applies the Docker firewall policy and reads the firewall chains back to prove it
is in force. It replaces two hand-run scripts, one that installed the deploy tooling
and one that installed the firewall policy.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

A host is told its **class**. The role has no default for it: a host that is not told
what it is is not guessed.

- **Class `gateway`** (the host that holds the estate's shared address): the two
  directories, the deploy wrapper, the compose template unit, and the sudoers check. The
  policy program refuses to run on the gateway, so this class gets none of it.
- **Class `app`** (a host that runs tenants' containers): everything above, and the
  policy program, its unit enabled at boot, the program applied, and the firewall chains
  read back and compared with what the program builds. An app host also names its
  **variant**: `standard`, or `protected_no_db` for the host that serves the control
  plane (it carries the protected-port drops and no database exception).

The role does not write the sudoers drop-in. First-boot configuration writes it, and a
broken sudoers file locks every account out of `sudo`, so the role reads it and refuses
anything but the one grant. It does not start, enable or restart a compose instance
(`branchleft-compose@`): a restart redeploys a tenant's stack. It does not edit the
policy program, and it does not decide which host is which class: that belongs to the
inventory or the play.

**Do not apply this role while a second writer exists.** Two hand-run scripts install
the same files today: `hetzner/provision/30-install-deploy-tooling.sh` (the wrapper and
the template unit) and `hetzner/provision/app-host-isolation.sh` (the policy program and
its unit). They write the same bytes with the same modes and compare bytes first, so
they cannot undo each other's work, but a host where all three ran is a host with three
writers of one file. Retiring the scripts is a separate change, made after the role has
run on the hosts. Until then, do not run either script on a host this role manages.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every input, and
[`defaults/main.yml`](defaults/main.yml) holds the one default. Ansible checks the
inputs when the role starts.

| Variable                        | Default          | Meaning                                                                                                                     |
| ------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `deploy_tooling_host_class`     | none, required   | `app` or `gateway`.                                                                                                         |
| `deploy_tooling_policy_variant` | `not_applicable` | `standard` or `protected_no_db`. Required for class `app` (the role refuses `not_applicable` there); ignored for `gateway`. |

The variant is the role's **expectation**, never an input to the policy program. The
program decides for itself from the host's own address, and the read-back fails when the
chain it finds is not the one the variant names.

Nothing is a secret (ANS-16). Everything else the role uses is fixed in
[`vars/main.yml`](vars/main.yml), each with the reason for it, and an inventory value
does not change it: the paths, the modes, the sudoers line, and the list of chain names
another tool may put a jump to above the policy (empty, see "Named limits").

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` in
  `meta/main.yml` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3. A host of class `app` needs `iptables` and `ip6tables`
  (the read-back runs both) and a running systemd. All hosts need `sudo`'s `visudo` and
  `getfacl` (Debian's `acl` package); a host without `getfacl` is refused, not taken for
  having no ACL.
- A host created from the platform's first-boot configuration, so that the sudoers
  drop-in exists. A host without it is refused, not repaired.

## What it changes on a host

- `/etc/branchleft/` and `/opt/branchleft/`: owner and group `root`, mode `0755`. Other
  roles state the same two directories with the same values.
- `/usr/local/sbin/branchleft-deploy` (`root:root`, `0755`): the wrapper, the only
  program the sudoers grant names.
- `/etc/systemd/system/branchleft-compose@.service` (`root:root`, `0644`): the template
  unit. systemd is told to reload when it changes. No instance of it is touched.
- Class `app` only: `/usr/local/sbin/branchleft-docker-user-policy` (`root:root`,
  `0755`) and `/etc/systemd/system/branchleft-docker-user-policy.service` (`root:root`,
  `0644`); the unit is enabled; and when either file changed the unit is **restarted**,
  which runs the program and adds the firewall rules.

A file target that is a symbolic link is replaced, never written through. A directory at
a file target is removed only when it is empty; one with anything in it stops the run.
After the files are written the role reads every target again and refuses one that is
not owned by `root`, not in group `root`, not the mode it is installed with, or not a
regular file or directory as it should be.

The role also reads every directory on the path to each target (and to the sudoers
drop-in), up to `/`, because an account that can write to a directory can replace a file
in it that runs as root, and an account that can write to a directory above that one can
rename it aside and put its own in its place. The rule is one strict shape, and it asks
nothing about who is in which group. Every such directory must be a directory (a link
anywhere on the path is refused, never followed), owned by `root`, free of an extended ACL,
and not writable by any group or any other account: its mode has no group-write and no
other-write bit, whatever the group is, `root`'s own included. Every target (the two
directories, the four files) and the sudoers drop-in must carry no extended ACL either. The
group database is not read. It does not repair any of this. A `/usr/local/sbin` that is
`root:staff` and group-writable (2775), as a host that has `/etc/staff-group-for-usr-local`
gets, is refused, and has to be made `root:root` `0755` first by whoever owns the host. A
fresh `debian:13`, `debian:12` or `ubuntu:24.04` has `/usr/local/sbin` at `root:root` `0755`
and no such marker file. These reads come first, before the role writes a
file, so a run that is refused has written nothing into the directory it refused.

The four files are read from `hetzner/provision/` of the checkout the playbook runs from,
which stays their single home: the role holds no copy of them and no link to them (a link
under the role would be a second path to the same bytes, and a check that reads it would
treat the role as the author of a program it does not write). This differs from the note
that asked for a download at a pinned commit: no other repository holds these programs, so
a download would have meant a second copy in the repository that is downloaded from.

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/deploy_tooling
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a second
converge that must change nothing, verify, a configured-state check-mode run that must
show no change, Molecule's own check action and destroy. It needs Docker on the machine
and creates one container running systemd as process 1, with the `NET_ADMIN`
capability so that it can hold its own firewall chains. The container has no network.
It never touches a host. The role's module and the checks that bind it to the rest of
the repository have unit tests: from `ansible/roles/deploy_tooling` run
`PYTHONPATH=library python -m unittest discover -s tests/unit`, and from the repository
root run `python -m unittest discover -s ansible/checks`. CI runs all of them.

Only `ip` is a stand-in in the container: the policy program picks its variant from the
output of `ip -4 -o addr show scope global`, so the test's `ip` prints a chosen address
when a file says so. The firewall is the real one, the real program runs through its
real unit, and the test reads the real chains. A stub `docker.service` and a `docker`
command that succeeds stand in for Docker, which the template unit requires and the
image does not have.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode, the
approval of the protected environment, a pull of that exact commit on the host, and a
second run that must report zero changes. Nothing in this repository applies the role by
hand, and an author's local run is the container test. The gateway host plays the role as
class gateway, named in that host's play vars and pinned by the enrolment check. `app1`
plays it as class app with the standard variant, named in its play vars and pinned the same way,
after the website role and before `deploy_slot_keys`. The first apply on app1 re-applies the
Docker firewall policy on a live app host: installing the policy program and its unit notifies
the "Restart the policy unit" handler. The owner reads the plan job before approving. The real `iptables -S INPUT` and
`iptables -S DOCKER-USER` (and the IPv6 pair) have still not been captured from a real app
host (see "Named limits").

## How to change it safely

- A path or a mode changes in one place, `vars/main.yml`, and in the same change
  wherever else it is written: the check `ansible/checks/test_deploy_tooling_links.py`
  fails when the role and the two hand-run scripts disagree about a path, a mode or a
  source, and `ansible/checks/test_deploy_tooling_sudoers_seam.py` fails when the line the
  role expects differs from the one first-boot configuration writes.
- The role builds nothing the policy program does not build. If the read-back fails on a
  rule the program does not produce, the module's expectation is wrong; do not edit the
  program to satisfy the module. The module reads the program's own literals (the
  addresses, the ports, the bridge) from the program and restates none of them. A rule
  the program respells (a new flag, a new address) leaves the old rule in the chain next
  to the new one, because the program only adds what is missing: flush the chain and
  re-apply (restart the unit) on each host after such a change.
- Run the whole harness, not the step you touched. Every control below has a test that
  fails when the control is removed; keep it that way.
- Never loosen the whole-file comparison of the sudoers drop-in or the read-back's
  foreign-rule bound to make a run pass. A host that cannot satisfy them is the thing to
  fix.

## Why each part is the way it is

- **The read-back is a module.** The firewall chains are command output that has to be
  parsed, and ANS-9 makes that a typed, tested module (ANS-2). The module lives in this
  role's `library/` and is called by its bare name, which begins with the role's name; the
  standard does not yet say this in words (a follow-up amends it), and the lint accepts it.
  It runs `iptables -w -S` and `ip6tables -w -S` as argv with no shell, never changes
  anything, and on failure prints the first mismatch and never the text of a rule the
  policy did not put there. A failure names the chain and says how many other rules it
  holds; for a rule above the policy's last drop it names only that rule's place in the
  chain and its target. The log of a plan is public, and a real chain holds the addresses
  and ports of the host's administration. On success it reports how many rules it
  recognised as the policy's and how many it did not.
- **What the listing looks like.** The program builds four chains: DOCKER-USER and INPUT
  for IPv4, and INPUT and, where Docker made one, DOCKER-USER for IPv6. On Debian 13
  (iptables 1.8.11, nf_tables) `iptables -S` prints an option order the module matches
  exactly, and prints an address with a `/32`. A host that may reach the database has, in
  DOCKER-USER: the established accept, the bridge drop, the database accept, the drop of
  the whole subnet, the drop of the metadata address, and Docker's own final return, which
  is not the policy's. The control-plane host prints two more drops, `! -s <gateway>/32
-p tcp -m conntrack --ctorigdst <address> --ctorigdstport <port> -j DROP`, in place of
  the database accept. IPv6 prints the INPUT pair and, in DOCKER-USER, only the bridge drop.
- **The chain is checked as an ordered subsequence.** The policy's rules must appear in the
  order the program builds them; foreign rules between them are allowed, but not any that
  can let a packet past: above the policy's last drop, a foreign rule must be a drop or
  reject that has a match, or a jump to a chain named in `vars/main.yml`. Docker's own
  `RETURN` sits below everything and is never moved. IPv4 `DOCKER-USER` carries the
  established-traffic accept, the mail-spool bridge forward drop, the protected-port drops
  (variant `protected_no_db` only), the database accept (variant `standard` only), the
  subnet drop and the metadata drop. IPv6 `DOCKER-USER`, when the chain exists, carries
  the forward drop alone. IPv4 and IPv6 `INPUT` each carry the established accept and the
  drop for the mail-spool bridge. A host whose Docker made no IPv6 chain is checked
  without it.
- **`DOCKER-USER` has to be reached first.** Every drop of the policy sits in `DOCKER-USER`,
  and a packet only meets them if `FORWARD` sends it there before any other rule can accept
  it. Docker puts that jump first in `FORWARD`. In each family where `DOCKER-USER` exists the
  module fails unless the first rule of `FORWARD` is the plain jump to it. The container
  test has no Docker, so it puts the jump in place the way Docker does. That Docker puts it
  first on a real app host is read from Docker's behaviour, not from a capture, and a
  capture is in the acceptance criteria of the ticket that wires the app hosts.
- **A flushed chain is repaired once.** Docker rebuilds the chain when it restarts and the
  unit follows that restart, but a chain flushed by anything else would stay open until
  the next boot. The read-back sits in a block; if it fails, the unit is restarted and the
  chains are read again, and a second failure fails the run. A chain that holds the right
  rules in the wrong order is not reordered, because a restart only adds what is missing;
  that fails with the module's message.
- **The handler restarts; it never starts.** The unit is a oneshot that stays active once
  it has run, so a start of an active unit does nothing and a changed program would sit
  unrun until the next boot. It restarts when the program or its unit file changed, and at
  no other time.
- **Check mode.** The role runs to completion under `--check --diff` on a host in either
  state. `stat`, `slurp`, the sudoers syntax check and the firewall read-back all run in
  check mode, so the plan log shows what they found. The read-back is skipped, with the
  reason printed, only while the program, its unit or the unit's enabled state would
  change: the handler that applies them does not run in check mode, so the chains cannot
  yet be what the new program would build, and a read-back would fail every first plan of
  a host. When none of them would change, the read-back runs, and fails, because a host
  whose files are right and whose chains are wrong is drift the plan has to show.
- **The sudoers drop-in is compared whole.** After the owner, group, mode and `visudo`
  checks, the drop-in must be exactly the one grant and a final newline. A line that
  includes another directory, continues onto a second line, hides a wider grant in a
  comment, adds a second grant, lacks its final newline or has trailing space is refused,
  though `visudo` accepts each of them.
- **Nothing printed is secret.** The plan log carries the `stat` results, the drop-in line
  (a root-owned grant that names the wrapper) and the read-back's first mismatch, so the
  approver reads them before approving.

## What the test proves

The test runs in one Debian 13 container with systemd. Each control in the table is
removed in turn, by one edit, and the harness is run: the removal makes the named step
fail with the message shown, and the file is restored afterwards. A control whose removal
leaves every step green is not claimed.

| Control                                                                               | Removed by                                                      | The harness then fails at                                                                                                                                                   |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Owner of each target is root                                                          | the owner left out of the repair tasks                          | verify, targets repaired: `owner is nobody, expected root`, naming the path                                                                                                 |
| Group of each target is root                                                          | the group left out of the repair tasks                          | verify, targets repaired: `group is nogroup, expected root`, naming the path                                                                                                |
| Mode of each target is the installed one                                              | the mode left out of the repair tasks                           | verify, targets repaired: `mode is 0644, expected 0755`, naming the path                                                                                                    |
| A link at a file target is replaced, never followed                                   | the copy told to follow links and the link left in place        | verify, target kinds: `is missing, is a link, or is not a file`, naming the path                                                                                            |
| A directory that holds files is never removed                                         | the check that it is empty taken out                            | verify, target kinds: `EXPECTED A FAILURE, GOT NONE` for the directory that holds a file                                                                                    |
| The drop-in is owned by root                                                          | the owner assertion taken out                                   | verify, sudoers: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in owner`                                                                                                      |
| The drop-in is in the root group                                                      | the group assertion taken out                                   | verify, sudoers: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in group`                                                                                                      |
| The drop-in has the mode sudo requires                                                | the mode assertion taken out                                    | verify, sudoers: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in mode`                                                                                                       |
| The drop-in passes `visudo`                                                           | the `visudo` task made a no-op                                  | verify, sudoers: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in with a syntax error`                                                                                        |
| The drop-in is exactly the one grant                                                  | the whole-file comparison taken out                             | verify, sudoers: `EXPECTED A FAILURE, GOT NONE` for the include directive after the grant                                                                                   |
| The role never writes the drop-in                                                     | a task that copies the drop-in added                            | verify, sudoers: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in owner`                                                                                                      |
| A gateway gets none of the isolation                                                  | the class condition taken off the isolation include             | verify, gateway phase: `Could not find the requested service` for the policy unit                                                                                           |
| A gateway gets no policy program or unit                                              | the class condition taken off the policy copy                   | verify, gateway phase: `is present on a gateway host`, naming the path                                                                                                      |
| A refused policy program fails the run                                                | `failed_when: false` on the restart handler                     | verify, refusal phase: `WRONG FAILURE`, the run failing at the rescue restart and not at the handler                                                                        |
| The policy unit is restarted only when something changed                              | a restart of the unit on every run                              | idempotence: `changed=1` on the second converge                                                                                                                             |
| A changed program is applied by the handler                                           | the handler made a `started` instead of a `restarted`           | verify, program changed: `The chain was put right by the read-back's repair`                                                                                                |
| The role never restarts a compose instance                                            | a restart handler notified when the template unit is written    | verify, compose probe: `The role restarted a compose instance`, the invocation id changed                                                                                   |
| The role never enables a compose instance                                             | an `enabled: true` task for the probe instance                  | verify, compose probe: `A compose unit is enabled`                                                                                                                          |
| The compose probe is real                                                             | the start of the probe instance taken out                       | verify, compose probe: `The probe instance did not start`                                                                                                                   |
| The firewall chains are read back                                                     | the read-back task replaced by a no-op                          | verify, chain: `The role did not notice that the chains had been flushed`                                                                                                   |
| A flushed chain is repaired once                                                      | the restart in the rescue taken out                             | verify, chain: the second read-back fails with the module's `established accept is missing`                                                                                 |
| The read-back waits only for a pending apply                                          | the skip condition taken off the read-back                      | check-fresh: `cannot read the policy program`, because the fresh host has none                                                                                              |
| The read-back runs in check mode on a configured host                                 | `not ansible_check_mode` added to the read-back's condition     | check-configured: `EXPECTED A FAILURE, GOT NONE: check mode on a configured host with a rule missing`                                                                       |
| The variant is the role's expectation, read from its input                            | the variant written into the read-back                          | verify, protected phase: `the database accept is missing`                                                                                                                   |
| An app host must name its variant                                                     | the variant assertion taken out                                 | verify, interface: `WRONG FAILURE for app host with no variant`, failing at the read-back                                                                                   |
| The host class is required, with no default                                           | `required: true` taken off the class                            | verify, interface: `WRONG FAILURE for no host class`, failing at the role's own assertion and not the argument spec                                                         |
| Docker's return stays last in `DOCKER-USER`                                           | the return left out of the chain reset                          | verify, chain: `DOCKER-USER does not end in the return`                                                                                                                     |
| The policy unit follows a restart of Docker                                           | `PartOf=docker.service` taken out of the unit in the one home   | verify, Docker restart: `The policy unit did not follow a restart of docker.service`                                                                                        |
| Every rule of the chain table is expected                                             | one row (the metadata drop) taken out of the module             | the module's unit tests: every case of the standard and protected chains                                                                                                    |
| A rule of the wrong variant is refused                                                | the forbidden-rule loop taken out of the module                 | the module's unit tests: the standard host with the protected drops, the protected host with the database accept                                                            |
| A foreign rule above the last drop is bounded                                         | the bypass test made to accept every rule                       | the module's unit tests: the foreign accept, the return, the unmatched drop, the goto and the unlisted chain                                                                |
| The rule named as displaced is the one that moved                                     | the module made to name the rule after it                       | the module's unit tests: `the_rule_named_is_the_one_that_moved_not_the_one_after_it`                                                                                        |
| The sudoers line agrees with the cloud-init constant                                  | the wrapper path changed in the cloud-init source               | the repository checks: `test_the_real_files_agree`                                                                                                                          |
| The role and the hand scripts install the same modes                                  | the wrapper's mode changed in the role                          | the repository checks: `test_the_role_and_the_hand_scripts_install_the_same_paths_and_modes`                                                                                |
| A program has one home and the role holds none                                        | a byte copy of a program put under the role                     | the repository checks: `test_every_program_is_read_from_the_one_home_and_none_is_held`                                                                                      |
| One role owns the policy program                                                      | a second role given a copy                                      | the repository checks: `test_the_real_tree_has_one_owner`                                                                                                                   |
| No second role reads a program from its home                                          | a second role's task given `src` under `hetzner/provision`      | the repository checks: `test_a_second_role_reading_a_program_by_path_is_found`                                                                                              |
| No second role names a path this role installs, by any key                            | the match narrowed to a `dest` key again                        | the repository checks: the `path`, `name`, `lineinfile`, free-form, shell and argument-list cases, and the playbook cases                                                   |
| A path set in any file under `vars/` or `defaults/` is read                           | the variables read from `main.yml` only                         | the repository checks: the sibling `vars/other.yml` and `defaults/extra/paths.yml` cases, and the program read through one                                                  |
| A path is compared in its one normal spelling                                         | `posixpath.normpath` taken out of the match                     | the repository checks: the `//`, `/./`, `x/../`, shell-string, variable, `name` and program-path respelling cases                                                           |
| A role may run the wrapper but not write it                                           | the run exemption taken out (or made to accept shell syntax)    | the repository checks: `test_a_role_that_only_runs_the_wrapper_or_writes_its_own_paths_is_not_found`, and the `&&` case                                                     |
| The second role is exempt for the policy files only                                   | the exemption made to cover the whole role                      | the repository checks: the wrapper's copy, read and path under the allowed role                                                                                             |
| The programs are those the role's target lists name                                   | the four names written into the check again                     | the repository checks: `test_a_program_added_to_the_target_lists_is_covered_with_no_edit_here`                                                                              |
| The probe check reads every shape the contract scan reads                             | the slot shape left out of the contract scan's list             | the repository checks: `test_a_name_the_wrapper_accepts_is_found_in_every_shape`                                                                                            |
| Nothing is written into a directory the run refuses                                   | a copy of the wrapper put before the directory checks           | verify, parent directories: `A run that refused the directory had already written`                                                                                          |
| ... and every directory above it is checked as well                                   | the path taken to the immediate directory only                  | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory above the one that holds the wrapper`                                                                  |
| The compose probe can never be a stack                                                | the probe renamed to a name the deploy wrapper accepts          | the repository checks: `test_a_name_the_wrapper_accepts_is_found_in_every_shape`; the compose unit contract test                                                            |
| A failure prints no text of a foreign rule                                            | the rule's text put back into the bypass message                | the module's unit tests and verify, chain: the whole message of the bypass is matched                                                                                       |
| `FORWARD` reaches `DOCKER-USER` first                                                 | the `FORWARD` check taken out of the module                     | the module's unit tests; verify, chain: `an accept above the jump to DOCKER-USER`                                                                                           |
| A directory that holds a target is owned by root                                      | the owner assertion taken out of the directory check            | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory that holds the wrapper owned by another account`                                                       |
| ... and no account can write to it                                                    | the other-writable assertion taken out                          | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory that holds the wrapper writable by any account`                                                        |
| ... and no group can write to it, whichever group it is                               | the group-write assertion taken out                             | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory that holds the wrapper owned by root:staff and writable by the group`; the same for `root:root` `0775` |
| ... and it carries no extended ACL                                                    | the ACL assertion taken out                                     | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory that holds the wrapper with an ACL its mode bits do not show`                                          |
| A target carries no extended ACL                                                      | the ACL check taken out of the target loop                      | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: wrapper with a write ACL for an account`                                                                         |
| ... and a link in the path is refused, never followed                                 | the link assertion taken out of the directory check             | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: directory that holds the wrapper is a link to a directory that is root's own`                                    |
| `/etc/sudoers.d` is on the path of the drop-in, and no group can write to it          | the sudoers term taken out of the path list in `tasks/main.yml` | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: sudoers drop-in directory owned by root:staff and writable by the group`                                         |
| `/etc/systemd/system` is on the path of the policy unit, and no group can write to it | the group-write assertion taken out                             | verify, parent directories: `EXPECTED A FAILURE, GOT NONE: unit directory writable by its group`                                                                            |

Two limits of this table. The check-mode rows run the role under the real `--check` flag:
the magic variable `ansible_check_mode` is set by that flag alone, so a case that runs the
role from a verify task with the `check_mode` keyword cannot show them. The converge
playbook runs the case itself when it is run under `--check` on a host that is already
configured. The sabotages were run in throwaway copies of the role, so the working tree
stayed clean; the harness run that follows them is the green.

## Named limits

- **The foreign-chain allow-list is empty and has never met a real host.** It is for a
  brute-force blocker that re-inserts a jump to its own chain at the top of `INPUT` or
  `DOCKER-USER`; its chain name is not known until it is read from a real app host. The
  gateway has no read-back, so nothing here exercised the list against a real host.
  Capturing the real `iptables -S INPUT` and `iptables -S DOCKER-USER` (and the IPv6
  pair) from an app host with the policy applied is a precondition of wiring the app
  hosts; until then a jump to any other chain above the policy's drops is refused.
  Two things about the list are known and are not fixed here, because they need a real
  chain to be right. A jump is accepted only when it has no match module beyond conntrack,
  tcp and udp, so a brute-force blocker's `-p tcp -m multiport --dports ... -j <chain>`
  is refused even when its chain is listed (the role fails closed on such a host). And the
  chain a listed jump goes to is not read, so a rule inside it that accepts would pass.
  Both are in the acceptance criteria of the ticket that wires the app hosts, with a
  captured real chain as the fixture the fix is tested against.
- **The single-owner check has limits.** It finds, in another role or a playbook, a link to
  or a byte copy of a program; a string in its tasks, handlers, variables or defaults that
  is a program's file name or a path under `hetzner/provision/`; and a string, under any
  key, that is or contains a path this role installs (a `dest`, `path`, `name` or `src`, a
  free-form `dest=...`, a shell string, an argument). The programs and paths are those the
  role's own target lists name. A command that only runs the wrapper (an argument list or
  a plain command string whose program is the wrapper, behind `sudo` and its options) is a
  use and is not found; a shell string with any shell syntax is not trusted to be one. A
  task title is a label: only a `name` that is the path alone counts. A variable is filled
  in from every YAML file under the role's own `vars/` and `defaults/` (at any depth), the
  inventory's group and host variables and a play's `vars`; a path set only there is read
  where it is used. Every path-shaped word is compared after `posixpath.normpath`, so a
  `//`, a `/./` or an `x/../` in it does not hide it. It does not resolve a value set by
  `set_fact`, by `register`, or by `include_vars` of a file outside the role's `vars/` and
  `defaults/`; a variable that holds such a value stays as its raw text and matches
  nothing. A path assembled in a loop from separate parts, a variable set by the host's
  own facts or by a file outside the tree, and a task file that includes a template which
  writes it are not seen by the path rules either; the byte-copy rule still sees a copy.
  The check is a floor, not a proof that no second writer exists. Fixtures under a role's
  `molecule/` stand in for a host and are not read. The one allowed second role is exempt
  for the policy program and its unit only, not for the wrapper or the compose unit, and is
  retired by its own follow-up after this role has run live. Three shapes are also not
  seen: a Jinja `~` join inside one string (`'/usr/local' ~ '/sbin/branchleft-deploy'`), a
  directory `dest` with the program named only in `src` or a loop item, and a shell
  `cd /usr/local/sbin && cp x branchleft-deploy`.
- **The directory checks refuse; they do not repair.** A directory that fails them is
  somebody else's to change. The rule is the strict shape described under "What it changes
  on a host": root-owned, no extended ACL, no group-write and no other-write bit, and no
  link anywhere on the path. It is a check of the mode bits and of `getfacl`'s extended
  entries as they stand when the role runs, and nothing more: it does not read the group
  database, an account's groups, file attributes (`chattr`), a mount's options, or any
  other mandatory access control, and it does not look at the other ancestors of a
  directory that is reached through a link, because a link is refused. A `/usr/local/sbin`
  that is `root:staff` and group-writable, as a host with `/etc/staff-group-for-usr-local`
  gets, is refused until it is made `root:root` `0755`.
- **The Docker-daemon restart is tested against a stub.** The test restarts a stub
  `docker.service` and shows the policy unit restarted with it and the chain intact,
  which proves the unit follows that service. It does not prove the same for a real Docker
  daemon, which rebuilds the chain itself.
- **The test host is not the real estate.** The container holds the real firewall tools,
  the real program and the real unit, but one machine type (arm64 Docker Desktop on the
  author's machine, amd64 in CI); the `ip` output is a stand-in; Docker is a stub; and the
  address that makes a host the gateway, or the control-plane host, is a file the test
  writes.
- **The role has not been applied to a host.** The gateway's apply is waiting on the gated
  workflow being available for this repository, and app1's playbook now applies it but no
  gated run has applied it yet. The ticket is unfinished on both halves until each has run
  live and a second run of the same commit has reported no change.
- **The unit tests of the module read the real program.** They parse
  `hetzner/provision/branchleft_docker_user_policy.sh` itself, so a change to a literal in
  the program changes what the module expects; they do not pin a copy of it.

## Clauses this role exercises

ANS-2 (a typed module in `library/`), ANS-7 (argument specs), ANS-9 (a module before a
command), ANS-10 (check mode and what is skipped in it), ANS-11 (a second run changes
nothing), ANS-12 (one role, one reason to change), ANS-14 (this order), ANS-15 (the test
runs in a container only), ANS-16 (nothing is a secret) and ANS-17 (delivery through the
gated workflow only).
