# test_compose_unit_contract.py

Every committed Compose stack must agree with the unit template's image pin.

`branchleft-compose@.service` loads `/etc/branchleft/%i.image.env` with no
leading dash, so systemd fails the unit start outright when that file is
absent. Only `branchleft-deploy` writes it, and it refuses to write one for a
stack whose Compose file does not resolve `${IMAGE}`.

Those two rules are each correct and together they are a trap: a stack that
pins its images inline has no writer for a file it cannot start without. The
failure is invisible in review, invisible to `docker compose config`, and
invisible to the config-validation jobs, because none of them load the systemd
unit -- it appears for the first time as a failed `systemctl start` on a real
host, which is where it appeared.

The escape is an instance drop-in resetting `EnvironmentFile=`, which drops the
pin for that instance alone. This asserts the two halves stay consistent, in
both directions: an inline-pinned stack has the reset, and an `${IMAGE}` stack
does not -- a stray reset there would silently disable the mandatory pin, which
is the guarantee the no-leading-dash was chosen for.

The same file holds a second contract, for the same reason: `--wait` is only a
deploy signal for a service that declares a `healthcheck:`. Without one Compose
waits for _running_, which a crash-looping container transiently is, so the
stack reports a clean start in front of it and branchleft-deploy's rollback --
which fires on a non-zero `systemctl restart` and nothing else -- never runs.
That is invisible to `docker compose config` and to the config-validation jobs,
because none of them start a container.

The only way past the assertion below is `IMAGE_PROVIDED_HEALTHCHECK`, which
claims the image carries a probe rather than that none is needed. Excusing a
service outright would mean writing a second register and the tests that
police it, which is a visible decision rather than one more key in a dict
somebody already trusts.

This module's assertion only reaches a stack whose Compose file is committed
in this repository, at test time. `branchleft_deploy.py`'s `deploy()` reads
the same `healthcheck_states()` a second time, at deploy time, for whatever
stack is about to be restarted -- committed here or not, including a stack
this module has never heard of. Its own exemption table,
`KNOWN_UNHEALTHCHECKED_SERVICES`, is what backs a gap this module finds; it
lives beside `deploy()` rather than here because a gap this module cannot see
at all still has to be decided by something that can.

The third contract is the reach of the first two, and it is the one a glob
cannot state. `branchleft-compose@.service` is installed by
30-install-deploy-tooling.sh, which run-all.sh runs on every host role, and
`branchleft-deploy` restarts `branchleft-compose@<stack>` for any stack name.
The template therefore starts instances whose Compose file is committed in a
different repository, and nothing here reads those -- so for them "no assertion
failed" means no file was read at all, which is the opposite of what it means
for a stack this repository commits. `CONTRACT_COVERS` and
`CONTRACT_DOES_NOT_REACH` name both sides, and the scan below refuses to let
this repository write down a stack that is in neither.

Everything here reads the `[Service]` section only, and matches whole stripped
lines. systemd ignores assignments before a section header, so a directive
found anywhere in the file is not a directive systemd applies.

## comment before `CONTRACT_DOES_NOT_REACH: dict[str, str] = {`

The instances the same template starts whose Compose file lives in another
repository, mapped to where that file is. Nothing here reads any of them: a
service in one that declares no health signal reaches a running host with
`--wait` reporting a clean start, and the rollback never fires. Written down
because the alternative is a glob that reads as full coverage of a set it
defines silently -- a reader of the unit template sees `%i` and cannot tell
which instances have been checked and which have not.

This list is a floor, not a census, and the difference is load-bearing. A
stack introduced entirely from another repository -- a tenant slug is the
ordinary case -- is named in no file here, so nothing in this module can
discover it. What the scan below does guarantee is that a stack this
repository _does_ write down cannot stay unclassified.

## walked_files

Every git-tracked file under the tree the scan is allowed to see, before filtering.

    Was an `os.walk`, pruning UNSCANNED_DIRECTORIES as it descended. A
    filesystem walk cannot tell an authored file from one nobody committed:
    `hetzner-host/dist/` is gitignored build output, `git status` stays
    clean after an ordinary `npm run build` fills it with generated
    `.js`/`.map` files, and the walk reported them as native to the tree it
    audits -- there is no suffix that could excuse them here without also
    excusing a hand-authored file of the same suffix.

    `git ls-files` reports exactly what this repository commits, so build
    output -- or any other untracked file -- never reaches the scan.
    `hetzner/test_passphrase_probe_pattern.py`'s `_tracked_scan_files()`
    already made this same choice for the same reason. UNSCANNED_DIRECTORIES
    still applies, filtered by path instead of pruned mid-walk, as a
    defensive check even though none of its names are ever tracked in the
    first place.

    Accepted risk: a file that ought to be scanned but has not yet been
    `git add`ed is invisible here until it is -- the same trade
    `_tracked_scan_files()` already made, preferred over parsing
    `.gitignore` or hand-listing excused suffixes, either of which
    reintroduces the exact drift this test exists to catch.

## stacks_named_in_this_repository

Stack instance names this repository writes down, each with where.

    Carries the files rather than returning bare names so a failure can say
    where the unclassified name came from; a name with nowhere to look is a
    failure whose author has to reproduce the scan by hand before acting on it.

    Drop-in filenames are a source in their own right: `<stack>.override.conf`
    names an instance whether or not any prose mentions it, and a drop-in is
    exactly what a stack from another repository needs if it pins its images
    inline.

## test_an_inline_pinned_stack_resets_the_image_pin_assert

The [Service] EnvironmentFile reset is not enough on its own.

        `branchleft-compose@.service` also carries
        `AssertPathExists=/etc/branchleft/%i.image.env` in [Unit], and systemd
        evaluates asserts before ExecStartPre and before any EnvironmentFile is
        read. So a stack that resets only the EnvironmentFile still cannot
        start: the unit goes inactive with "Assertion failed" and, on a reboot,
        never comes back. Verified live on edge1 on 2026-09-17, where the
        monitoring stack had been unrestartable for days while its containers
        stayed up -- nothing had asked the unit to start.

## test_a_restart_never_tears_the_stack_down_first

No `ExecStop`, so a restart's stop transition executes nothing.

        A `Type=oneshot` unit with no `ExecStop` treats `stop` as marking
        itself inactive and running no command. `branchleft-deploy` restarts
        this unit for every image bump; with an `ExecStop` present, that
        restart's stop half would run `docker compose down` ahead of every
        `ExecStart`, tearing down every container in the stack -- including
        ones the pinned image never touched -- to change one. Its absence is
        what makes a restart a Compose-level rolling replace of only the
        service whose config changed, rather than a full stop/start of the
        whole stack.

## MonitoringForceRecreateTests

`branchLeft/workspace#666`: a bind-mounted config change is invisible to
Compose's own per-service hash, so the template's selective ExecStart
(relied on by `edge`, per branchLeft/shared-infra#171) silently does not
redeploy a rules or scrape-config edit to `monitoring`. `monitoring` has
none of `edge`'s multi-tenant reason to stay selective -- one stack, one
reason to restart -- so its own drop-in overrides ExecStart to force a
recreate every time, the same way it already resets EnvironmentFile= for
a reason specific to this instance.

    This only pins the unit files' *shape*: whether `docker compose up`
    actually gets asked to recreate an unchanged container is systemd and
    Compose runtime behaviour this module cannot exercise without a host,
    same limitation `UnitTemplateAssumptionTests` above already carries for
    `ExecStop`.

## test_the_scan_still_sees_both_sides_of_the_boundary

Otherwise the assertion above passes over an empty scan.

        The covered half is structural: this repository commits those stacks,
        so their names are in its own configuration whatever the prose says.

        The other half is not, and the difference is worth stating rather than
        implying. `website`, `db` and `blog` are named in `hetzner/README.md`
        and nowhere else here, and the README assertion below is what puts two
        of them there -- so this half detects the registers being emptied and
        does not prove the scan can see a mention from outside. Nothing in this
        repository can prove that, which is the same limit as the register being
        a floor rather than a census.
