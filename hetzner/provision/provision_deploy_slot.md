# provision_deploy_slot.py

Narrative moved out of `provision_deploy_slot.py` under the CMT-3 gate (a comment block of 25 lines
or more fails). The program's docstring keeps its first line, which `--help` shows, the usage, and a
pointer to this file.

## Module overview

Idempotent grant of one deploy slot: a key that can restart one stack only.

Run by hand on the app host itself (as root, once per stack whose repository deploys to this host,
before that repository's first deploy):

```
provision_deploy_slot.py --public-key-file blog.pub blog
provision_deploy_slot.py --revoke blog
provision_deploy_slot.py --list-slots
```

The problem it solves is not argument validation. `branchleft-deploy` already refuses a malformed
stack name; what it cannot do in its unscoped form is refuse a _well-formed_ one belonging to
somebody else, because the caller is the one who names it. On a host running one stack that
distinction is invisible. On a host running N tenants it is the whole boundary: one deploy key shared
by N repositories means any one of those repositories can pin an arbitrary image into any other's
Compose slot and restart it, which is complete takeover of that tenant's site by a credential that
was only ever meant to redeploy its own.

**The binding is the forced command, and the reason is that it removes the name rather than checking
it.** The stack name is written into the `command=` of the authorized_keys entry, in this file, as
root. sshd then executes exactly that command whatever the client asked for, so a slot key's entire
capability is `branchleft-deploy --slot <its own stack>` with one image reference on stdin. There is
no caller-supplied stack name anywhere on the path, and therefore nothing for any later code to
validate correctly.

The alternative shape -- one shared account, and the wrapper deciding from which key authenticated --
is not impossible. sshd can be told to expose the authenticating credential. `ExposeAuthInfo` writes
the accepted key to a file named by `SSH_USER_AUTH`, and `AuthorizedKeysCommand` receives the key's
fingerprint as `%f`. Both are server-side and neither is writable by the account. It loses on a
different property: every such design still has to compare a caller-supplied stack name against an
identity, correctly, on every future edit of that comparison -- and a mistake there is silent,
because a wrong comparison still deploys something. A forced command has no comparison to get wrong.
(`environment=` in authorized_keys is a third option and a bad one: it needs `PermitUserEnvironment`,
which also lets anything holding this account set `BASH_ENV` for the non-interactive shell every
forced command runs under.)

## Five properties this script exists to hold

None of them is recoverable by hand afterwards.

1. **One key holds at most one slot.** sshd returns on the _first_ matching authorized_keys line, so
   a public key installed against two slots always resolves to whichever renders first -- giving the
   second slot's repository arbitrary code execution inside the first slot's container, which is the
   exact primitive this file exists to remove. Granting a slot the _host-level_ key is the sharper
   form: the unmanaged line renders first, so that slot keeps host-wide reach while looking correctly
   scoped in the register. Refused here rather than left to operator discipline, because the
   fingerprints needed to detect it are already computed.

2. **The caller's key comment never reaches the file.** Only the key type and its base64 blob are
   re-emitted; whatever trailed them is discarded. The comment field is free text ending at a
   newline, and this file's lines are `restrict,command="..."` -- so a comment carrying a quote closes
   the forced command, and one carrying a newline appends an entry with no forced command at all,
   which is a shell on the deploy account. Discarding the field is cheaper than escaping it and
   leaves nothing to escape.

3. **authorized_keys is rendered from the register, and reconciled against it before every write.**
   The register is `/etc/branchleft/deploy-slots/<stack>.pub`, root-owned `0700` directory, `0600`
   files. `reconcile()` is the single arbiter of whether the file and the register agree, and grant,
   revoke and the audit path all call it -- a marked line the register cannot explain stops the run
   rather than being silently dropped by the re-render. That mattered: the marker is a plain last
   field, so an unmanaged key whose comment happened to end in one would otherwise have been deleted
   by the next grant, and on this estate that is the host-level key the marketing site deploys
   through.

4. **The deploy account cannot write anything in its own home.** Ownership of the home, `.ssh`,
   `authorized_keys` and **every file beneath them** moves to root. Unlink permission comes from the
   containing directory, so leaving the home owned by `deploy` leaves an account that can delete
   authorized_keys and write a replacement -- and every restriction in this design is a line in that
   file. The recursion is not tidiness either: sshd runs a forced command through `$SHELL -c`, this
   account's shell is bash, and Debian builds bash with `SSH_SOURCE_BASHRC`, so `~/.bashrc` is
   sourced for exactly that session type. A writable dotfile runs ahead of every slot key's forced
   command. It also closes `~/.ssh/authorized_keys2`, which sshd's default `AuthorizedKeysFile` still
   includes.

5. **A slug that names a stack already on this host is refused** unless the operator says otherwise
   with `--adopt-existing-stack`. A hardcoded reserved list was rejected: `RESERVED_STACK_NAMES`
   lives in `branchLeft/ghost-platform` and a copy here is cross-repo drift waiting to happen, where
   the copy going stale fails open. The host's own `/opt/branchleft` is the fact that matters and
   cannot drift from itself. A tenant being onboarded has no stack directory yet, so the normal path
   never sees this; granting a slot on `website` does, which is the case worth stopping.

## What a slot does not carry with it

The forced command bounds which stack the key may restart. It says nothing about whether that
stack's Compose file declares a health signal, and the unit template's `--wait` is a rollback signal
only for a service that does -- without one it waits for _running_, which a crash-looping container
transiently is. Every stack reached through a slot has its Compose file in the repository being
granted the slot, or has it rendered by the tooling that builds that repository, so nothing here
reads it. The register in `test_compose_unit_contract.py` records which instances that leaves
unchecked, and by whom.

## Residual, stated rather than implied

The `deploy` account's sudoers grant still names `/usr/local/sbin/branchleft-deploy` with no argument
restriction. Nothing reaches it through this account today, so the forced command is not currently
the only layer by necessity -- it is the only layer because the broader grant has not yet been
withdrawn. Withdrawing it is tracked as its own item.

## Exit codes

0 on success, 1 on any refusal or failure, 2 on usage error.

## The plan's diff of this file

The program is copied whole by the `deploy_slot_keys` role, so its text appears in the plan's diff
and is read by the plan's secret scan. No line of it may read as a credential assignment to that
scan (a secret word, then a colon or equals sign, then a value), or the plan of the host is
withheld. `ansible/checks/test_plan_diff_scan.py` scans this file and fails if one does; reword the
sentence rather than hiding the diff.
