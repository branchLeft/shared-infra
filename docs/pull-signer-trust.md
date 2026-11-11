# Pull signer trust: threat model and the design of signing releases ourselves

Audience: maintainers and reviewers of the signed pull route (`pull_trigger`, the trust files, the delivery workflow), people and agents. Drafted by an agent. A person reviews it before it merges, and the security review is a deep one.

This document is the design. It changes no trust file, role, check or workflow. Every build step it names is a separate pull request.

## Summary

Eight hosts apply a commit of `main` as root when that commit carries a signature from a key in their trust file (`ansible/trust/HOST.yml`). Every one of the eight lists the same key: GitHub's `web-flow` key, which signs every squash merge, web edit and merge-queue commit GitHub makes.

That signature proves "GitHub made this commit". It does not prove who asked for it, who reviewed it, or that a person released it. In practice the trust is "whatever reaches `main`", and the protection of `main` is the protection of every host.

The recommendation is a release tag signed with a dedicated hardware key held by the owner. A host applies a commit only if an annotated tag `release/*` signed by a listed release key points at exactly that commit. The tag is required in every mode the program has (apply, check and step), because check and step modes run the commit's content as root too (T2). Agents keep merging, reviewing and queueing as now. The owner becomes the release step: one command, a PIN and a touch.

Decided already: the four hosts (edge1, ops1, app1, db1) trust hardware-signed releases, built after the 14 Nov go-live as separate items, each an owner merge, with a spike first to check that the Mac can use a security key. The spend on tokens is decided later. Open items for the owner are in "Decisions still open".

## Facts this design rests on

Observed in the repository, the live ruleset or GitHub's published data. Anything not observed is marked "believed" and has a check that would prove it.

### How a host decides today

`pull-trigger` runs as root and receives one commit id from the CI job. It then:

1. fetches `main` only, with no tags, over read-only HTTPS;
2. refuses the commit unless it is an ancestor of the fetched tip of `main`;
3. refuses a commit older than the last one applied (the rollback floor);
4. checks the commit's signature against the host's signer list, comparing the signing key's fingerprint as well as git's verdict;
5. checks out exactly that commit and runs the host's playbook as root.

The program has three modes: `apply`, `check` and `step` (a routine step of a role that the playbook keeps behind the `never` tag, on a key of its own). All three go through one admission path, so steps 1 to 4 are the same for each. Check mode then runs the playbook with `--check --diff`; step mode runs it with only the step's tag, and tasks tagged `always` still run.

### Hosts and trust files

| Trust file | Route                  | Notes                                                                                                                         |
| ---------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `edge1`    | pull                   | The estate's gateway and the jump hop to the private hosts. A refusal here stops delivery to the hosts behind it.             |
| `ops1`     | pull                   | Covered by the owner's ruling.                                                                                                |
| `app1`     | pull                   | Covered by the owner's ruling.                                                                                                |
| `db1`      | pull                   | Covered by the owner's ruling.                                                                                                |
| `dbt1`     | pull                   | The tenants project's database host. Not named in the ruling; its file says it follows every other host.                      |
| `appt1`    | pull                   | The tenants project's app host. Not named in the ruling; its file says it follows every other host.                           |
| `edget`    | pull                   | The tenants project's base host, reached from edge1 only. Not named in the ruling; its file says it follows every other host. |
| `demo1`    | push (bundle on stdin) | Has no `main` to compare with, so step 2 does not exist there. Its limit is named in the role README ("Push receiver").       |

The design treats all eight as one estate. The ruling names four. That the other four follow is recommended and needs the owner's confirmation (D3).

### The signature key

- Current key: OpenPGP `968479A1AFF927E37D1A566BB5690EEEBB952194`, created January 2024. The published key carries no expiry date.
- The previous key expired in January 2024 and is deliberately not listed.
- Every commit on `main` at the time of writing, except the root commit, was committed by GitHub with a valid signature.

### The protection of `main`

The ruleset on the default branch is active, with no bypass actors. It requires: deletion and non-fast-forward blocked, linear history, signed commits, a pull request with one approval, code-owner review, last-push approval and dismissal of stale reviews, squash merges only, the listed status checks, and a merge queue. Not read: organisation-level rulesets and the membership of the owner team.

`.github/CODEOWNERS` gives the owner these paths: `ansible/trust/`, `ansible/roles/pull_trigger/`, `ansible_runtime`, `host_inputs`, `ci_login`, `ci_jump`, `deploy_slot_keys`, other credential roles, `ansible/checks/`, `ansible/harness/` and `.github/`. It does not give the owner the other roles, although every role runs as root.

### The delivery

`ansible-delivery.yml` runs on a push to `main`. Its plan job asks every host for a check-mode run of that commit with a check key, then the apply job waits on the `ansible-hosts` environment (deployment branches: `main` only) and asks every host to apply the same commit with an apply key. The check keys are repository secrets. The apply keys are environment secrets, released only to the job that has passed the environment.

Who answers the environment is a setting that changes. The workspace registry records that an automated reviewer account answers it inside stated conditions and that the required-reviewers rule was taken off. A read-only API read of the environment while revising this document listed a required-reviewers rule naming the owner team, and a custom branch policy. The two disagree and the live setting is what counts; the workflow header also says the reviewer is one user, no team, and `check_delivery.py` should be asked why it passes. This design assumes the weaker case, an automated answer inside stated conditions with no person asked on each run.

## Assets

| Asset                                         | Why it matters                                                                             |
| --------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Root on each host                             | Includes every secret the host holds (host inputs, credentials of the roles) and its data. |
| The estate gateway (edge1)                    | The one route to the private hosts. Root there reaches the second hop.                     |
| The signer list in each trust file            | Whoever rewrites it chooses who may run code as root next, which is persistence.           |
| The rollback floor and the cache on each host | They decide which commit may run; they are root-owned state.                               |
| The release signing keys (new)                | Whoever holds one can release any commit on `main` that is newer than the floor.           |
| The CI keys (check, apply, jump)              | They reach the forced command; bounded by what the host verifies.                          |
| Delivery availability                         | A fail-closed host is safe and also stuck; recovery is by hand as root.                    |

## Actors

| Actor                                          | Capability that matters here                                                                                     |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Owner account                                  | Merges owner-only paths, edits rulesets, CODEOWNERS and environments, approves deployments.                      |
| Agent App                                      | Raises pull requests and merges them through the queue on the reviewer App's approval, outside owner-only paths. |
| Reviewer App                                   | Approves pull requests and, inside stated conditions, answers the `ansible-hosts` environment.                   |
| Anyone with write access to the repository     | Pushes branches, workflows and tags. A workflow on a branch can read repository secrets.                         |
| Dependency suppliers                           | Reach the hosts through merged lockfile bumps and the packages the roles install.                                |
| GitHub (platform, staff, breach)               | Serves `main` and holds the `web-flow` private key.                                                              |
| The network path to GitHub                     | A TLS or DNS failure between the host and GitHub.                                                                |
| Whoever holds the owner's workstation or token | New with this design; see T9 and T10.                                                                            |

An attacker who already has root on a host, or who can write the host's root-owned configuration, is out of scope: no signature design helps.

## What the `web-flow` signature lets an attacker do

GitHub signs with this key every commit it creates: squash and rebase merges, merge-queue commits, edits in the web editor and, believed and unproved, commits it creates for an App through the contents API (check C13). The key therefore signs commits on any branch, not only `main`. A commit signed by `web-flow` says nothing about review.

What stops a `web-flow`-signed commit from running as root today is steps 2 and 3 of the host's decision, which are not signature checks:

- On the six pulled hosts a commit that is not an ancestor of `main` is refused, so a signed commit on a branch or a fork pull request's merge ref is refused. The signature adds nothing there.
- On demo1 there is no ancestor test. A commit made in the web editor on a branch that descends from the floor is accepted by the host if the CI job sends it. What stops that is the CI key, not the signature.
- Everything that is on `main` and newer than the floor is accepted, whoever merged it and whether or not a person has seen it.

The signature has real value in exactly one case: the host fetches `main` over HTTPS, so a forged `main` served through a TLS or DNS failure fails the signature check. That is also the case a release tag covers.

## Threats, ranked

Rank is the order in which to close them: likelihood of the route being used, then reach. "After" means after the release-tag design is enforced on every host.

| Rank | Id  | Threat                                                                                                                                                                                                                                                     | Control today                                                                                                                                              | Stopped by `web-flow` trust? | Control after                                                                                                                                 | Checks   |
| ---- | --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| 1    | T1  | A malicious change is merged outside owner-only paths (a prompt-injected agent, a bad dependency bump, a role that carries a task run as root) and is delivered.                                                                                           | One review round, queue checks, the approval conditions. Owner-only paths cover a subset of the roles.                                                     | No                           | The owner reads what a release contains and signs it. An unreleased merge reaches no host.                                                    | C1 C6 C7 |
| 2    | T2  | The plan job runs the merged commit in check mode as root on every host at merge time, before any gate. Lookups, templates and tasks marked `check_mode: false` execute in check mode. Conditions that hold back an apply (credential roles) do not apply. | Merge control only.                                                                                                                                        | No                           | Check mode requires the release tag too. The plan runs after the owner signs, not before.                                                     | C6 C7    |
| 3    | T3  | The agent App's credential is stolen: the attacker merges and the reviewer path approves.                                                                                                                                                                  | Both Apps' keys are held where the agents run; the registry's conditions narrow the apply.                                                                 | No                           | The attacker cannot produce a release signature. Their merges wait for the next release the owner reads.                                      | C6 C7    |
| 4    | T4  | GitHub rotates the `web-flow` key. Hosts fail closed, and the fix commit is signed by the new key, so it is refused. Recovery is a by-hand edit on each host.                                                                                              | None; the previous key was left off on purpose.                                                                                                            | Causes it                    | Applying no longer depends on GitHub's key. A release is signed by the owner's keys, rotated by a release.                                    | C6 C9    |
| 5    | T5  | The owner's GitHub account or session is compromised: merge anything, edit rulesets, CODEOWNERS, the environment and the trust files.                                                                                                                      | Nothing outside GitHub is asked.                                                                                                                           | No                           | Root still needs the hardware key, a PIN and a touch. The attacker can stop delivery, not take over a host.                                   | C6 C9    |
| 6    | T6  | Anyone with write access runs a workflow from a branch that reads the repository secrets, including the check keys, and asks any host to check any commit of `main` newer than the floor.                                                                  | The host's checks bound the commit to one already on `main`, so this repeats content the push-time plan already ran: repeat runs and timing, not new code. | No                           | Check mode refuses an untagged commit. Interim: a build item (see "Interim for T6").                                                          | C7 C12   |
| 7    | T7  | GitHub itself (a breach of the signing service, an insider, a forged `main`) signs and serves any history.                                                                                                                                                 | None; the signature and the history have the same source.                                                                                                  | No                           | The release signature is independent of GitHub.                                                                                               | C6       |
| 8    | T8  | demo1 accepts a signed commit that is not on `main`.                                                                                                                                                                                                       | The CI key, the floor, the playbook allowlist.                                                                                                             | No                           | The bundle carries the tag, and the receiver requires it. That removes the named limit.                                                       | C6 C11   |
| 9    | T9  | A release key is lost or stolen (new with this design).                                                                                                                                                                                                    | n/a                                                                                                                                                        | n/a                          | Two keys on every host from the first day; PIN and touch; rotation and loss procedure below.                                                  | C4 C5    |
| 10   | T10 | The owner's workstation is compromised and the owner is induced to sign a different commit than the one shown (new). A token has no display, so it cannot show what it signs.                                                                              | n/a                                                                                                                                                        | n/a                          | The release tool prints the commit and the manifest, signing needs a touch, and the host log names the applied commit. Residual: named below. | C5       |
| 11   | T11 | A tag signed for another purpose, or an old valid tag, is replayed as a release (new).                                                                                                                                                                     | n/a                                                                                                                                                        | n/a                          | A dedicated key, a fixed name prefix inside the signed text, object checks, the floor.                                                        | C6       |

Two points from the ranking:

- T2 is not hypothetical bookkeeping. The registry holds back an apply that touches credential roles, sudoers or mail. A merged change to such a role still runs in check mode on every host at merge time, because the plan job asks first. Closing T2 is why the tag is required in check mode too, and why a host plan runs after the signature, not before it. Whether check mode really executes a lookup is believed from Ansible's documented behaviour and is proved by check C7.
- Step mode (`--mode step`) is the third path to root from a signed commit. It is owner-dispatched under a protected environment today, which makes it unlikely rather than closed: it passes the same signature check, then runs the commit's playbook with a step's tag as root. Without the tag it would stay on the GitHub signature after every other mode was enforced, so the tag is required in step mode too.
- Apply-time protection (the environment, the approval conditions, the merge queue) stays. It is the control for availability and for a bad release; the signature is the control for who may cause a root-run pull.

## Options for signing as ourselves

Cost is the owner's attention per release. A release is one go to the hosts and may cover every merge since the last.

The design round started from four options (an owner or release-key tag, commits re-signed in CI, merge commits signed locally by the owner, and GitHub's signing for Apps). Each is mapped below as "issue option 1" to "issue option 4".

| Option                                                | Idea                                                                                             | Defends against                                      | Owner attention                           | Spend                         | Verdict              |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------- | ----------------------------------------- | ----------------------------- | -------------------- |
| A. Keep `web-flow` trust, hardened                    | Status quo; list two GitHub keys so a rotation does not strand the hosts.                        | Only a forged `main` fetch.                          | None added.                               | None                          | Fallback only        |
| B. Release tag, hardware key held by the owner        | The host requires an annotated tag signed by a key on the owner's token. Issue option 1 (owner). | T1 to T8, T11.                                       | Per release: one command, a PIN, a touch. | Two tokens, the owner's       | **Recommended**      |
| C. Release tag, online key (CI secret or signer host) | Issue option 1 (dedicated release key) and option 2 in their only workable form.                 | Only a commit that never passed the signer's checks. | None per release.                         | CI secret free; host is spend | Rejected             |
| D. Re-sign commits in CI                              | Issue option 2 as written.                                                                       | Nothing.                                             | None.                                     | None                          | Rejected, structural |
| E. Owner signs merge commits locally                  | Issue option 3.                                                                                  | Same as B, but per merge.                            | Per merge. Agents can no longer merge.    | Tokens                        | Rejected             |
| F. GitHub signs for Apps                              | Issue option 4: commits an App makes through the API.                                            | Nothing new.                                         | None.                                     | None                          | Rejected             |
| G. Sigstore keyless                                   | Short-lived certificates tied to a login.                                                        | A stolen long-lived key.                             | Per release, or none.                     | Public service free           | Rejected             |

Why each rejection:

- **C. An online key.** A key in a CI secret is exposed to the same actors as the apply keys, and a signer host that decides from the GitHub API is defeated by the compromises that defeat A. It adds a key and a system without independence from GitHub or the account. A signer host is also a spend (PRIN-3) and must not be one of the deploy targets.
- **D. Re-signing commits.** A commit's signature is inside its hash. A re-signed commit is a different commit, so it is not on `main` and fails the ancestor test. Making it land on `main` needs a bypass actor on the ruleset, which removes the controls the ruleset provides. The only workable form signs a tag, which is C.
- **E. Local merge signing.** `main` accepts only squash merges through the queue with a pull request and a review. Owner-signed merge commits need a bypass actor, or every merge needs the owner. The first removes the review and queue checks for those merges; the second ends agent merging.
- **F. GitHub signing for Apps.** Believed and unproved: GitHub signs these with the same `web-flow` key (check C13). The signer is still GitHub, so the trust set is unchanged.
- **G. Keyless.** The identity is still a login at GitHub or another identity provider, so it is the same trust as A. The public instance's hosting needs checking against the no-US-hyperscaler rule (PRIN-4) before it could be considered. The host would need a verifier that `pull-trigger` does not have (it knows `git`, `gpg` and `ssh-keygen`).

Variant of B not recommended: require the tag only when a diff touches owner-only paths. Roles outside that list run as root too, and check mode (T2) cannot be limited by path.

Variant of B not recommended: require the web-flow commit signature as well as the tag. Once the tag is required, a host also checks the ancestor of `main` and the floor. A stolen release key can then release only commits that are already on `main`, so the second signature adds almost nothing, and it keeps the GitHub rotation lockout (T4).

## Recommended design: B

### What a release is

A release is an annotated, signed tag on a commit of `main`, named `release/` followed by a UTC date and a counter, for example `release/20261114.1`. The tag message carries the release manifest: the merges since the previous release (commit, pull request, merger, approver), the paths each touches with owner-only and credential paths marked, and any change to a lockfile.

### What the host requires

For every mode (`apply`, `check` and `step`), when `pull_trigger_require_release_tag` is true. The requirement sits in the common admission path, before any playbook is chosen, and not in a mode's own branch, so a mode added later is covered or refused, never silently exempt:

1. The earlier steps are unchanged: `main` fetched, the commit an ancestor of `main`, the commit not older than the floor.
2. The host fetches release tags into a private namespace that it empties first, so a withdrawn tag is gone on the next fetch. It drops every ref that is not an annotated tag object pointing at the requested commit with a name in the fixed pattern, then verifies signatures in a fixed order and accepts the first valid one. Verification work is capped at 64 candidates; more than that is its own refusal (`too-many-release-tags`), not a silent truncation, so junk tags cannot crowd a real tag out unseen. A flood of junk tags is a denial of release, not a compromise, and the tag ruleset (below) is what prevents it.
3. A tag is accepted only if all of these hold:
   - the tag object is annotated (`cat-file -t` prints `tag`), and its `object` is the requested commit with `type commit`: a lightweight tag, and a tag of a tag, are refused;
   - the tag name inside the signed text matches `release/` and the fixed pattern, whatever the ref is called, so a signed tag made for another purpose cannot be replayed;
   - the signature is by a key in `pull_trigger_release_signers`, judged by the same fingerprint rule as a commit signature (`judge_signature`) and read from the tag's own signature, not the commit's;
   - a key from `pull_trigger_signers` is never accepted for a tag.
4. The commit signature is not checked on a host in tag mode. Signing no longer depends on GitHub's key.
5. A refusal leaves the host untouched, like every other refusal. The request shape is unchanged: one 40-digit commit id. No caller-typed string is added, and the forced command, the sudoers line and the sender need no change for the host's sake.

A trap for the tests: `git show -s --format=%G?` on a tag object answers for the tag's commit. The tag's signature must be read from the tag, and a test must fail if the commit's signature decides.

### Keys

- **Dedicated.** The release keys sign nothing else. Git uses one signature namespace for commits and tags, so a key that also signs the owner's commits would make every signed tag or commit by that key a release authority.
- **Two keys on every host from the first day.** The primary (K1) is kept on the daily token; the backup (K2) is kept in a different physical place. The host accepts one signature from either (one of two, not two of two): the second key is for loss.
- **Hardware, PIN and touch.** An `ed25519-sk` key on a FIDO2 token created with `verify-required`, or an OpenPGP key on a card. Creating the key with the PIN requirement does not make the host demand it: a client that does not ask for the PIN could sign with a stolen token. So the host must require user verification as well: the allowed-signers line of each release signer carries `verify-required`, and a signature made without it is refused (check C6). Whether `git` passes that option through to `ssh-keygen -Y` as the program builds the line is a spike question. If the host cannot enforce it, the PIN is a property of the token only, and the design records that as a residual risk. `pull-trigger` already accepts `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` public keys and OpenPGP blocks, so the format is chosen by the spike, not by a code change. An OpenPGP key carries an expiry, which the program refuses on (stated in the role README, no test makes such a key yet; check C6 adds one); an SSH key has none.
- **Never usable by an agent.** The registry's grant to cut signed tags as the owner must exclude `release/*`, and the keys are not on any disk an agent reads.

What the Mac supports is not yet known. Observed: the Apple `ssh` here is OpenSSH 9.4p1, lists the `sk-` key types and ships `ssh-sk-helper`. Not observed: a token. Whether it can use one without a third-party provider library is the first spike question.

### CI changes

All are separate pull requests and several are owner-only settings.

- **First, the tag ruleset.** It limits creating, updating and deleting `release/*` to the owner. It must exist before the trigger and the environment tag policy, because a tag trigger runs the workflow file from the tagged commit: without the ruleset, anyone with write access could push a `release/` tag on a crafted commit and have it wait on the environment. The probe that reads the ruleset (C14) passes before the tag route is declared done.
- Then a `release/*` tag trigger on the delivery workflow, and the `ansible-hosts` environment gains a deployment tag policy `release/*` next to `main`. `check_delivery.py` must accept exactly that and nothing wider.
- Push to `main` keeps lint, Molecule and the offline render, and stops contacting hosts once the route switch is flipped. The host plan and the apply run on the tag. The merge-queue proof for the tagged commit works as now, because it is keyed on the commit.
- The nightly drift check compares the hosts with the latest release tag, not with `main`. Merges after the last release are not drift.
- The ruleset also stops noise, junk-tag crowding and replay of a withdrawn tag; the host would refuse a bogus tag without it.
- CI verifies the tag with the public release keys before it spends a host call. This is advisory; the host decides.

### Interim for T6

Moving the check keys out of the repository secrets is not a settings change. The plan job lives in the reusable workflow in `branchLeft/github-workflows`, and the caller `delivery` job is a reusable-workflow call, which cannot declare an environment. The interim needs a change and a new input in `branchLeft/github-workflows` so that the plan job runs in an environment limited to `main`, a new environment that holds the check keys, and the same change in the drift caller, which also passes the check keys. T6 adds only repeat runs and timing, so this is a build item to schedule, not an urgent fix, and the tag requirement closes it without it.

### Who answers the environment

On a tag run, the owner has just signed. Two ways to answer the environment, an owner decision (D2):

- **Recommended: the owner answers.** One more click per release, from a phone. It adds a second signal that is independent of the key: a stolen key and a pushed tag would otherwise deploy with nobody told. It needs the environment set so that its only gate is the owner (the required-reviewers rule on, the reviewer App's rule off), which ends the App's part in `ansible-hosts`. That reverses the present terms for this route, so it needs its own ruling and registry edit.
- The reviewer App answers tag runs. The App refuses a run that is not on `main`, so this needs the registry row and `ci_deploy_approve.py` to learn tag runs. A stolen key plus write access would then deploy without a person being asked.

### The release card

The owner's release card must show: the commit to be signed in full, the merges since the last release with merger and approver, every path touched with owner-only, credential and lockfile paths marked, and the exact command. The owner types the PIN, checks the commit shown against the card, and touches.

### demo1 and the test hosts

- dbt1 and edget follow the four hosts (D3).
- demo1 joins in a second phase: the sender includes the tag in the bundle and the receiver requires it. A tag-required receiver needs no `main`, which removes the named limit (T8).

## Migration order

Each stage has an exit that is evidence, not a merge, and a way back.

| Stage | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Exit evidence                                                                                                                                                                                                                                                                                    | Way back                                                                                                            |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| 0     | Spike. Make a release key on a token the owner already has or a borrowed one, sign a throwaway tag on a scratch clone, verify it with the program's own verifier on Debian 13. Settle SSH or OpenPGP.                                                                                                                                                                                                                                                                           | A captured real tag signature verifies under the program's code path. The Mac signing command is written down and works.                                                                                                                                                                         | Nothing changed.                                                                                                    |
| 1     | Owner buys two tokens (spend, the owner's). The interim for T6 is a build item, not a setting (see "Interim for T6").                                                                                                                                                                                                                                                                                                                                                           | Tokens in hand.                                                                                                                                                                                                                                                                                  | Move the secrets back.                                                                                              |
| 2     | Program: tag verification, two lists, the flag defaulting to false, observe-only logging to the host log (not to the summary line, which the workflow matches whole). Unit tests, Molecule, sabotage.                                                                                                                                                                                                                                                                           | Merged and delivered under the old trust; every host's configuration unchanged; the new program is installed and dormant.                                                                                                                                                                        | Revert the pull request; the host runs the old program next apply.                                                  |
| 3     | Trust files gain `pull_trigger_release_signers` (two keys) and the flag at `false`. The checks learn the new keys. The proof of possession (C5) passes. The trust README and check README are corrected.                                                                                                                                                                                                                                                                        | Each host's configuration lists both release fingerprints.                                                                                                                                                                                                                                       | Remove the keys; flag was never true.                                                                               |
| 4     | CI tag route added next to the `main` route, with a route switch (a repository variable) the owner sets. While the switch says `main`, a tag run plans only and a push to `main` plans and applies as now. Order inside the stage: the tag ruleset first, then the environment tag policy and the trigger, then the registry edits. A tag trigger runs the workflow file from the tagged commit, so it must not exist before the ruleset does.                                  | The ruleset probe (C14) has passed. A tag run completes the plan on all pulled hosts and applies nothing.                                                                                                                                                                                        | Remove the trigger.                                                                                                 |
| 5     | Observe. The owner signs a release tag on the current `main` tip with K1, and a second tag on the same tip with K2. The tag run's plan reaches each host, which logs whether a valid tag existed for the commit.                                                                                                                                                                                                                                                                | Every pulled host logged a valid tag for the released commit under K1 and another under K2, on the real host, with real keys and the host's own git. K2 is the recovery key, so it is proved on each host before any host depends on either key.                                                 | Delete the tag.                                                                                                     |
| 6     | Enforce, in this order. (a) The owner sets the switch to `tag`: pushes to `main` stop contacting hosts. (b) One pull request sets the flag true in every pulled host file; it merges with no host contact. (c) The owner signs a release on that merge commit; the tag run applies it under the old rule (the tag and the GitHub signature are both valid). (d) The second pass of the same commit runs under the new rule. (e) A one-off check of an unreleased `main` commit. | (d) is clean on every host, and (e) is refused on every host for the missing tag with no playbook run, for a check, an apply and, on a host that has step entries, a step. Before (a): the by-hand recovery runbook exists and the owner has read it through for edge1 and for one private host. | Set the switch to `main` and release a commit with the flag false; if every host refuses, the by-hand edit as root. |
| 7     | demo1 joins: tag in the bundle, receiver requires it.                                                                                                                                                                                                                                                                                                                                                                                                                           | demo1 applies a tagged bundle and refuses an untagged one.                                                                                                                                                                                                                                       | Flag false for demo1.                                                                                               |
| 8     | Retire the commit-signer mode: remove the `web-flow` key and `pull_trigger_signers` from the trust files, the program and the checks, after every host has run in tag mode for a full cycle.                                                                                                                                                                                                                                                                                    | No trust file lists the `web-flow` key; checks pass.                                                                                                                                                                                                                                             | Revert; hosts would need a release to take effect.                                                                  |

Notes on the order:

- All pulled hosts are flipped by one release at stage 6. A delivery run asks every host for the same commit and, unless the caller opts into `skip-failed-hosts`, must plan and apply every host. A mixed estate (some hosts requiring the tag, some not) therefore stops the run. The risk of the single flip is cut by stage 5: tag verification has already worked on each real host before any host depends on it. Sequence (a) before (b) means no push to `main` meets a host that requires the tag.
- edge1 is the jump hop to the private hosts. A refusal there strands delivery to them. This is why stage 5 must pass on edge1 before stage 6, and why the by-hand recovery path must be written and read through beforehand (see "Rotation and loss": the repository does not evidence it today).
- Stage 2 changes a program that runs as root. It is an owner merge and gets the same deep review as the pull role did.

## Rotation and loss

Both keys are on every host from stage 3. No key is ever the only one.

- **Planned rotation.** Make K3 on a new token. A pull request adds K3 to the trust files. Release it, signed by K1. Read back that each host lists K3. Sign the next release with K3 and confirm it applies. Only then a pull request removes K1, released by K3. Destroy K1. Never remove a key in the release that first relies on its replacement.
- **K1 lost.** Sign with K2. Remove K1 by pull request, released with K2. Buy a token and run the planned rotation to get back to two keys.
- **K1 stolen or suspected.** The same, at once, plus one check: compare each host's floor with the last release the owner signed. If a host is past it, treat the range as hostile: revert by pull request and release with K2.
- **K1 and K2 lost.** Every host refuses everything, which is the safe failure. Recovery is the by-hand root path for each host in the private runbook, writing a new key into the configuration. The repository does not evidence that path: the role README's "Taking over by hand" covers a damaged floor and a rewritten `main`, not rewriting the signer list, and the runbook is a build item in a private repository. Writing it, and the owner reading it through, is a precondition of stage 6, and it stays as the last resort. Storing K2 in a different place from K1 makes this unlikely. The place is not written here.
- **GitHub rotates its key.** In tag mode this does not matter to applying.

## What the trust files must say

Public keys only. A trust file holds exactly the keys below (check C2); the names are fixed here so the checks can pin them.

### Before (today, all seven files)

One key, `pull_trigger_signers`, holding the `web-flow` public key, with a comment that says any GitHub-signed commit on `main` is applied as root and that the protection of `main` is the protection of the host. That comment is true and stays true until stage 6.

### During stages 3 to 5

```yaml
pull_trigger_signers:
  - format: openpgp
    key: WEB_FLOW_PUBLIC_KEY_BLOCK
pull_trigger_release_signers:
  - format: ssh
    key: RELEASE_KEY_1_PUBLIC_LINE
  - format: ssh
    key: RELEASE_KEY_2_PUBLIC_LINE
pull_trigger_require_release_tag: false
```

The comment must say: the release keys are listed and not yet required; commits are still trusted by the GitHub signature; the next change sets the flag.

### After stage 6

The same lists with `pull_trigger_require_release_tag: true`. The comment must say, in the file's own words:

- a commit is applied only if an annotated tag `release/*` signed by one of the release keys points at it, in every mode: apply, check and step;
- the commit signature is not checked, and the `web-flow` entry is kept only so that setting the flag back restores the earlier behaviour;
- the protection of `main` is no longer the protection of this host;
- the release keys are the owner's hardware keys, and their custody is in the private runbook.

### After stage 8

`pull_trigger_signers` and the `web-flow` key are gone. The trust file holds `pull_trigger_release_signers` and the flag. demo1 holds the same, with its own limit text removed.

### Text that must change with them

- `ansible/trust/README.md` and `ansible/checks/README.md` say the gated apply is not wired and nothing in the repo calls it. That is already untrue: `ansible-delivery.yml` calls it. Correct both at stage 3.
- The role README's "Named limits" entry on signer key handling and its "Push receiver" limit, at stages 2 and 7, and its "Step requests" section, which says a step passes every check of an apply: it must add the tag.
- The playbook includes: `require_signers.yml` asserts the commit list is non-empty. In tag mode it must assert the release list is non-empty, and the program's configuration check must match, so that an empty release list fails closed.

## Checks and tests that keep it true

Each control needs a recorded red then green by sabotage. Ids are for the pull requests to cite.

| Id  | Check                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Where                                                  | Sabotage that must fail it                                                  |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------------- |
| C1  | A change to a trust file, the program, the delivery workflow, the release tooling or the proof file is an owner merge.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `test_codeowners.py`, CODEOWNERS                       | Remove a CODEOWNERS line.                                                   |
| C2  | Each trust file holds exactly the three keys; the flag is a boolean literal; at least two release keys; fingerprints distinct; none equals a commit-signer key; the release list is identical in every pulled host file.                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `check_enrolment.py` (R5, R6, R8 extend)               | Set a different list in one host; list the `web-flow` key as a release key. |
| C3  | A flag of true with an empty release list is refused by the playbook and by the program, before any task.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Includes, unit test, Molecule                          | Remove the assert.                                                          |
| C4  | Rotation and loss: a unit test applies a tag signed by K2 with K1 absent, refuses a tag signed by a removed key, and refuses a tag signed by an unlisted key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `test_pull_trigger.py`                                 | Accept any listed-or-not key.                                               |
| C5  | Proof of possession: for each listed release key a detached signature over a fixed string is checked against the listed public key. A mistyped or wrong key fails the pull request. The file lives outside `trust/`, whose name rule allows only `HOST.yml`.                                                                                                                                                                                                                                                                                                                                                                                                                      | New check beside `ansible/checks/`                     | Change one character of a listed key.                                       |
| C6  | Verifier table for tags: lightweight; unsigned annotated; signed by an unlisted key; signed by a commit-signer key; pointing at another commit; tag of a tag; name outside `release/` inside the signed text; ref name that differs from the signed name; tag of a commit not on `main`; commit older than the floor; expired or revoked OpenPGP key; tampered message; more than 64 candidates (its own refusal, and a real tag is not displaced by unsigned ones before the cap); a signature made without user verification when the host requires it; withdrawn tag; signature read from the commit instead of the tag. Each refusal leaves the host byte for byte unchanged. | Unit tests and the default Molecule scenario           | Remove each refusal in turn in a copy, as the role does for A1 to A16.      |
| C7  | Check and step modes execute content: a fixture playbook with a lookup that writes a marker shows the marker after an untagged check, and after a step request on a host with a step entry, in observe mode, and shows no marker and a refusal in tag mode.                                                                                                                                                                                                                                                                                                                                                                                                                       | Molecule                                               | Let check mode accept an untagged commit.                                   |
| C8  | The request shape is unchanged for apply, check and step: the hostile-request tables (the step table too) and the random request tests still pass, and no new field exists.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `test_pull_trigger.py`                                 | Accept a trailing token.                                                    |
| C9  | The delivery workflow files: a tag trigger only for `release/*`; no apply on a push to `main` once the route is tag; the drift check compares with the latest release. CI-runnable, as file rules. The environment's tag policy is not a file: it is read by hand with `check_delivery.py environment` from three captured API answers, as that command is run today, and recorded (owner-run).                                                                                                                                                                                                                                                                                   | `check_delivery.py`, `test_drift_caller.py`            | Widen the tag pattern; add an apply on `main`.                              |
| C10 | The host's configuration carries the flag and both key lists: a Molecule test shows the role writes them and that a changed configuration makes a check-mode converge report a change (CI-runnable). That the nightly drift check then shows a hand edit on a real host is a single recorded probe on a test host at stage 6 (owner-run).                                                                                                                                                                                                                                                                                                                                         | Drift check                                            | Edit the configuration on a test host.                                      |
| C11 | demo1: the receiver refuses an untagged bundle and a bundle whose tag is not on its HEAD.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Push scenario                                          | Remove the tag test.                                                        |
| C12 | The check keys cannot be read by a branch workflow (the interim): the plan job names an environment (a workflow-file rule in `check_delivery.py caller`, CI-runnable), and that environment's branch policy is `main` only (read by hand like C9, owner-run).                                                                                                                                                                                                                                                                                                                                                                                                                     | Extension of the environment probe                     | Remove the branch policy.                                                   |
| C13 | Provenance of App-made commits: a scratch commit made by an App through the contents API is signed by the `web-flow` fingerprint. Confirms or reverses the rejection of F. Needs a scratch repository that only the owner can create, so it is owner-run.                                                                                                                                                                                                                                                                                                                                                                                                                         | One-off spike on a scratch repo                        | n/a                                                                         |
| C14 | The ruleset and the tag ruleset match the design: signed commits required, no bypass actors, the tag ruleset restricts `release/*`. The comparison of a captured ruleset answer with a committed expectation is offline-testable; the capture is a live read. A scheduled probe needs a token that can read rulesets, and the workflow token has not been shown to, so until it is, the capture is owner-run, recorded before stage 4 is declared done.                                                                                                                                                                                                                           | A scheduled read-only probe like the environment probe | Remove a rule on a scratch repo.                                            |
| C15 | This document's host table equals the set of trust files; the fingerprint it names equals the one in the files until stage 8.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | A docs test                                            | Add a trust file without a row.                                             |
| C16 | Every mode is covered: a test iterates over the program's `Mode` members and, with the flag true, refuses an untagged commit in each (apply, check, step), leaving the host byte for byte unchanged. A mode added later fails the test until it is covered.                                                                                                                                                                                                                                                                                                                                                                                                                       | `test_pull_trigger.py`, default Molecule scenario      | Skip the tag test in the step branch.                                       |

## Residual risks

- **The owner signs what a compromised workstation shows.** A token has no display. The release tool shows the commit and the manifest, signing needs a touch, the host log names the applied commit, and the release card carries the full commit id. A compromised Mac that swaps the commit before signing is not defeated by any of this.
- **The owner releases a bad diff.** The manifest and the owner-only and credential marking exist to make the touch an informed one. A person can still be wrong.
- **A stolen key plus a ruleset-level compromise.** A stolen key can release only commits already on `main`. If an attacker can also change `main`, the signature does not help; the ruleset and CODEOWNERS are the control there.
- **Root-owned state is trusted.** Anyone who can write the host's configuration as root changes what the host trusts. This is the existing named limit.
- **Availability.** A fail-closed host stays stuck until a person recovers it by hand. That is the intended direction of failure. The cost is that delivery needs the owner's keys.
- **Batching.** Merges wait for a release. The owner chooses the cadence; every release covers every merge since the last.

## Decisions still open

Each decision is readable alone. None is taken by merging this document.

### D1. Which tokens sign releases, and when they are bought

A wrong answer costs money if tokens are bought before the Mac is known to work with them, or a delay if the build waits on a purchase that was not needed.

- Option 1: buy two security tokens now (spend, the owner's), from a European maker.
- Option 2: use tokens the owner already holds, if any, for the spike, and buy after it.
- Recommendation: option 2. The spike (stage 0) decides whether the Mac signs with an SSH security key or needs an OpenPGP card, and the purchase follows from that.

### D2. Who answers the `ansible-hosts` environment on a release tag run

A wrong answer costs either one extra click per release or, the other way, a stolen release key plus write access deploying with nobody told.

- Option 1: the owner answers (the required-reviewers rule on, the reviewer App's rule off for this route). One click per release. This reverses the present terms for the tag route and needs its own ruling and registry edit.
- Option 2: the reviewer App answers tag runs inside stated conditions. Needs the registry row and `ci_deploy_approve.py` to learn tag runs.
- Recommendation: option 1. It is a second signal independent of the key. The live environment was read as listing a required-reviewers rule naming the owner team, which sits closer to option 1 than the registry text suggests; confirm the live setting first.

### D3. Which other hosts follow the four

A wrong answer costs either three hosts left on the weaker trust, or a delivery run that cannot plan every host because some require the tag and some do not.

- Option 1: dbt1 and edget follow the four at the same flip, and demo1 joins in phase two (tag in the bundle).
- Option 2: dbt1 and edget stay on the GitHub signature. Not workable while a delivery run must plan and apply every host: it would need the `skip-failed-hosts` opt-in.
- Option 3: demo1 stays on the GitHub signature, keeping its named limit (a signed commit not on `main`).
- Recommendation: option 1. The files for dbt1 and edget already say they follow every other host, and demo1 has the weakest posture today.

### D4. Release cadence

A wrong answer costs either too many releases to read carefully, or merges that wait too long to reach the hosts.

- Option 1: release on demand, when the owner chooses, covering every merge since the last.
- Option 2: a fixed cadence, such as once a day on working days, with on-demand releases for urgent fixes.
- Recommendation: option 1 to start, and fix a cadence once a few releases show how large a batch is comfortable to read. The design works at any cadence.

## Build items this design implies

Each is a separate pull request. Items marked owner touch an owner-only path.

1. Spike (stage 0) and the App-commit provenance check (C13). No host.
2. `pull_trigger` role: tag verification, flag, observe-only logging, tests, README (owner).
3. Trust files, `check_enrolment.py`, proof file and check, README corrections (owner).
4. Release tool on the workstation: manifest, tag, local verify, push. Python, typed, no new shell.
5. Delivery: tag route and route switch in `ansible-delivery.yml` and the reusable workflow in `branchLeft/github-workflows`; `check_delivery.py`; drift check (owner).
6. Registry (`AUTHORISATIONS.md`): the signed-tag grant excludes `release/*`; the tag route's approval terms (owner).
7. Settings, all the owner's, in this order: tag ruleset, environment tag policy, route switch.
8. Optional interim for T6, a change in `branchLeft/github-workflows` plus a new environment and the drift caller (see "Interim for T6").
9. demo1: sender and receiver (phase two).
10. Private runbook: key ceremony, custody places, rotation, loss and by-hand recovery (a precondition of stage 6).
11. Retire the commit-signer mode.
