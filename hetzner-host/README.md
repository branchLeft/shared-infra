# @branchleft/hetzner-host

The Hetzner Cloud VM-create pattern: a server, a role-scoped firewall, a
private-network attachment at a fixed address, and (unless disabled) a pair
of primary IPs.

This package deliberately holds no Pulumi project of its own and creates
nothing at import time — every export is a class, a function or a constant.
The stateful pieces — the private network, and the stacks that call `Host`
to actually build a host — stay in each consuming repository; that split is
what makes this package safe to depend on from more than one place without
each dependent creating its own copy of shared infrastructure.

## Exports

- `Host`, `HostArgs`, `HostRole` — the component and its arguments.
- `EDGE_RULES`, `INTERNAL_RULES` — per-role firewall rule sets.
- `renderCloudInit`, `CloudInitArgs`, `assertDeployPublicKey` — the first-boot
  user-data and the validation that protects it.
- `Enrolment`, `PullBootstrap`, `PullBootstrapFile`, `assertEnrolment`,
  `assertPullBootstrap`, `assertPgpPublicKeyBlock`, `renderEnrolmentScript`,
  `ENROLMENT_PACKAGES`, `PRODUCTION_LAYOUT`, `EnrolmentLayout` — the optional
  enrolment of an edge host into the gated pull, and its validation
  ("Enrolment" below).
- `NETWORK_CIDR`, `SUBNET_CIDR`, `HOST_IPS`, `APP_HOST_IPS`,
  `ESTATE_LOCATION`, `EuCentralLocation`, `EstateLocation` — the shared
  address plan every host and its peers are named from.

## `Host`

`Host` creates a machine outright, rather than importing a hand-provisioned
one and reconciling around it — a different problem from adopting an
existing server, with a different set of `ignoreChanges`. `sshKeys` and
`image` are ignored on the underlying `hcloud.Server` because both are
create-time-only at the provider, regardless of how the server came to
exist.

A public `Host` produces five resources: the server, a role-scoped firewall,
a private-network attachment at its fixed address, and an IPv4 and an IPv6
primary IP of its own. A private-only host (`publicNetworking: false`)
produces two — server and firewall — because its network rides _inline on
the server_ rather than as a separate attachment: with no public interface
and no inline network, Hetzner refuses to start the server at all, and the
separate attachment lands only after creation, which is too late to boot.
The shape is fixed at creation; moving a live host between the two shapes is
not a supported in-place edit, and whether the inline `networks` field is
create-time-only at the provider is unverified — preview any such flip
against a lab host before trusting it. Four
properties are worth knowing before using it:

- **The firewall is declared on the server, not attached afterwards.** An
  attachment applied as a following step leaves a window in which a freshly
  created host is on the public internet with no filter.
- **`userData` is in `ignoreChanges`.** Cloud-init runs once, on first boot,
  so a later edit to the template cannot affect a running host — but the
  provider treats the field as replacing, and without this an edit here
  proposes rebuilding the whole estate for no effect. The consequence: a
  deploy-key rotation cannot go through Pulumi at all on a host this
  component created. It has to be delivered directly to the running host
  (writing `authorized_keys` over SSH, or equivalent) — a consuming stack's
  own provisioning runbook is where that procedure belongs, not this
  package, since it depends on how that stack reaches its hosts.
- **Primary IPs are declared, not allocated.** Left to server creation they
  carry `auto_delete`, so a rebuild releases the address. With HTTP-01
  issuance, an address that changes breaks every hostname until each record
  naming it has been repointed and has propagated, and a mail host's sending
  reputation does not move with it at all.
- **`publicNetworking` is a create-time decision.** Flipping it from `true`
  to `false` on a live host asks Pulumi to delete two delete-protected
  primary IPs, the API refuses, and the stack wedges mid-update. Changing it
  afterwards means applying once with `protection: false` and then again with
  `publicNetworking: false`.

**Lab hosts set `protection: false` and `environment: 'lab'`.** With
protection on, `pulumi destroy` cannot tear a spike down without editing the
component, which turns every throwaway host into manual console cleanup; and
a lab host labelled `env: production` corrupts cost attribution and any
label-selector rule that reads it. Both default to the production values, so
a lab stack has to say so — which is the right way round.

## Cloud-init

**A beachhead, not configuration management.** `renderCloudInit` creates the
deploy account, closes password authentication, and makes the directories the
rest needs. Everything that must _stay_ true belongs in the consuming
repository's own provisioning scripts, which are idempotent and re-runnable.
If you find yourself wanting to add a package or a config file to
`cloudInit.ts`, it almost certainly belongs there instead.

The one validation this package carries, `assertDeployPublicKey`, is the only
control between stack config and a document that grants `deploy` an
`authorized_keys` entry and a sudoers rule: a newline in the value appends
arbitrary cloud-config to it. Three properties make that worth failing closed
over rather than trusting the input — cloud-init runs once and cannot be
re-run, `userData` is create-time-only at the provider, and it is in `Host`'s
`ignoreChanges` — so an injected document is permanent and absent from every
later diff.

## Enrolment

The one exception to "a beachhead, not configuration management": an edge
`Host` given an `enrolment` brings itself under the gated pull at first boot,
so the owner does not install the pull by hand. Without `enrolment` the
document is byte-for-byte what it was before the option existed (held by golden
files in `testdata/`, captured from the code before the change and never
regenerated). With it:

- **No deploy account.** Setting both `enrolment` and `deployPublicKey`, or
  neither, throws before a resource exists. An enrolled host's deploy path is
  the pull; a deploy key beside it would be a second way in with root-equivalent
  reach.
- **Two restricted keys on root.** `applyPublicKey` and `checkPublicKey` (public
  halves only, which must differ) become `authorized_keys` lines of root, each
  restricted to one command of the pull program (`pull-trigger --mode apply` or
  `--mode check`). They are written as `users` entries and not `write_files`, so
  the key the datasource injects for the owner stays. The private halves are the
  owner's to hold and are never stack config.
- **One script, last, that stops at its first failure.** `runcmd` is a single
  shell script with no `errexit`, so the enrolment is its own final entry and
  checks every step itself. It downloads the pull program, the program that
  installs the pinned Ansible and the hash-locked requirements, each over HTTPS
  from a commit of `main`, and checks each against the SHA-256 in the record
  before anything runs. The files are too large for the 32 KiB user-data limit,
  so they are fetched and not embedded. It then runs the install program (the
  same one the `ansible_runtime` role runs, with `--link`), places the pull
  program and writes its configuration. A failure writes a marker
  (`/var/lib/branchleft/pull-enrolment.failed`, with the step that failed) and
  stops; success writes `pull-enrolment.done`.
- **A failed host stays un-enrolled.** There is no fallback to an unpinned
  engine and no retry loop: the owner reads the marker and installs by hand.
  The pull program is placed last of all, after the engine is installed and
  linked, so until the script has succeeded the restricted keys do nothing (a
  `command=` naming a missing path fails closed).
- **The record is an input.** `ansible/tools/pull_bootstrap.py` builds it from
  `main` at publish time (`generate`) and checks one against the repository
  (`verify`): each file is pinned to the last commit that changed it, so a
  squash merge cannot remove the pinned commit, and the configuration is
  rendered from the role's own task and variable files, never written a second
  time (`ansible/tools/test_pull_bootstrap.py` runs the role's task and compares
  bytes). `assertPullBootstrap` refuses anything that is not exactly that shape.
  The package carries no copy of the record; the stack passes the one it was
  given with the package. The committed record, its drift check and its
  packaging are a separate change.
- **Packages.** `ENROLMENT_PACKAGES` is held equal to the two roles' lists
  (`pull_trigger`, `ansible_runtime`) less the base ones by the tools' tests.
  The engine itself is never in the list.
- **Edge only.** Any other role with an `enrolment` throws.
- **Key rotation is a replacement.** `userData` is create-time-only and in
  `ignoreChanges`, so changing a key in stack config does not change a running
  host. Rotating either key means replacing the host.
- **A private-only host** is accepted by the type but its first-boot route to
  GitHub is the network's own gateway (`privateOnly`), so enrolment there
  depends on that route being up at first boot.
- **Not proven on a live host.** The first real host is the proof: no
  throwaway server was created and no live apply was run.

## Firewalls

A Hetzner Cloud firewall filters the public interface only — traffic arriving
over the private network is never evaluated against `EDGE_RULES` or
`INTERNAL_RULES`. Private-side exposure is controlled by what a service binds
to, which is the consuming stack's Compose file, not this package. Egress is
left unrestricted deliberately: Hetzner's default with only inbound rules
present is to allow all outbound, and adding any outbound rule flips a host
to default-deny, silently breaking package updates, ACME, registry pulls and
outbound mail at the moment it applies.

## Versioning

`@pulumi/hcloud` is a `peerDependency`, pinned to an exact version rather
than a caret range: the provider version is part of every resource's URN, so
a consumer resolving a different version than this package's own resources
use would put one topology behind two provider instances. Install your own
`@pulumi/hcloud` at the exact version this package's `peerDependencies`
names; npm refuses the install otherwise rather than silently nesting a
second copy.

## Local development

```bash
nvm use && npm ci
npm run typecheck
npm test
```
