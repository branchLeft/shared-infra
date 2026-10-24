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
  from a commit that the record names (a commit of `main`, as the record's
  tool enforces below), and checks each against the SHA-256 in the record
  before anything runs. The files are too large for the 32 KiB user-data limit
  (the Hetzner Cloud API reference for creating a server: "Cloud-Init user data
  to use during Server creation. This field is limited to 32KiB."), so they are
  fetched and not embedded. It then runs the install program (the
  same one the `ansible_runtime` role runs, with `--link`), writes the
  directories and the configuration, and places the pull program last of all.
  A failure writes a marker (`/var/lib/branchleft/pull-enrolment.failed`, with
  the step that failed) and stops; success writes `pull-enrolment.done`.
- **A failed host stays un-enrolled.** There is no fallback to an unpinned
  engine and no retry loop: the owner reads the marker and installs by hand.
  What a failed host holds depends on the step. Before `install-engine` it has
  nothing. At `install-engine` or after it, it may hold the `ansible-playbook`
  link (the hash-locked engine, never another) and, from `write-config`, the
  directories and the configuration; it never holds the pull program, which is
  the last step before the done marker. The two restricted keys name the pull
  program's path, so while it is absent they run nothing (a `command=` naming a
  missing path fails closed), and the owner's keys are the only way in.
  `enrolment.test.ts` runs a failure at `install-engine`, at `write-config` and
  at `install-trigger` and asserts the pull program is absent in each.
- **The record is an input.** `ansible/tools/pull_bootstrap.py` builds it from
  `main` at publish time (`generate`) and checks one against the repository
  (`verify`): each file is pinned to the last commit that changed it, so a
  squash merge cannot remove the pinned commit, and the configuration is
  rendered from the role's own task and variable files, never written a second
  time (`ansible/tools/test_pull_bootstrap.py` runs the role's task and compares
  bytes). Both commands refuse a shallow clone (in one, every file's last commit
  reads as HEAD, so no pin could be stale), then fetch `main` from `origin`
  afresh and refuse unless HEAD is the tip of it, because the history a pin is read from and the
  files the configuration is rendered from are HEAD's: a checkout behind `main`
  would otherwise call current a record that `main` has since replaced.
  `verify` also refuses a record whose pin is not an ancestor of the tip, so a
  record built on a branch, or one naming a commit that only a pull request ref
  or a fork holds, is never accepted.
  `assertPullBootstrap` refuses anything that is not exactly that shape; it
  cannot tell which commits are on `main`, so the binding is the tool's.
  The package carries no copy of the record; the stack passes the one it was
  given with the package. The committed record, its drift check and its
  packaging are a separate change.
- **The fixed values live once.** Where the files are served from, which three
  files, the one playbook, the remote and the keys the configuration needs are in
  `pullBootstrapFixed.json`. `cloudInit.ts` imports it (the build copies it into
  `dist`) and `pull_bootstrap.py` reads it, so a path that moves is changed in one
  file and neither side holds a copy; the tools' tests fail when either source
  writes one of the values again. The paths the two roles keep (the pull program,
  its configuration, the state and log directories, the Ansible environment) are
  written in `PRODUCTION_LAYOUT` too, since a first boot has no Ansible to read
  them from; `ansible/tools/test_pull_bootstrap.py` holds each equal to the role
  variable that owns it (`LayoutTest`). These and `ENROLMENT_PACKAGES` are the
  accepted second spellings; the rest live once.
- **Two readers are written by hand, and why.** `assertPgpPublicKeyBlock` (an
  OpenPGP packet walk) and the install program's `REQUIREMENT` pattern parse input
  on the first-boot path. The maintained options are `gpg --show-keys` and
  `packaging.requirements`, with pip's own `--require-hashes`. The package's only
  runtime dependency is Pulumi and a Pulumi program cannot assume a gpg binary
  (an OpenPGP library would add a large parser and a lock change); the install
  program runs under `python -I` before any package exists. pip's
  `--require-hashes`, with `--only-binary=:all:` (pip does not hash-check the
  build dependencies of a source build, so nothing is built), is the control that
  stays on; the pattern only refuses early. Both inputs come from reviewed `main`. A publish-time `gpg --show-keys`
  in the Python tool is not built.
- **Until the record has a producer, nothing checks where it came from.**
  `assertPullBootstrap` checks the shape of a record, not its provenance. Nothing
  produces a record in a stack yet, so a hand-made record that has the right
  shape reaches a script that root runs at first boot. A consumer must use the
  output of `generate` and `verify`, run from the tip of `main`, and cite that
  `verify` output.
- **Root keeps its console login.** The `root` entry sets `lock_passwd: false`.
  cloud-init defaults it to true and applies it to an account that already
  exists, which would lock the password. Key access is unaffected either way; the
  provider console is the break-glass way in when sshd is down.
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

## Notes kept from the source

These notes were cut from `cloudInit.ts`, `cloudInit.test.ts`, `host.ts` and `host.test.ts`
when their comment blocks went below the CMT-3 limit (11 lines). The code keeps a one-line
pointer to this section, and the constraints each block states are still in the code.

### cloudInit.ts

The first-boot user-data every platform host is created with.

**Cloud-init runs once, on first boot, and never again.** Nothing that has to stay true over
the host's life belongs here: it belongs in `provision/`, whose scripts are idempotent and
re-runnable. This file's only job is to make the host reachable by the two identities that do
the rest: the platform owner's key on `root`, and the CI deploy key on `deploy`.

One deliberate exception: a private-only host's `bootcmd` entries (see `PRIVATE_ONLY_BOOTCMD`
below) re-run on every boot, not once. `bootcmd` is the only cloud-init stage early enough to
matter here, and re-running is also the point of putting them there: it covers the window
between first boot and `provision/05-configure-host-egress.sh` (and the systemd unit it
installs) actually taking over the same job permanently. Both commands are idempotent, so the
repetition costs nothing once that unit exists.

The image is Debian, whose cloud image ships cloud-init with the standard modules; nothing here
depends on a Hetzner-specific datasource.

`CloudInitArgs.privateOnly`: whether this host has no public interface at all. A plain boolean,
not an `Input`: it comes from `HostArgs.publicNetworking`, itself a plain boolean because the
networking shape is a creation-time decision, never a stack output.

A private-only host's only route off the subnet is the network's own gateway, and Hetzner's DHCP
delivers the subnet route but never a default (`hetzner/egress.ts`). Left false, `package_update`
below is the first thing on such a host with nowhere to reach, and every apt mirror fails
"temporary failure resolving" for the rest of first boot.

`Enrolment`, the host-level deploy key: options on the **host-level** deploy key, the one this
document installs at first boot. `restrict` is the whole-set deny (no agent forwarding, no port
forwarding, no X11, no pty, no user-rc), with nothing added back.

Deliberately no forced command here, and that is now a scoping decision rather than a deferral.
This key is the platform's own and names the stack it deploys, so it reaches every stack on the
host; per-stack keys carry `restrict` **plus** a `command=` naming one stack, and are added after
first boot by `hetzner/provision/provision_deploy_slot.py`, which is the only writer of
`authorized_keys` thereafter. Cloud-init cannot install them: it runs once, and slots are granted
per tenant over the host's life.

`AUTHORIZED_KEY_OPTIONS`: `deploy` gets no shell privileges and no membership of the `docker`
group. Docker group membership is root-equivalent (the socket will build a container that mounts
the host filesystem), so a deploy user placed in it is unrestricted however carefully its sudoers
entry is written.

Instead the one privileged action CI needs runs through a single root-owned wrapper, and the
sudoers entry names that binary with **no wildcard**. A wildcard in a sudoers command matches
spaces, which turns any `systemctl restart something@*` style entry into arbitrary argument
injection. Argument validation is the wrapper's job, where it can be tested, not sudoers'.

`assertDeployPublicKey`: rejects anything that is not a single-line OpenSSH public key.

This is the only validation between stack config and a document that grants `deploy` an
`authorized_keys` entry and a sudoers rule, and a newline in the value appends arbitrary
cloud-config to it: a second `users:` entry, a `runcmd`, a `write_files` overwriting the sudoers
drop-in. Three properties make that worth failing closed over rather than trusting the input:
cloud-init runs once and cannot be re-run, `userData` is create-time-only at the provider, and it
is in the component's `ignoreChanges`, so an injected document is permanent and absent from every
later diff.

`PRIVATE_ONLY_BOOTCMD`: the `bootcmd` entries that give a private-only host a working default
route and resolver before `package_update`/`packages` below installs anything.

This has to be `bootcmd`, not `runcmd`, and the distinction is not cosmetic. `runcmd`'s own
module only _writes_ the command list to a script on disk during cloud-init's config stage; that
script is not actually _executed_ until the `scripts-user` module, which sits near the end of the
later final stage, and `package-update-upgrade-install` (the module behind
`package_update`/`packages`) is at the _start_ of that same final stage. A `runcmd` entry here
would therefore still run after package installation has already failed, which is the exact bug
this block exists to fix. `bootcmd` is a separate, earlier module in cloud-init's very first
(init) stage, which precedes the config stage entirely (config, in turn, precedes final), so this
is the one placement that actually lands ahead of `package_update`.

The trade-off named at the top of this file: `bootcmd` re-runs on every boot, not once, which is
why both commands are written to be safe to repeat (`ip route replace`, and a plain
overwrite-and-`resolvconf -u` with no compare-first check, since bootcmd has no equivalent of a
provisioning log to skip redundant work against).

Exec form is avoided here (unlike the plain commands below) because the gateway has to be derived
from the routing table, which needs a shell. Every string literal in the embedded awk/shell is
double-quoted rather than single-quoted so that wrapping the whole command in a YAML double-quoted
scalar needs no nested-quote gymnastics beyond escaping those doubles for YAML itself.

`BASE_PACKAGES` (the packages block): what an enrolled host needs on it before the pull can run:
`git`, `gpg` and `gpgconf` and `openssh-client` for the pull program (the
`pull_trigger_packages` of that role), and `python3` and `python3-venv` for the Ansible install
(the `ansible_runtime_packages` of that role). `curl` and `ca-certificates` are in the base list.
`ansible/tools/test_pull_bootstrap.py` holds this list equal to the two roles' lists, so a
package added to a role fails there until it is added here.

The engine itself is never in this list: it is installed by the pinned, hash-checked program,
and by nothing that resolves its own version.

The OpenPGP walker (`pgpPacketTags` and its caller): refuses anything but an armoured OpenPGP
**public** key block.

The signer block ends up in user-data, which is readable by anything on the host and by whoever
can read the Hetzner project. The checks are an allowlist and not a scan for the word PRIVATE:
exactly one public header and one public footer, nothing else that looks like an armour line, a
first packet that is a public key (tag 6), and then every packet of the data, walked header by
header, of a type that a public key is made of (public key, public subkey, user id, user
attribute, signature). A secret key (tag 5) or a secret subkey (tag 7) anywhere in the data, after
a public key or not, does not pass.

Why a walker and not a maintained OpenPGP library: this package's only runtime dependency is
Pulumi itself, and a library (openpgp.js) would put a large parser and a lock change on the path
of a production Pulumi program. `gpg --show-keys` is not an option here: this runs inside the
Pulumi program, where a subprocess and a gpg binary cannot be assumed. The walker reads only
packet headers and lengths, accepts a short allowlist, and refuses everything it cannot account
for. It is the only check on the block today. The key comes from edge1's trust file
(`ansible/trust/edge1.yml`) on main, so a publish-time `gpg --show-keys` over that file, run by the
Python tool, would be a maintained check ahead of it; it is not built.

The enrolment `runcmd` script (the shell that brings a host under the pull): it is one `sh -c`
entry of `runcmd`, and it is the last one.

Order matters and is the whole control. All three files are fetched and each is checked against
its recorded SHA-256 first; only then does the install program run; after it has succeeded the
state directories and the configuration are put in place; the pull program is placed last of all,
as the final step before the done marker. A failure anywhere writes the step it failed at to a
marker file and stops.

What a failure leaves depends on where it happened, and each state is safe: before
`install-engine` the host has nothing installed; at or after it the host may have the
`ansible-playbook` link, which is the hash-locked engine and never another, and possibly the
directories and the configuration, but never the pull program unless every earlier step
succeeded. The two command-restricted keys name the pull program's path, so while it is absent
they run nothing, and the owner's keys are the only way in. There is no fallback that installs an
engine that is not hash-locked.

### cloudInit.test.ts

`renderCloudInit` builds a `#cloud-config` document that creates the `deploy` account, installs
its `authorized_keys` entry, and writes a sudoers drop-in granting that account a root command.
The only value flowing into it from stack configuration is the public key, and a newline in it
appends arbitrary cloud-config to the document.

Three properties make that permanent rather than merely wrong: cloud-init runs once and never
again, `userData` is create-time-only at the provider, and it sits in the component's
`ignoreChanges`, so an injected document survives every later apply and appears in no diff. There
is no second control behind this one.

The `bootcmd` test (a private-only host's DHCP lease carries the private subnet route and the
metadata route, but never a default one, and no resolver at all, so without this, `package_update`
below is the first thing on such a host with nowhere to reach, and cloud-init's package
installation fails for the whole of first boot. `privateOnly` is what threads that host shape
through from `Host`):

The bootstrap has to land in `bootcmd`, not `runcmd`: `runcmd`'s own module only writes the
command list to disk during cloud-init's config stage, and that script is not actually executed
until `scripts-user`, which runs near the end of the _later_ final stage, after
`package-update-upgrade-install`, which sits at the _start_ of that same final stage. Putting the
bootstrap in `runcmd` would place it in the document but have it execute too late to help, which
is exactly what an earlier version of this file got wrong (and asserted incorrectly, via a test
that only checked string position in the rendered YAML rather than which module the position
belongs to). `bootcmd` is a distinct, earlier module in cloud-init's _init_ stage, which precedes
both config and final. The assertions check block membership, not text order, because text order
is exactly what let the wrong placement pass before.

### host.ts

The create pattern for a platform host: server, firewall, private-network attachment at a fixed
address.

This is the piece the mx1 stack does not provide. That stack _imports_ a hand-built server and is
written to never create or replace it, and its `ignoreChanges` on `publicNets` and `firewallIds`
exists to make a pre-existing machine reconcile cleanly. Neither generalises to a machine this
program creates, where both are inputs rather than facts to be tolerated. `sshKeys` and `image`
are different: they are create-time-only at the provider regardless of how the server came to
exist, and both are ignored here for that reason rather than by inheritance.

Consumed by the per-role host stacks rather than instantiated here: the network must never share a
stack with anything applied on a delivery cadence, so this project declares the pattern and
creates no host with it.

`HostArgs.publicNetworking`: whether the host gets public addresses at all. Defaulted on because
the deploy path is SSH from GitHub-hosted runners, and a host CI must reach needs a public address
to reach.

A host no deploy path touches should set this to `false` and be reached over the private network
from a host that does. Only the hosts that terminate public traffic need an address of their own;
every other public address that exists is a standing exception to that. Doing so means accepting
that recovery is the Hetzner console.

**Choose this at creation.** Flipping it from `true` to `false` on a live host removes two
delete-protected primary IPs from the program, and the API refuses to delete them, which wedges
the stack mid-update. To change it later, apply once with `protection: false` so the protection
comes off, then apply again with `publicNetworking: false`.

The primary IPs are declared as their own resources rather than left to Hetzner's server-creation
allocation, which sets `auto_delete` and releases the address back to the pool when the server
goes.

That is not survivable here. Certificate issuance is HTTP-01, so an address that changes breaks
every hostname until each record naming it has been repointed and has propagated, and only then
can any of them reissue. A mail host's sending reputation is attached to its address and does not
move at all. The rebuild that this component deliberately permits would otherwise take the whole
estate's public reachability with it.

The private-only network attachment: a private-only host must carry its network interface at
first boot. With no public interface and no inline network, Hetzner refuses to start the server at
all ("no public or private network interfaces found"). The separate ServerNetwork attachment is
created only after the server exists, which is too late for that case, so a private-only host
attaches inline and skips the separate resource. A public host keeps the separate attachment:
moving a live host between the two shapes plans a detach/attach, so the shape is fixed at
creation. `aliasIps: []` is required: left undefined, the provider detaches and reattaches the
network on every apply (upstream provider issue #650).

### host.test.ts

`Host` has three branches whose failure modes are all silent at apply time: the role picks the
firewall rule set, `publicNetworking` decides whether two primary IPs exist, and the firewall is
declared _on the server_ rather than attached afterwards. A wrong branch produces a host that
boots, answers SSH, and is exposed; nothing errors.

`setMocks` runs in `beforeAll`, which is early enough: `host.ts` constructs nothing at module
scope, so the mocks only have to be in place before the first `new Host(...)`. `estate.ts` and
`network.ts` are the modules that do build resources on import, and neither is imported here.
