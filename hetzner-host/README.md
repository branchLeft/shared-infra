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
  carry `auto_delete`, so a rebuild releases the address. With a manual DNS
  zone and HTTP-01 issuance, an address that changes cannot be repaired by
  any program — every record is hand-edited and has to propagate before a
  single hostname can reissue.
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
