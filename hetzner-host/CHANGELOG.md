# Changelog

All notable changes to `@branchleft/hetzner-host` are recorded here.

## 0.5.0

Versions 0.4.0 and 0.5.0 were set in `package.json` by the changes below and
never tagged, so nothing after 0.3.0 is on the registry yet. This is the first
release since 0.3.0, and the next tag is `hetzner-host-v0.5.0`.

**Upgrading from 0.3.0.** `@pulumi/hcloud` is a peer dependency pinned
exactly, and it moved from 1.41.0 to 1.43.4: a consumer must install that exact
version beside this one, or the install is refused. `@pulumi/pulumi` moved to
`^3.275.0`. The licence is now PolyForm Shield 1.0.0 (`LICENSE` is in the
package).

**Hosts can be adopted instead of created.**

- **Additive:** `Host` takes an optional `adopt` (`AdoptArgs`): the numeric
  Hetzner id of an existing server and, for a public host, of its two primary
  IPs. Adoption is two stages, `import` then `converge`. `assertAdoption` is
  exported. An adopted host ignores the create-time-only fields (`userData`,
  `sshKeys`, `image`, `firewallIds`) and `publicNets`, so an apply cannot plan a
  replacement or delete its primary IP. Absent `adopt`, every resource is
  unchanged.
- **Fixed:** a private-only adopted host gets no `FirewallAttachment`, at either
  stage, because Hetzner firewalls filter only a public interface and the
  provider refuses the attachment. A public adopted host gets exactly one.
- **Fixed:** the two `PrimaryIp` resources no longer declare the deprecated
  `assigneeType`, which the provider ignored without `assigneeId` and warned
  about on every preview. The attribute is removed, not replaced, so the
  address resources keep their identity.

**An edge host enrols itself into the gated pull at first boot.**

- **Additive:** `renderCloudInit` takes an optional `Enrolment` and
  `PullBootstrap` record: root gets two command-restricted keys, and a last
  script downloads the pull program and the hash-locked requirements, checks
  each against a recorded SHA-256, installs the pinned Ansible and places the
  pull program. A host that fails stays un-enrolled; nothing falls back to an
  unpinned engine. `assertEnrolment`, `assertPullBootstrap` and
  `assertPgpPublicKeyBlock` are exported, with the types `Enrolment`,
  `PullBootstrap` and `PullBootstrapFile`.

**A host can take SSH from one address, and the tenants range has a register.**

- **Additive:** `Host` takes an optional `sshSourceIp`, one public IPv4 `/32`
  that narrows the role's SSH rule to that source and nothing else. Exported:
  `edgeRulesSshFrom`, `sshRestrictedRules`, `sshFromOneAddressViolations`,
  `assertSshSourceAddress`. Absent, the rule set is unchanged.
- **Additive:** `ADDRESS_REGISTER`, `TENANTS_HOST_IPS` and
  `duplicateAddresses` record every fixed host address across both projects and
  refuse a duplicate.

## 0.3.0

A private-only host provisions the host half of its egress path.

## 0.2.0

A private-only host attaches its network inline, so it can boot.

## 0.1.0

The first release: the `Host` component, the edge and internal firewall rules,
the cloud-init renderer and the estate address plan.
