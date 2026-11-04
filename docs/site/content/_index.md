+++
title = "Overview"
+++

## What this repository is

`shared-infra` holds the infrastructure that several branchLeft services share. It is code, not a
console: the machines, networks and their configuration are declared here, checked by CI, and
applied from a reviewed commit. If you are new, read this page for the map and
[How it works](how-it-works/) for the moving parts.

It holds four things:

| Part               | Where                      | What it does                                                                                                                                                                      |
| ------------------ | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mail delivery host | `mail/`                    | The self-hosted outbound mail host, `mx1`. Its own Pulumi project, because its two resources are imported rather than created and must never be disturbed by an unrelated change. |
| Hetzner estate     | `hetzner/`                 | The network, the hosts and their firewalls, and the edge VM `edge1` that runs Caddy and CrowdSec. Two Pulumi projects, one for the network and one for the estate.                |
| Hostname registry  | `sites.ts`, `siteTypes.ts` | One list of the hostnames the edge serves and where each is served from. Renderers read it to produce the web server configuration and the monitoring probe targets.              |
| Host configuration | `ansible/`                 | Ansible roles, one per job, plus the harness and checks that test them and the signed pull that applies them to each host.                                                        |

## The rules that shape everything

- **Nothing is applied by hand.** CI plans each stack on a merge to `main`, shows the plan, and
  waits for a human to approve it before it applies. A hand-run apply is only for first-time setup.
- **No secrets, ever.** The repository is public. It holds hostnames and addresses of services,
  not key material, credentials, member data or anything that names a customer who has not agreed
  to appear. Operators supply secrets out of band, from root-only files on the host.
- **The registry is the one source for hostnames.** A site is added with one entry in `sites.ts`;
  the web server and monitoring configuration are generated from it, never edited by hand.
- **Merge through the queue.** The merge queue keeps the delivery run approvable. A merge that
  bypasses it starts a run that its own merger cannot approve.

## Where to start reading

1. `README.md` at the repository root, for the layout and the operating rules.
2. `sites.ts` and its documentation, to see what a site entry looks like and why.
3. `hetzner/README.md`, for the network, the hosts, how they are identified and how they deploy.
4. `docs/ansible-handbook.md`, for how to write, test and change a role.
5. A role that is small enough to read in one sitting, such as `ansible/roles/example_config`,
   which is the worked example.
