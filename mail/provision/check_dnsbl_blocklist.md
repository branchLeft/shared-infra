# check_dnsbl_blocklist.py

## Module overview

Checks the mail host's public IP against the major DNSBLs (DNS-based
blocklists) and raises a clear, actionable signal the moment any of them
lists it. A listed address silently kills deliverability for every sender
behind this host, which is exactly the kind of failure that must not wait
for someone to notice complaints. The same run also checks each sending
domain on a domain blocklist; see "Sending-domain blocklist" below.

Query mechanics (verified against each list's own docs and live DNS, not
assumed identical -- see mail/RUNBOOK-mx1-provision.md's "DNSBL blocklist
monitoring" section for the executed checks): every list in this set uses
the same reversed-octet query -- `<reversed IP>.<zone>` -- and answers with
either NXDOMAIN (not listed) or one or more A records in 127.0.0.0/8
(listed; the last octet encodes the sub-list/reason and differs per list,
irrelevant to this script beyond logging it). Spamhaus additionally
documents a distinct 127.255.255.0/24 range for _query_ errors (e.g. "this
resolver is a public/open one and is blocked") that must never be read as
a reputation signal -- applied defensively to every zone here, since no
other list in this set is known to use that range for a real listing.

Self-test before trusting a "not listed" result: every run also queries
each zone for the industry-standard always-listed test address 127.0.0.2
(confirmed live for Spamhaus/Barracuda/SpamCop/UCEPROTECT). If that
sentinel doesn't come back listed, the zone isn't answering meaningfully --
dead, unreachable, or rate-limiting this host -- and the real target's
result for that zone is reported as inconclusive rather than clean. This
is not hypothetical: dnsbl.sorbs.net currently has no DNS delegation at
all (NXDOMAIN at the .net level, confirmed live) despite being in the
minimum DNSBL set here, so without this self-test the SORBS entry would
silently and permanently report "clean" while providing zero real signal.
See the RUNBOOK for the live evidence.

Queries go to the host's own local recursive resolver (127.0.0.1, unbound,
installed by 65-install-local-resolver.sh) addressed explicitly rather than
through the system resolver: Spamhaus answers 127.255.255.254 ("query
blocked") to anything reaching it from a high-volume shared resolver, which
a hosting provider's default resolvers and every public one are. If that local resolver is
down or broken every lookup fails, the zone self-test below fails with it,
and the run reports inconclusive -- never a false clean.

## Sending-domain blocklist (Spamhaus DBL)

Each run also looks up every sending domain by name on Spamhaus DBL
(`<domain>.dbl.spamhaus.org`). A listed domain is reported the same way as a
listed address, under the key `dbl:<domain>`.

- The self-test is `dbltest.com`, the DBL's documented test point. The
  sentinel counts only when it answers exactly `127.0.1.2`. Any other answer,
  a failed lookup, or a 127.255.255.x query error makes every domain
  inconclusive for that run, never clean. The sentinel is queried once per run.
- The domain list is `DNSBL_SENDING_DOMAINS` (comma-separated). Unset or blank
  means the default list in the script. A value with no domain in it (for
  example `,`) stops the run and pings `/fail`, so an empty list cannot pass as
  a quiet run. A malformed domain name also stops the run.
- **The default list is the production list.** The cron line that runs this
  script (ansible/roles/mx1_stack, `vars/main.yml`) passes no environment, and
  the env file carries only the ping URL, so `DNSBL_SENDING_DOMAINS` cannot be
  set in production today. Passing the variable needs a role change to the
  cron line; that is a separate change.

### Default list and the repo proof for each domain

Each default domain is included only because a repo file shows that mail is
sent from it or signed with it. The test
`DefaultSendingDomainProofTests` in `test_check_dnsbl_blocklist.py` pins each
domain to its proof text and fails if a domain is added without one.

| Domain                  | Proof file                                                    | What it shows                                                                                                                                                             |
| ----------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `branchleft.co.uk`      | `hetzner/dns/zone.json`                                       | The apex SPF authorises mx1's address `167.233.252.240`, and the MX points at mx1.                                                                                        |
| `blog.branchleft.co.uk` | `mail/RUNBOOK-mx1-provision.md`                               | The shim's registered sending tenants include the blog ("Register the blog").                                                                                             |
| `publicpress.co.uk`     | `hetzner/dns/publicpress.co.uk.json`                          | The platform DKIM selector `bl._domainkey` is published for the domain. Zitadel also sends as `noreply@publicpress.co.uk` (`provision_zitadel_submission_credential.py`). |
| `trypublicpress.co.uk`  | `mail/provision/provision_collector_submission_credential.py` | `COLLECTOR_SENDING_DOMAINS` is the collector's only sending domain.                                                                                                       |

Excluded, with reason: `demo.trypublicpress.co.uk` (no repo file uses it),
`demo.example` (a placeholder in the runbook), and every tenant domain.

**Tenant sending domains are not checked yet.** The repo has no tenant
registry file. The shim keeps its registered sending tenants in its own store
on mx1, which is not readable without the shim's CLI on the host. Feeding that
list into this check would be a follow-up that reads the shim's own list; it
adds no dependency here.

Uses only the standard library, consistent with this directory's other
scripts (see configure_stalwart.py's docstring for why) -- including the
DNS query itself, which is why there is a small wire-format encoder and
parser here rather than a dnspython dependency.

## Forwarding findings

Every run also reports to a Healthchecks.io check: a success ping when every list is clean, and a `/fail` ping carrying the finding lines when any list is listed or inconclusive, or when the check crashes. The journal stays the record. The ping is what tells the owner about a finding, and its absence is what tells the owner the hourly run has stopped. The ping URL is a credential: it is read from the environment or a root-only file and is never logged. See the runbook section "Forwarding findings to Healthchecks.io" in mail/RUNBOOK-mx1-provision.md.
