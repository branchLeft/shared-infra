import type * as hcloud from '@pulumi/hcloud';

/**
 * Per-role inbound rule sets for Hetzner Cloud firewalls.
 *
 * The constraint that shapes all of them: **a Hetzner Cloud firewall filters
 * the public interface only.** Traffic arriving over the private network is
 * never evaluated against these rules, so nothing here isolates one host from
 * another. Private-side exposure is controlled by what a service binds to —
 * a database or an exporter binds its private address, never `0.0.0.0` — and
 * that is a property of the host's Compose file, not of this file.
 *
 * Egress is left unrestricted deliberately. Hetzner's default with only
 * inbound rules present is to allow all outbound; adding any outbound rule
 * switches the host to default-deny, which silently breaks package updates,
 * ACME, registry pulls and outbound mail at the moment it is applied. That is
 * a change worth making with a specific allow-list per role, not as a
 * side effect of adding an inbound rule.
 */

type Rule = hcloud.types.input.FirewallRule;

const ANY_SOURCE = ['0.0.0.0/0', '::/0'];

/**
 * Management access is open to the internet on every role because deploys run
 * from GitHub-hosted runners, whose egress addresses are a large published
 * range that changes without notice — pinning it would turn a routine runner
 * pool change into an outage of the deploy path. Key-only auth, no root
 * login and fail2ban are what actually carry this exposure; see
 * provision/00-harden-ssh.sh.
 */
const SSH: Rule = {
  direction: 'in',
  protocol: 'tcp',
  port: '22',
  sourceIps: ANY_SOURCE,
};

/** Kept open on every role: without it path-MTU discovery blackholes, which
 * presents as large responses hanging rather than as a firewall problem. */
const ICMP: Rule = {
  direction: 'in',
  protocol: 'icmp',
  sourceIps: ANY_SOURCE,
};

/** The only role that terminates public traffic. Port 80 is not redundant
 * with 443: HTTP-01 challenge validation arrives there, and with the DNS zone
 * held at a registrar with no API, HTTP-01 is the only issuance path
 * available. */
export const EDGE_RULES: Rule[] = [
  SSH,
  ICMP,
  { direction: 'in', protocol: 'tcp', port: '80', sourceIps: ANY_SOURCE },
  { direction: 'in', protocol: 'tcp', port: '443', sourceIps: ANY_SOURCE },
];

/**
 * App, database and monitoring hosts publish nothing publicly. Their service
 * ports are reachable from the edge and from each other over the private
 * network, which these rules neither permit nor deny — see the note above.
 */
export const INTERNAL_RULES: Rule[] = [SSH, ICMP];
