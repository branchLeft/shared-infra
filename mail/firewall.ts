import { isIPv4 } from 'node:net';
import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';
import { mx1 } from './server';

/**
 * The application hosts stack's outputs (branchLeft/ghost-platform,
 * `infra/hosts`, which creates app1). A DIY (non-Pulumi-Cloud) backend fixes
 * the organisation segment to the literal `organization`, as
 * `hetzner/tenants.ts` does for the estate stack. The stack lives in this
 * program's own backend, so the reference resolves; a stack that has not been
 * applied, or an output that is missing, fails the preview instead of planning
 * a rule.
 */
const hostsStack = new pulumi.StackReference(
  'organization/branchleft-ghost-platform-hosts/production'
);

/**
 * The estate stack's outputs (this repository's `hetzner/estate.ts`, which
 * creates edge1), read the same way `hetzner/tenants.ts` reads them.
 */
const estateStack = new pulumi.StackReference('organization/branchleft-hetzner-estate/production');

/**
 * Ranges that are never the public source of a caller on the internet:
 * this-network, private, shared (CGNAT), loopback, link-local, IETF protocol,
 * benchmarking, multicast and reserved space. A rule naming one matches
 * nothing that can reach mx1, which would silently stop the blog's mail.
 * Documentation ranges (TEST-NET) are allowed: they match nothing on the
 * internet, so they cannot widen access.
 */
const NEVER_A_PUBLIC_SOURCE: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const ipv4ToNumber = (address: string): number =>
  address.split('.').reduce((accumulator, octet) => accumulator * 256 + Number(octet), 0);

/**
 * The one source the bulk-mail rule accepts, as a /32. A dotted-quad IPv4
 * address only (`isIPv4` refuses leading zeros, which different parsers read
 * as octal or decimal), then not private, shared, loopback, link-local,
 * multicast or reserved. Anything else throws, which fails the preview and
 * leaves the live rule as it is.
 */
export function bulkMailSourceCidr(address: string): string {
  if (!isIPv4(address)) {
    throw new Error(
      `bulk-mail source "${address}" is not a dotted-quad IPv4 address; give one public address, not a CIDR, an IPv6 address or a hostname`
    );
  }
  const numeric = ipv4ToNumber(address);
  const refused = NEVER_A_PUBLIC_SOURCE.find(([base, bits]) => {
    const start = ipv4ToNumber(base);
    return numeric >= start && numeric < start + 2 ** (32 - bits);
  });
  if (refused !== undefined) {
    throw new Error(
      `bulk-mail source ${address} is inside ${refused[0]}/${refused[1]}, which is not a public address`
    );
  }
  return `${address}/32`;
}

/**
 * app1's own public IPv4, as a /32. app1 is created with public networking
 * (`infra/hosts/index.ts` in ghost-platform: its deploy path is SSH from
 * GitHub-hosted runners), so it has its own public interface and reaches mx1
 * from that address, not through edge1's NAT: the NAT carries only hosts with
 * no public address (`ansible/roles/egress_nat`). Ghost runs in Docker on
 * app1, and Docker masquerades container traffic to the host's public IPv4.
 * Read from the hosts stack's `app1PublicIpv4` output (app1's primary IP),
 * never typed, so the rule follows the address if the primary IP ever changes.
 */
const app1EgressSource = hostsStack
  .requireOutput('app1PublicIpv4')
  .apply((address) => bulkMailSourceCidr(String(address)));

/**
 * edge1's own public IPv4, as a /32. edge1 runs the blackbox probe that checks
 * the shim's TLS endpoint and its certificate expiry
 * (`hetzner/monitoring/stack/prometheus/prometheus.yml`, job `blackbox_mail`),
 * and that probe leaves from edge1's public interface. Without this source the
 * probe is refused and the mail liveness alert fires for good. edge1 is also
 * the NAT for the estate's private-only hosts, so this admits them too (the
 * ops1 collector among them, which will call the shim's drain route). Read
 * from the estate stack's `edge1PublicIpv4` output, never typed.
 */
const edge1ProbeSource = estateStack
  .requireOutput('edge1PublicIpv4')
  .apply((address) => bulkMailSourceCidr(String(address)));

/**
 * The mail delivery host's firewall. Hand-created alongside the server and
 * imported rather than created here; `name` must match whatever the provider
 * assigned, which is not necessarily the name this program would have chosen.
 * RUNBOOK-import-mail-host.md covers importing against the pre-mail-rules
 * baseline first and applying this rule set second, for a clean zero-diff
 * import.
 */
export const mailFirewall = new hcloud.Firewall(
  'mail-firewall',
  {
    name: 'firewall-1',
    labels: {},
    rules: [
      {
        direction: 'in',
        protocol: 'tcp',
        port: '22',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      {
        direction: 'in',
        protocol: 'icmp',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // Relay-to-relay SMTP (this host -> a recipient's MX) and the
      // bulk-mail shim's own SMTP AUTH submission both arrive inbound here.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '25',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // Implicit-TLS SMTP submission.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '465',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // STARTTLS SMTP submission -- what the transactional path and the
      // shim's bulk-mail relay both actually use.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '587',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // IMAP over TLS, for mailbox hosting.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '993',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // ACME TLS-ALPN-01 challenge reachability. Not in the original
      // planned inbound set (25/465/587/993) -- added because Stalwart's
      // certificate issuance needs a challenge type, and the two
      // alternatives don't fit: HTTP-01 needs 80 (no HTTP service runs
      // here), and DNS-01/DNS-PERSIST-01 both need Stalwart to hold a
      // write credential for the zone's DNS API -- confirmed against
      // Stalwart's own source, not just its docs. TLS-ALPN-01 needs
      // only this one port and no credential, and RFC 8737 fixes the CA's validation
      // connection at 443 -- not configurable to reuse 465/587/993.
      // This listener carries no HTTP/admin traffic (see
      // mail/RUNBOOK-mx1-provision.md's ACME section) -- opening it
      // doesn't expose the webadmin.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '443',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // ACME HTTP-01 validation for the shim's TLS -- Caddy's own
      // issuer, entirely separate from Stalwart's TLS-ALPN-01 use of
      // 443 above (see mail/RUNBOOK-mx1-provision.md's "Mailgun
      // shim" section). CAs validate from arbitrary IPs, not a fixed
      // range.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '80',
        sourceIps: ['0.0.0.0/0', '::/0'],
      },
      // The sending application -> the mailgun-shim's bulk-mail API,
      // terminated by Caddy. Two sources only: the blog's Ghost on app1
      // (`app1EgressSource` above) and edge1, which carries the blackbox probe
      // of this port and the NAT of the estate's private-only hosts
      // (`edge1ProbeSource` above). IPv4 only: Ghost runs in a container on
      // Docker's IPv4 networks, so its traffic leaves app1 as IPv4, and no
      // IPv6 source is allowed. The endpoint itself stays API-key-authenticated
      // and rate-limited. This stays narrowed until the shim is retired and the
      // port closed.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '8443',
        sourceIps: [app1EgressSource, edge1ProbeSource],
      },
    ],
    applyTos: [
      {
        server: mx1.id.apply((id) => Number(id)),
      },
    ],
  },
  {
    protect: true,
  }
);
