import * as hcloud from '@pulumi/hcloud';
import { mx1 } from './server';

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
      // here), DNS-01 needs a DNS provider with an API (IONOS has none,
      // and DNS-01/DNS-PERSIST-01 both require one -- confirmed against
      // Stalwart's own source, not just its docs). TLS-ALPN-01 needs
      // only this one port, and RFC 8737 fixes the CA's validation
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
      // terminated by Caddy. A serverless caller's egress addresses
      // aren't enumerable, so this can't be narrowed by source; the
      // endpoint itself is API-key-authenticated and rate-limited.
      {
        direction: 'in',
        protocol: 'tcp',
        port: '8443',
        sourceIps: ['0.0.0.0/0', '::/0'],
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
