import * as hcloud from '@pulumi/hcloud';

/**
 * The mail delivery host, hand-provisioned and imported here without ever
 * having been created or recreated by this program. It is not on GCP because
 * GCP blocks outbound port 25 unconditionally, which makes a delivery host
 * impossible there. See RUNBOOK-import-mail-host.md for the import procedure
 * and its zero-diff check.
 */
export const mx1 = new hcloud.Server(
  'mx1',
  {
    name: 'mx1',
    serverType: 'cx23',
    location: 'nbg1',
    image: 'debian-13',
    backups: true,
    // These track the server's provider-side protection state. Changing
    // either is a real apply and a deliberate hardening step: setting a
    // value here that the live server does not have is a diff against the
    // zero-diff import gate, not a hardening.
    deleteProtection: false,
    rebuildProtection: false,
    labels: {
      role: 'mail',
      env: 'production',
      'managed-by': 'pulumi',
    },
  },
  {
    // Pulumi-level protection: this program can never delete or replace
    // mx1, independent of whatever `deleteProtection`/`rebuildProtection`
    // say at the Hetzner API level. Removing this resource from the
    // program with `protect: true` still set is a no-op destroy that
    // Pulumi refuses outright.
    protect: true,
    ignoreChanges: [
      // Create-time only: the provider cannot update this list in
      // place and would otherwise propose a destroy/recreate the
      // first time it saw a value here, including the empty list an
      // import produces for a server whose keys were never tracked as
      // Pulumi inputs.
      'sshKeys',
      // The two primary IP objects (IPv4 and IPv6) were allocated by
      // Hetzner at server-creation time; this program never declares
      // or manages them as their own resources, so the IDs the API
      // reports back for them are not something a diff here should
      // ever act on.
      'publicNets',
      // Hetzner's own image field can drift after the fact (e.g. a
      // later distro point release reusing the same name) without the
      // running server having been rebuilt. Ignoring it avoids a
      // spurious replace proposal for a property this program has no
      // way to act on without actually rebuilding the box.
      'image',
      // Firewall attachment is declared once, on the Firewall side
      // (`applyTos` in firewall.ts). This field is a plain
      // optional input here too, so left unset it would read live
      // state's populated list as drift and propose clearing it --
      // detaching the host's only firewall. See firewall.ts.
      'firewallIds',
    ],
  }
);

export const mx1Ipv4Address = mx1.ipv4Address;
export const mx1Ipv6Address = mx1.ipv6Address;
