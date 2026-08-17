import { mx1, mx1Ipv4Address, mx1Ipv6Address } from './server';
import { mailFirewall } from './firewall';

// Re-exported so `pulumi stack output` can confirm the imported resources'
// live values without a separate `hcloud` lookup.
export const mx1ServerId = mx1.id;
export const mx1PublicIpv4 = mx1Ipv4Address;
export const mx1PublicIpv6 = mx1Ipv6Address;
export const mailFirewallId = mailFirewall.id;
