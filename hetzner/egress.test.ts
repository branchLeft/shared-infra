import { HOST_IPS, NETWORK_CIDR } from '@branchleft/hetzner-host';
import { describe, expect, it } from 'vitest';

import { INTERNET_DESTINATION, internetEgressRoute } from './egress';

/**
 * The route these arguments describe is the estate's only default route. A
 * gateway the provider accepts but nothing forwards is an estate whose
 * private hosts silently stop reaching the internet — including for security
 * updates — so the validation is asserted directly rather than left to a
 * preview that only ever sees the one committed value.
 */

describe('internetEgressRoute', () => {
  it('routes the default destination at the address the edge host holds', () => {
    expect(internetEgressRoute(HOST_IPS.edge1)).toEqual({
      destination: '0.0.0.0/0',
      gateway: '10.20.1.10',
    });
    expect(INTERNET_DESTINATION).toBe('0.0.0.0/0');
  });

  it('accepts any address inside the network range, not only the current gateway', () => {
    expect(internetEgressRoute(HOST_IPS.mon1).gateway).toBe('10.20.1.30');
    expect(internetEgressRoute('10.20.255.254').gateway).toBe('10.20.255.254');
  });

  it('refuses an address outside the network range', () => {
    expect(() => internetEgressRoute('10.21.1.10')).toThrow(
      `egress gateway 10.21.1.10 is outside the network range ${NETWORK_CIDR}`
    );
    // A public address is the specific mistake worth naming: it is what
    // someone reaches for when told the route is the path to the internet.
    expect(() => internetEgressRoute('203.0.113.10')).toThrow('outside the network range');
  });

  it('refuses the first two addresses of the network range', () => {
    expect(() => internetEgressRoute('10.20.0.0')).toThrow('is reserved');
    expect(() => internetEgressRoute('10.20.0.1')).toThrow('is reserved');
    expect(internetEgressRoute('10.20.0.2').gateway).toBe('10.20.0.2');
  });

  it("refuses Hetzner's public-interface gateway", () => {
    // Refused by name rather than by falling out of the range check, which
    // is what keeps the guard meaningful for a range that did contain it.
    expect(() => internetEgressRoute('172.31.1.1')).toThrow(
      "is Hetzner's public-interface gateway"
    );
  });

  it('validates against a range it is given, not only the estate’s own', () => {
    expect(internetEgressRoute('172.20.0.5', '172.16.0.0/12').gateway).toBe('172.20.0.5');
    expect(() => internetEgressRoute('10.20.1.10', '172.16.0.0/12')).toThrow(
      'is outside the network range 172.16.0.0/12'
    );
    // The whole-internet range: every address is inside it, so the first-two
    // reservation is the only rule with anything left to say.
    expect(internetEgressRoute('10.20.1.10', '0.0.0.0/0').gateway).toBe('10.20.1.10');
    expect(() => internetEgressRoute('0.0.0.1', '0.0.0.0/0')).toThrow('is reserved');
  });

  it('refuses a malformed network range rather than deriving a mask from it', () => {
    for (const cidr of ['10.20.0.0', '10.20.0.0/33', '10.20.0.0/-1', '10.20.0.0/half']) {
      expect(() => internetEgressRoute('10.20.1.10', cidr)).toThrow('is not an IPv4 CIDR');
    }
  });

  it('refuses every prefix `Number` would silently accept', () => {
    // Each of these converts to an integer in 0..32 and would pass a
    // `Number.isInteger` check. The first is the dangerous one: an empty
    // prefix reads as /0, whose mask is zero, and every address on the
    // internet is then inside the range.
    for (const cidr of ['10.20.0.0/', '10.20.0.0/ 8', '10.20.0.0/1e1', '10.20.0.0/0x10']) {
      expect(() => internetEgressRoute('10.20.1.10', cidr)).toThrow('is not an IPv4 CIDR');
    }
    expect(() => internetEgressRoute('203.0.113.10', '10.20.0.0/')).toThrow('is not an IPv4 CIDR');
  });

  it('refuses a range carrying more than one prefix', () => {
    expect(() => internetEgressRoute('10.20.1.10', '10.20.0.0/16/16')).toThrow(
      'is not an IPv4 CIDR'
    );
  });

  it('refuses anything that is not a dotted-quad IPv4 address', () => {
    for (const value of ['', '10.20.1', '10.20.1.10.1', '10.20.1.256', '10.20.1.x', '10.20.1.-1']) {
      expect(() => internetEgressRoute(value)).toThrow('is not a dotted-quad IPv4 address');
    }
  });

  it('refuses a leading-zero octet rather than guessing its base', () => {
    // `010.20.1.10` is 8.20.1.10 read as octal and 10.20.1.10 read as
    // decimal. Accepting it would mean the validator and the provider could
    // disagree about which host the estate routes through.
    expect(() => internetEgressRoute('010.20.1.10')).toThrow('is not a dotted-quad IPv4 address');
    expect(() => internetEgressRoute('10.20.01.10')).toThrow('is not a dotted-quad IPv4 address');
  });
});
