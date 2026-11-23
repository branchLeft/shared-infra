import * as fs from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import { ZONE_FILES } from '../dnsZone';
import { blackboxTargets } from '../monitoring/render';
import { POSTURE, RATE_LIMIT_EVENTS, RATE_LIMIT_WINDOW_SECONDS, type EdgePosture } from './posture';
import { renderCaddyfile, resolvePrivateAddress, servableSites } from './render';

// Why: see render.md section "siteBlock: signed object gateway".

const ENFORCING: EdgePosture = {
  crowdsec: 'enforcing',
  rateLimit: 'enforcing',
  membersMagicLinkRateLimit: 'enforcing',
};
const DETECT_ONLY: EdgePosture = {
  crowdsec: 'detect-only',
  rateLimit: 'off',
  membersMagicLinkRateLimit: 'off',
};

const STATE_HOSTNAME = 'state.branchleft.co.uk';
const registryEntry = sites.find((entry) => entry.name === 'state-gateway');

/**
 * The registry entry with the two values this repository does not hold (the
 * gateway host's address and the state listener's port) filled in by a
 * stand-in. The stand-in is `app1` on an unused port: the real host is not in
 * the address plan yet, and this test must not invent an address for it.
 */
const named = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  ...(registryEntry as EdgeSite),
  hostnames: [STATE_HOSTNAME],
  privateUpstream: { host: 'app1', port: 9998 },
  ...overrides,
});

const GATEWAY_ADDRESS = '10.20.1.100:9998';

const renderWith = (posture: EdgePosture, gateway: EdgeSite = named()): string =>
  renderCaddyfile([...sites, gateway], hostRedirects, posture, staticSites);

/** The text of the top-level block whose address line is exactly `address`. */
function blockOf(rendered: string, address: string): string {
  const start = rendered.indexOf(`\n${address} {`);
  expect(start, `block ${address} must be rendered`).toBeGreaterThanOrEqual(0);
  return rendered.slice(start, rendered.indexOf('\n}\n', start));
}

const gatewayBlock = (posture: EdgePosture = ENFORCING): string =>
  blockOf(renderWith(posture), STATE_HOSTNAME);

/** The regular expression a named matcher in the block carries, as a JavaScript one. */
function regexpOf(block: string, matcher: string): RegExp {
  const found = new RegExp(`@${matcher} \\{[^}]*?path_regexp (\\S+)`).exec(block);
  expect(found, `matcher @${matcher} must carry a path_regexp`).not.toBeNull();
  return new RegExp(found?.[1] as string);
}

describe('the registry entry while the gateway host and port are not in the repository', () => {
  it('exists, with the 8 MiB ceiling and the gateway marker', () => {
    expect(registryEntry).toBeDefined();
    expect(registryEntry?.signedObjectGateway).toBe(true);
    expect(registryEntry?.requestBodyMaxSize).toBe('8MiB');
    expect(registryEntry?.backend).toBe('other');
  });

  it('claims no hostname and has no upstream, so it serves nothing and asks for no certificate', () => {
    expect(registryEntry?.hostnames).toEqual([]);
    expect(registryEntry?.privateUpstream).toBeUndefined();
    expect(servableSites(sites).map((entry) => entry.name)).not.toContain('state-gateway');
  });

  it('adds nothing to the rendered edge configuration', () => {
    const rendered = renderCaddyfile(sites, hostRedirects, POSTURE, staticSites);
    expect(rendered).not.toContain('state-gateway');
    expect(rendered).not.toContain(STATE_HOSTNAME);
    expect(rendered).not.toContain('@gateway');
    expect(rendered).toBe(
      renderCaddyfile(
        sites.filter((entry) => entry.name !== 'state-gateway'),
        hostRedirects,
        POSTURE,
        staticSites
      )
    );
  });

  it('once set, names the ruled hostname and an upstream the renderer resolves', () => {
    if (registryEntry?.privateUpstream === undefined) return;
    expect(registryEntry.hostnames).toEqual([STATE_HOSTNAME]);
    const { host, port } = registryEntry.privateUpstream;
    expect(() => resolvePrivateAddress(host, port)).not.toThrow();
  });
});

describe('the state hostname in the zone', () => {
  const zone = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'dns', ZONE_FILES[0].file), 'utf8')
  ) as {
    zone: string;
    rrsets: { name: string; type: string; values: string[] }[];
    probe_names: string[];
  };
  const addressesOf = (owner: string): string[] =>
    zone.rrsets.filter((r) => r.name === owner && r.type === 'A').flatMap((r) => r.values);

  it('is the ruled name in the branchleft.co.uk zone', () => {
    expect(zone.zone).toBe('branchleft.co.uk');
    expect(STATE_HOSTNAME).toBe(`state.${zone.zone}`);
  });

  it('has one A record, at the address the edge hostnames in the same zone use', () => {
    const edge = new Set(
      ['status', 'ntfy', 'console', 'cloud'].flatMap((owner) => addressesOf(owner))
    );
    expect(edge.size).toBe(1);
    expect(addressesOf('state')).toEqual([...edge]);
  });

  it('is in probe_names, so the zone comparison probes it at both providers', () => {
    expect(zone.probe_names).toContain('state');
  });

  it('carries no record of another type, so it points at the edge and nowhere else', () => {
    expect(zone.rrsets.filter((r) => r.name === 'state').map((r) => r.type)).toEqual(['A']);
  });
});

describe('a rendered state gateway block', () => {
  it('caps the request body at 8 MiB, ahead of the proxy', () => {
    const block = gatewayBlock();
    expect(block).toMatch(/request_body \{\s+max_size 8MiB\s+\}/);
    expect(block.indexOf('max_size 8MiB')).toBeLessThan(block.indexOf('reverse_proxy'));
  });

  it('refuses to render with no body ceiling at all', () => {
    expect(() => renderWith(ENFORCING, named({ requestBodyMaxSize: undefined }))).toThrow(
      /declares no requestBodyMaxSize/
    );
  });

  it('terminates TLS at the floor and sets HSTS first in the route', () => {
    const block = gatewayBlock();
    expect(block).toContain('protocols tls1.2 tls1.3');
    const hsts = block.indexOf('header Strict-Transport-Security');
    expect(hsts).toBeGreaterThan(-1);
    expect(hsts).toBeLessThan(block.indexOf('request_body'));
  });

  it('logs to the access log CrowdSec reads, like every other public hostname', () => {
    expect(gatewayBlock()).toContain('output file /var/log/caddy/access.log');
  });

  it('carries the general per-IP throttle, CrowdSec and AppSec in front of the proxy', () => {
    const block = gatewayBlock(ENFORCING);
    const general = /rate_limit \{\s+zone state-gateway_per_ip \{((?:[^\n]*\n){4})/.exec(block);
    expect(general, 'the general rate_limit must be rendered').not.toBeNull();
    expect(general?.[1]).toContain('key {http.request.remote.host}');
    expect(general?.[1]).toContain(`window ${RATE_LIMIT_WINDOW_SECONDS}s`);
    expect(general?.[1]).toContain(`events ${RATE_LIMIT_EVENTS}`);
    const proxy = block.indexOf('reverse_proxy');
    expect(block.indexOf('rate_limit {')).toBeLessThan(block.indexOf('crowdsec\n'));
    for (const marker of ['rate_limit {', 'crowdsec\n', 'appsec\n']) {
      expect(block.indexOf(marker), marker).toBeGreaterThan(-1);
      expect(block.indexOf(marker), marker).toBeLessThan(proxy);
    }
  });

  it('gives the throttle a zone of its own, shared with no other block', () => {
    const rendered = renderWith(ENFORCING);
    expect(rendered.split('zone state-gateway_per_ip {').length - 1).toBe(1);
  });

  it('follows the committed posture, as every other hostname does', () => {
    const block = gatewayBlock(DETECT_ONLY);
    expect(block).not.toContain('rate_limit');
    expect(blockOf(renderWith(POSTURE), STATE_HOSTNAME)).toContain('crowdsec');
  });

  it('proxies one upstream, the private address the entry names, and no other', () => {
    const block = gatewayBlock();
    expect(block.match(/reverse_proxy/g)).toHaveLength(1);
    expect(block).toContain(`reverse_proxy @gateway ${GATEWAY_ADDRESS} {`);
    expect(block.match(/\d+\.\d+\.\d+\.\d+:\d+/g)).toEqual([GATEWAY_ADDRESS]);
  });

  it('bounds the upstream dial and the wait for the first response byte', () => {
    expect(gatewayBlock()).toMatch(
      /transport http \{\s+dial_timeout 5s\s+response_header_timeout 30s\s+\}/
    );
  });

  it('forwards the request as the client signed it: no header, path or query is changed', () => {
    // From the first matcher on, so the access-log filter above it (which
    // redacts, and so names `uri`) is not read as a request rewrite.
    const full = gatewayBlock();
    const block = full.slice(full.indexOf('@gateway_probe_write {'));
    for (const forbidden of [
      'header_up',
      'header_down',
      'request_header',
      'rewrite',
      'uri ',
      'handle_path',
      'strip_prefix',
      'redir',
      'encode',
      'bl_break_glass',
    ]) {
      expect(block, `the block must not use ${forbidden}`).not.toContain(forbidden);
    }
  });

  it('answers every proxied response and the edge own 404 and 405 with Cache-Control: no-store', () => {
    const block = gatewayBlock();
    expect(block).toContain('header >Cache-Control "no-store"');
    expect(block.indexOf('header >Cache-Control')).toBeLessThan(block.indexOf('respond'));
    expect(block.indexOf('header >Cache-Control')).toBeLessThan(block.indexOf('reverse_proxy'));
  });

  it('configures no cache of any kind', () => {
    expect(renderWith(ENFORCING)).not.toMatch(/^\s*cache\b/m);
  });

  it('forwards only the five methods an object store call uses', () => {
    const block = gatewayBlock();
    expect(block).toMatch(/@gateway \{\s+method GET HEAD PUT POST DELETE\s+path_regexp /);
    expect(block).toMatch(/@gateway_wrong_method \{\s+not method GET HEAD PUT POST DELETE\s+\}/);
    expect(block).toContain('header @gateway_wrong_method Allow "GET, HEAD, PUT, POST, DELETE"');
    expect(block).toContain('respond @gateway_wrong_method 405');
  });

  it('serves the two probe paths to reads only', () => {
    const block = gatewayBlock();
    expect(block).toMatch(
      /@gateway_probe_write \{\s+method PUT POST DELETE\s+path \/healthz \/readyz\s+\}/
    );
    expect(block).toContain('header @gateway_probe_write Allow "GET, HEAD"');
    expect(block).toContain('respond @gateway_probe_write 405');
    expect(block.indexOf('respond @gateway_probe_write')).toBeLessThan(
      block.indexOf('reverse_proxy')
    );
  });

  it('forwards a path-style request or a probe path, and nothing else', () => {
    const pathStyle = regexpOf(gatewayBlock(), 'gateway');
    for (const allowed of [
      '/bucket',
      '/bucket/',
      '/bucket/prefix/.pulumi/meta.yaml',
      '/healthz',
      '/readyz',
    ]) {
      expect(pathStyle.test(allowed), allowed).toBe(true);
    }
    for (const refused of ['/', '', '//bucket', 'bucket', '//']) {
      expect(pathStyle.test(refused), `"${refused}"`).toBe(false);
    }
  });

  it('refuses a dot segment in the raw path with 400, before anything is proxied', () => {
    const block = gatewayBlock();
    const found =
      /@gateway_dot_segments \{\s+expression `\{http\.request\.orig_uri\}\.matches\('([^']+)'\)`/.exec(
        block
      );
    expect(
      found,
      'the dot-segment matcher must be an expression on the original URI'
    ).not.toBeNull();
    const dots = new RegExp(found?.[1] as string);
    // A placeholder reads `{`, so the expression carries no brace.
    expect(found?.[1]).not.toMatch(/[{}]/);
    for (const refused of [
      '/b/..',
      '/b/../c',
      '/b/./c',
      '/..',
      '/./b',
      '/b/c/..',
      '/b/%2e%2e/c',
      '/b/%2E/c',
      '/b/.%2e',
      '/b/..?x=1',
    ]) {
      expect(dots.test(refused), refused).toBe(true);
    }
    for (const fine of [
      '/b/..x',
      '/b/a..b',
      '/b/.hidden',
      '/b/c.d',
      '/b/...',
      '/b?prefix=a/../b',
      '/b/k?prefix=%2e%2e/',
    ]) {
      expect(dots.test(fine), fine).toBe(false);
    }
    expect(block).not.toMatch(/@gateway_dot_segments \{\s+path_regexp/);
    expect(block).toContain('respond @gateway_dot_segments 400');
    expect(block.indexOf('respond @gateway_dot_segments')).toBeLessThan(
      block.indexOf('reverse_proxy')
    );
  });

  it('ends with a matcher-less 404, so a case nothing above answered fails closed', () => {
    const block = gatewayBlock();
    const routeLines = block.trim().split('\n');
    expect(routeLines.at(-2)?.trim()).toBe('respond 404');
    expect(block.indexOf('respond 404')).toBeGreaterThan(block.indexOf('reverse_proxy'));
  });

  it('cannot be combined with a webhook, Ghost or Nextcloud site, or the exemptions', () => {
    for (const overrides of [
      { inboundWebhookPath: '/webhook' },
      { discardRoute: '/x' },
      { injectionWafPreviewOnly: true },
      { trustedSession: 'ghost-staff' as const },
      { backend: 'ghost' as const },
      { backend: 'nextcloud' as const },
    ] satisfies Partial<EdgeSite>[]) {
      expect(() => renderWith(ENFORCING, named(overrides)), JSON.stringify(overrides)).toThrow(
        /is a signed object gateway and cannot also be/
      );
    }
  });

  it('renders no gateway block for an entry with no upstream', () => {
    const rendered = renderWith(ENFORCING, named({ privateUpstream: undefined }));
    expect(rendered).not.toContain(STATE_HOSTNAME);
  });
});

describe('the state gateway block among the others', () => {
  it('leaves every other block exactly as it was', () => {
    const rendered = renderWith(ENFORCING);
    const without = renderCaddyfile(sites, hostRedirects, ENFORCING, staticSites);
    const other = (text: string) =>
      text.split('\n\n').filter((part) => !part.startsWith(`${STATE_HOSTNAME} {`));
    expect(other(rendered)).toEqual(other(without));
  });

  it('names no part of the Ghost, login-mail or webhook routes', () => {
    const block = gatewayBlock();
    expect(block).not.toContain('members_magic_link');
    expect(block).not.toContain('send-magic-link');
    expect(block).not.toContain('ghost');
    expect(block).not.toContain('@webhook');
  });

  it('shares its upstream with no other site and never fronts the mail host', () => {
    const others = servableSites(sites).map((entry) =>
      resolvePrivateAddress(entry.privateUpstream!.host, entry.privateUpstream!.port)
    );
    expect(others).not.toContain(GATEWAY_ADDRESS);
    expect(() => resolvePrivateAddress('mx1', 443)).toThrow(/not a backend this edge proxies to/);
  });
});

describe('the probe target of a gateway', () => {
  it('is its health path, because it answers 404 at the root by design', () => {
    expect(blackboxTargets([named()])).toEqual([`https://${STATE_HOSTNAME}/healthz`]);
  });

  it('leaves every other site probed at its root, and an unset gateway unprobed', () => {
    expect(blackboxTargets([named({ signedObjectGateway: undefined })])).toEqual([
      `https://${STATE_HOSTNAME}`,
    ]);
    expect(blackboxTargets(sites).some((target) => target.includes('state'))).toBe(false);
  });
});

describe('the configuration CI loads before anything depends on it', () => {
  it('renders a state gateway on its own, the shape the committed edge will gain once it is set', async () => {
    await expect(renderCaddyfile([named()], [], ENFORCING)).toMatchFileSnapshot(
      './validation/Caddyfile.state-gateway'
    );
  });
});
