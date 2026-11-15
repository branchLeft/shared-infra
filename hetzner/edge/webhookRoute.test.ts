import { describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import {
  POSTURE,
  RATE_LIMIT_EVENTS,
  RATE_LIMIT_WINDOW_SECONDS,
  WEBHOOK_RATE_LIMIT_EVENTS,
  WEBHOOK_RATE_LIMIT_WINDOW_SECONDS,
  type EdgePosture,
} from './posture';
import { renderCaddyfile, resolvePrivateAddress, servableSites } from './render';

// Why: see render.md section "siteBlock: inbound webhook".

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

const registryEntry = sites.find((entry) => entry.name === 'sweego-webhook');

/**
 * The registry entry with the two values the owner has not named filled in by
 * a stand-in. The stand-in upstream is `ops1`, not the real `edge1`, because
 * the renderer refuses `edge1` on every port but the pager's; that refusal is
 * asserted below rather than worked around.
 */
const named = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  ...(registryEntry as EdgeSite),
  hostnames: ['hooks.invalid'],
  privateUpstream: { host: 'ops1', port: 9999 },
  ...overrides,
});

const WEBHOOK_ADDRESS = '10.20.1.50:9999';

const renderWith = (posture: EdgePosture, webhook: EdgeSite = named()): string =>
  renderCaddyfile([...sites, webhook], hostRedirects, posture, staticSites);

/** The text of the top-level block whose address line is exactly `address`. */
function blockOf(rendered: string, address: string): string {
  const start = rendered.indexOf(`\n${address} {`);
  expect(start, `block ${address} must be rendered`).toBeGreaterThanOrEqual(0);
  return rendered.slice(start, rendered.indexOf('\n}\n', start));
}

const webhookBlock = (posture: EdgePosture = ENFORCING): string =>
  blockOf(renderWith(posture), 'hooks.invalid');

describe('the registry entry while the owner has not named the hostname and port', () => {
  it('exists, with the path and the 16 KiB ceiling', () => {
    expect(registryEntry).toBeDefined();
    expect(registryEntry?.inboundWebhookPath).toBe('/webhook');
    expect(registryEntry?.requestBodyMaxSize).toBe('16KiB');
  });

  it('claims no hostname and has no upstream, so it serves nothing and asks for no certificate', () => {
    expect(registryEntry?.hostnames).toEqual([]);
    expect(registryEntry?.privateUpstream).toBeUndefined();
    expect(servableSites(sites).map((entry) => entry.name)).not.toContain('sweego-webhook');
  });

  it('adds nothing to the rendered edge configuration', () => {
    const rendered = renderCaddyfile(sites, hostRedirects, POSTURE, staticSites);
    expect(rendered).not.toContain('sweego-webhook');
    expect(rendered).not.toContain('@webhook');
    expect(rendered).toBe(
      renderCaddyfile(
        sites.filter((entry) => entry.name !== 'sweego-webhook'),
        hostRedirects,
        POSTURE,
        staticSites
      )
    );
  });

  it('once named, proxies to edge1 and nowhere else', () => {
    if (registryEntry?.privateUpstream === undefined) return;
    expect(registryEntry.privateUpstream.host).toBe('edge1');
    expect(registryEntry.hostnames.length).toBeGreaterThan(0);
  });
});

describe('edge1 as an upstream', () => {
  it('is refused on a port the pager does not use, so naming the port needs a deliberate renderer change', () => {
    expect(() => resolvePrivateAddress('edge1', 8088)).toThrow(
      /not a backend this edge proxies to/
    );
  });
});

describe('a rendered webhook block', () => {
  it('caps the request body at 16 KiB', () => {
    expect(webhookBlock()).toMatch(/request_body \{\s+max_size 16KiB\s+\}/);
  });

  it('refuses to render with no body ceiling at all', () => {
    expect(() => renderWith(ENFORCING, named({ requestBodyMaxSize: undefined }))).toThrow(
      /declares no requestBodyMaxSize/
    );
  });

  it('carries a dedicated per-IP zone keyed on the direct peer, at the committed budget', () => {
    const block = webhookBlock();
    const dedicated = /rate_limit @webhook \{\s+zone (\S+) \{((?:[^\n]*\n){4})/.exec(block);
    expect(dedicated, 'the dedicated rate_limit must be rendered').not.toBeNull();
    expect(dedicated?.[1]).toBe('sweego-webhook_inbound_per_ip');
    expect(dedicated?.[2]).toContain('key {http.request.remote.host}');
    expect(dedicated?.[2]).toContain(`window ${WEBHOOK_RATE_LIMIT_WINDOW_SECONDS}s`);
    expect(dedicated?.[2]).toContain(`events ${WEBHOOK_RATE_LIMIT_EVENTS}`);
  });

  it('is much tighter than the general throttle', () => {
    expect(WEBHOOK_RATE_LIMIT_EVENTS / WEBHOOK_RATE_LIMIT_WINDOW_SECONDS).toBeLessThan(
      RATE_LIMIT_EVENTS / RATE_LIMIT_WINDOW_SECONDS / 4
    );
  });

  it('keeps the general throttle, unchanged, ahead of the dedicated one', () => {
    const block = webhookBlock();
    const general = /rate_limit \{\s+zone sweego-webhook_per_ip \{((?:[^\n]*\n){4})/.exec(block);
    expect(general, 'the general rate_limit must be rendered').not.toBeNull();
    expect(general?.[1]).toContain(`window ${RATE_LIMIT_WINDOW_SECONDS}s`);
    expect(general?.[1]).toContain(`events ${RATE_LIMIT_EVENTS}`);
    expect(block.indexOf('rate_limit {')).toBeLessThan(block.indexOf('rate_limit @webhook {'));
  });

  it('keeps the dedicated zone under every posture, because it guards a public route', () => {
    for (const posture of [ENFORCING, DETECT_ONLY]) {
      expect(webhookBlock(posture)).toContain('rate_limit @webhook {');
    }
  });

  it('runs the body cap and both throttles before anything is proxied', () => {
    const block = webhookBlock();
    const proxy = block.indexOf('reverse_proxy');
    for (const marker of ['max_size 16KiB', 'rate_limit {', 'rate_limit @webhook {']) {
      expect(block.indexOf(marker), marker).toBeGreaterThan(-1);
      expect(block.indexOf(marker), marker).toBeLessThan(proxy);
    }
  });

  it('proxies POST on the one path and nothing else', () => {
    const block = webhookBlock();
    expect(block.match(/reverse_proxy/g)).toHaveLength(1);
    expect(block).toContain(`reverse_proxy @webhook ${WEBHOOK_ADDRESS}`);
    expect(block).toMatch(/@webhook \{\s+method POST\s+path \/webhook\s+\}/);
    const paths = [...block.matchAll(/^\s+(?:not )?path (.+)$/gm)].map(([, path]) => path);
    expect(paths).toEqual(['/webhook', '/webhook']);
  });

  it('answers any other method on the path with 405, and every other request with 404 last', () => {
    const block = webhookBlock();
    expect(block).toMatch(/@webhook_wrong_method \{\s+not method POST\s+path \/webhook\s+\}/);
    expect(block).toContain('header @webhook_wrong_method Allow POST');
    expect(block).toContain('respond @webhook_wrong_method 405');
    // The block ends with the route's closing brace; the 404 is the line before it.
    const routeLines = block.trim().split('\n');
    expect(routeLines.at(-2)?.trim()).toBe('respond 404');
    expect(block.indexOf('respond 404')).toBeGreaterThan(block.indexOf('reverse_proxy'));
  });

  it('routes only the upstream the entry names, never a second port on that host', () => {
    expect(webhookBlock().match(/\d+\.\d+\.\d+\.\d+:\d+/g)).toEqual([WEBHOOK_ADDRESS]);
  });

  it('refuses a path that could widen the match', () => {
    for (const path of ['/webhook/*', '/', 'webhook', '/web hook', '/webhook{x}']) {
      expect(() => renderWith(ENFORCING, named({ inboundWebhookPath: path }))).toThrow(
        /plain literal path/
      );
    }
  });

  it('cannot be combined with a discard route or the authoring exemption', () => {
    expect(() => renderWith(ENFORCING, named({ discardRoute: '/x' }))).toThrow(
      /cannot also declare/
    );
    expect(() => renderWith(ENFORCING, named({ injectionWafPreviewOnly: true }))).toThrow(
      /cannot also declare/
    );
  });
});

describe('the login-mail path and the webhook route', () => {
  const rendered = renderWith(ENFORCING);
  const block = blockOf(rendered, 'hooks.invalid');

  it('share no zone: every zone the webhook block names appears in no other block', () => {
    const zones = [...block.matchAll(/zone (\S+) \{/g)].map(([, zone]) => zone);
    expect(zones.length).toBeGreaterThanOrEqual(2);
    for (const zone of zones) {
      const everywhere = rendered.split(`zone ${zone} {`).length - 1;
      expect(everywhere, `zone ${zone}`).toBe(1);
    }
  });

  it('names no part of the login-mail route', () => {
    expect(block).not.toContain('members_magic_link');
    expect(block).not.toContain('send-magic-link');
    expect(block).not.toContain('ghost');
  });

  it('shares no queue or process: its upstream is its own address, on no other site and never the mail host', () => {
    const others = servableSites(sites).map((entry) =>
      resolvePrivateAddress(entry.privateUpstream!.host, entry.privateUpstream!.port)
    );
    expect(others).not.toContain(WEBHOOK_ADDRESS);
    expect(() => resolvePrivateAddress('mx1', 587)).toThrow(/not a backend this edge proxies to/);
  });

  it('leaves every other block exactly as it was', () => {
    const without = renderCaddyfile(sites, hostRedirects, ENFORCING, staticSites);
    const other = (text: string) =>
      text.split('\n\n').filter((part) => !part.startsWith('hooks.invalid'));
    expect(other(rendered)).toEqual(other(without));
  });
});

describe('the configuration CI loads before anything depends on it', () => {
  it('renders a webhook site on its own, the shape the committed edge will gain once it is named', async () => {
    await expect(renderCaddyfile([named()], [], ENFORCING)).toMatchFileSnapshot(
      './validation/Caddyfile.webhook'
    );
  });
});
