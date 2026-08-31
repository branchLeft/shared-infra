import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { hostRedirects, sites } from '../../sites';
import type { EdgeSite, HostRedirect } from '../../siteTypes';
import {
  MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS,
  MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS,
  POSTURE,
  RATE_LIMIT_EVENTS,
  RATE_LIMIT_WINDOW_SECONDS,
  TLS_PROTOCOLS,
} from './posture';
import type { EdgePosture } from './posture';
import {
  renderAppsecAcquisition,
  renderCaddyfile,
  renderCaddyLogAcquisition,
  resolvePrivateAddress,
  servableSites,
} from './render';

/**
 * The file-snapshot assertions at the bottom are not snapshots in the usual
 * sense: `stack/` is the directory copied onto the edge host, so those three
 * files *are* the deployment. Writing them through Vitest is what makes
 * "regenerate" and "prove the committed copy is current" the same mechanism,
 * with no second tool to install and nothing that can render on one machine and
 * not another. `npm run render` updates them; `npm test` fails if they drift.
 */

const DETECT_ONLY: EdgePosture = {
  crowdsec: 'detect-only',
  rateLimit: 'off',
  membersMagicLinkRateLimit: 'off',
};
const ENFORCING: EdgePosture = {
  crowdsec: 'enforcing',
  rateLimit: 'enforcing',
  membersMagicLinkRateLimit: 'enforcing',
};

const site = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  name: 'example',
  hostnames: ['example.test'],
  cloudRunService: 'example-service',
  privateUpstream: { host: 'app1', port: 2368 },
  ...overrides,
});

const render = (
  posture: EdgePosture,
  entries: EdgeSite[] = [site()],
  redirects: HostRedirect[] = []
) => renderCaddyfile(entries, redirects, posture);

describe('resolvePrivateAddress', () => {
  it('resolves an address-plan host name to its fixed private address', () => {
    expect(resolvePrivateAddress('app1', 2368)).toBe('10.20.1.100:2368');
    expect(resolvePrivateAddress('db1', 3306)).toBe('10.20.1.20:3306');
  });

  it('refuses a host that is not in the address plan', () => {
    expect(() => resolvePrivateAddress('app9', 2368)).toThrow(/unknown upstream host app9/);
  });

  it('refuses the mail host, which this edge never fronts', () => {
    expect(() => resolvePrivateAddress('mx1', 443)).toThrow(/not a backend this edge proxies to/);
  });

  it.each([0, -1, 65536, 1.5, Number.NaN])('refuses port %s', (port) => {
    expect(() => resolvePrivateAddress('app1', port)).toThrow(/between 1 and 65535/);
  });
});

describe('sites without a private upstream', () => {
  it('are not rendered at all, so the edge asks for no certificate it cannot serve', () => {
    const pending = site({ hostnames: ['pending.test'], privateUpstream: undefined });
    expect(servableSites([pending])).toEqual([]);
    expect(render(ENFORCING, [pending])).not.toContain('pending.test');
  });

  it('take their redirect sources with them', () => {
    const pending = site({
      hostnames: ['pending.test', 'www.pending.test'],
      privateUpstream: undefined,
    });
    const rendered = render(
      ENFORCING,
      [pending],
      [{ from: 'www.pending.test', to: 'pending.test' }]
    );
    expect(rendered).not.toContain('www.pending.test');
  });

  it('leaves the real registry renderable whatever it currently declares', () => {
    for (const entry of sites) {
      const upstream = entry.privateUpstream;
      if (upstream !== undefined) {
        expect(() => resolvePrivateAddress(upstream.host, upstream.port)).not.toThrow();
      }
    }
    expect(() => renderCaddyfile(sites, hostRedirects, POSTURE)).not.toThrow();
  });
});

describe('the rendered Caddyfile', () => {
  it('serves a site at its hostnames over its private upstream', () => {
    const rendered = render(ENFORCING, [
      site({ hostnames: ['a.test', 'b.test'], privateUpstream: { host: 'app2', port: 3000 } }),
    ]);
    expect(rendered).toContain('a.test, b.test {');
    expect(rendered).toContain('reverse_proxy 10.20.1.101:3000');
  });

  it('sets the TLS 1.2 floor on every site block', () => {
    const rendered = render(ENFORCING);
    expect(rendered).toContain('protocols tls1.2 tls1.3');
  });

  it('renders a redirect source as its own block rather than as a served hostname', () => {
    const rendered = render(
      ENFORCING,
      [site({ hostnames: ['apex.test', 'www.apex.test'] })],
      [{ from: 'www.apex.test', to: 'apex.test' }]
    );
    expect(rendered).toContain('apex.test {');
    expect(rendered).toContain('www.apex.test {');
    expect(rendered).toContain('redir https://apex.test{uri} permanent');
    expect(rendered).not.toContain('apex.test, www.apex.test');
  });

  it('refuses a hostname that could break out of the site address it is written into', () => {
    for (const hostname of ['bad host.test', 'a.test {\n\trespond 200', 'a.test, evil.test']) {
      expect(() => render(ENFORCING, [site({ hostnames: [hostname] })])).toThrow(
        /not a hostname this renderer will write/
      );
    }
  });

  it('always carries a loopback probe listener so the posture is observable', () => {
    expect(render(DETECT_ONLY)).toContain(':8080 {');
    expect(render(ENFORCING)).toContain(':8080 {');
  });

  it('always carries a metrics listener, independent of posture', () => {
    expect(render(DETECT_ONLY)).toContain(':9091 {');
    expect(render(ENFORCING)).toContain(':9091 {');
  });

  it('serves metrics with no protection chain in front of it', () => {
    const rendered = render(ENFORCING);
    const block = rendered.split(':9091 {')[1]?.split('\n}')[0] ?? '';
    expect(block).toContain('metrics');
    expect(block).not.toContain('rate_limit');
    expect(block).not.toContain('crowdsec');
    expect(block).not.toContain('appsec');
  });

  it('turns on request-metrics collection globally, alongside the HTTP/3 option it shares a block with', () => {
    const rendered = render(DETECT_ONLY);
    expect(rendered).toMatch(/servers \{\n\t\tprotocols h1 h2\n\t\tmetrics\n\t\}/);
  });

  it('keeps probe traffic out of the log CrowdSec parses', () => {
    const rendered = render(ENFORCING);
    expect(rendered).toContain('output file /var/log/caddy/probe.log');
    expect(rendered).toContain('output file /var/log/caddy/access.log');
  });

  it('keys the throttle on the direct peer, not on a header a client controls', () => {
    expect(render(ENFORCING)).toContain('key {http.request.remote.host}');
    expect(render(ENFORCING)).not.toContain('client_ip');
  });

  it('reproduces the captured baseline throttle', () => {
    const rendered = render(ENFORCING);
    expect(rendered).toContain(`events ${RATE_LIMIT_EVENTS}`);
    expect(rendered).toContain(`window ${RATE_LIMIT_WINDOW_SECONDS}s`);
    expect(RATE_LIMIT_EVENTS).toBe(200);
    expect(RATE_LIMIT_WINDOW_SECONDS).toBe(60);
  });

  it('throttles first (general, then members magic-link), then checks IP decisions, then inspects, then proxies', () => {
    const chain = render(ENFORCING)
      .split('\n')
      .filter((line) => /^\t\t(rate_limit|crowdsec|appsec|reverse_proxy)\b/.test(line))
      .map((line) => line.trim().split(' ')[0]);
    expect(chain.slice(0, 5)).toEqual([
      'rate_limit',
      'rate_limit',
      'crowdsec',
      'appsec',
      'reverse_proxy',
    ]);
  });

  it('throttles the members magic-link path far below the general per-site threshold', () => {
    const rendered = render(ENFORCING);
    expect(rendered).toContain('@members_magic_link {');
    expect(rendered).toContain('method POST');
    expect(rendered).toContain('rate_limit @members_magic_link {');
    expect(rendered).toContain(`events ${MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS}`);
    expect(rendered).toContain(`window ${MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS}s`);
    expect(MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS).toBeLessThan(RATE_LIMIT_EVENTS / 10);
  });

  it('matches both the bare path and its trailing-slash form, exactly -- not a prefix wildcard', () => {
    // Express's default router (strict: false) treats a trailing slash as the
    // same route, so a matcher that only listed the bare path would let an
    // attacker who appends '/' spend the general 200/60s zone instead of this
    // one. A '*' suffix would close that gap too, but would also swallow any
    // longer, unrelated path sharing this prefix -- exact enumeration is the
    // narrower fix.
    const rendered = render(ENFORCING);
    const matcherBlock = rendered.split('@members_magic_link {')[1]?.split('\n\t}')[0] ?? '';
    expect(matcherBlock).toContain(
      'path /members/api/send-magic-link /members/api/send-magic-link/'
    );
    expect(matcherBlock).not.toContain('*');
  });

  it('needs no case-variant path listed -- Caddy path matching is case-insensitive on the pinned 2.11.4', () => {
    // Not exercised by the renderer's own output (there is nothing case-variant
    // to assert in a string it emits); recorded here as the test that would
    // need to change, and the comment that would need revisiting, if the
    // Dockerfile's CADDY_VERSION ever moves.
    const rendered = render(ENFORCING);
    expect(rendered).not.toMatch(/path .*[A-Z].*[sS]end-[mM]agic-[lL]ink/);
  });

  it('declares the same members magic-link zone name in every site, unlike the per-site zone above', () => {
    // Caddy has no "reference a zone declared elsewhere" syntax, so each site's
    // route carries its own full declaration -- but caddy-ratelimit's zone
    // registry is keyed by name and shared process-wide (`LoadOrStore`), so
    // repeating the identical name attaches every site to the same counter
    // rather than giving each its own, which is what makes this control see a
    // client across tenant hostnames. `zone one_per_ip` / `zone two_per_ip`
    // below prove the *general* throttle does the opposite on purpose.
    const rendered = render(ENFORCING, [
      site({ name: 'one', hostnames: ['one.test'] }),
      site({ name: 'two', hostnames: ['two.test'] }),
    ]);
    // Four, not two: both loopback probes below carry the same matcher and
    // zone so the throttle can be trip-tested before any site serves the path.
    const zoneMatches = rendered.match(/zone members_magic_link_per_ip \{/g) ?? [];
    expect(zoneMatches).toHaveLength(4);
    expect(rendered).toContain('zone one_per_ip {');
    expect(rendered).toContain('zone two_per_ip {');
  });

  it('carries the members magic-link throttle on the loopback probe too, so it can be trip-tested before any site serves the path', () => {
    const rendered = render(ENFORCING);
    const probeBlockText = rendered.split('\n:8080 {')[1]?.split('\n}')[0] ?? '';
    expect(probeBlockText).toContain('@members_magic_link {');
    expect(probeBlockText).toContain('rate_limit @members_magic_link {');
  });

  it('renders a host-qualified probe on the same port, so the throttle can be tripped through a site block and not only on a bare port', () => {
    // A bare `:8080` address matches every Host, so tripping the throttle
    // there exercises no host routing whatsoever. This second address is the
    // only way to prove, before a tenant hostname resolves here, that a
    // request reaches the throttle *through* Caddy's site selection -- the
    // path a real request actually takes.
    const rendered = render(ENFORCING);
    const hostProbe = rendered.split('http://edge-probe.invalid:8080 {')[1]?.split('\n}')[0] ?? '';
    expect(hostProbe).toContain('@members_magic_link {');
    expect(hostProbe).toContain('rate_limit @members_magic_link {');
    expect(hostProbe).toContain('respond 204');
  });

  it('gives the host-qualified probe the same global magic-link zone but its own general zone', () => {
    // The shared magic-link zone is the property under test in §8b(4): a
    // budget spent on the bare port must already be spent when the same client
    // arrives on the host-qualified address, which is exactly what Ghost's
    // per-instance limiter cannot do. The *general* throttle keeps separate
    // zones, matching how real sites treat it.
    const rendered = render({ ...ENFORCING, rateLimit: 'enforcing' });
    const hostProbe = rendered.split('http://edge-probe.invalid:8080 {')[1]?.split('\n}')[0] ?? '';
    const barePort = rendered.split('\n:8080 {')[1]?.split('\n}')[0] ?? '';
    expect(hostProbe).toContain('zone members_magic_link_per_ip {');
    expect(barePort).toContain('zone members_magic_link_per_ip {');
    expect(hostProbe).toContain('zone probe_host_per_ip {');
    expect(barePort).toContain('zone probe_per_ip {');
  });

  it('never renders the probe hostname as a TLS site, so no CA is ever asked to validate an unresolvable name', () => {
    // `.invalid` is RFC 2606 reserved and can never be validated. Without the
    // explicit `http://` scheme Caddy would try ACME for it on every start.
    const rendered = render(ENFORCING);
    expect(rendered).toContain('http://edge-probe.invalid:8080 {');
    expect(rendered).not.toMatch(/^edge-probe\.invalid/m);
  });

  it('renders no members magic-link throttle when both rate limiters are off', () => {
    const rendered = render(DETECT_ONLY);
    expect(rendered).not.toContain('members_magic_link');
  });

  /**
   * The two throttles are the same Caddy module protecting different things at
   * opposite risk profiles, and they were briefly gated behind one flag — the
   * magic-link directive nested inside the general one's conditional. That made
   * the narrow, well-derived control unreachable without also enabling a
   * general threshold inherited from a Cloud Armor rule that has never
   * enforced. These four assertions are what stop them being recoupled: each
   * posture is rendered and checked for the presence of one and the absence of
   * the other, in both directions.
   */
  describe('the two throttles are independently switchable', () => {
    const MAGIC_LINK_ONLY: EdgePosture = {
      crowdsec: 'detect-only',
      rateLimit: 'off',
      membersMagicLinkRateLimit: 'enforcing',
    };
    const GENERAL_ONLY: EdgePosture = {
      crowdsec: 'detect-only',
      rateLimit: 'enforcing',
      membersMagicLinkRateLimit: 'off',
    };

    it('renders the magic-link throttle with the general one off — the committed posture', () => {
      const rendered = render(MAGIC_LINK_ONLY);
      expect(rendered).toContain('rate_limit @members_magic_link {');
      expect(rendered).toContain('zone members_magic_link_per_ip {');
      // `rate_limit {` matches only the general, matcher-less directive: the
      // magic-link one always renders as `rate_limit @members_magic_link {`.
      expect(rendered).not.toContain('rate_limit {');
    });

    /**
     * The matcher is gated separately from the directive that references it, so
     * this is the assertion that catches the two drifting apart. A rendered
     * `rate_limit @members_magic_link` whose `@members_magic_link` matcher was
     * not emitted is a Caddyfile that fails to load — the flip would take the
     * whole edge down rather than throttle one path.
     */
    it('emits the magic-link matcher wherever it emits the directive that references it', () => {
      const rendered = render(MAGIC_LINK_ONLY);
      const directives = (rendered.match(/rate_limit @members_magic_link \{/g) ?? []).length;
      const matchers = (rendered.match(/@members_magic_link \{\n\t{1,2}method POST/g) ?? []).length;
      expect(directives).toBeGreaterThan(0);
      expect(matchers).toBe(directives);
    });

    it('renders the general throttle with the magic-link one off, and no matcher for the path', () => {
      const rendered = render(GENERAL_ONLY);
      expect(rendered).toContain('rate_limit {');
      expect(rendered).not.toContain('members_magic_link');
    });

    it('renders the general throttle on the loopback probe when only it is enforcing', () => {
      const probeBlockText = render(GENERAL_ONLY).split(':8080 {')[1] ?? '';
      expect(probeBlockText).toContain('rate_limit {');
      expect(probeBlockText).not.toContain('members_magic_link');
    });

    /**
     * The highest-consequence regression this split could produce, named
     * explicitly rather than left to the committed-Caddyfile snapshot.
     *
     * `redirectBlock()` gets its chain from `protectionChain()` without
     * `membersMagicLink: true`, so the directive cannot render there — but that
     * is a property of one argument at one call site, and a redirect block has
     * no matcher to reference. If it ever gained the directive, the rendered
     * Caddyfile would carry `rate_limit @members_magic_link` against an
     * undefined matcher, Caddy would refuse to load the file, and the restart
     * that deployed it would take every hostname on this edge down rather than
     * throttling one path.
     */
    it('never renders the magic-link directive into a redirect block, which has no matcher to reference', () => {
      const rendered = render(
        MAGIC_LINK_ONLY,
        [site({ hostnames: ['apex.test', 'www.apex.test'] })],
        [{ from: 'www.apex.test', to: 'apex.test' }]
      );
      const redirectBlockText = rendered.split('www.apex.test {')[1]?.split('\n}')[0] ?? '';
      expect(redirectBlockText).toContain('redir https://apex.test{uri} permanent');
      expect(redirectBlockText).not.toContain('members_magic_link');
      expect(redirectBlockText).not.toContain('rate_limit');
    });
  });

  it('gives each site its own throttle zone, so one site cannot spend another site budget', () => {
    const rendered = render(ENFORCING, [
      site({ name: 'one', hostnames: ['one.test'] }),
      site({ name: 'two', hostnames: ['two.test'] }),
    ]);
    expect(rendered).toContain('zone one_per_ip {');
    expect(rendered).toContain('zone two_per_ip {');
  });

  it('narrows the authoring exemption to the admin API rather than the whole hostname', () => {
    const rendered = render(ENFORCING, [site({ injectionWafPreviewOnly: true })]);
    expect(rendered).toContain('@inspected not path /ghost/api/*');
    expect(rendered).toContain('appsec @inspected');
    // The IP-decision handler is not exempted with it: this is a matcher on one
    // handler, not a hole in the route. Anchored, because an unanchored
    // `toContain('crowdsec')` is satisfied by the global `crowdsec {` block and
    // asserts nothing at all.
    expect(rendered).toMatch(/^\t\tcrowdsec$/m);
  });

  it('exempts nothing outside the admin API on an authoring site', () => {
    const rendered = render(ENFORCING, [site({ injectionWafPreviewOnly: true })]);
    // The exemption removes every AppSec rule on its prefix, the filesystem-probe
    // family included, so its width is the whole of the disclosed difference.
    // `/ghost` itself, the admin UI bundle, stays inspected.
    expect(rendered).not.toContain('/ghost/*');
    expect(rendered).not.toContain('not path /ghost ');
  });

  it('inspects every path of a site with no authoring surface', () => {
    const rendered = render(ENFORCING);
    expect(rendered).not.toContain('@inspected');
    expect(rendered).toContain('\t\tappsec\n');
  });

  it('emits the bouncer tokens its parser accepts, not the ones its README documents', () => {
    // `appsec_fail_open` takes no argument and `appsec_max_timeout` is not a
    // token at all -- both were written from upstream's option table, which
    // disagrees with upstream's own Caddyfile parser. A whole-file load is the
    // only thing that catches this, so the CI job that runs `caddy validate` is
    // the real gate; these two are the cheap reminder of which spelling won.
    const rendered = render(DETECT_ONLY);
    expect(rendered).toMatch(/^\t\tappsec_fail_open$/m);
    expect(rendered).toContain('appsec_timeout 1s');
    expect(rendered).not.toContain('appsec_max_timeout');
  });

  it('fails open on AppSec in every posture, including the one that cannot block', () => {
    // Absent, the bouncer fails closed, and the appsec handler is in the route
    // whatever the posture -- so this line is what stands between a CrowdSec
    // restart and a 500 on every request to every site.
    for (const posture of [DETECT_ONLY, ENFORCING]) {
      expect(render(posture)).toMatch(/^\t\tappsec_fail_open$/m);
      expect(render(posture)).toContain('appsec');
    }
  });

  it('pins the ACME issuer and takes its account address from the environment', () => {
    const rendered = render(DETECT_ONLY);
    expect(rendered).toContain('acme_ca https://acme-v02.api.letsencrypt.org/directory');
    expect(rendered).toContain('email {env.ACME_EMAIL}');
  });

  it('disables HTTP/3, because the host firewall opens no UDP port', () => {
    expect(render(DETECT_ONLY)).toContain('protocols h1 h2');
  });

  it('reads the bouncer key from the environment, never from the committed file', () => {
    expect(render(DETECT_ONLY)).toContain('api_key {env.CROWDSEC_BOUNCER_KEY}');
  });
});

describe('detect-only', () => {
  it('leaves the IP-decision handler out of every route', () => {
    const rendered = render(DETECT_ONLY, [site({ injectionWafPreviewOnly: true })]);
    expect(rendered).not.toMatch(/^\t+crowdsec$/m);
  });

  it('still forwards requests to AppSec, so detections accumulate', () => {
    expect(render(DETECT_ONLY)).toContain('appsec');
  });

  it('renders no throttle at all, because the module has no non-enforcing mode', () => {
    expect(render(DETECT_ONLY)).not.toContain('rate_limit');
  });

  it('loads only the out-of-band AppSec configuration', () => {
    const acquisition = renderAppsecAcquisition(DETECT_ONLY);
    expect(acquisition).toContain('- crowdsecurity/crs');
    expect(acquisition).not.toContain('crowdsecurity/appsec-default');
  });

  it('adds the in-band configuration when the posture enforces, and nothing else', () => {
    // Exact, not containment. Every in-band AppSec configuration on the hub
    // carries `default_remediation: ban`, so which ones this file names is the
    // whole of what decides the enforcing posture's remediation behaviour.
    const configs = renderAppsecAcquisition(ENFORCING)
      .split('\n')
      .filter((line) => line.startsWith('  - '))
      .map((line) => line.slice(4));
    expect(configs).toEqual(['crowdsecurity/appsec-default', 'crowdsecurity/crs']);
  });

  /**
   * Exact equality against a literal, not a containment check, and the literal
   * is spelled out here rather than reusing a named constant. Every field of
   * the committed posture is a decision about what the edge does to live
   * traffic, so changing one has to change this line too — which is what makes
   * a posture flip impossible to land as an incidental diff, and impossible to
   * arrive at by redeploying an unchanged tree.
   */
  it('is what the committed posture says, so enforcement cannot arrive by redeploy', () => {
    expect(POSTURE).toEqual({
      crowdsec: 'detect-only',
      // Still off: its threshold is inherited from a Cloud Armor rule that has
      // never enforced, so it is a number no traffic has been measured
      // against. branchLeft/workspace#323.
      rateLimit: 'off',
      // On: bounded to one POST path, threshold derived in `posture.ts`, and
      // what it protects is mx1's deliverability rather than edge compute.
      membersMagicLinkRateLimit: 'enforcing',
    });
  });
});

describe('the CrowdSec acquisition files', () => {
  it('never publish the AppSec port beyond the Compose network', () => {
    expect(renderAppsecAcquisition(POSTURE)).toContain('listen_addr: 0.0.0.0:7422');
  });

  it('acquire the access log under the label the Caddy parser expects', () => {
    const acquisition = renderCaddyLogAcquisition();
    expect(acquisition).toContain('- /var/log/caddy/access.log');
    expect(acquisition).toContain('type: caddy');
  });
});

/**
 * Vitest runs from this project's root, so the repository root is one level up.
 * A wrong path throws out of `readFileSync` rather than passing quietly, which
 * is the only property these two need from it.
 */
const repositoryFile = (name: string) => readFileSync(resolve(process.cwd(), '..', name), 'utf-8');

const numericConstant = (source: string, name: string): number => {
  const match = new RegExp(`const ${name} = (\\d+);`).exec(source);
  if (match?.[1] === undefined) {
    throw new Error(`could not find ${name} in edge.ts`);
  }
  return Number(match[1]);
};

describe('parity with the edge this one replaces', () => {
  /**
   * `edge.ts` and `posture.ts` state the same three thresholds in two
   * programs that cannot import each other, so nothing but this stops them
   * drifting apart while both suites stay green — and the drift would be
   * invisible, because each side is internally consistent.
   */
  const edgeTs = repositoryFile('edge.ts');

  it('carries the same per-IP throttle the GCP edge declares', () => {
    expect(RATE_LIMIT_EVENTS).toBe(numericConstant(edgeTs, 'RATE_LIMIT_REQUESTS'));
    expect(RATE_LIMIT_WINDOW_SECONDS).toBe(numericConstant(edgeTs, 'RATE_LIMIT_INTERVAL_SEC'));
  });

  it('carries the same TLS floor', () => {
    expect(edgeTs).toContain("const TLS_MIN_VERSION = 'TLS_1_2'");
    expect(TLS_PROTOCOLS[0]).toBe('tls1.2');
  });
});

describe('the parity artifact', () => {
  /**
   * The §13 gate reads `CLOUD-ARMOR-BASELINE.md`, not this repository's code, so
   * a remediation behaviour that is only in a runbook is a behaviour the gate
   * cannot see. Both scenarios below turn an AppSec match into an IP ban, which
   * the Cloud Armor rules being replaced never did.
   */
  const baseline = repositoryFile('CLOUD-ARMOR-BASELINE.md');

  it('discloses that in-band and out-of-band matches both end in an IP ban', () => {
    expect(baseline).toContain('crowdsecurity/appsec-vpatch');
    expect(baseline).toContain('crowdsecurity/crowdsec-appsec-outofband');
  });

  it('discloses that the authoring exemption removes every rule on its prefix', () => {
    expect(baseline).toContain('/ghost/api/');
  });
});

describe('the fully enforcing posture', () => {
  /**
   * Committed but never deployed. The posture flip is designed to be reviewed
   * as the literal configuration the host will run, which is worth nothing if
   * that configuration is first parsed by a Caddy binary on the day it is
   * flipped. CI loads this file through `caddy validate` alongside the live one,
   * so a directive that only appears under enforcement fails now rather than
   * during the flip.
   */
  it('renders a configuration CI can load before anything depends on it', async () => {
    await expect(renderCaddyfile(sites, hostRedirects, ENFORCING)).toMatchFileSnapshot(
      './validation/Caddyfile.enforcing'
    );
  });

  it('renders a configuration for an authoring site too, which the live one has none of', async () => {
    const authoring: EdgeSite = {
      name: 'authoring',
      hostnames: ['authoring.invalid'],
      cloudRunService: 'unused',
      injectionWafPreviewOnly: true,
      privateUpstream: { host: 'app1', port: 2368 },
    };
    await expect(renderCaddyfile([authoring], [], ENFORCING)).toMatchFileSnapshot(
      './validation/Caddyfile.authoring'
    );
  });
});

describe('the committed stack directory', () => {
  it('is what this renderer produces from the registry and the committed posture', async () => {
    await expect(renderCaddyfile(sites, hostRedirects, POSTURE)).toMatchFileSnapshot(
      './stack/Caddyfile'
    );
    await expect(renderAppsecAcquisition(POSTURE)).toMatchFileSnapshot(
      './stack/crowdsec/acquis.d/appsec.yaml'
    );
    await expect(renderCaddyLogAcquisition()).toMatchFileSnapshot(
      './stack/crowdsec/acquis.d/caddy.yaml'
    );
  });
});
