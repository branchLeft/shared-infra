import { describe, expect, it } from 'vitest';

import { hostRedirects, sites } from '../../sites';
import type { EdgeSite, HostRedirect } from '../../siteTypes';
import { POSTURE, RATE_LIMIT_EVENTS, RATE_LIMIT_WINDOW_SECONDS } from './posture';
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

const DETECT_ONLY: EdgePosture = { crowdsec: 'detect-only', rateLimit: 'off' };
const ENFORCING: EdgePosture = { crowdsec: 'enforcing', rateLimit: 'enforcing' };

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

  it('throttles first, then checks IP decisions, then inspects, then proxies', () => {
    const chain = render(ENFORCING)
      .split('\n')
      .filter((line) => /^\t\t(rate_limit|crowdsec|appsec|reverse_proxy)\b/.test(line))
      .map((line) => line.trim().split(' ')[0]);
    expect(chain.slice(0, 4)).toEqual(['rate_limit', 'crowdsec', 'appsec', 'reverse_proxy']);
  });

  it('gives each site its own throttle zone, so one site cannot spend another site budget', () => {
    const rendered = render(ENFORCING, [
      site({ name: 'one', hostnames: ['one.test'] }),
      site({ name: 'two', hostnames: ['two.test'] }),
    ]);
    expect(rendered).toContain('zone one_per_ip {');
    expect(rendered).toContain('zone two_per_ip {');
  });

  it('narrows the authoring exemption to the authoring paths rather than the whole hostname', () => {
    const rendered = render(ENFORCING, [site({ injectionWafPreviewOnly: true })]);
    expect(rendered).toContain('@inspected not path /ghost /ghost/*');
    expect(rendered).toContain('appsec @inspected');
    expect(rendered).toContain('crowdsec');
  });

  it('inspects every path of a site with no authoring surface', () => {
    const rendered = render(ENFORCING);
    expect(rendered).not.toContain('@inspected');
    expect(rendered).toContain('\t\tappsec\n');
  });

  it('fails open on AppSec so a sidecar restart degrades inspection instead of the site', () => {
    expect(render(DETECT_ONLY)).toContain('appsec_fail_open true');
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

  it('adds the in-band configuration when the posture enforces', () => {
    const acquisition = renderAppsecAcquisition(ENFORCING);
    expect(acquisition).toContain('- crowdsecurity/appsec-default');
    expect(acquisition).toContain('- crowdsecurity/crs');
  });

  it('is what the committed posture says, so enforcement cannot arrive by redeploy', () => {
    expect(POSTURE).toEqual(DETECT_ONLY);
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
