import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import { HOST_IPS, TENANTS_HOST_IPS } from '@branchleft/hetzner-host';
import { describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import { POSTURE } from '../edge/posture';
import {
  renderCaddyfile,
  renderGhostAdminAppsecConfig,
  renderGhostAdminPostoverflow,
  renderGhostBruteForceScenario,
} from '../edge/render';
import {
  TENANT_POSTURE,
  UNKNOWN_HOST_STATUS,
  renderTenantCaddyfile,
  renderTenantGhostAdminAppsecConfig,
  renderTenantGhostAdminPostoverflow,
  renderTenantGhostBruteForceScenario,
  renderTenantStack,
} from './render';

const STACK = path.join(__dirname, 'stack');
const ESTATE_STACK = path.join(__dirname, '..', 'edge', 'stack');

/** The files of the tenant stack that a person writes, so nothing renders them. */
const HAND_WRITTEN = ['compose.yml', 'crowdsec/config.yaml.local'];

/**
 * Every name the estate's registry serves or redirects. The tenant edge must never carry
 * one: its own names are data the repository does not hold. A tenant's name under
 * `sites.publicpress.co.uk` is not on this list, and is not meant to be.
 */
const ESTATE_HOSTNAMES: readonly string[] = [
  ...sites.flatMap((site) => site.hostnames),
  ...hostRedirects.flatMap((redirect) => [redirect.from, redirect.to]),
  ...staticSites.map((site) => site.hostname),
];

/** The estate's own domain, which no tenant file has a reason to name at all. */
const ESTATE_DOMAIN = 'branchleft.co.uk';

/** What in `text` names the estate: a registered hostname, or its domain. */
function estateNames(text: string): string[] {
  const found = ESTATE_HOSTNAMES.filter((hostname) => {
    const pattern = new RegExp(
      `(?<![a-z0-9.-])${hostname.replaceAll('.', '[.]')}(?![a-z0-9-])`,
      'i'
    );
    return pattern.test(text);
  });
  if (text.toLowerCase().includes(ESTATE_DOMAIN)) {
    found.push(ESTATE_DOMAIN);
  }
  return [...new Set(found)];
}

function filesUnder(directory: string, prefix = ''): string[] {
  return readdirSync(directory)
    .sort()
    .flatMap((entry) => {
      const relative = prefix === '' ? entry : `${prefix}/${entry}`;
      return statSync(path.join(directory, entry)).isDirectory()
        ? filesUnder(path.join(directory, entry), relative)
        : [relative];
    });
}

const read = (...parts: string[]): string => readFileSync(path.join(...parts), 'utf8');

/** A file's lines with comments and blank lines dropped: what the file says, not how. */
const meaning = (text: string): string[] =>
  text.split('\n').filter((line) => line.trim() !== '' && !line.trim().startsWith('#'));

describe('the committed tenant stack directory', () => {
  it('is what this renderer produces', async () => {
    for (const [file, rendered] of renderTenantStack()) {
      await expect(rendered).toMatchFileSnapshot(`./stack/${file}`);
    }
  });

  it('holds the rendered files and the two hand-written ones, and nothing else', () => {
    expect(filesUnder(STACK)).toEqual([...renderTenantStack().keys(), ...HAND_WRITTEN].sort());
  });

  it('carries its own banner, never the estate registry as its source', () => {
    for (const [file, rendered] of renderTenantStack()) {
      expect(rendered, file).toMatch(/^# Generated from hetzner\/edge-t\/render\.ts/);
      expect(rendered, file).not.toContain('sites.ts');
    }
  });
});

// Why: render.md, "The tenant profile". The estate's names are the one thing this edge's
// files must never carry; each test below has a control that shows the check can fail.
describe('no hostname of the estate reaches the tenant stack', () => {
  it('has a list of estate names to check against', () => {
    expect(ESTATE_HOSTNAMES.length).toBeGreaterThan(5);
    expect(ESTATE_HOSTNAMES).toContain('blog.branchleft.co.uk');
  });

  it('control: the check finds the estate in the estate edge’s own files', () => {
    expect(estateNames(renderCaddyfile(sites, hostRedirects, POSTURE, staticSites))).toContain(
      'blog.branchleft.co.uk'
    );
    expect(estateNames(renderGhostAdminAppsecConfig(sites))).toContain('blog.branchleft.co.uk');
    expect(estateNames(renderGhostAdminPostoverflow(sites))).toContain('blog.branchleft.co.uk');
    expect(estateNames(renderGhostBruteForceScenario(sites))).toContain('blog.branchleft.co.uk');
  });

  it('names none in any file the renderer produces', () => {
    for (const [file, rendered] of renderTenantStack()) {
      expect(estateNames(rendered), file).toEqual([]);
    }
  });

  it('names none in any file committed under the tenant stack directory', () => {
    for (const file of filesUnder(STACK)) {
      expect(estateNames(read(STACK, file)), file).toEqual([]);
    }
  });

  it('takes no hostname or registry as an argument that could carry one in', () => {
    expect(renderTenantGhostAdminAppsecConfig).toHaveLength(0);
    expect(renderTenantGhostAdminPostoverflow).toHaveLength(0);
    expect(renderTenantGhostBruteForceScenario).toHaveLength(0);
    expect(renderTenantCaddyfile.length).toBeLessThanOrEqual(1);
  });

  it('narrows no Ghost file to a hostname list, because every name here is a tenant’s', () => {
    const files = renderTenantStack();
    for (const file of [
      'crowdsec/appsec-configs/ghost-admin-previews.yaml',
      'crowdsec/postoverflows/ghost-admin-api-postoverflow.yaml',
      'crowdsec/scenarios/ghost-admin-login-bruteforce.yaml',
    ]) {
      const text = files.get(file) ?? '';
      expect(text, file).not.toMatch(/req\.Host in|target_fqdn'?\)? in|target_fqdn in/);
      expect(text, file).not.toMatch(/\[\s*'[^']*\.[^']*'/);
    }
  });
});

describe('the tenant Caddyfile', () => {
  const caddyfile = renderTenantCaddyfile();
  const addresses = [...caddyfile.matchAll(/^(\S.*) \{$/gm)].map((match) => match[1]);

  it('answers an unknown Host on port 80 with 503, behind the throttle and the bouncer', () => {
    expect(UNKNOWN_HOST_STATUS).toBe(503);
    const block = caddyfile.slice(
      caddyfile.indexOf(':80 {'),
      caddyfile.indexOf('\n}\n', caddyfile.indexOf(':80 {'))
    );
    expect(block).toContain(`respond "No site is served at this name." ${UNKNOWN_HOST_STATUS}`);
    expect(block).toContain('zone unknown_host_per_ip');
    expect(block).toContain('crowdsec');
    expect(block).not.toContain('appsec');
  });

  it('has the catch-all, the two probes and the metrics listener, and no site of any name', () => {
    expect(addresses).toEqual([':80', 'http://edge-probe.invalid:8080', ':8080', ':9091']);
    expect(caddyfile).not.toContain('reverse_proxy');
    expect(caddyfile).not.toMatch(/^\s*tls\b/m);
  });

  it('is spelled out in posture, not borrowed from the estate’s', () => {
    expect(TENANT_POSTURE).toEqual(POSTURE);
    expect(TENANT_POSTURE).not.toBe(POSTURE);
  });
});

describe('the tenant Compose file', () => {
  const compose = read(STACK, 'compose.yml');
  const estateCompose = read(ESTATE_STACK, 'compose.yml');

  it('pins CrowdSec to exactly the image the estate pins', () => {
    const imageLine = (text: string): string | undefined =>
      text.split('\n').find((line) => line.includes('crowdsecurity/crowdsec:'));
    expect(imageLine(compose)).toBeDefined();
    expect(imageLine(compose)).toEqual(imageLine(estateCompose));
  });

  it('publishes its metrics ports on this host’s private address and never the estate’s', () => {
    expect(compose).toContain(`'${TENANTS_HOST_IPS.edgeT}:9091:9091'`);
    expect(compose).toContain(`'${TENANTS_HOST_IPS.edgeT}:6060:6060'`);
    expect(compose).not.toContain(HOST_IPS.edge1);
    expect(compose).toContain('CUSTOM_HOSTNAME: edge-t');
    expect(compose).not.toContain('CUSTOM_HOSTNAME: edge1');
  });

  it('mounts every directory the stack holds for CrowdSec, and no parsers directory', () => {
    for (const mount of [
      './crowdsec/acquis.d:',
      './crowdsec/config.yaml.local:',
      './crowdsec/appsec-configs:',
      './crowdsec/postoverflows:',
      './crowdsec/scenarios:',
      './crowdsec/remediation:',
    ]) {
      expect(compose, mount).toContain(mount);
    }
    expect(compose).not.toContain('./crowdsec/parsers');
    expect(filesUnder(STACK).some((file) => file.startsWith('crowdsec/parsers/'))).toBe(false);
  });
});

describe('the tenant CrowdSec overlay', () => {
  it('says what the estate’s overlay says, so the two cannot drift', () => {
    expect(meaning(read(STACK, 'crowdsec/config.yaml.local'))).toEqual(
      meaning(read(ESTATE_STACK, 'crowdsec/config.yaml.local'))
    );
  });
});
