import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * `blackbox.yml` is hand-written, so nothing here compares it to a renderer.
 * These assert what the mail modules must *do*, because every other gate is
 * blind to it: `blackbox_exporter --config.check` validates syntax only,
 * promtool feeds synthetic `probe_success` values, and the render tests
 * assert a module's name rather than its behaviour. Loosening the banner
 * regex to `.*` passed all of them.
 */
const CONFIG = readFileSync(join(__dirname, 'stack', 'blackbox', 'blackbox.yml'), 'utf8');

/** The module's own block, so an assertion cannot pass on a sibling's line. */
function moduleBlock(name: string): string {
  const start = CONFIG.indexOf(`  ${name}:`);
  expect(start, `module ${name} is absent`).toBeGreaterThan(-1);
  const rest = CONFIG.slice(start + 1);
  const next = rest.search(/\n {2}\w[\w-]*:\n/);
  return next === -1 ? rest : rest.slice(0, next);
}

const smtpBanner = moduleBlock('smtp_banner');
const tlsConnect = moduleBlock('tls_connect');

function expectPatterns(block: string): string[] {
  return [...block.matchAll(/- expect: '([^']*)'/g)].map((m) => m[1]);
}

describe('the mail probe modules', () => {
  /**
   * The outage this job exists to catch presented as a completed TCP
   * handshake followed by EOF with no banner -- a bare connect check reports
   * success in that state. The greeting pattern is the whole difference, so
   * it is asserted by behaviour rather than by string equality: a pattern
   * changed to something permissive fails here even though the module name,
   * the YAML syntax and every rendered file stay identical.
   */
  it('rejects the incident signature: a connection that yields no banner', () => {
    const greeting = new RegExp(expectPatterns(smtpBanner)[0]);
    expect(greeting.test('')).toBe(false);
  });

  it('accepts a real ESMTP greeting', () => {
    const greeting = new RegExp(expectPatterns(smtpBanner)[0]);
    expect(greeting.test('220 mx1.branchleft.co.uk Stalwart ESMTP at your service')).toBe(true);
  });

  it('rejects a greeting that is not a 220', () => {
    const greeting = new RegExp(expectPatterns(smtpBanner)[0]);
    expect(greeting.test('421 Service not available')).toBe(false);
    expect(greeting.test('554 Transaction failed')).toBe(false);
    // A greeting is 220 specifically, so a pattern loose enough to take any
    // 2xx is wrong even though it still rejects the empty line above -- that
    // weaker form passed an earlier version of these assertions.
    expect(greeting.test('250 OK')).toBe(false);
    expect(greeting.test('221 Bye')).toBe(false);
  });

  /**
   * Closing while the server's reply is still inbound makes the kernel answer
   * it with an RST. Twice a minute on two mail ports, that is a steady stream
   * of abnormally terminated sessions -- the shape a scan heuristic keys on.
   */
  it('reads the goodbye reply so the session closes without a reset', () => {
    const patterns = expectPatterns(smtpBanner);
    // Double quotes matter: YAML keeps a backslash literal inside single
    // quotes, so the single-quoted form sends six characters instead of a
    // CRLF-terminated command. Against a real server that is a malformed
    // command, and it reports success unless the reply is read.
    expect(smtpBanner).toContain('send: "QUIT\\r\\n"');
    expect(smtpBanner).not.toContain("send: 'QUIT");
    expect(new RegExp(patterns[patterns.length - 1]).test('221 Bye')).toBe(true);
  });

  /**
   * The prober defaults to ip6. mx1 publishes an AAAA record the monitoring
   * network cannot route to, so omitting this makes every probe fail on dial
   * and the alert page permanently -- green in CI, broken in production.
   */
  it.each([
    ['smtp_banner', smtpBanner],
    ['tls_connect', tlsConnect],
  ])('%s pins the IP family rather than taking the ip6 default', (_n, block) => {
    expect(block).toMatch(/preferred_ip_protocol:\s*ip4/);
  });

  it('verifies the certificate on the implicit-TLS ports', () => {
    expect(tlsConnect).toMatch(/tls:\s*true/);
    expect(tlsConnect).toMatch(/insecure_skip_verify:\s*false/);
  });
});
