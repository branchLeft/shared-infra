import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

// The edge image's build inputs. The runtime base digest is the one the image
// scan (Grype, SEC-4) was run against; a change to it must come with a new scan.
const SCANNED_RUNTIME_BASE =
  'sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee';
const SCANNED_CADDY_VERSION = '2.11.9';

const dockerfile = readFileSync(join(__dirname, 'Dockerfile'), 'utf8');
const fromLines = dockerfile.split('\n').filter((line) => /^FROM\s/.test(line));

describe('edge Caddy Dockerfile pins', () => {
  it('names the Caddy version the image scan was run against', () => {
    expect(dockerfile).toMatch(
      new RegExp(`^ARG CADDY_VERSION=${SCANNED_CADDY_VERSION.replace(/\./g, '\\.')}$`, 'm')
    );
  });

  it('pins every base image by digest, never by tag alone', () => {
    expect(fromLines).toHaveLength(2);
    for (const line of fromLines) {
      expect(line).toMatch(/@sha256:[0-9a-f]{64}(\s|$)/);
    }
  });

  it('runs the image on the digest the scan covered', () => {
    const runtime = fromLines[1];
    expect(runtime).toBe(`FROM caddy:\${CADDY_VERSION}-alpine@${SCANNED_RUNTIME_BASE}`);
  });

  it('builds Caddy at the named version, not xcaddy default latest', () => {
    expect(dockerfile).toMatch(/xcaddy build v\$\{CADDY_VERSION\}/);
  });

  it('pins the zlib release that fixes the base image finding', () => {
    expect(dockerfile).toMatch(/^RUN apk add --no-cache zlib=1\.4-r0$/m);
  });
});
