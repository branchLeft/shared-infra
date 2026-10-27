import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { type ReasonCode, scanTenantsSource } from './tenants.structure.scan';

/**
 * The gate covers the resources the program declares. A provider resource
 * added outside the Host, and not wired to the verified value, would register
 * under a wrong-project token. This test reads the source and fails on any
 * provider resource declared directly, so the gap is a red test, not a review
 * finding. The two declared directly are gated in their own inputs.
 */

const source = readFileSync(join(__dirname, 'tenants.ts'), 'utf8');

describe('tenants program declarations', () => {
  it('declares directly only the network and subnet, both gated', () => {
    const direct = [...source.matchAll(/new hcloud\.(\w+)\(/g)].map((match) => match[1]);
    expect(direct).toEqual(['Network', 'NetworkSubnet']);
    expect(source).toMatch(/name: verified\('tenants'\)/);
    expect(source).toMatch(/networkId: verified\(tenantsNetwork\.id\)/);
  });

  it('declares the Host once, with the gate transformation', () => {
    expect([...source.matchAll(/new Host\(/g)].length).toBe(1);
    expect([...source.matchAll(/transformations: \[gateRegistration\]/g)]).toHaveLength(1);
  });

  it('gates the firewall, server and PrimaryIp through the transformation', () => {
    expect(source).toMatch(/'hcloud:index\/firewall:Firewall': 'name'/);
    expect(source).toMatch(/'hcloud:index\/server:Server': 'serverType'/);
    expect(source).toMatch(/'hcloud:index\/primaryIp:PrimaryIp': 'name'/);
  });
});

interface FixtureOptions {
  extra?: string;
  hostArgs?: string;
  hostFirstArgument?: string;
  hostImport?: string;
  hostPrefix?: string;
  hostConstructor?: string;
}

interface ViolationRow extends FixtureOptions {
  id: string;
  code: ReasonCode;
}

interface ControlRow extends FixtureOptions {
  id: string;
}

const DEFAULT_HOST_ARGS = ', { transformations: [gateRegistration] }';
const HOST_IMPORT = "import { Host } from '@branchleft/hetzner-host';";

function buildProgram(options: FixtureOptions): string {
  const {
    extra = '',
    hostArgs = DEFAULT_HOST_ARGS,
    hostFirstArgument = 'args',
    hostImport = HOST_IMPORT,
    hostPrefix = '',
    hostConstructor = 'Host',
  } = options;
  return [
    "import * as hcloud from '@pulumi/hcloud';",
    "import * as pulumi from '@pulumi/pulumi';",
    hostImport,
    'export const gateRegistration = () => undefined;',
    'const config = new pulumi.Config();',
    'const args = {};',
    "export const net = new hcloud.Network('n', {});",
    "export const sub = new hcloud.NetworkSubnet('s', {});",
    `${hostPrefix}export const db = new ${hostConstructor}(${hostFirstArgument}${hostArgs});`,
    extra,
  ].join('\n');
}

const VIOLATION_ROWS: ViolationRow[] = [
  {
    id: 'P1-alias-const',
    extra: "const V = hcloud.Volume; export const v = new V('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P2-destructure',
    extra: "const { Volume } = hcloud; export const v = new Volume('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P3-named-import-as',
    extra: "import { Volume as V } from '@pulumi/hcloud'; export const v = new V('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P4-renamed-namespace',
    extra: "import * as h from '@pulumi/hcloud'; export const v = new h.Volume('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P5-alias-chain',
    extra: "const V = hcloud.Volume; const W = V; export const v = new W('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P6a-parens',
    extra: "export const v = new (hcloud.Volume)('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P6b-quoted-member',
    extra: "export const v = new hcloud['Volume']('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P7-unresolvable',
    extra: "export const v = new hcloud[name]('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'P8-namespace-alias',
    extra: "const h = hcloud; export const v = new h.Volume('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P9-type-wrapper',
    extra: "export const v = new (hcloud.Volume as any)('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'P10-comma',
    extra: "export const v = new (0, hcloud.Volume)('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'P11-optional-chain',
    extra: "export const v = new (hcloud?.Volume)('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'L1-local-import',
    extra: "import { Volume } from './lib'; export const v = new Volume('v', {});",
    code: 'unresolved-constructor',
  },
  { id: 'L2-global', extra: 'export const d = new Date();', code: 'unresolved-constructor' },
  {
    id: 'L3-other-pulumi-member',
    extra: "export const r = new pulumi.StackReference('x');",
    code: 'forbidden-constructor',
  },
  {
    id: 'H1-second-host-plain',
    extra: 'export const h2 = new Host(args);',
    code: 'host-count',
  },
  {
    id: 'H2-alias-host-no-options',
    extra: 'const H = Host; export const h2 = new H(args);',
    code: 'host-count',
  },
  {
    id: 'H3-named-import-as-host',
    extra:
      "import { Host as H } from '@branchleft/hetzner-host'; export const h2 = new H(args, { transformations: [other] });",
    code: 'host-count',
  },
  {
    id: 'H4-options-variable',
    extra: 'const opts = { transformations: [gateRegistration] };',
    hostArgs: ', opts',
    code: 'host-gate',
  },
  {
    id: 'H5-gate-text-only-in-comment',
    extra: '// transformations: [gateRegistration]',
    hostArgs: ', { transformations: [other] }',
    code: 'host-gate',
  },
  {
    id: 'H6-second-host-gated',
    extra: 'export const h2 = new Host(args, { transformations: [gateRegistration] });',
    code: 'host-count',
  },
  {
    id: 'H7-shadowed-gate',
    extra: 'export function f(gateRegistration: unknown) { return gateRegistration; }',
    code: 'host-gate',
  },
  {
    id: 'H8-computed-key',
    hostArgs: ", { ['transformations']: [gateRegistration] }",
    code: 'host-gate',
  },
  {
    id: 'H9-nested-gate',
    hostArgs: ', { transformations: [wrap({ gate: gateRegistration })] }',
    code: 'host-gate',
  },
  {
    id: 'H10-spread-options',
    hostArgs: ', { ...other, transformations: [gateRegistration] }',
    code: 'host-gate',
  },
  { id: 'H11-no-options', hostArgs: '', code: 'host-gate' },
  { id: 'H12-empty-array', hostArgs: ', { transformations: [] }', code: 'host-gate' },
  { id: 'U1-host-no-import', hostImport: '', code: 'unresolved-constructor' },
  {
    id: 'X1-let-binding',
    extra: "let V = hcloud.Volume; export const v = new V('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X2-var-binding',
    extra: "var V = hcloud.Volume; export const v = new V('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X3-shadowed-namespace-parameter',
    extra:
      "export function f(hcloud: unknown) { return hcloud; } export const v = new hcloud.Network('x', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X4-alias-cycle',
    extra: "const A = B; const B = A; export const v = new A('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X5-default-import',
    extra: "import Volume from '@pulumi/hcloud'; export const v = new Volume('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X6-destructure-default',
    extra: "const { Network = hcloud.Volume } = hcloud; export const v = new Network('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X7-conditional',
    extra: "export const v = new (flag ? hcloud.Network : hcloud.Volume)('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X8-type-only-import',
    extra: "import type { Volume } from '@pulumi/hcloud'; export const v = new Volume('v', {});",
    code: 'unresolved-constructor',
  },
  {
    id: 'X9-non-null-wrapper',
    extra: "export const v = new hcloud!.Volume('v', {});",
    code: 'forbidden-constructor',
  },
  {
    id: 'X10-second-transformations-key',
    hostArgs: ", { transformations: [gateRegistration], ['transformations']: [] }",
    code: 'host-gate',
  },
  {
    id: 'X11-gate-imported',
    extra: "import { gateRegistration as gate } from './other';",
    hostArgs: ', { transformations: [gate] }',
    code: 'host-gate',
  },
  {
    id: 'X12-spread-before-options',
    hostFirstArgument: '...rest',
    code: 'host-gate',
  },
  {
    id: 'X13-parenthesised-gate',
    hostArgs: ', { transformations: [(gateRegistration)] }',
    code: 'host-gate',
  },
  {
    id: 'X14-quoted-key',
    hostArgs: ", { 'transformations': [gateRegistration] }",
    code: 'host-gate',
  },
  {
    id: 'X15-shorthand-key',
    extra: 'const transformations = [gateRegistration];',
    hostArgs: ', { transformations }',
    code: 'host-gate',
  },
];

const CONTROL_ROWS: ControlRow[] = [
  { id: 'C1-current-shape' },
  {
    id: 'C2-allowed-aliases',
    extra:
      "const N = hcloud.Network; export const n2 = new N('n2', {}); import { NetworkSubnet as S } from '@pulumi/hcloud'; export const s2 = new S('s2', {});",
  },
  {
    id: 'C3-extra-transformations',
    hostArgs: ', { transformations: [other, gateRegistration] }',
  },
  { id: 'C4-config-alias', extra: 'const { Config } = pulumi; export const c2 = new Config();' },
  {
    id: 'C5-host-alias-gated',
    hostPrefix: 'const H = Host; ',
    hostConstructor: 'H',
  },
];

describe('tenants source scanner', () => {
  it.each(VIOLATION_ROWS)('$id is reported as $code', ({ code, ...options }) => {
    const messages = scanTenantsSource(buildProgram(options));
    expect(messages.some((message) => message.startsWith(`${code} line `))).toBe(true);
  });

  it.each(CONTROL_ROWS)('$id is clean', (options) => {
    expect(scanTenantsSource(buildProgram(options))).toEqual([]);
  });

  it('reports no violation in the real tenants program', () => {
    expect(scanTenantsSource(source)).toEqual([]);
  });
});
