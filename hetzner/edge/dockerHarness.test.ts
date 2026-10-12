import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { createServer, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

// A hook run just before the harness writes a slot's owner file, to put another
// session's reclaim exactly between that holder's `mkdir` and its owner write.
const ownerWrite = vi.hoisted(() => ({
  before: undefined as (() => void) | undefined,
  beforeRemove: undefined as (() => void) | undefined,
}));
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    writeFileSync: (...args: Parameters<typeof actual.writeFileSync>) => {
      const hook = ownerWrite.before;
      if (hook && String(args[0]).endsWith('/owner')) {
        ownerWrite.before = undefined;
        hook();
      }
      return actual.writeFileSync(...args);
    },
    rmSync: (...args: Parameters<typeof actual.rmSync>) => {
      const hook = ownerWrite.beforeRemove;
      if (hook) {
        ownerWrite.beforeRemove = undefined;
        hook();
      }
      return actual.rmSync(...args);
    },
  };
});

const errno = (code: string) => Object.assign(new Error(`${code}: injected`), { code });

import {
  CONTAINER_LIMITS,
  DEFAULT_STEP_DEADLINE_MS,
  DockerFailure,
  IMAGE_LIMITS,
  ORPHAN_SLOT_AGE_MS,
  STEP_DEADLINE_ENV,
  docker,
  ensureImage,
  probeEngine,
  probeEngineSync,
  removeByName,
  startContainer,
  stepDeadlineMs,
  takeSlot,
  type ContainerLimits,
  type ContainerSpec,
} from './dockerHarness';

// The controls run against a fake daemon on a unix socket, so they need the
// docker CLI but no engine and no Docker Hub: a wedged or unreachable engine
// is exactly what the fake reproduces.
// Synchronous because it picks `describe.skipIf` at collection; it needs no daemon.
const hasCli =
  spawnSync('docker', ['--version'], { timeout: 10_000, killSignal: 'SIGKILL' }).status === 0;
if (!hasCli && process.env.CI) throw new Error('the docker client is required in CI');

type Mode = 'ok' | 'stall' | 'fail' | 'absent';
interface Script {
  inspectImage?: Mode;
  pull?: Mode;
  create?: Mode;
  start?: Mode;
  inspectContainer?: Mode;
  remove?: Mode;
  info?: Mode;
}

interface Fake {
  env: NodeJS.ProcessEnv;
  requests: string[];
  close(): Promise<void>;
}

const NAME = 'bl-test-container';
const IMAGE = 'registry.invalid/branchleft-absent:none';

async function fakeDaemon(script: Script): Promise<Fake> {
  const dir = mkdtempSync(join(tmpdir(), 'bl-fd-'));
  const sock = join(dir, 'd.sock');
  const requests: string[] = [];
  const json = (res: ServerResponse, code: number, body: unknown) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const server: Server = createServer((req, res) => {
    const url = (req.url ?? '').replace(/^\/v[\d.]+/, '');
    requests.push(`${req.method} ${url}`);
    req.resume();
    if (url === '/_ping') {
      res.writeHead(200, { 'API-Version': '1.47', OSType: 'linux', 'Content-Type': 'text/plain' });
      res.end(req.method === 'HEAD' ? undefined : 'OK');
      return;
    }
    const answer = (mode: Mode | undefined, ok: () => void, failBody = 'fake failure') => {
      if (mode === 'stall') return;
      if (mode === 'fail') return json(res, 500, { message: failBody });
      if (mode === 'absent') return json(res, 404, { message: `No such object: ${url}` });
      ok();
    };
    if (req.method === 'GET' && url === '/info') {
      answer(script.info, () => json(res, 200, { ID: 'fake', ServerVersion: '27.0.0' }));
    } else if (req.method === 'GET' && url.startsWith('/images/') && url.endsWith('/json')) {
      answer(script.inspectImage, () => json(res, 200, { Id: 'sha256:' + 'b'.repeat(64) }));
    } else if (req.method === 'POST' && url.startsWith('/images/create')) {
      answer(
        script.pull,
        () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"status":"done"}\n');
        },
        'Get "https://registry.invalid/v2/": dial tcp: lookup registry.invalid: no such host'
      );
    } else if (req.method === 'POST' && url.startsWith('/containers/create')) {
      answer(script.create, () => json(res, 201, { Id: 'a'.repeat(64), Warnings: [] }));
    } else if (req.method === 'POST' && url.endsWith('/start')) {
      answer(script.start, () => {
        res.writeHead(204);
        res.end();
      });
    } else if (req.method === 'GET' && url.startsWith('/containers/') && url.endsWith('/json')) {
      answer(script.inspectContainer, () =>
        json(res, 200, {
          Id: 'a'.repeat(64),
          Name: `/${NAME}`,
          NetworkSettings: { Ports: { '8081/tcp': [{ HostIp: '127.0.0.1', HostPort: '49153' }] } },
        })
      );
    } else if (req.method === 'DELETE' && url.startsWith('/containers/')) {
      answer(script.remove, () => {
        res.writeHead(204);
        res.end();
      });
    } else {
      json(res, 404, { message: `unexpected ${req.method} ${url}` });
    }
  });
  await new Promise<void>((resolve) => server.listen(sock, resolve));
  return {
    env: { ...process.env, DOCKER_HOST: `unix://${sock}`, DOCKER_CONFIG: dir },
    requests,
    close: async () => {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const spec: ContainerSpec = {
  name: NAME,
  label: 'branchleft.agent=docker-harness-test',
  image: 'caddy:test',
  containerPort: 8081,
  mountSource: '/tmp/Caddyfile',
  mountTarget: '/etc/caddy/Caddyfile',
};
const fast: ContainerLimits = { createMs: 1_500, startMs: 1_500, portMs: 1_500, removeMs: 1_500 };
const removals = (f: Fake) => f.requests.filter((r) => r.startsWith(`DELETE /containers/${NAME}`));

const RUNNER = join(__dirname, 'fixtures', 'interruptRunner.mjs');
const cleanup: Array<() => void> = [];

/** A directory holding a `docker` that is just this shell script. */
function shim(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'bl-shim-'));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'docker'), `#!/bin/sh\n${body}\n`);
  chmodSync(join(dir, 'docker'), 0o755);
  return dir;
}

const isAlive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

async function waitFor(check: () => boolean, ms: number) {
  const until = Date.now() + ms;
  while (!check()) {
    if (Date.now() > until) throw new Error(`condition not met within ${ms} ms`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe.skipIf(!hasCli)(
  'a container start against a daemon that goes silent',
  { timeout: 20_000 },
  () => {
    const open: Fake[] = [];
    afterEach(async () => {
      await Promise.all(open.splice(0).map((f) => f.close()));
      cleanup.splice(0).forEach((fn) => fn());
    });
    const daemon = async (script: Script) => {
      const f = await fakeDaemon(script);
      open.push(f);
      return f;
    };

    it('starts, reads the port, and removes nothing when every step answers', async () => {
      const f = await daemon({ create: 'ok', start: 'ok', inspectContainer: 'ok' });
      await expect(startContainer(spec, { env: f.env }, fast)).resolves.toBe(49153);
      expect(removals(f)).toEqual([]);
    });

    it('kills a client stuck after create, and removes the container by its exact name', async () => {
      const f = await daemon({ create: 'ok', start: 'stall', remove: 'ok' });
      const t0 = Date.now();
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(DockerFailure);
      expect((failure as Error).message).toContain(`docker start ${NAME}`);
      expect((failure as Error).message).toContain('wedged');
      expect((failure as Error).message).toContain(`${NAME} was removed by name`);
      expect(Date.now() - t0, 'fails in seconds, not minutes').toBeLessThan(8_000);
      expect(removals(f)).toHaveLength(1);
      expect(removals(f)[0]).toMatch(/force=1/);
    }, 20_000);

    it('says that a loaded engine can look wedged, and names the bound that raises it', async () => {
      const f = await daemon({ create: 'ok', start: 'stall', remove: 'ok' });
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      const message = (failure as Error).message;
      expect(message).toContain('A loaded engine can look wedged');
      expect(message).toContain(`${STEP_DEADLINE_ENV} above 1.5s`);
      expect(message).toContain('Otherwise report the engine as wedged');
    }, 20_000);

    it('says the same of a silent image inspection', async () => {
      const f = await daemon({ inspectImage: 'stall' });
      const failure = await ensureImage(
        'caddy:test',
        { env: f.env },
        { inspectMs: 1_500, pullMs: 1_500 }
      ).catch((e: unknown) => e);
      expect((failure as Error).message).toContain('A loaded engine can look wedged');
      expect((failure as Error).message).toContain(`${STEP_DEADLINE_ENV} above 1.5s`);
    }, 20_000);

    it('does not blame the load when the engine answered with a refusal', async () => {
      const f = await daemon({ create: 'ok', start: 'fail', remove: 'ok' });
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect((failure as Error).message).not.toContain('loaded engine');
    }, 20_000);

    it('bounds the removal too, and says how to remove the container by hand', async () => {
      const f = await daemon({ create: 'ok', start: 'stall', remove: 'stall' });
      const t0 = Date.now();
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect((failure as Error).message).toContain(`docker rm -f -v ${NAME}`);
      expect(Date.now() - t0).toBeLessThan(10_000);
    }, 20_000);

    it('removes a container whose create call never came back', async () => {
      const f = await daemon({ create: 'stall', remove: 'ok' });
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect((failure as Error).message).toContain(`docker create ${NAME}`);
      expect(removals(f)).toHaveLength(1);
    }, 20_000);

    it('reports a refused start with the daemon message and still removes by name', async () => {
      const f = await daemon({ create: 'ok', start: 'fail', remove: 'ok' });
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect((failure as Error).message).toContain('fake failure');
      expect((failure as Error).message).not.toContain('wedged');
      expect(removals(f)).toHaveLength(1);
    }, 20_000);

    it('removes the container when the port read gives no answer', async () => {
      const f = await daemon({
        create: 'ok',
        start: 'ok',
        inspectContainer: 'stall',
        remove: 'ok',
      });
      const failure = await startContainer(spec, { env: f.env }, fast).catch((e: unknown) => e);
      expect((failure as Error).message).toContain(`docker port ${NAME}`);
      expect(removals(f)).toHaveLength(1);
    }, 20_000);

    it('treats an already-removed container as removed', async () => {
      const f = await daemon({ remove: 'absent' });
      await expect(removeByName(NAME, { env: f.env }, 1_500)).resolves.toBeUndefined();
    });

    it('gives up on a silent engine in seconds, naming the cause', async () => {
      const f = await daemon({ inspectImage: 'stall' });
      const t0 = Date.now();
      await expect(
        ensureImage('caddy:test', { env: f.env }, { inspectMs: 1_500, pullMs: 1_500 })
      ).rejects.toThrow(/Docker engine is not answering/);
      expect(Date.now() - t0).toBeLessThan(8_000);
      expect(f.requests.some((r) => r.startsWith('POST /images/create'))).toBe(false);
    }, 20_000);

    it('fails in seconds when the image is absent and the registry is unreachable', async () => {
      const f = await daemon({ inspectImage: 'absent', pull: 'fail' });
      const t0 = Date.now();
      const failure = await ensureImage(
        IMAGE,
        { env: f.env },
        { inspectMs: 5_000, pullMs: 5_000 }
      ).catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(DockerFailure);
      expect((failure as Error).message).toContain(IMAGE);
      expect((failure as Error).message).toMatch(/not present locally and could not be pulled/);
      expect((failure as Error).message).toContain('no such host');
      expect(Date.now() - t0, 'fails in seconds, not minutes').toBeLessThan(10_000);
    }, 20_000);

    it('does not wait on a pull that never finishes', async () => {
      const f = await daemon({ inspectImage: 'absent', pull: 'stall' });
      const failure = await ensureImage(
        IMAGE,
        { env: f.env },
        { inspectMs: 5_000, pullMs: 1_500 }
      ).catch((e: unknown) => e);
      expect((failure as Error).message).toMatch(/did not finish within/);
    }, 20_000);

    it('does not pull an image that is already present', async () => {
      const f = await daemon({ inspectImage: 'ok' });
      await ensureImage('caddy:test', { env: f.env });
      expect(f.requests.some((r) => r.startsWith('POST /images/create'))).toBe(false);
    });

    it('pulls an absent image under a deadline and then goes on', async () => {
      const f = await daemon({ inspectImage: 'absent', pull: 'ok' });
      await ensureImage('caddy:test', { env: f.env }, { inspectMs: 5_000, pullMs: 5_000 });
      expect(f.requests.filter((r) => r.startsWith('POST /images/create'))).toHaveLength(1);
    }, 20_000);

    it('reports a stopped engine as unreachable, not as a missing image', async () => {
      const env = { ...process.env, DOCKER_HOST: `unix://${join(tmpdir(), 'bl-no-such.sock')}` };
      const failure = await ensureImage(IMAGE, { env }).catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(DockerFailure);
      expect((failure as Error).message).toContain('No Docker engine is reachable');
      expect((failure as Error).message).not.toContain('could not be pulled');
    }, 20_000);

    it('treats a missing socket as no engine in both probes', async () => {
      const env = { ...process.env, DOCKER_HOST: `unix://${join(tmpdir(), 'bl-no-such.sock')}` };
      const lazy = await probeEngine({ env }, 5_000);
      expect(lazy.up).toBe(false);
      expect(lazy.reason).toContain('found no engine');
      const eager = probeEngineSync({ env }, 5_000);
      expect(eager.up).toBe(false);
      expect(eager.reason).toContain('found no engine');
    }, 20_000);

    it('does not take exit status 0 as proof: an empty or non-numeric version is no engine', async () => {
      const empty = shim('exit 0');
      const junk = shim('echo "not a version"');
      const good = shim('echo 27.0.3');
      for (const [dir, up] of [
        [empty, false],
        [junk, false],
        [good, true],
      ] as const) {
        const env = { ...process.env, PATH: `${dir}:${process.env.PATH}` };
        expect((await probeEngine({ env }, 5_000)).up, `async, ${dir}`).toBe(up);
        expect(probeEngineSync({ env }, 5_000).up, `sync, ${dir}`).toBe(up);
      }
    }, 20_000);

    it('kills the whole process group of a client that ignores the deadline', async () => {
      const pidFile = join(mkdtempSync(join(tmpdir(), 'bl-pid-')), 'child.pid');
      cleanup.push(() => rmSync(pidFile, { force: true }));
      const dir = shim(`sleep 60 &\necho $! > "${pidFile}"\nwait`);
      const env = { ...process.env, PATH: `${dir}:${process.env.PATH}` };
      const r = await docker(['anything'], 800, { env });
      expect(r.timedOut).toBe(true);
      const grandchild = Number(readFileSync(pidFile, 'utf8').trim());
      expect(grandchild).toBeGreaterThan(0);
      await waitFor(() => !isAlive(grandchild), 3_000);
    }, 20_000);

    it('removes the container by name when the run is interrupted during a silent start', async () => {
      const f = await daemon({ create: 'ok', start: 'stall', remove: 'ok' });
      const child = spawn(process.execPath, [RUNNER, 'interrupt', NAME], {
        env: f.env,
        stdio: 'ignore',
      });
      const ended = new Promise<string | null>((r) => child.on('exit', (_c, s) => r(s)));
      await waitFor(() => f.requests.some((r) => r.endsWith(`/containers/${NAME}/start`)), 10_000);
      child.kill('SIGINT');
      await expect(ended).resolves.toBe('SIGINT');
      await waitFor(() => removals(f).length === 1, 5_000);
    }, 30_000);

    it('removes a container the run forgot, when the process exits', async () => {
      const f = await daemon({ create: 'ok', start: 'ok', inspectContainer: 'ok', remove: 'ok' });
      const child = spawn(process.execPath, [RUNNER, 'forget', NAME], {
        env: f.env,
        stdio: 'ignore',
      });
      await new Promise((r) => child.on('exit', r));
      await waitFor(() => removals(f).length === 1, 5_000);
    }, 30_000);

    it('probes the engine: an answer, silence and a missing client are each named', async () => {
      const answering = await daemon({ info: 'ok' });
      await expect(probeEngine({ env: answering.env }, 5_000)).resolves.toMatchObject({ up: true });

      const silent = await daemon({ info: 'stall' });
      const t0 = Date.now();
      const quiet = await probeEngine({ env: silent.env }, 1_500);
      expect(quiet.up).toBe(false);
      expect(quiet.reason).toMatch(/gave no answer within 1\.5s/);
      expect(Date.now() - t0).toBeLessThan(8_000);

      const t1 = Date.now();
      const quietSync = probeEngineSync({ env: silent.env }, 1_500);
      expect(quietSync.up).toBe(false);
      expect(quietSync.reason).toMatch(/gave no answer within 1\.5s/);
      expect(Date.now() - t1).toBeLessThan(8_000);

      const env = { ...answering.env, PATH: '/nonexistent' };
      expect(probeEngineSync({ env }, 1_500).reason).toContain('found no engine');
      const gone = await docker(['info'], 1_500, { env });
      expect(gone.status).toBeNull();
      expect(gone.stderr).toMatch(/ENOENT/);
      const missing = await probeEngine({ env }, 1_500);
      expect(missing.up).toBe(false);
      expect(missing.reason).toContain('found no engine');
    }, 20_000);
  }
);

// The same control against the real engine, when one answers: an image that
// cannot exist, on a registry address that refuses connections.
const real = hasCli ? probeEngineSync() : { up: false, reason: 'no docker client' };
describe.skipIf(!real.up)('an absent image against the real engine', () => {
  it('fails in seconds with a message that names the image', async () => {
    const slot = await takeSlot({ waitMs: 90_000, label: 'docker-harness-test' });
    try {
      const t0 = Date.now();
      const image = '127.0.0.1:1/branchleft-absent-image:none';
      const failure = await ensureImage(image, {}, { inspectMs: 20_000, pullMs: 30_000 }).catch(
        (e: unknown) => e
      );
      expect(failure).toBeInstanceOf(DockerFailure);
      expect((failure as Error).message).toContain(image);
      expect((failure as Error).message).toContain('could not be pulled');
      expect((failure as Error).message).not.toContain('No Docker engine is reachable');
      expect(Date.now() - t0, 'fails in seconds, not minutes').toBeLessThan(25_000);
    } finally {
      slot.release();
    }
  }, 150_000);
});

describe('the bound on one engine step', () => {
  it('is 30 s unless the environment says otherwise', () => {
    expect(DEFAULT_STEP_DEADLINE_MS).toBe(30_000);
    expect(stepDeadlineMs({})).toBe(30_000);
    expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: '' })).toBe(30_000);
  });

  it('takes a whole number of milliseconds from the environment', () => {
    expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: '75000' })).toBe(75_000);
    expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: ' 45000 ' })).toBe(45_000);
  });

  it('falls back to the default for a value it cannot honour', () => {
    for (const bad of ['abc', '-5', '0', '999', '1.5e3x', '12.5', 'Infinity', '2147483648']) {
      expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: bad }), bad).toBe(30_000);
    }
  });

  it('stops at the largest delay a timer honours: a larger one would fire after 1 ms', () => {
    expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: '2147483647' })).toBe(2_147_483_647);
    expect(stepDeadlineMs({ [STEP_DEADLINE_ENV]: '3000000000' })).toBe(30_000);
  });

  it('is the bound image inspection, create and start run under', () => {
    const bound = stepDeadlineMs();
    expect(IMAGE_LIMITS.inspectMs).toBe(bound);
    expect(CONTAINER_LIMITS.createMs).toBe(bound);
    expect(CONTAINER_LIMITS.startMs).toBe(bound);
  });

  it('reaches those three limits when the environment sets it', async () => {
    vi.stubEnv(STEP_DEADLINE_ENV, '75000');
    vi.resetModules();
    try {
      const fresh = await import('./dockerHarness.js');
      expect(fresh.IMAGE_LIMITS.inspectMs).toBe(75_000);
      expect(fresh.CONTAINER_LIMITS.createMs).toBe(75_000);
      expect(fresh.CONTAINER_LIMITS.startMs).toBe(75_000);
      expect(fresh.CONTAINER_LIMITS.portMs).toBe(15_000);
      expect(fresh.IMAGE_LIMITS.pullMs).toBe(120_000);
    } finally {
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});

describe('a Docker slot', { timeout: 20_000 }, () => {
  const made: string[] = [];
  const fresh = () => {
    const dir = mkdtempSync(join(tmpdir(), 'bl-slots-'));
    made.push(dir);
    return dir;
  };
  afterEach(() => {
    ownerWrite.before = undefined;
    ownerWrite.beforeRemove = undefined;
    made.splice(0).forEach((d) => {
      try {
        chmodSync(d, 0o755);
      } catch {
        // already gone
      }
      rmSync(d, { recursive: true, force: true });
    });
  });
  const isRoot = process.getuid?.() === 0;

  it('is taken by exact name and released', async () => {
    const dir = fresh();
    const slot = await takeSlot({ dir, waitMs: 500, label: 'a' });
    expect(slot.name).toBe('slot-1');
    expect(readdirSync(dir)).toEqual(['slot-1']);
    slot.release();
    slot.release();
    expect(readdirSync(dir)).toEqual([]);
  });

  it('refuses, naming the holders, when every slot is held elsewhere', async () => {
    const dir = fresh();
    for (const n of ['slot-1', 'slot-2']) {
      mkdirSync(join(dir, n));
      writeFileSync(join(dir, n, 'owner'), `got ${n} (builder)\n`);
    }
    const t0 = Date.now();
    await expect(takeSlot({ dir, waitMs: 400, pollMs: 100, label: 'a' })).rejects.toThrow(
      /No Docker slot became free.*slot-1: got slot-1 \(builder\).*Nothing was started/
    );
    expect(Date.now() - t0).toBeGreaterThanOrEqual(400);
    expect(readdirSync(dir).sort()).toEqual(['slot-1', 'slot-2']);
  });

  it('takes the second slot when the first is held, and the first again once freed', async () => {
    const dir = fresh();
    const first = await takeSlot({ dir, waitMs: 500, label: 'a' });
    const second = await takeSlot({ dir, waitMs: 500, label: 'b' });
    expect([first.name, second.name]).toEqual(['slot-1', 'slot-2']);
    first.release();
    const third = await takeSlot({ dir, waitMs: 500, label: 'c' });
    expect(third.name).toBe('slot-1');
    second.release();
    third.release();
  });

  it('waits for a slot that frees while it polls', async () => {
    const dir = fresh();
    const a = await takeSlot({ dir, max: 1, waitMs: 500, label: 'a' });
    setTimeout(() => a.release(), 250);
    const b = await takeSlot({ dir, max: 1, waitMs: 3_000, pollMs: 50, label: 'b' });
    expect(b.name).toBe('slot-1');
    b.release();
  });

  it('reclaims a slot only when its own owner file names a dead process', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), 'pid=2147483646 edge-ghost-setup-test\n');
    const slot = await takeSlot({ dir, max: 1, waitMs: 300, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    slot.release();

    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), `pid=${process.pid} still-running\n`);
    await expect(takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' })).rejects.toThrow(
      /No Docker slot became free/
    );
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('leaves a slot with no owner file alone while it is young, and says it will be reclaimed', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    expect(failure).toBeInstanceOf(DockerFailure);
    const message = (failure as Error).message;
    expect(message).toMatch(/slot-1: no owner file/);
    expect(message).toMatch(/reclaimed once it is older than 10s; re-run shortly/);
    expect(message).not.toContain('wait for it to finish');
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('reclaims a slot with no owner file once it is older than the stated age', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    const old = new Date(Date.now() - ORPHAN_SLOT_AGE_MS - 5_000);
    utimesSync(join(dir, 'slot-1'), old, old);
    const slot = await takeSlot({ dir, max: 1, waitMs: 300, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    expect(readFileSync(join(dir, 'slot-1', 'owner'), 'utf8')).toBe(`pid=${process.pid} a\n`);
    slot.release();
    expect(readdirSync(dir)).toEqual([]);
  });

  it('reclaims an aged slot whose owner file was left empty', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), '');
    const old = new Date(Date.now() - ORPHAN_SLOT_AGE_MS - 5_000);
    utimesSync(join(dir, 'slot-1'), old, old);
    const slot = await takeSlot({ dir, max: 1, waitMs: 300, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    slot.release();
  });

  it('does not reclaim a slot with no owner file that was made just now', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    await expect(takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' })).rejects.toThrow(
      /No Docker slot became free/
    );
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('tells the truth for a holder it cannot reclaim: how to clear it, not to wait', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), 'got slot-1 (by hand)\n');
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    const message = (failure as Error).message;
    expect(message).toContain(`rm -r '${join(dir, 'slot-1')}'`);
    expect(message).toContain('names no running process');
    expect(message).not.toContain('wait for it to finish');
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('says to wait only when a holder is a running process', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), `pid=${process.pid} other-proof\n`);
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    const message = (failure as Error).message;
    expect(message).toContain(`slot-1: pid=${process.pid} other-proof`);
    expect(message).toContain('wait for it to finish and re-run');
    expect(message).not.toContain('rm -r');
  });

  it('never removes a slot another holder has since taken', async () => {
    const dir = fresh();
    const slot = await takeSlot({ dir, max: 1, waitMs: 200, label: 'a' });
    writeFileSync(join(dir, 'slot-1', 'owner'), 'pid=1 someone-else\n');
    slot.release();
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('never overwrites the owner of a slot reclaimed while its first holder was suspended', async () => {
    const dir = fresh();
    ownerWrite.before = () => {
      rmSync(join(dir, 'slot-1'), { recursive: true });
      mkdirSync(join(dir, 'slot-1'));
      writeFileSync(join(dir, 'slot-1', 'owner'), `pid=${process.pid} newer-holder\n`);
    };
    await expect(takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' })).rejects.toThrow(
      /No Docker slot became free/
    );
    expect(readFileSync(join(dir, 'slot-1', 'owner'), 'utf8')).toBe(
      `pid=${process.pid} newer-holder\n`
    );
  });

  it('takes the slot again when it was reclaimed and not yet taken by another', async () => {
    const dir = fresh();
    ownerWrite.before = () => rmSync(join(dir, 'slot-1'), { recursive: true });
    const slot = await takeSlot({ dir, max: 1, waitMs: 2_000, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    expect(readFileSync(join(dir, 'slot-1', 'owner'), 'utf8')).toBe(`pid=${process.pid} a\n`);
    slot.release();
  });

  it('looks again when its own owner write fails because the slot is being removed', async () => {
    const dir = fresh();
    ownerWrite.before = () => {
      rmSync(join(dir, 'slot-1'), { recursive: true });
      throw errno('EINVAL');
    };
    const slot = await takeSlot({ dir, max: 1, waitMs: 2_000, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    slot.release();
  });

  it('looks again when another session is already removing the stale slot', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    writeFileSync(join(dir, 'slot-1', 'owner'), 'pid=2147483646 gone\n');
    ownerWrite.beforeRemove = () => {
      throw errno('ENOTEMPTY');
    };
    const slot = await takeSlot({ dir, max: 1, waitMs: 2_000, pollMs: 50, label: 'a' });
    expect(slot.name).toBe('slot-1');
    slot.release();
  });

  it('leaves a slot alone whose owner file exists but cannot be read, and says how to clear it', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1', 'owner'), { recursive: true });
    const old = new Date(Date.now() - ORPHAN_SLOT_AGE_MS - 60_000);
    utimesSync(join(dir, 'slot-1'), old, old);
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    expect(failure).toBeInstanceOf(DockerFailure);
    const message = (failure as Error).message;
    expect(message).toContain('slot-1: owner file cannot be read');
    expect(message).toContain(`rm -r '${join(dir, 'slot-1')}'`);
    expect(message).not.toContain('re-run shortly');
    expect(message).not.toContain('wait for it to finish');
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('keeps a holder with an empty label running: taken, found, and released', async () => {
    const dir = fresh();
    const slot = await takeSlot({ dir, max: 1, waitMs: 200, label: '' });
    expect(readFileSync(join(dir, 'slot-1', 'owner'), 'utf8')).toBe(`pid=${process.pid}\n`);
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'b' }).catch(
      (e: unknown) => e
    );
    expect((failure as Error).message).toContain('wait for it to finish and re-run');
    expect((failure as Error).message).not.toContain('rm -r');
    slot.release();
    expect(readdirSync(dir)).toEqual([]);
  });

  it('quotes a slot path that holds a single quote so the shell reads it back whole', async () => {
    const dir = join(fresh(), "it's a dir");
    mkdirSync(join(dir, 'slot-1'), { recursive: true });
    writeFileSync(join(dir, 'slot-1', 'owner'), 'got slot-1 (by hand)\n');
    const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    const message = (failure as Error).message;
    const quoted = message.slice(message.indexOf('rm -r ') + 'rm -r '.length);
    const printed = spawnSync('sh', ['-c', `printf %s ${quoted}`], { encoding: 'utf8' });
    expect(printed.stdout).toBe(join(dir, 'slot-1'));
  });

  it('does not promise a reclaim for a slot whose age cannot be told', async () => {
    const dir = fresh();
    symlinkSync(join(dir, 'nowhere'), join(dir, 'slot-1'));
    mkdirSync(join(dir, 'slot-2'));
    const future = new Date(Date.now() + 3_600_000);
    utimesSync(join(dir, 'slot-2'), future, future);
    const failure = await takeSlot({ dir, max: 2, waitMs: 200, pollMs: 50, label: 'a' }).catch(
      (e: unknown) => e
    );
    const message = (failure as Error).message;
    expect(message).toContain('slot-1: no owner file (its age cannot be told)');
    expect(message).toContain('slot-2: no owner file (its age cannot be told)');
    expect(message).not.toContain('re-run shortly');
    expect(message).toContain(`rm -r '${join(dir, 'slot-1')}' && rm -r '${join(dir, 'slot-2')}'`);
  });

  it.skipIf(isRoot)(
    'names a stale slot it cannot remove, with the command, not a raw error',
    async () => {
      const dir = fresh();
      mkdirSync(join(dir, 'slot-1'));
      writeFileSync(join(dir, 'slot-1', 'owner'), 'pid=2147483646 gone\n');
      chmodSync(dir, 0o555);
      const failure = await takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' }).catch(
        (e: unknown) => e
      );
      expect(failure).toBeInstanceOf(DockerFailure);
      expect((failure as Error).message).toMatch(/slot-1 in .* is stale but could not be removed/);
      expect((failure as Error).message).toContain(`rm -r '${join(dir, 'slot-1')}'`);
    }
  );
});
