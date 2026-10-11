import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  DockerFailure,
  docker,
  ensureImage,
  probeEngine,
  probeEngineSync,
  removeByName,
  startContainer,
  takeSlot,
  type ContainerLimits,
  type ContainerSpec,
} from './dockerHarness';

// The controls run against a fake daemon on a unix socket, so they need the
// docker CLI but no engine and no Docker Hub: a wedged or unreachable engine
// is exactly what the fake reproduces.
const hasCli = spawnSync('docker', ['--version'], { timeout: 10_000 }).status === 0;
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

describe.skipIf(!hasCli)(
  'a container start against a daemon that goes silent',
  { timeout: 20_000 },
  () => {
    const open: Fake[] = [];
    afterEach(async () => {
      await Promise.all(open.splice(0).map((f) => f.close()));
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
      expect(probeEngineSync({ env }, 1_500).reason).toContain('`docker info` failed');
      const gone = await docker(['info'], 1_500, { env });
      expect(gone.status).toBeNull();
      expect(gone.stderr).toMatch(/ENOENT/);
      const missing = await probeEngine({ env }, 1_500);
      expect(missing.up).toBe(false);
      expect(missing.reason).toContain('`docker info` failed');
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
      expect(Date.now() - t0, 'fails in seconds, not minutes').toBeLessThan(25_000);
    } finally {
      slot.release();
    }
  }, 150_000);
});

describe('a Docker slot', { timeout: 20_000 }, () => {
  const made: string[] = [];
  const fresh = () => {
    const dir = mkdtempSync(join(tmpdir(), 'bl-slots-'));
    made.push(dir);
    return dir;
  };
  afterEach(() => {
    made.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true }));
  });

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

  it('leaves a slot alone when the owner file is not in this format', async () => {
    const dir = fresh();
    mkdirSync(join(dir, 'slot-1'));
    await expect(takeSlot({ dir, max: 1, waitMs: 200, pollMs: 50, label: 'a' })).rejects.toThrow(
      /owner unreadable/
    );
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });

  it('never removes a slot another holder has since taken', async () => {
    const dir = fresh();
    const slot = await takeSlot({ dir, max: 1, waitMs: 200, label: 'a' });
    writeFileSync(join(dir, 'slot-1', 'owner'), 'pid=1 someone-else\n');
    slot.release();
    expect(readdirSync(dir)).toEqual(['slot-1']);
  });
});
