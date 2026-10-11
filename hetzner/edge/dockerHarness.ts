import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Helpers for tests that start a container. Every call has a hard deadline and
// a SIGKILL: the docker client traps SIGTERM and forwards it to the container,
// so a polite signal never ends a client stuck on a silent daemon. A container
// is removed by its exact name on every exit path.

export class DockerFailure extends Error {}

export interface DockerContext {
  /** Environment for the docker client; defaults to the process environment. */
  env?: NodeJS.ProcessEnv;
}

export interface DockerResult {
  status: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  elapsedMs: number;
}

/** Run the docker client with a hard deadline. Never rejects, never hangs. */
export function docker(
  args: string[],
  deadlineMs: number,
  ctx: DockerContext = {}
): Promise<DockerResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    const timers: NodeJS.Timeout[] = [];

    const child = spawn('docker', args, {
      env: ctx.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const finish = (status: number | null) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      child.stdout.destroy();
      child.stderr.destroy();
      resolve({ status, stdout, stderr, timedOut, elapsedMs: Date.now() - started });
    };

    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('error', (e: Error) => {
      stderr += e.message;
      finish(null);
    });
    child.on('close', (code) => finish(code));
    // A grandchild holding the pipes open must not keep us waiting.
    child.on('exit', (code) => {
      if (!settled) timers.push(setTimeout(() => finish(code), 500));
    });
    timers.push(
      setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
        timers.push(setTimeout(() => finish(null), 2_000));
      }, deadlineMs)
    );
  });
}

const firstLine = (text: string) =>
  text
    .trim()
    .split('\n')
    .find((l) => l.trim() !== '')
    ?.slice(0, 300) ?? 'no output';

const seconds = (ms: number) => `${Math.round(ms / 100) / 10}s`;

export interface EngineProbe {
  up: boolean;
  reason: string;
}

const INFO_ARGS = ['info', '--format', '{{.ServerVersion}}'];

const probeVerdict = (
  status: number | null,
  timedOut: boolean,
  stderr: string,
  deadlineMs: number
): EngineProbe => {
  if (status === 0) return { up: true, reason: 'engine answered' };
  return {
    up: false,
    reason: timedOut
      ? `\`docker info\` gave no answer within ${seconds(deadlineMs)}`
      : `\`docker info\` failed: ${firstLine(stderr)}`,
  };
};

/** Whether the engine answers `docker info` within a short deadline. */
export async function probeEngine(
  ctx: DockerContext = {},
  deadlineMs = 10_000
): Promise<EngineProbe> {
  const r = await docker(INFO_ARGS, deadlineMs, ctx);
  return probeVerdict(r.status, r.timedOut, r.stderr, deadlineMs);
}

/** The same probe where nothing can await (`describe.skipIf`); blocks at most `deadlineMs`. */
export function probeEngineSync(ctx: DockerContext = {}, deadlineMs = 10_000): EngineProbe {
  const r = spawnSync('docker', INFO_ARGS, {
    env: ctx.env ?? process.env,
    encoding: 'utf8',
    timeout: deadlineMs,
    killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const timedOut = (r.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
  const stderr = r.error && !timedOut ? r.error.message : (r.stderr ?? '');
  return probeVerdict(r.status, timedOut, stderr, deadlineMs);
}

export interface ImageLimits {
  inspectMs: number;
  pullMs: number;
}

export const IMAGE_LIMITS: ImageLimits = { inspectMs: 30_000, pullMs: 120_000 };

/** The image is present locally, or has been pulled within a deadline. */
export async function ensureImage(
  image: string,
  ctx: DockerContext = {},
  limits: ImageLimits = IMAGE_LIMITS
): Promise<void> {
  const have = await docker(
    ['image', 'inspect', '--format', '{{.Id}}', image],
    limits.inspectMs,
    ctx
  );
  if (have.status === 0) return;
  if (have.timedOut) {
    throw new DockerFailure(
      `The Docker engine is not answering: \`docker image inspect ${image}\` gave no answer within ` +
        `${seconds(limits.inspectMs)}. No container was started. Do not retry in a loop: report the engine as wedged.`
    );
  }
  const pull = await docker(['pull', '--quiet', image], limits.pullMs, ctx);
  if (pull.status === 0) return;
  const cause = pull.timedOut
    ? `the pull did not finish within ${seconds(limits.pullMs)} (registry slow, unreachable or rate-limited)`
    : firstLine(pull.stderr);
  throw new DockerFailure(
    `Image ${image} is not present locally and could not be pulled: ${cause}. No container was started. ` +
      `Pull it by hand once (docker pull ${image}) or fix registry access, then re-run.`
  );
}

export interface ContainerSpec {
  name: string;
  label: string;
  image: string;
  containerPort: number;
  /** A file on the host, mounted read-only at `mountTarget`. */
  mountSource: string;
  mountTarget: string;
}

export interface ContainerLimits {
  createMs: number;
  startMs: number;
  portMs: number;
  removeMs: number;
}

export const CONTAINER_LIMITS: ContainerLimits = {
  createMs: 30_000,
  startMs: 30_000,
  portMs: 15_000,
  removeMs: 20_000,
};

/**
 * Remove a container by its exact name. Never throws. Returns undefined when
 * it is gone (or was never there), otherwise a message for the caller.
 */
export async function removeByName(
  name: string,
  ctx: DockerContext = {},
  deadlineMs = CONTAINER_LIMITS.removeMs
): Promise<string | undefined> {
  const r = await docker(['rm', '-f', '-v', name], deadlineMs, ctx);
  if (r.status === 0 || /No such container/i.test(r.stderr)) return undefined;
  const cause = r.timedOut ? `no answer within ${seconds(deadlineMs)}` : firstLine(r.stderr);
  return `The container ${name} could not be removed (${cause}). Remove it by hand: docker rm -f -v ${name}`;
}

/**
 * Create, start and read the port of one container, each step with its own
 * deadline. Any failure removes it by name and the error names the cause.
 */
export async function startContainer(
  spec: ContainerSpec,
  ctx: DockerContext = {},
  limits: ContainerLimits = CONTAINER_LIMITS
): Promise<number> {
  const fail = async (step: string, r: DockerResult, ms: number): Promise<never> => {
    const cause = r.timedOut
      ? `gave no answer within ${seconds(ms)}: the Docker engine is wedged`
      : `failed: ${firstLine(r.stderr)}`;
    const left = await removeByName(spec.name, ctx, limits.removeMs);
    throw new DockerFailure(
      `\`docker ${step} ${spec.name}\` ${cause}. ` +
        (left ? left : `The container ${spec.name} was removed by name.`) +
        (r.timedOut ? ' Do not retry in a loop: report the engine as wedged.' : '')
    );
  };

  const created = await docker(
    [
      'create',
      '--rm',
      '--pull',
      'never',
      '--name',
      spec.name,
      '--label',
      spec.label,
      '-p',
      `127.0.0.1::${spec.containerPort}`,
      '-v',
      `${spec.mountSource}:${spec.mountTarget}:ro`,
      spec.image,
    ],
    limits.createMs,
    ctx
  );
  if (created.status !== 0) return fail('create', created, limits.createMs);

  const started = await docker(['start', spec.name], limits.startMs, ctx);
  if (started.status !== 0) return fail('start', started, limits.startMs);

  const mapped = await docker(['port', spec.name, `${spec.containerPort}/tcp`], limits.portMs, ctx);
  if (mapped.status !== 0) return fail('port', mapped, limits.portMs);
  const port = Number(mapped.stdout.trim().split('\n')[0]?.split(':').pop());
  if (!Number.isInteger(port) || port <= 0) {
    await removeByName(spec.name, ctx, limits.removeMs);
    throw new DockerFailure(
      `\`docker port ${spec.name}\` printed no usable port (${firstLine(mapped.stdout)}). The container was removed.`
    );
  }
  return port;
}

export interface Slot {
  name: string;
  release(): void;
}

export interface SlotOptions {
  /** Defaults to BRANCHLEFT_DOCKER_SLOTS, then a directory under the temp dir. */
  dir?: string;
  max?: number;
  waitMs: number;
  pollMs?: number;
  label: string;
}

export const slotDir = () =>
  process.env.BRANCHLEFT_DOCKER_SLOTS || join(tmpdir(), 'branchleft-docker-slots');

const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
};

const readOwner = (path: string) => {
  try {
    return readFileSync(join(path, 'owner'), 'utf8').trim();
  } catch {
    return '';
  }
};

/**
 * Take one of `max` Docker slots (an atomic `mkdir`). Reclaims only a dead
 * `pid=` owner this function wrote; refuses, naming holders, after `waitMs`.
 */
export async function takeSlot(opts: SlotOptions): Promise<Slot> {
  const dir = opts.dir ?? slotDir();
  const max = opts.max ?? 2;
  const poll = opts.pollMs ?? 1_000;
  mkdirSync(dir, { recursive: true });
  const until = Date.now() + opts.waitMs;

  for (;;) {
    for (let i = 1; i <= max; i += 1) {
      const name = `slot-${i}`;
      const path = join(dir, name);
      try {
        mkdirSync(path);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
        const pid = /^pid=(\d+) /.exec(readOwner(path))?.[1];
        if (pid !== undefined && !alive(Number(pid))) {
          rmSync(path, { recursive: true, force: true });
          i -= 1;
        }
        continue;
      }
      const mine = `pid=${process.pid} ${opts.label}`;
      writeFileSync(join(path, 'owner'), `${mine}\n`);
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        if (readOwner(path) === mine) rmSync(path, { recursive: true, force: true });
      };
      process.once('exit', release);
      return { name, release };
    }
    if (Date.now() >= until) {
      const held = readdirSync(dir)
        .filter((n) => n.startsWith('slot-'))
        .map((n) => `${n}: ${readOwner(join(dir, n)) || 'owner unreadable'}`)
        .join('; ');
      throw new DockerFailure(
        `No Docker slot became free within ${seconds(opts.waitMs)} in ${dir} (${held}). ` +
          `Another Docker proof is running; wait for it to finish and re-run. Nothing was started.`
      );
    }
    await new Promise((r) => setTimeout(r, poll));
  }
}
