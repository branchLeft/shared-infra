import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Helpers for tests that start a container. Every call has a hard deadline and
// a SIGKILL: the docker client traps SIGTERM and forwards it to the container,
// so a polite signal never ends a client stuck on a silent daemon. A container
// is removed by its exact name on every exit path.

// The bounds, the slot rules and the limits left in place: dockerHarness.md.

/** The environment variable that sets the bound on one engine call that inspects, creates or starts. */
export const STEP_DEADLINE_ENV = 'BRANCHLEFT_DOCKER_STEP_MS';
export const DEFAULT_STEP_DEADLINE_MS = 30_000;
// The largest delay a timer honours; a larger one fires after 1 ms.
const MAX_TIMER_MS = 2_147_483_647;

/**
 * The bound, in milliseconds, on a single `image inspect`, `create` or `start`.
 * A whole number from one second to the timer ceiling, otherwise the default applies.
 */
export function stepDeadlineMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number((env[STEP_DEADLINE_ENV] ?? '').trim());
  const ok = Number.isInteger(n) && n >= 1_000 && n <= MAX_TIMER_MS;
  return ok ? n : DEFAULT_STEP_DEADLINE_MS;
}

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

// Clients still running, and containers created and not yet confirmed removed.
// An interrupt or a process exit sweeps both, so neither outlives the run.
const live = new Set<ChildProcess>();
const owned = new Map<string, NodeJS.ProcessEnv | undefined>();
const held = new Set<() => void>();
let armed = false;

/** SIGKILL the client's whole process group (it is spawned as a group leader). */
function killGroup(child: ChildProcess) {
  try {
    if (child.pid !== undefined) process.kill(-child.pid, 'SIGKILL');
  } catch {
    child.kill('SIGKILL');
  }
}

function sweep() {
  live.forEach(killGroup);
  live.clear();
  for (const [name, env] of owned) {
    spawnSync('docker', ['rm', '-f', '-v', name], {
      env: env ?? process.env,
      timeout: 5_000,
      killSignal: 'SIGKILL',
      stdio: 'ignore',
    });
  }
  owned.clear();
  [...held].forEach((release) => release());
}

function arm() {
  if (armed) return;
  armed = true;
  process.on('exit', sweep);
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.once(signal, () => {
      sweep();
      process.kill(process.pid, signal);
    });
  }
}

/** Run the docker client with a hard deadline. Never rejects, never hangs. */
export function docker(
  args: string[],
  deadlineMs: number,
  ctx: DockerContext = {}
): Promise<DockerResult> {
  arm();
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
      detached: true,
    });
    live.add(child);

    const finish = (status: number | null) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      live.delete(child);
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
        killGroup(child);
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

// A busy engine can answer `docker info` and still take longer than a step's
// bound, so a silent step is not proof of a wedged engine.
const loadedEngineNote = (ms: number) =>
  `A loaded engine can look wedged: if the machine was busy, re-run once it is idle, or raise ` +
  `${STEP_DEADLINE_ENV} above ${seconds(ms)}.`;

export interface EngineProbe {
  up: boolean;
  reason: string;
}

const INFO_ARGS = ['info', '--format', '{{.ServerVersion}}'];

// Exit status is not enough: with `--format`, client 27 exits 0 with an empty
// stdout when no daemon is reachable. Only a printed server version is "up".
const probeVerdict = (
  status: number | null,
  timedOut: boolean,
  stdout: string,
  stderr: string,
  deadlineMs: number
): EngineProbe => {
  if (status === 0 && /^\d/.test(stdout.trim())) return { up: true, reason: 'engine answered' };
  if (timedOut) {
    return { up: false, reason: `\`docker info\` gave no answer within ${seconds(deadlineMs)}` };
  }
  const why = status === 0 ? `no server version printed (${firstLine(stderr)})` : firstLine(stderr);
  return { up: false, reason: `\`docker info\` found no engine: ${why}` };
};

/** Whether the engine answers `docker info` within a short deadline. */
export async function probeEngine(
  ctx: DockerContext = {},
  deadlineMs = 10_000
): Promise<EngineProbe> {
  const r = await docker(INFO_ARGS, deadlineMs, ctx);
  return probeVerdict(r.status, r.timedOut, r.stdout, r.stderr, deadlineMs);
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
  return probeVerdict(r.status, timedOut, r.stdout ?? '', stderr, deadlineMs);
}

export interface ImageLimits {
  inspectMs: number;
  pullMs: number;
}

export const IMAGE_LIMITS: ImageLimits = { inspectMs: stepDeadlineMs(), pullMs: 120_000 };

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
        `${seconds(limits.inspectMs)}. No container was started. Do not retry in a loop. ` +
        `${loadedEngineNote(limits.inspectMs)} Otherwise report the engine as wedged.`
    );
  }
  // A failed inspect is an absent image or an engine that is not there. Which one is
  // asked of the engine (`docker info`), not read from the client's wording: Docker 27
  // said "Cannot connect to the Docker daemon", Docker 29 says "failed to connect to the
  // docker API", and a pull attempted against a stopped engine reports the wrong fault.
  const engine = await probeEngine(ctx, limits.inspectMs);
  if (!engine.up) {
    throw new DockerFailure(
      `No Docker engine is reachable: ${firstLine(have.stderr)}. No container was started. ` +
        'Start Docker and re-run, or leave it stopped to skip this check locally.'
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
  createMs: stepDeadlineMs(),
  startMs: stepDeadlineMs(),
  portMs: 15_000,
  removeMs: 10_000,
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
  if (r.status === 0 || /No such container/i.test(r.stderr)) {
    owned.delete(name);
    return undefined;
  }
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
        (r.timedOut
          ? ` Do not retry in a loop. ${loadedEngineNote(ms)} Otherwise report the engine as wedged.`
          : '')
    );
  };

  arm();
  owned.set(spec.name, ctx.env);
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

/** The owner text; '' when there is no owner file; null when it exists and cannot be read. */
const readOwner = (path: string): string | null => {
  try {
    return readFileSync(join(path, 'owner'), 'utf8').trim();
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'ENOENT' ? '' : null;
  }
};

const ownerPid = (owner: string | null) => {
  const pid = /^pid=(\d+)(?: |$)/.exec(owner ?? '')?.[1];
  return pid === undefined ? undefined : Number(pid);
};

const shellQuote = (text: string) => `'${text.replace(/'/g, `'\\''`)}'`;

/**
 * A slot directory with no owner file is a holder that died between `mkdir` and
 * writing its owner, or one still writing it, which takes microseconds.
 */
export const ORPHAN_SLOT_AGE_MS = 10_000;

// Errors from writing the owner file that mean another session took or removed the slot
// (EINVAL is what macOS gives for a create inside a directory that is being removed).
const LOST_SLOT_ERRORS = new Set(['EEXIST', 'ENOENT', 'ENOTDIR', 'EINVAL']);
// Errors from removing a stale slot that will not clear by themselves.
const HARD_REMOVE_ERRORS = new Set(['EACCES', 'EPERM', 'EROFS']);

// A directory dated further ahead than this is not "just made": clock skew.
const FUTURE_SLACK_MS = 1_000;

/** How long ago the slot directory was last changed; undefined when that cannot be told. */
const ageMs = (path: string): number | undefined => {
  try {
    const age = Date.now() - statSync(path).mtimeMs;
    return age < -FUTURE_SLACK_MS ? undefined : Math.max(0, age);
  } catch {
    return undefined;
  }
};

interface Holder {
  name: string;
  path: string;
  /** What the slot's state means for the caller. */
  state: 'running' | 'unowned' | 'stuck' | 'unreadable';
  text: string;
}

function describeHolder(dir: string, name: string): Holder {
  const path = join(dir, name);
  const owner = readOwner(path);
  const age = ageMs(path);
  if (owner === null) {
    return { name, path, state: 'unreadable', text: `${name}: owner file cannot be read` };
  }
  if (owner === '' && age === undefined) {
    const text = `${name}: no owner file (its age cannot be told)`;
    return { name, path, state: 'unreadable', text };
  }
  if (owner === '') {
    const note = `${seconds(age ?? 0)} old, reclaimed once older than ${seconds(ORPHAN_SLOT_AGE_MS)}`;
    return { name, path, state: 'unowned', text: `${name}: no owner file (${note})` };
  }
  const pid = ownerPid(owner);
  const running = pid !== undefined && alive(pid);
  return { name, path, state: running ? 'running' : 'stuck', text: `${name}: ${owner}` };
}

const clearCommand = (holders: Holder[]) =>
  holders.map((h) => `rm -r ${shellQuote(h.path)}`).join(' && ');

/** The advice that is true of every state a held slot can be in. */
function slotAdvice(holders: Holder[]): string {
  const named = (state: Holder['state']) => holders.filter((h) => h.state === state);
  const running = named('running');
  const unowned = named('unowned');
  const stuck = named('stuck');
  const unreadable = named('unreadable');
  const parts: string[] = [];
  if (running.length > 0) {
    parts.push('Another Docker proof is running; wait for it to finish and re-run.');
  }
  if (unowned.length > 0) {
    parts.push(
      `${unowned.map((h) => h.name).join(', ')} has no owner file yet and is reclaimed ` +
        `once it is older than ${seconds(ORPHAN_SLOT_AGE_MS)}; re-run shortly.`
    );
  }
  if (stuck.length > 0) {
    parts.push(
      `${stuck.map((h) => h.name).join(', ')} names no running process and this harness will not ` +
        `reclaim it; when no Docker proof is running, clear it with: ${clearCommand(stuck)}`
    );
  }
  if (unreadable.length > 0) {
    parts.push(
      `${unreadable.map((h) => h.name).join(', ')} cannot be classified (its owner file cannot be ` +
        `read, or its age cannot be told) so it is left alone; when no Docker proof is running, ` +
        `clear it with: ${clearCommand(unreadable)}`
    );
  }
  return parts.join(' ');
}

/**
 * Take one of `max` Docker slots (an atomic `mkdir`). Reclaims a dead `pid=` owner
 * or an owner-less slot older than `ORPHAN_SLOT_AGE_MS`; refuses after `waitMs`.
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
        const owner = readOwner(path);
        const pid = ownerPid(owner);
        const dead = pid !== undefined && !alive(pid);
        const age = ageMs(path);
        const orphaned = owner === '' && age !== undefined && age > ORPHAN_SLOT_AGE_MS;
        if (dead || orphaned) {
          try {
            rmSync(path, { recursive: true, force: true });
          } catch (err) {
            const code = (err as NodeJS.ErrnoException).code;
            // Another session removing the same slot is not a failure: look again at the next poll.
            if (!HARD_REMOVE_ERRORS.has(code ?? '')) continue;
            throw new DockerFailure(
              `Docker slot ${name} in ${dir} is stale but could not be removed (${code}). ` +
                `Nothing was started. When no Docker proof is running, clear it with: ` +
                `rm -r ${shellQuote(path)}`
            );
          }
          i -= 1;
        }
        continue;
      }
      const mine = `pid=${process.pid} ${opts.label}`.trim();
      try {
        // `wx`: a holder suspended since its `mkdir` may have been reclaimed meanwhile; it
        // must then lose the slot, never overwrite the owner file of the one that took it.
        writeFileSync(join(path, 'owner'), `${mine}\n`, { flag: 'wx' });
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? '';
        if (LOST_SLOT_ERRORS.has(code)) continue;
        throw err;
      }
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        held.delete(release);
        if (readOwner(path) === mine) rmSync(path, { recursive: true, force: true });
      };
      arm();
      held.add(release);
      return { name, release };
    }
    if (Date.now() >= until) {
      const holders = readdirSync(dir)
        .filter((n) => n.startsWith('slot-'))
        .map((n) => describeHolder(dir, n));
      throw new DockerFailure(
        `No Docker slot became free within ${seconds(opts.waitMs)} in ${dir} ` +
          `(${holders.map((h) => h.text).join('; ')}). Nothing was started. ${slotAdvice(holders)}`
      );
    }
    await new Promise((r) => setTimeout(r, poll));
  }
}
