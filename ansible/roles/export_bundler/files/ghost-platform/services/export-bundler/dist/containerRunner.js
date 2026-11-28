import { execFile } from 'node:child_process';
import { dockerRemoveSync, dockerRemoveUntilGoneSync, installSignalCleanup, processCleanup, } from './cleanup.js';
import { withEnvFile } from './envFile.js';
/**
 * Every container in a run that carries tenant data on stdout or stderr --
 * the dump, the scratch database, the status probe, the SQLite backup, the
 * export colour, the relay -- runs with no log driver. Docker's default
 * json-file driver would otherwise write that output, uncapped, to
 * /var/lib/docker on the shared host. Attached stdout (what `docker run`
 * without `-d` prints) still reaches the caller: the log driver only decides
 * what Docker keeps.
 */
export const NO_CONTAINER_LOGS = ['--log-driver', 'none'];
export function tenantContainerArgs(config) {
    const args = [...NO_CONTAINER_LOGS, '--env-file', config.envFile];
    if (config.user !== null)
        args.push('--user', config.user);
    for (const mount of config.volumes) {
        const ro = mount.readOnly ? ',readonly' : '';
        args.push('--mount', `type=volume,src=${mount.volume},dst=${mount.mountPath}${ro}`);
    }
    return args;
}
/**
 * LLD-8 §08b: "The tenant's image is started on the tenant's data with no
 * route pointed at it." On the run's own network (always, in production)
 * the colour publishes nothing: that network is `--internal`, so it has no
 * route out of the host and Docker publishes no port for it. The relay below
 * is its one way in, bound to `127.0.0.1`. Without a network the colour
 * publishes on `127.0.0.1` itself -- never `0.0.0.0` -- as
 * render-core/test/live-demo-boot.test.ts proves for a demo colour.
 */
export function buildDockerRunArgs(spec) {
    const args = ['run', '-d', '--name', spec.containerName];
    if (spec.network !== null) {
        args.push('--network', spec.network);
    }
    else {
        args.push('-p', `127.0.0.1:${spec.loopbackPort}:2368`);
    }
    args.push(...tenantContainerArgs(spec));
    args.push(spec.image);
    return args;
}
export function relayNames(containerName) {
    return { relay: `${containerName}-relay`, edge: `${containerName}-edge` };
}
/**
 * Forwards one loopback port to the colour on the internal network, and does
 * nothing else: no environment, no volume, no tenant data at rest.
 */
export const RELAY_SCRIPT = "const net=require('net');const target=process.argv[1];" +
    'net.createServer((c)=>{const u=net.connect(2368,target);c.pipe(u);u.pipe(c);' +
    "c.on('error',()=>u.destroy());u.on('error',()=>c.destroy());}).listen(2368,'0.0.0.0');";
export function buildRelayRunArgs(spec) {
    const { relay, edge } = relayNames(spec.containerName);
    return [
        'run',
        '-d',
        '--name',
        relay,
        '--network',
        edge,
        '-p',
        `127.0.0.1:${spec.loopbackPort}:2368`,
        ...NO_CONTAINER_LOGS,
        '--read-only',
        '--cap-drop',
        'ALL',
        '--security-opt',
        'no-new-privileges',
        '--pids-limit',
        '64',
        '--memory',
        '128m',
        '--user',
        'node',
        '--entrypoint',
        'node',
        spec.image,
        '-e',
        RELAY_SCRIPT,
        spec.containerName,
    ];
}
export function buildDockerStopArgs(containerName) {
    return ['rm', '-f', containerName];
}
export function buildDockerInspectEnvArgs(containerName) {
    return ['inspect', '--format', '{{json .Config.Env}}', containerName];
}
/** Docker's `KEY=VALUE` list, as a map; the first `=` splits. */
export function parseInspectedEnv(stdout) {
    const parsed = JSON.parse(stdout);
    if (!Array.isArray(parsed))
        throw new Error('docker inspect did not return an env list');
    const env = {};
    for (const entry of parsed) {
        if (typeof entry !== 'string')
            continue;
        const eq = entry.indexOf('=');
        if (eq > 0)
            env[entry.slice(0, eq)] = entry.slice(eq + 1);
    }
    return env;
}
/** Ghost's content directory inside the tenant's image; the volume mounted here holds its media. */
export const GHOST_CONTENT_DIR = '/var/lib/ghost/content';
export function runDocker(dockerCommand, argv, registry = processCleanup, timeoutMs) {
    return new Promise((resolve, reject) => {
        // Explicit, minimal env: PATH only, never the ambient environment this
        // shell carries (which holds live production credentials this process
        // has no business handing to `docker`).
        const child = execFile(dockerCommand, [...argv], {
            env: { PATH: process.env.PATH ?? '' },
            maxBuffer: 16 * 1024 * 1024,
            // No timeout unless asked for: a dump or a copy runs as long as the data needs.
            ...(timeoutMs === undefined ? {} : { timeout: timeoutMs, killSignal: 'SIGKILL' }),
        }, (err, stdout, stderr) => {
            untrack();
            if (err) {
                if (timeoutMs !== undefined && err.killed === true) {
                    reject(new Error(`docker ${argv[0]} timed out after ${String(timeoutMs)} ms`));
                    return;
                }
                // Never err.message: it repeats the whole argv, env values included.
                reject(new Error(`docker ${argv[0]} failed (exit ${String(err.code)}): ${stderr}`));
                return;
            }
            resolve(stdout);
        });
        // Tracked while in flight: a signal kills this client before the removers
        // run, so a `create` it has not yet sent is never sent.
        const untrack = registry.trackChild(child);
    });
}
/** How long `docker version` may take before the engine is treated as unreadable. */
export const DOCKER_VERSION_TIMEOUT_MS = 30_000;
/** The oldest Docker Engine this package runs a tenant's data on. */
export const MIN_DOCKER_ENGINE_MAJOR = 28;
export class DockerEngineTooOldError extends Error {
    constructor(detail) {
        super(`refused: the Docker engine must be ${String(MIN_DOCKER_ENGINE_MAJOR)} or newer (${detail}); ` +
            `nothing was started`);
        this.name = 'DockerEngineTooOldError';
    }
}
// `N.N`, optionally `.N` and a `-rc.1` / `+dfsg` suffix; anything else is not a version.
const ENGINE_VERSION = /^(\d+)\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.+-]*)?$/;
/**
 * Refuses to run on a Docker engine older than 28, before anything is
 * created. Reads the engine (`Server`) version, not the client's, and fails
 * closed: a missing binary, a daemon that does not answer, or output that is
 * not a version is refused the same as an old engine. `docker version` is
 * killed after `timeoutMs`, so a daemon that accepts the connection and never
 * answers is refused too instead of hanging the run. Returns the version.
 */
export async function assertDockerEngineAtLeast28(dockerCommand = 'docker', registry = processCleanup, timeoutMs = DOCKER_VERSION_TIMEOUT_MS) {
    let stdout;
    try {
        stdout = await runDocker(dockerCommand, ['version', '--format', '{{.Server.Version}}'], registry, timeoutMs);
    }
    catch (err) {
        throw new DockerEngineTooOldError(`its version could not be read: ${err.message.slice(0, 300)}`);
    }
    const version = stdout.trim();
    const match = ENGINE_VERSION.exec(version);
    if (match === null) {
        throw new DockerEngineTooOldError(`its version reads as ${JSON.stringify(version.slice(0, 40))}`);
    }
    if (Number(match[1]) < MIN_DOCKER_ENGINE_MAJOR) {
        throw new DockerEngineTooOldError(`the engine is ${version}`);
    }
    return version;
}
/**
 * The first thing a run does, in this order: install the signal cleanup, then
 * check the Docker engine. Nothing that creates a resource runs before both.
 * Returns the function that uninstalls the signal handlers; when the engine
 * is refused the handlers are uninstalled and the refusal is thrown.
 */
export async function startup(options = {}) {
    const registry = options.registry ?? processCleanup;
    const uninstall = installSignalCleanup(registry, options.exit, options.signalTarget, options.writeStderr);
    try {
        await assertDockerEngineAtLeast28(options.dockerCommand ?? 'docker', registry);
    }
    catch (err) {
        uninstall();
        throw err;
    }
    return uninstall;
}
/**
 * `dockerCommand` defaults to the real binary; test/unit/containerRunner.test.ts
 * points it at a fixture script instead (mirroring
 * services/broker/test/helpers/fakeWrapper.mjs's own reasoning), so the
 * success and failure paths through `execFile` are proven without a real
 * Docker daemon -- a dependency no unit-test CI job here carries.
 */
export function createDockerContainerRunner(template, dockerCommand = 'docker', registry = processCleanup) {
    const { relay, edge } = relayNames(template.containerName);
    let relayed = false;
    let unregister;
    const removeRelaySync = () => {
        dockerRemoveUntilGoneSync(relay, dockerCommand, registry);
        try {
            dockerRemoveSync(['network', 'rm', edge], dockerCommand);
        }
        catch {
            // Already gone, or never created.
        }
    };
    const removeAllSync = () => {
        dockerRemoveUntilGoneSync(template.containerName, dockerCommand, registry);
        if (relayed)
            removeRelaySync();
    };
    return {
        async start(env, attach) {
            const spec = {
                ...template,
                network: attach?.network ?? template.network,
                volumes: [...template.volumes, ...(attach?.volumes ?? [])],
            };
            relayed = spec.network !== null;
            // Registered before `docker run`, so a signal mid-start still removes it.
            unregister = registry.register(`export colour ${template.containerName}`, removeAllSync);
            try {
                await withEnvFile(env, (envFile) => runDocker(dockerCommand, buildDockerRunArgs({ ...spec, envFile }), registry), registry);
                if (spec.network !== null) {
                    await runDocker(dockerCommand, ['network', 'create', edge], registry);
                    await runDocker(dockerCommand, buildRelayRunArgs(spec), registry);
                    await runDocker(dockerCommand, ['network', 'connect', spec.network, relay], registry);
                }
            }
            catch (err) {
                // `docker run -d` can create the container and then fail to start
                // it; the created container still holds the colour's environment.
                removeAllSync();
                unregister();
                throw err;
            }
            return { baseUrl: `http://127.0.0.1:${template.loopbackPort}` };
        },
        async readEnv() {
            return parseInspectedEnv(await runDocker(dockerCommand, buildDockerInspectEnvArgs(template.containerName), registry));
        },
        async stop() {
            if (relayed)
                removeRelaySync();
            await runDocker(dockerCommand, buildDockerStopArgs(template.containerName), registry);
            unregister?.();
        },
    };
}
