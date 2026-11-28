// dist/plugins/dockerImageLoader.js
import { realpath } from "node:fs/promises";
import { sep } from "node:path";

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/spool.js
var MAIL_SPOOL_STACK = "mail-spool";
var MAIL_SPOOL_SERVICE = "mail-spool";
var MAIL_SPOOL_HTTP_PORT = 8080;
var MAIL_SPOOL_BASE_URL = `http://${MAIL_SPOOL_SERVICE}:${MAIL_SPOOL_HTTP_PORT}`;
var DATA_MOUNT_PATH = "/data";
var DB_PATH = `${DATA_MOUNT_PATH}/spool.sqlite`;
var MAIL_SPOOL_SECRETS_PATH = `/etc/branchleft/${MAIL_SPOOL_STACK}.env`;

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/naming.js
var TENANT_DB_PREFIX = "ghost_";
var MAX_TENANT_SLUG_LENGTH = 32 - TENANT_DB_PREFIX.length;
var TENANT_NAME_REGISTER = [
  { name: "website", kind: "infrastructure" },
  { name: "edge", kind: "infrastructure" },
  { name: "db", kind: "infrastructure" },
  { name: "monitoring", kind: "infrastructure" },
  { name: "nextcloud1", kind: "infrastructure" },
  { name: "mail-spool", kind: "infrastructure" },
  { name: "blog", kind: "tenant", repo: "branchLeft/ghost-tenant-blog" }
];
var RESERVED_STACK_NAMES = TENANT_NAME_REGISTER.filter((entry) => entry.kind === "infrastructure").map((entry) => entry.name);

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/environment.js
var SECRET_ENV_KEYS = {
  databasePassword: "GHOST_DB_PASSWORD",
  s3AccessKeyId: "GHOST_S3_ACCESS_KEY_ID",
  s3SecretAccessKey: "GHOST_S3_SECRET_ACCESS_KEY",
  mailPassword: "GHOST_MAIL_PASSWORD",
  bulkEmailApiKey: "GHOST_BULK_EMAIL_API_KEY",
  ownerEmail: "GHOST_OWNER_EMAIL"
};
var METRICS_MOUNT_PATH = "/var/lib/ghost/metrics";
var METRICS_TEXTFILE_PATH = `${METRICS_MOUNT_PATH}/scanner.prom`;

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/validate.js
var DESCRIPTOR_KEYS = [
  "version",
  "kind",
  "slug",
  "siteUrl",
  "image",
  "ownerEmail",
  "uid",
  "ports",
  "appHostIp",
  "database",
  "media",
  "transport",
  "mail",
  "hostname",
  "gate",
  "backup",
  "codeInjection",
  "limits",
  "caps",
  "safety",
  "breakGlass",
  "expiresAt"
];
var STACK_DESCRIPTOR_KEYS = DESCRIPTOR_KEYS.filter((key) => key !== "ownerEmail");

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/compose.js
var CONTENT_MOUNT_PATH = "/var/lib/ghost/content";
var ADAPTERS_MOUNT_PATH = `${CONTENT_MOUNT_PATH}/adapters`;

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/runtime.js
var MIB = 1024 * 1024;

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/render.js
var REQUIRED_SECRET_KEYS = {
  sqlite: [],
  mysql: [SECRET_ENV_KEYS.databasePassword]
};

// dist/config.js
function positiveInteger(env, name, fallback, max) {
  const raw = env[name];
  if (raw === void 0 || raw === "")
    return fallback;
  if (!/^[1-9][0-9]*$/.test(raw) || Number(raw) > max) {
    throw new Error(`${name} must be a whole number between 1 and ${max}`);
  }
  return Number(raw);
}
function wrapperConfigFromEnv(env) {
  const wrapperPrefixRaw = env.BROKER_WRAPPER_PREFIX;
  return {
    command: env.BROKER_WRAPPER_COMMAND || "/usr/local/sbin/branchleft-slot",
    prefix: wrapperPrefixRaw === void 0 ? ["sudo", "-n"] : wrapperPrefixRaw.split(" ").filter(Boolean),
    timeoutMs: positiveInteger(env, "BROKER_WRAPPER_TIMEOUT_MS", 3e4, 3e5),
    detachTimeoutMs: positiveInteger(env, "BROKER_WRAPPER_DETACH_TIMEOUT_MS", 6e5, 36e5)
  };
}

// dist/wrapper.js
import { execFile } from "node:child_process";
var RECEIPT_ENTRY = /^[a-z0-9][a-z0-9-]*-[0-9]+$/;
var RECEIPT_DIGEST = /^[0-9a-f]{64}$/;
function isDetachReceipt(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const keys = Object.keys(value).sort();
  if (keys.length !== 3 || keys[0] !== "bytes" || keys[1] !== "entry" || keys[2] !== "sha256") {
    return false;
  }
  const { entry, sha256, bytes } = value;
  return typeof entry === "string" && RECEIPT_ENTRY.test(entry) && typeof sha256 === "string" && RECEIPT_DIGEST.test(sha256) && typeof bytes === "number" && Number.isSafeInteger(bytes) && bytes >= 0;
}
var DetachReceiptError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "DetachReceiptError";
  }
};
function parseDetachReceipt(stdout) {
  const lines = stdout.split("\n").filter((line) => line !== "");
  if (lines.length !== 1) {
    throw new DetachReceiptError("detach did not print exactly one receipt line");
  }
  let parsed;
  try {
    parsed = JSON.parse(lines[0]);
  } catch {
    throw new DetachReceiptError("detach receipt is not JSON");
  }
  if (!isDetachReceipt(parsed)) {
    throw new DetachReceiptError("detach receipt does not have the expected shape");
  }
  return { entry: parsed.entry, sha256: parsed.sha256, bytes: parsed.bytes };
}
var LINE_BREAKS = /\r\n|[\n\r\u0085\u2028\u2029]/;
var CONTROL_CHARS = /[\u0000-\u001f\u007f\u0085\u2028\u2029]/g;
function escapeControlChar(char) {
  if (char === "\r")
    return "\\r";
  if (char === "\n")
    return "\\n";
  if (char === "	")
    return "\\t";
  return `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`;
}
function escapeControls(text) {
  return text.replace(CONTROL_CHARS, escapeControlChar);
}
function stderrOneLine(stderr) {
  return escapeControls(stderr.trim());
}
var WrapperError = class extends Error {
  stdout;
  stderr;
  constructor(message, stdout, stderr) {
    super(message);
    this.stdout = stdout;
    this.stderr = stderr;
    this.name = "WrapperError";
  }
  /** The message and, when there is any, the child's stderr on the same line. For the log only. */
  get logMessage() {
    const reason = stderrOneLine(this.stderr);
    return reason === "" ? this.message : `${this.message} stderr: ${reason}`;
  }
};
function createSlotWrapper(config) {
  function run(args, timeoutMs = config.timeoutMs) {
    const argv = [...config.prefix, config.command, ...args];
    const [file, ...rest] = argv;
    if (!file)
      return Promise.reject(new Error("wrapper command is empty"));
    return new Promise((resolve, reject) => {
      execFile(file, rest, { timeout: timeoutMs }, (err, stdout, stderr) => {
        if (err) {
          const [head = ""] = err.message.split(LINE_BREAKS);
          reject(new WrapperError(`slot wrapper failed: ${escapeControls(head)}`, stdout, stderr));
          return;
        }
        resolve(stdout);
      });
    });
  }
  return {
    start: (slot, colour) => run([slot, colour, "start"]).then(() => void 0),
    stop: (slot, colour) => run([slot, colour, "stop"]).then(() => void 0),
    reset: (slot) => run([slot, "reset"]).then(() => void 0),
    // 'load' and the path are pushed as their own argv elements, same as
    // every other verb here -- never joined into one, for the identical
    // reason the module doc comment above gives for slot/colour/verb.
    load: (tarPath) => run(["load", tarPath]),
    // Same two-element shape as `reset`: the slot, then the literal verb.
    detach: async (slot) => parseDetachReceipt(await run([slot, "detach"], config.detachTimeoutMs ?? config.timeoutMs))
  };
}

// dist/plugins/dockerImageLoader.js
var LOADED_IMAGE_ID_PATTERN = /Loaded image ID:\s*(sha256:[0-9a-f]{64})/;
function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}
async function assertInsideFixedDirectory(tarPath, fixedDir) {
  const [realFixedDir, realTarPath] = await Promise.all([realpath(fixedDir), realpath(tarPath)]);
  const boundary = realFixedDir.endsWith(sep) ? realFixedDir : `${realFixedDir}${sep}`;
  if (!realTarPath.startsWith(boundary)) {
    throw new Error(`refusing to load "${tarPath}" -- it resolves outside the fixed image-staging directory "${fixedDir}"`);
  }
}
var dockerImageLoader = {
  real: true,
  async load(tarPath) {
    const fixedDir = requireEnv("BROKER_IMAGE_TMP_DIR");
    await assertInsideFixedDirectory(tarPath, fixedDir);
    const wrapper = createSlotWrapper(wrapperConfigFromEnv(process.env));
    const stdout = await wrapper.load(tarPath);
    const match = LOADED_IMAGE_ID_PATTERN.exec(stdout);
    if (!match?.[1]) {
      throw new Error(`"docker load" produced no bare image ID this loader recognises -- the tar must be saved by content digest ("docker save <imageId>"), never by a repo:tag reference, or "runs it by digest only" has nothing to check. Output:
${stdout}`);
    }
    return { imageId: match[1] };
  }
};
var dockerImageLoader_default = dockerImageLoader;
export {
  dockerImageLoader_default as default
};
