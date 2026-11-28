// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/brand.js
var FieldValidationError = class extends Error {
  field;
  constructor(field, message) {
    super(message);
    this.field = field;
    this.name = "FieldValidationError";
  }
};
function describeType(value) {
  if (value === null)
    return "null";
  if (value === void 0)
    return "undefined";
  return typeof value;
}
function assertString(value, field) {
  if (typeof value !== "string") {
    throw new FieldValidationError(field, `${field} must be a string, got ${describeType(value)}.`);
  }
}
var MAX_EMAIL_LENGTH = 254;
var NO_WHITESPACE_OR_AT = /^[^\s@]+$/;
function validateEmailAddress(value, field = "ownerEmail") {
  assertString(value, field);
  if (value.length === 0 || value.length > MAX_EMAIL_LENGTH) {
    throw new FieldValidationError(field, `${field} must be 1-${MAX_EMAIL_LENGTH} characters, got ${value.length}.`);
  }
  const atIndex = value.indexOf("@");
  if (atIndex === -1 || atIndex !== value.lastIndexOf("@")) {
    throw new FieldValidationError(field, `${field} "${value}" must contain exactly one "@".`);
  }
  const local = value.slice(0, atIndex);
  const domain = value.slice(atIndex + 1);
  if (!NO_WHITESPACE_OR_AT.test(local) || !NO_WHITESPACE_OR_AT.test(domain)) {
    throw new FieldValidationError(field, `${field} "${value}" must not contain whitespace.`);
  }
  const dotIndex = domain.lastIndexOf(".");
  if (dotIndex <= 0 || dotIndex === domain.length - 1) {
    throw new FieldValidationError(field, `${field} "${value}"'s domain must contain a "." with a label on each side.`);
  }
  return value;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/mail.js
var TENANT_SENDING_LOCAL_PART = "hello";
function sendingDomainOf(identity, zones) {
  return identity.kind === "demo" ? zones.demoMailDomain : identity.domain;
}
function renderSendingAddress(identity, zones) {
  const localPart = identity.kind === "demo" ? identity.localPart : TENANT_SENDING_LOCAL_PART;
  return `${localPart}@${sendingDomainOf(identity, zones)}`;
}

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

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/settings.js
var CODE_INJECTION_EXPLAINER = "ALL_CAPS_PLACEHOLDER: code injection explainer copy";
function codeInjectionSettings(codeInjection) {
  if (codeInjection.kind === "managed") {
    return { codeinjection_head: codeInjection.head, codeinjection_foot: codeInjection.foot };
  }
  return { codeinjection_head: "", codeinjection_foot: "" };
}
function renderSettings(descriptor, zones) {
  return {
    ...codeInjectionSettings(descriptor.codeInjection),
    codeInjectionExplainer: CODE_INJECTION_EXPLAINER,
    members_support_address: renderSendingAddress(descriptor.mail.identity, zones),
    social_web: false
  };
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/render.js
var REQUIRED_SECRET_KEYS = {
  sqlite: [],
  mysql: [SECRET_ENV_KEYS.databasePassword]
};

// dist/ownerDueDiligence.js
var OWNER_DUE_DILIGENCE_ENV = "OWNER_DUE_DILIGENCE_EMAIL";
var OwnerDueDiligenceUnsetError = class extends Error {
  constructor(why) {
    super(`${OWNER_DUE_DILIGENCE_ENV} ${why}: a demo is never created without the owner as a reader, so provisioning is refused rather than skipping the owner`);
    this.name = "OwnerDueDiligenceUnsetError";
  }
};
function assertOwnerDueDiligenceEmail(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new OwnerDueDiligenceUnsetError("is not set");
  }
  const trimmed = value.trim();
  if (/['"\\]/.test(trimmed)) {
    throw new OwnerDueDiligenceUnsetError("is not a valid email address (value withheld)");
  }
  try {
    return validateEmailAddress(trimmed, OWNER_DUE_DILIGENCE_ENV);
  } catch {
    throw new OwnerDueDiligenceUnsetError("is not a valid email address (value withheld)");
  }
}
function ownerDueDiligenceEmailFromEnv(env) {
  return assertOwnerDueDiligenceEmail(env[OWNER_DUE_DILIGENCE_ENV]);
}

// dist/config.js
function requireEnv(env, name) {
  const value = env[name];
  if (!value)
    throw new Error(`Missing required environment variable ${name}`);
  return value;
}
function positiveInteger(env, name, fallback, max) {
  const raw = env[name];
  if (raw === void 0 || raw === "")
    return fallback;
  if (!/^[1-9][0-9]*$/.test(raw) || Number(raw) > max) {
    throw new Error(`${name} must be a whole number between 1 and ${max}`);
  }
  return Number(raw);
}
function zonesFromEnv(env) {
  return {
    demoZone: requireEnv(env, "BROKER_DEMO_ZONE"),
    platformZone: requireEnv(env, "BROKER_PLATFORM_ZONE"),
    ownedDomains: requireEnv(env, "BROKER_OWNED_DOMAINS").split(",").map((s) => s.trim()).filter(Boolean),
    demoMailDomain: requireEnv(env, "BROKER_DEMO_MAIL_DOMAIN")
  };
}
function adminApiConfigFromEnv(env) {
  return {
    keyDir: requireEnv(env, "BROKER_ADMIN_KEY_DIR"),
    readyTimeoutMs: positiveInteger(env, "BROKER_GHOST_READY_TIMEOUT_MS", 3e4, 3e5),
    zones: zonesFromEnv(env),
    ownerReader: ownerDueDiligenceEmailFromEnv(env)
  };
}

// dist/ghostAdmin/client.js
import { randomBytes } from "node:crypto";

// dist/ghostAdmin/keyStore.js
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open as open2 } from "node:fs/promises";
import { join as join2 } from "node:path";

// dist/atomicFile.js
import { mkdtemp, open, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
async function writeFileAtomic(path, content, mode = 384) {
  const dir = dirname(path);
  const tmpPath = join(dir, `.${Math.random().toString(36).slice(2)}.tmp`);
  const handle = await open(tmpPath, "wx", mode);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(tmpPath, path);
  await syncDirectory(dir);
}
async function removeFileIfPresent(path) {
  await rm(path, { force: true });
  await syncDirectory(dirname(path));
}
async function syncDirectory(dir) {
  const handle = await open(dir, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

// dist/ghostAdmin/keyStore.js
var KEY_FILE = "ghost-admin-key";
var SLOT_PATTERN = /^[A-Za-z0-9-]{1,32}$/;
var KEY_PATTERN = /^[0-9a-f]{24}:[0-9a-f]{64}$/;
function isAdminApiKey(value) {
  return KEY_PATTERN.test(value);
}
function slotDir(baseDir, slot) {
  if (!SLOT_PATTERN.test(slot)) {
    throw new Error(`refusing a key path for slot "${slot}": not a plain slot name`);
  }
  return join2(baseDir, slot);
}
async function assertPlainDirectory(path) {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`refusing "${path}": not a plain directory`);
  }
}
function createAdminKeyStore(baseDir, ownUid = () => process.getuid?.() ?? -1) {
  return {
    async read(slot) {
      const path = join2(slotDir(baseDir, slot), KEY_FILE);
      let fh;
      try {
        fh = await open2(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      } catch (err) {
        const code = err.code;
        if (code === "ENOENT")
          return null;
        if (code === "ELOOP") {
          throw new Error(`refusing the stored access key for slot "${slot}": not a plain file`);
        }
        throw err;
      }
      try {
        const info = await fh.stat();
        if (!info.isFile()) {
          throw new Error(`refusing the stored access key for slot "${slot}": not a plain file`);
        }
        if ((info.mode & 511) !== 384) {
          throw new Error(`refusing the stored access key for slot "${slot}": mode ${(info.mode & 511).toString(8)}, not 600`);
        }
        if (info.uid !== ownUid()) {
          throw new Error(`refusing the stored access key for slot "${slot}": owned by uid ${info.uid}, not this service`);
        }
        const raw = await fh.readFile("utf8");
        const key = raw.trim();
        if (!isAdminApiKey(key)) {
          throw new Error(`the stored access key for slot "${slot}" is not a Ghost Admin API key`);
        }
        return key;
      } finally {
        await fh.close();
      }
    },
    async write(slot, key) {
      if (!isAdminApiKey(key)) {
        throw new Error("refusing to store a value that is not a Ghost Admin API key");
      }
      const dir = slotDir(baseDir, slot);
      await mkdir(baseDir, { recursive: true, mode: 448 });
      await assertPlainDirectory(baseDir);
      await chmod(baseDir, 448);
      await mkdir(dir, { recursive: true, mode: 448 });
      await assertPlainDirectory(dir);
      await chmod(dir, 448);
      await writeFileAtomic(join2(dir, KEY_FILE), `${key}
`, 384);
    },
    async remove(slot) {
      const dir = slotDir(baseDir, slot);
      try {
        await assertPlainDirectory(dir);
      } catch (err) {
        if (err.code === "ENOENT")
          return;
        throw err;
      }
      await removeFileIfPresent(join2(dir, KEY_FILE));
    }
  };
}

// dist/ghostAdmin/request.js
import { request as httpRequest } from "node:http";
function parseBody(raw) {
  if (raw === "")
    return void 0;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}
var loopbackGhostTransport = (req) => new Promise((resolve, reject) => {
  const payload = req.body === void 0 ? void 0 : JSON.stringify(req.body);
  const headers = {
    ...req.headers,
    Host: req.siteHost,
    "X-Forwarded-Proto": "https",
    Accept: "application/json"
  };
  if (payload !== void 0) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = String(Buffer.byteLength(payload));
  }
  let deadline;
  const fail = (err) => {
    clearTimeout(deadline);
    reject(err);
  };
  const outgoing = httpRequest({ host: "127.0.0.1", port: req.port, method: req.method, path: req.path, headers }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("end", () => {
      clearTimeout(deadline);
      resolve({
        status: res.statusCode ?? 0,
        headers: res.headers,
        body: parseBody(Buffer.concat(chunks).toString("utf8"))
      });
    });
    res.on("error", fail);
  });
  deadline = setTimeout(() => {
    const err = new Error(`Ghost did not answer ${req.method} ${req.path} in time`);
    fail(err);
    outgoing.destroy(err);
  }, req.timeoutMs);
  outgoing.on("error", fail);
  outgoing.end(payload);
});

// dist/ghostAdmin/token.js
import { createHmac } from "node:crypto";
var LIFETIME_SECONDS = 5 * 60;
function base64url(value) {
  return Buffer.from(value).toString("base64url");
}
function adminApiToken(key, nowSeconds) {
  if (!isAdminApiKey(key)) {
    throw new Error("not a Ghost Admin API key");
  }
  const [id, secret] = key.split(":");
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT", kid: id }));
  const payload = base64url(JSON.stringify({ iat: nowSeconds, exp: nowSeconds + LIFETIME_SECONDS, aud: "/admin/" }));
  const signature = createHmac("sha256", Buffer.from(secret, "hex")).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}

// dist/ghostAdmin/client.js
var OWNER_NAME_PLACEHOLDER = "ALL_CAPS_PLACEHOLDER_OWNER_NAME";
var SITE_TITLE_PLACEHOLDER = "ALL_CAPS_PLACEHOLDER_SITE_TITLE";
var ADMIN = "/ghost/api/admin";
var REQUEST_TIMEOUT_MS = 15e3;
var POLL_INTERVAL_MS = 500;
var AdminAccessLostError = class extends Error {
  constructor(slot, why) {
    super(`slot "${slot}": ${why}; the site's settings were not re-applied, so this change is refused and the demo stays as it was`);
    this.name = "AdminAccessLostError";
  }
};
function describe(res) {
  const body = res.body;
  const message = body?.errors?.[0]?.message;
  return message ? `${res.status} (${message})` : String(res.status);
}
function expectStatus(res, status, step) {
  if (res.status !== status) {
    throw new Error(`Ghost refused ${step}: ${describe(res)}`);
  }
}
function sessionCookie(res) {
  const cookies = (res.headers["set-cookie"] ?? []).map((c) => c.split(";")[0] ?? "");
  const session = cookies.filter((c) => c.startsWith("ghost-admin-api-session="));
  if (session.length !== 1)
    throw new Error("Ghost set no admin session cookie");
  return session[0];
}
function createGhostAdminClient(options) {
  const ownerReader = assertOwnerDueDiligenceEmail(options.ownerReader);
  const transport = options.transport ?? loopbackGhostTransport;
  const nowMs = options.nowMs ?? Date.now;
  const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const newPassword = options.newPassword ?? (() => randomBytes(32).toString("base64url"));
  function call(target, method, path, extra = {}) {
    return transport({
      port: target.port,
      siteHost: target.siteHost,
      method,
      path: `${ADMIN}${path}`,
      body: extra.body,
      headers: extra.headers,
      timeoutMs: REQUEST_TIMEOUT_MS
    });
  }
  async function isSetUp(target) {
    const deadline = nowMs() + options.readyTimeoutMs;
    let last = "no answer";
    for (; ; ) {
      try {
        const res = await call(target, "GET", "/authentication/setup/");
        const status = res.body?.setup?.[0]?.status;
        if (res.status === 200 && typeof status === "boolean")
          return status;
        last = describe(res);
      } catch (err) {
        last = err.message;
      }
      if (nowMs() >= deadline) {
        throw new Error(`Ghost's Admin API did not answer within ${options.readyTimeoutMs}ms (last: ${last})`);
      }
      await sleep(POLL_INTERVAL_MS);
    }
  }
  async function firstBuild(target, ownerEmail) {
    const password = newPassword();
    const origin = { Origin: `https://${target.siteHost}` };
    expectStatus(await call(target, "POST", "/authentication/setup/", {
      body: {
        setup: [
          {
            name: OWNER_NAME_PLACEHOLDER,
            email: ownerEmail,
            password,
            blogTitle: SITE_TITLE_PLACEHOLDER
          }
        ]
      }
    }), 201, "site setup");
    const signIn = await call(target, "POST", "/session/", {
      body: { username: ownerEmail, password },
      headers: origin
    });
    expectStatus(signIn, 201, "the first sign-in");
    const session = { ...origin, Cookie: sessionCookie(signIn) };
    try {
      const me = await call(target, "GET", "/users/me/", { headers: session });
      expectStatus(me, 200, "reading the owner");
      const id = me.body.users?.[0]?.id;
      if (typeof id !== "string" || !/^[0-9a-f]{24}$/.test(id)) {
        throw new Error("Ghost returned no owner id");
      }
      const tokenRes = await call(target, "GET", `/users/${id}/token/`, { headers: session });
      expectStatus(tokenRes, 200, "reading the owner's staff access token");
      const apiKey = tokenRes.body.apiKey;
      const key = `${String(apiKey?.id)}:${String(apiKey?.secret)}`;
      if (!isAdminApiKey(key))
        throw new Error("Ghost returned no usable staff access token");
      return key;
    } finally {
      await call(target, "DELETE", "/session/", { headers: session }).catch(() => void 0);
    }
  }
  async function applySettings(target, slot, key, descriptor) {
    const rendered = renderSettings(descriptor, options.zones);
    const wanted = {
      codeinjection_head: rendered.codeinjection_head,
      codeinjection_foot: rendered.codeinjection_foot,
      members_support_address: rendered.members_support_address
    };
    const res = await call(target, "PUT", "/settings/", {
      body: { settings: Object.entries(wanted).map(([k, value]) => ({ key: k, value })) },
      headers: { Authorization: `Ghost ${adminApiToken(key, Math.floor(nowMs() / 1e3))}` }
    });
    if (res.status === 401 || res.status === 403) {
      throw new AdminAccessLostError(slot, `Ghost no longer accepts the stored owner access token (${describe(res)}): the site owner regenerated or revoked it`);
    }
    expectStatus(res, 200, "the settings update");
    const got = new Map((res.body.settings ?? []).map((s) => [
      s.key,
      s.value ?? ""
    ]));
    for (const [k, value] of Object.entries(wanted)) {
      if (got.get(k) !== value) {
        throw new Error(`Ghost did not apply ${k}: it reads back a different value`);
      }
    }
  }
  async function ensureOwnerReader(target, slot, key) {
    const headers = {
      Authorization: `Ghost ${adminApiToken(key, Math.floor(nowMs() / 1e3))}`
    };
    const lookup = await call(target, "GET", `/members/?limit=1&filter=${encodeURIComponent(`email:'${ownerReader}'`)}`, { headers });
    if (lookup.status === 401 || lookup.status === 403) {
      throw new AdminAccessLostError(slot, "Ghost no longer accepts the stored owner access token");
    }
    if (lookup.status !== 200) {
      throw new Error(`Ghost refused looking up the due-diligence reader: ${lookup.status}`);
    }
    const present = lookup.body?.members ?? [];
    if (present.length > 0)
      return;
    const created = await call(target, "POST", "/members/", {
      body: { members: [{ email: ownerReader }] },
      headers
    });
    if (created.status !== 201) {
      throw new Error(`Ghost refused adding the due-diligence reader: ${created.status}`);
    }
    const stored = created.body?.members?.[0]?.email;
    if (typeof stored !== "string" || stored.toLowerCase() !== ownerReader.toLowerCase()) {
      throw new Error("Ghost did not read back the due-diligence reader it was asked to add");
    }
  }
  return {
    async configure(baseUrl, descriptor, slot) {
      const target = {
        port: Number(new URL(baseUrl).port),
        siteHost: new URL(descriptor.siteUrl).host
      };
      if (!await isSetUp(target)) {
        await options.keyStore.remove(slot);
        const key2 = await firstBuild(target, descriptor.ownerEmail);
        await options.keyStore.write(slot, key2);
        await applySettings(target, slot, key2, descriptor);
        await ensureOwnerReader(target, slot, key2);
        return;
      }
      const key = await options.keyStore.read(slot);
      if (key === null) {
        throw new AdminAccessLostError(slot, "no owner access token is stored for this site");
      }
      await applySettings(target, slot, key, descriptor);
      await ensureOwnerReader(target, slot, key);
    },
    async forget(slot) {
      await options.keyStore.remove(slot);
    }
  };
}

// dist/plugins/ghostAdminApi.js
var config = adminApiConfigFromEnv(process.env);
var adminApi = {
  real: true,
  ...createGhostAdminClient({
    keyStore: createAdminKeyStore(config.keyDir),
    zones: config.zones,
    readyTimeoutMs: config.readyTimeoutMs,
    ownerReader: config.ownerReader
  })
};
var ghostAdminApi_default = adminApi;
export {
  ghostAdminApi_default as default
};
