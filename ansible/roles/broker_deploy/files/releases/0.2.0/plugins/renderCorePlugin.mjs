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
function assertNumber(value, field) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new FieldValidationError(field, `${field} must be a number, got ${describeType(value)}.`);
  }
}
var SLUG_PATTERN = /^[a-z]([a-z0-9-]*[a-z0-9])?$/;
var MAX_SLUG_LENGTH = 63;
function validateSlug(value) {
  assertString(value, "slug");
  if (!SLUG_PATTERN.test(value)) {
    throw new FieldValidationError("slug", `slug "${value}" must start with a lowercase letter, end with a lowercase letter or digit, and contain only lowercase letters, digits and hyphens in between.`);
  }
  if (value.length > MAX_SLUG_LENGTH) {
    throw new FieldValidationError("slug", `slug "${value}" is ${value.length} characters; must be at most ${MAX_SLUG_LENGTH}.`);
  }
  return value;
}
var DIGEST_PINNED_PATTERN = /^[a-z0-9][a-z0-9._/-]*(:[\w.-]+)?@sha256:[0-9a-f]{64}$/;
function validateDigestPinnedRef(value) {
  assertString(value, "image");
  if (!DIGEST_PINNED_PATTERN.test(value)) {
    throw new FieldValidationError("image", `image "${value}" must be a digest-pinned reference: "<name>[:<tag>]@sha256:<64 hex characters>". A floating tag with no digest can move under the tenant without a descriptor change.`);
  }
  return value;
}
var TENANT_UID_MIN = 3e4;
var TENANT_UID_MAX = 30999;
function validateTenantUid(value) {
  assertNumber(value, "uid");
  if (!Number.isInteger(value) || value < TENANT_UID_MIN || value > TENANT_UID_MAX) {
    throw new FieldValidationError("uid", `uid ${value} must be an integer in the reserved tenant range ${TENANT_UID_MIN}-${TENANT_UID_MAX}.`);
  }
  return value;
}
function validatePort(value, field = "port") {
  assertNumber(value, field);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new FieldValidationError(field, `${field} ${value} must be an integer in 1-65535.`);
  }
  return value;
}
var PRIVATE_IPV4_RANGES = [
  [167772160, 184549375],
  // 10.0.0.0/8
  [2886729728, 2887778303],
  // 172.16.0.0/12
  [3232235520, 3232301055]
  // 192.168.0.0/16
];
function ipv4ToInt(address) {
  const octets = address.split(".");
  if (octets.length !== 4)
    return void 0;
  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet))
      return void 0;
    const part = Number(octet);
    if (part > 255)
      return void 0;
    if (octet.length > 1 && octet.startsWith("0"))
      return void 0;
    value = value * 256 + part;
  }
  return value;
}
function validatePrivateIpV4(value) {
  assertString(value, "appHostIp");
  const asInt = ipv4ToInt(value);
  if (asInt === void 0) {
    throw new FieldValidationError("appHostIp", `appHostIp "${value}" is not a dotted-quad IPv4 address.`);
  }
  if (!PRIVATE_IPV4_RANGES.some(([low, high]) => asInt >= low && asInt <= high)) {
    throw new FieldValidationError("appHostIp", `appHostIp "${value}" is not in a private IPv4 range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).`);
  }
  return value;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/mail.js
var TENANT_SENDING_LOCAL_PART = "hello";
function sendingDomainOf(identity, zones) {
  return identity.kind === "demo" ? zones.demoMailDomain : identity.domain;
}
function credentialDomainOf(identity, zones, uid) {
  return identity.kind === "demo" ? `slot-${uid}.${zones.demoMailDomain}` : identity.domain;
}
function renderSendingAddress(identity, zones) {
  const localPart = identity.kind === "demo" ? identity.localPart : TENANT_SENDING_LOCAL_PART;
  return `${localPart}@${sendingDomainOf(identity, zones)}`;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/media.js
var MEDIA_BUCKET_PREFIX = "branchleft-media-";
function mediaBucketName(slug) {
  return `${MEDIA_BUCKET_PREFIX}${slug}`;
}
function validateMediaBucket(slug, media) {
  if (media.kind !== "s3")
    return;
  const expected = mediaBucketName(slug);
  if (media.bucket !== expected) {
    throw new FieldValidationError("media.bucket", `media.bucket "${media.bucket}" must be "${expected}", the bucket this slug alone derives \u2014 a descriptor may never name another tenant's bucket.`);
  }
}
function mediaPublicBaseUrl(endpoint, slug) {
  if (!endpoint.startsWith("https://")) {
    throw new FieldValidationError("media.endpoint", `media.endpoint "${endpoint}" must be https. Ghost embeds this base URL in every published post, so an http endpoint would publish cleartext media URLs no later config change can recall.`);
  }
  let end = endpoint.length;
  while (end > 0 && endpoint.charAt(end - 1) === "/") {
    end -= 1;
  }
  const host = endpoint.slice(0, end);
  if (host.slice("https://".length).includes("/")) {
    throw new FieldValidationError("media.endpoint", `media.endpoint "${endpoint}" must be a bare host, with no path \u2014 the bucket is the first path segment under it.`);
  }
  return `${host}/${mediaBucketName(slug)}`;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/yaml.js
var INDENT = "  ";
var UNQUOTABLE = /[\u0000-\u001f\u007f-\u009f]/;
function quote(value) {
  const offending = UNQUOTABLE.exec(value);
  if (offending) {
    const code = offending[0].codePointAt(0) ?? 0;
    throw new Error(`toYaml: refusing to emit a string containing U+${code.toString(16).toUpperCase().padStart(4, "0")} at index ${offending.index}. A control character in a quoted scalar is either re-read as document structure or silently transformed, so there is no faithful single-quoted form of it.`);
  }
  return `'${value.replaceAll("'", "''")}'`;
}
function scalar(value) {
  if (typeof value === "string")
    return quote(value);
  if (typeof value === "boolean")
    return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`toYaml: ${value} is not a finite number.`);
    }
    return String(value);
  }
  throw new Error(`toYaml: unsupported scalar ${typeof value}.`);
}
function isContainer(value) {
  return typeof value === "object" && value !== null;
}
function emit(value, depth, lines) {
  const pad = INDENT.repeat(depth);
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new Error("toYaml: an empty sequence has no unambiguous block form.");
    }
    for (const item of value) {
      if (isContainer(item)) {
        const nested = [];
        emit(item, depth + 1, nested);
        lines.push(`${pad}- ${nested[0].slice((depth + 1) * INDENT.length)}`);
        lines.push(...nested.slice(1));
      } else {
        lines.push(`${pad}- ${scalar(item)}`);
      }
    }
    return;
  }
  if (isContainer(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      throw new Error("toYaml: an empty mapping has no unambiguous block form.");
    }
    for (const [key, child] of entries) {
      quote(key);
      if (isContainer(child)) {
        lines.push(`${pad}${key}:`);
        emit(child, depth + 1, lines);
      } else {
        lines.push(`${pad}${key}: ${scalar(child)}`);
      }
    }
    return;
  }
  lines.push(`${pad}${scalar(value)}`);
}
function toYaml(document) {
  const lines = [];
  emit(document, 0, lines);
  return `${lines.join("\n")}
`;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/spool.js
var MAIL_SPOOL_STACK = "mail-spool";
var MAIL_SPOOL_SERVICE = "mail-spool";
var MAIL_SPOOL_HTTP_PORT = 8080;
var MAIL_SPOOL_SMTP_PORT = 2525;
var MAIL_SPOOL_BASE_URL = `http://${MAIL_SPOOL_SERVICE}:${MAIL_SPOOL_HTTP_PORT}`;
var DATA_MOUNT_PATH = "/data";
var DB_PATH = `${DATA_MOUNT_PATH}/spool.sqlite`;
var MAIL_SPOOL_SECRETS_PATH = `/etc/branchleft/${MAIL_SPOOL_STACK}.env`;
function mailSpoolNetworkName(uid) {
  return `branchleft-mail-${uid}`;
}

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
function validateSlugAvailability(slug, claimant) {
  if (slug.length > MAX_TENANT_SLUG_LENGTH) {
    throw new FieldValidationError("slug", `slug "${slug}" is ${slug.length} characters; must be at most ${MAX_TENANT_SLUG_LENGTH} so "${TENANT_DB_PREFIX}" plus the slug fits MySQL's 32-character account-name limit.`);
  }
  if (RESERVED_STACK_NAMES.includes(slug)) {
    throw new FieldValidationError("slug", `slug "${slug}" is reserved \u2014 an app host already runs a Compose stack of that name, and a tenant using it would overwrite that stack's directory, secrets file and systemd unit. Reserved: ${RESERVED_STACK_NAMES.join(", ")}.`);
  }
  if (claimant === void 0) {
    return;
  }
  const entry = TENANT_NAME_REGISTER.find((candidate) => candidate.name === slug);
  if (entry === void 0 || entry.kind !== "tenant") {
    return;
  }
  const owns = claimant.kind === "tenant" && claimant.repo !== void 0 && claimant.repo.toLowerCase() === entry.repo.toLowerCase();
  if (!owns) {
    throw new FieldValidationError("slug", `slug "${slug}" is registered to ${entry.repo} and cannot be taken by ${claimant.kind === "demo" ? "a demo" : "any other repository"}.`);
  }
}
function sqlIdentifier(slug) {
  return slug.replaceAll("-", "_");
}
function databaseAndUserName(slug) {
  return `${TENANT_DB_PREFIX}${sqlIdentifier(slug)}`;
}
function validateDatabaseIdentity(slug, database) {
  const expected = databaseAndUserName(slug);
  if (database.name !== expected) {
    throw new FieldValidationError("database.name", `database.name "${database.name}" must be "${expected}", the name this slug alone derives \u2014 a descriptor may never name another tenant's database.`);
  }
  if (database.user !== expected) {
    throw new FieldValidationError("database.user", `database.user "${database.user}" must be "${expected}", the name this slug alone derives \u2014 a descriptor may never name another tenant's database user.`);
  }
}
function stackName(slug) {
  return slug;
}
function secretsEnvPath(slug) {
  return `/etc/branchleft/${stackName(slug)}.env`;
}
function contentVolumeName(slug) {
  return `ghost-${slug}-content`;
}
function adaptersVolumeName(slug) {
  return `ghost-${slug}-adapters`;
}
function metricsVolumeName(slug) {
  return `ghost-${slug}-metrics`;
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/environment.js
var SECRET_ENV_KEYS = {
  databasePassword: "GHOST_DB_PASSWORD",
  s3AccessKeyId: "GHOST_S3_ACCESS_KEY_ID",
  s3SecretAccessKey: "GHOST_S3_SECRET_ACCESS_KEY",
  mailPassword: "GHOST_MAIL_PASSWORD",
  bulkEmailApiKey: "GHOST_BULK_EMAIL_API_KEY",
  ownerEmail: "GHOST_OWNER_EMAIL"
};
var MULTIPART_UPLOAD_THRESHOLD_BYTES = 10485760;
var MULTIPART_CHUNK_SIZE_BYTES = 5242880;
var MAIL_CONNECTION_TIMEOUT_MILLISECONDS = 5e3;
var MAIL_GREETING_TIMEOUT_MILLISECONDS = 5e3;
var MAIL_SOCKET_TIMEOUT_MILLISECONDS = 1e4;
var STORAGE_FEATURES = ["images", "media", "files"];
var STATIC_FILE_URL_PREFIX = {
  images: "content/images",
  media: "content/media",
  files: "content/files"
};
var SCANNING_STORAGE_ADAPTER = "ScanningStorageAdapter";
var LOCAL_WRAPPED_ADAPTER = {
  images: "LocalImagesStorage",
  media: "LocalMediaStorage",
  files: "LocalFilesStorage"
};
var QUARANTINE_PATH = "/var/lib/ghost/content/quarantine";
var METRICS_MOUNT_PATH = "/var/lib/ghost/metrics";
var METRICS_TEXTFILE_PATH = `${METRICS_MOUNT_PATH}/scanner.prom`;
var ALLOW_LOCAL_STORAGE_ENV_VAR = "BRANCHLEFT_ALLOW_LOCAL_STORAGE";
function required(name, secretsFilePath) {
  return `\${${SECRET_ENV_KEYS[name]}:?set ${SECRET_ENV_KEYS[name]} in ${secretsFilePath}}`;
}
function escapeComposeDollar(value) {
  return value.replaceAll("$", "$$$$");
}
function escapeEnvValues(env) {
  const escaped = {};
  for (const [key, value] of Object.entries(env)) {
    escaped[key] = typeof value === "string" ? escapeComposeDollar(value) : value;
  }
  return escaped;
}
function databaseEnvironment(slug, database) {
  if (database.kind === "sqlite") {
    return {
      database__client: "sqlite3",
      database__connection__filename: database.path
    };
  }
  validateDatabaseIdentity(slug, database);
  const name = databaseAndUserName(slug);
  return {
    database__client: "mysql",
    database__connection__host: database.host,
    database__connection__port: database.port,
    database__connection__database: name,
    database__connection__user: name,
    // The password is never a parameter of this function — see the module
    // doc comment. `secretsFilePath` closes over it from the caller.
    database__connection__ssl__rejectUnauthorized: false
  };
}
function isScanningRequired(safety) {
  return safety.near || safety.exact;
}
function mediaEnvironment(slug, media, safety) {
  const scanningRequired = isScanningRequired(safety);
  const env = {};
  if (media.kind === "local") {
    for (const feature of STORAGE_FEATURES) {
      if (scanningRequired) {
        env[`storage__${feature}__adapter`] = SCANNING_STORAGE_ADAPTER;
        env[`storage__${feature}__wraps`] = LOCAL_WRAPPED_ADAPTER[feature];
        env[`storage__${feature}__quarantinePath`] = QUARANTINE_PATH;
      } else {
        env[`storage__${feature}__adapter`] = LOCAL_WRAPPED_ADAPTER[feature];
      }
    }
    env[ALLOW_LOCAL_STORAGE_ENV_VAR] = true;
    return env;
  }
  validateMediaBucket(slug, media);
  const bucket = mediaBucketName(slug);
  for (const feature of STORAGE_FEATURES) {
    if (scanningRequired) {
      env[`storage__${feature}__adapter`] = SCANNING_STORAGE_ADAPTER;
      env[`storage__${feature}__wraps`] = "S3Storage";
      env[`storage__${feature}__quarantinePath`] = QUARANTINE_PATH;
      env[`storage__${feature}__metricsTextfilePath`] = METRICS_TEXTFILE_PATH;
      env[`storage__${feature}__metricsTenant`] = slug;
      env[`storage__${feature}__wrappedConfig__bucket`] = bucket;
      env[`storage__${feature}__wrappedConfig__region`] = media.region;
      env[`storage__${feature}__wrappedConfig__endpoint`] = media.endpoint;
      env[`storage__${feature}__wrappedConfig__forcePathStyle`] = true;
      env[`storage__${feature}__wrappedConfig__staticFileURLPrefix`] = STATIC_FILE_URL_PREFIX[feature];
      env[`storage__${feature}__wrappedConfig__cdnUrl`] = mediaPublicBaseUrl(media.endpoint, slug);
      env[`storage__${feature}__wrappedConfig__multipartUploadThresholdBytes`] = MULTIPART_UPLOAD_THRESHOLD_BYTES;
      env[`storage__${feature}__wrappedConfig__multipartChunkSizeBytes`] = MULTIPART_CHUNK_SIZE_BYTES;
    } else {
      env[`storage__${feature}__adapter`] = "S3Storage";
      env[`storage__${feature}__bucket`] = bucket;
      env[`storage__${feature}__region`] = media.region;
      env[`storage__${feature}__endpoint`] = media.endpoint;
      env[`storage__${feature}__forcePathStyle`] = true;
      env[`storage__${feature}__staticFileURLPrefix`] = STATIC_FILE_URL_PREFIX[feature];
      env[`storage__${feature}__cdnUrl`] = mediaPublicBaseUrl(media.endpoint, slug);
      env[`storage__${feature}__multipartUploadThresholdBytes`] = MULTIPART_UPLOAD_THRESHOLD_BYTES;
      env[`storage__${feature}__multipartChunkSizeBytes`] = MULTIPART_CHUNK_SIZE_BYTES;
    }
  }
  return env;
}
function transportEnvironment(transport, mail, zones, uid) {
  if (transport.kind === "queue") {
    if (!mail.enabled) {
      return {};
    }
    return {
      mail__transport: "SMTP",
      mail__options__host: MAIL_SPOOL_SERVICE,
      mail__options__port: MAIL_SPOOL_SMTP_PORT,
      mail__options__secure: false,
      mail__options__auth__user: credentialDomainOf(mail.identity, zones, uid),
      mail__options__connectionTimeout: MAIL_CONNECTION_TIMEOUT_MILLISECONDS,
      mail__options__greetingTimeout: MAIL_GREETING_TIMEOUT_MILLISECONDS,
      mail__options__socketTimeout: MAIL_SOCKET_TIMEOUT_MILLISECONDS
    };
  }
  return {
    mail__transport: "SMTP",
    mail__options__host: transport.host,
    mail__options__port: transport.port,
    mail__options__secure: false,
    mail__options__auth__user: transport.user
  };
}
function breakGlassEnvironment(breakGlass) {
  if (breakGlass.kind !== "enabled") {
    return {};
  }
  return {
    adapters__sso__active: "BreakGlassSSO",
    adapters__sso__BreakGlassSSO__publicKey: breakGlass.publicKey,
    adapters__sso__BreakGlassSSO__tenant: breakGlass.tenant,
    adapters__sso__BreakGlassSSO__supportIdentity: breakGlass.supportIdentity
  };
}
function bulkMailEnvironment(mail, zones, uid) {
  const env = {
    mail__from: renderSendingAddress(mail.identity, zones)
  };
  if (mail.enabled) {
    env.bulkEmail__mailgun__baseUrl = MAIL_SPOOL_BASE_URL;
    env.bulkEmail__mailgun__domain = credentialDomainOf(mail.identity, zones, uid);
  }
  return env;
}
function hostLimitsEnvironment(limits) {
  const env = {};
  if (limits.membersCap !== null) {
    env.hostSettings__limits__members__max = limits.membersCap;
  }
  if (limits.staffCap !== null) {
    env.hostSettings__limits__staff__max = limits.staffCap;
  }
  return env;
}
function hostStripeEnvironment(kind) {
  return kind === "demo" ? { hostSettings__limits__limitStripeConnect__disabled: true } : {};
}
function tenantEnvironment(descriptor, limits, secretsFilePath, zones) {
  const env = {
    url: descriptor.siteUrl,
    ...databaseEnvironment(descriptor.slug, descriptor.database),
    ...mediaEnvironment(descriptor.slug, descriptor.media, descriptor.safety),
    ...transportEnvironment(descriptor.transport, descriptor.mail, zones, descriptor.uid),
    ...bulkMailEnvironment(descriptor.mail, zones, descriptor.uid),
    ...hostLimitsEnvironment(descriptor.limits),
    ...breakGlassEnvironment(descriptor.breakGlass),
    security__allowWebhookInternalIPs: false,
    // Locks the ActivityPub setting off for every tenant: the admin's Network
    // tab is that feature's surface and nothing serves the paths it calls, so
    // it would only ever show an error. Ghost reads this flag from config
    // only, and unlike a cap it is unconditional, so it is not part of
    // `hostLimitsEnvironment`. `settings.ts` sets `social_web` off as well,
    // because the lock does not remove what an existing tenant already has.
    hostSettings__limits__limitSocialWeb__disabled: true,
    ...hostStripeEnvironment(descriptor.kind),
    theme__uploadLimits__compressedBytes: limits.themeCompressedBytes,
    theme__uploadLimits__entryUncompressedBytes: limits.themeEntryUncompressedBytes,
    theme__uploadLimits__totalUncompressedBytes: limits.themeTotalUncompressedBytes,
    privacy__useUpdateCheck: false,
    logging__transports: '["stdout"]'
  };
  const escaped = escapeEnvValues(env);
  if (descriptor.database.kind === "mysql") {
    escaped.database__connection__password = required("databasePassword", secretsFilePath);
  }
  if (descriptor.media.kind === "s3") {
    const scanningRequired = isScanningRequired(descriptor.safety);
    for (const feature of STORAGE_FEATURES) {
      const prefix = scanningRequired ? `storage__${feature}__wrappedConfig__` : `storage__${feature}__`;
      escaped[`${prefix}accessKeyId`] = required("s3AccessKeyId", secretsFilePath);
      escaped[`${prefix}secretAccessKey`] = required("s3SecretAccessKey", secretsFilePath);
    }
  }
  if (descriptor.transport.kind === "smtp") {
    escaped.mail__options__auth__pass = required("mailPassword", secretsFilePath);
  } else if (descriptor.mail.enabled) {
    escaped.mail__options__auth__pass = required("bulkEmailApiKey", secretsFilePath);
  }
  if (descriptor.mail.enabled) {
    escaped.bulkEmail__mailgun__apiKey = required("bulkEmailApiKey", secretsFilePath);
  }
  return escaped;
}

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
function normalizeDomain(value) {
  const withoutTrailingDot = value.endsWith(".") ? value.slice(0, -1) : value;
  return withoutTrailingDot.toLowerCase();
}
function isEqualToOrSubdomainOf(fqdn, domain) {
  const normalizedFqdn = normalizeDomain(fqdn);
  const normalizedDomain = normalizeDomain(domain);
  return normalizedFqdn === normalizedDomain || normalizedFqdn.endsWith(`.${normalizedDomain}`);
}
function isOutsideOwnedDomains(fqdn, ownedDomains) {
  return !ownedDomains.some((domain) => isEqualToOrSubdomainOf(fqdn, domain));
}
var HOSTNAME_LABEL_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
var MAX_FQDN_LENGTH = 253;
var NUMERIC_SHORTHAND_LAST_LABEL = /^(0x[0-9a-f]+|[0-9]+)$/i;
function isWellFormedFqdn(fqdn) {
  if (fqdn.length === 0 || fqdn.length > MAX_FQDN_LENGTH) {
    return false;
  }
  const labels = fqdn.split(".");
  if (labels.length < 2 || !labels.every((label) => HOSTNAME_LABEL_PATTERN.test(label))) {
    return false;
  }
  return !NUMERIC_SHORTHAND_LAST_LABEL.test(labels[labels.length - 1]);
}
function servedHostnameOf(descriptor, zones) {
  if (descriptor.hostname.kind === "ours") {
    if (descriptor.kind === "demo") {
      return null;
    }
    if (!HOSTNAME_LABEL_PATTERN.test(descriptor.hostname.sub)) {
      return null;
    }
    return normalizeDomain(`${descriptor.hostname.sub}.${zones.platformZone}`);
  }
  const fqdn = descriptor.hostname.fqdn;
  if (!isWellFormedFqdn(fqdn)) {
    return null;
  }
  if (!isOutsideOwnedDomains(fqdn, zones.ownedDomains)) {
    return null;
  }
  return normalizeDomain(fqdn);
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/compose.js
var GHOST_CONTAINER_PORT = 2368;
var HEALTHCHECK_FORWARDED_PROTO = "X-Forwarded-Proto: https";
var GHOST_STOP_GRACE_PERIOD = "60s";
var CONTENT_MOUNT_PATH = "/var/lib/ghost/content";
var ADAPTERS_MOUNT_PATH = `${CONTENT_MOUNT_PATH}/adapters`;
var DEMO_BIND_ADDRESS = "127.0.0.1";
var COLOURS = ["a", "b"];
function coloursToRender(activeColour) {
  if (activeColour === void 0)
    return COLOURS;
  if (!COLOURS.includes(activeColour)) {
    throw new FieldValidationError("activeColour", `activeColour must be "a" or "b" when given, got ${JSON.stringify(activeColour)}.`);
  }
  return [activeColour];
}
function bindAddress(args) {
  return args.kind === "demo" ? DEMO_BIND_ADDRESS : args.appHostPrivateIp;
}
function ghostService(args, colour, content, adapters, metrics) {
  const hostPort = colour === "a" ? args.ports.a : args.ports.b;
  const volumes = [`${content}:${CONTENT_MOUNT_PATH}`, `${adapters}:${ADAPTERS_MOUNT_PATH}:ro`];
  if (metrics !== null) {
    volumes.push(`${metrics}:${METRICS_MOUNT_PATH}`);
  }
  if (args.dataMount) {
    volumes.push(`${args.dataMount.volumeName}:${args.dataMount.path}`);
  }
  return {
    image: "${IMAGE}",
    restart: "unless-stopped",
    stop_grace_period: GHOST_STOP_GRACE_PERIOD,
    // Distinct per tenant, never reused — the one control that separates
    // one tenant's data from another's on a shared host.
    user: `${args.uid}:${args.uid}`,
    init: true,
    read_only: true,
    tmpfs: [`/tmp:rw,noexec,nosuid,nodev,size=${args.limits.tmpfsSize}`],
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    pids_limit: args.caps.pidsLimit,
    mem_limit: args.limits.memoryLimit,
    memswap_limit: args.limits.memoryLimit,
    cpus: args.caps.cpus,
    cpu_shares: args.caps.cpuShares,
    ulimits: {
      nofile: { soft: args.caps.nofile, hard: args.caps.nofile }
    },
    logging: {
      driver: "json-file",
      options: { "max-size": "10m", "max-file": "3" }
    },
    ports: [`${bindAddress(args)}:${hostPort}:${GHOST_CONTAINER_PORT}`],
    environment: args.environment,
    ...args.mailNetwork ? { networks: ["default", args.mailNetwork] } : {},
    volumes,
    healthcheck: {
      test: [
        "CMD",
        "wget",
        "-q",
        "-O",
        "/dev/null",
        "--header",
        HEALTHCHECK_FORWARDED_PROTO,
        `http://127.0.0.1:${GHOST_CONTAINER_PORT}/`
      ],
      interval: "30s",
      timeout: "5s",
      retries: 3,
      start_period: "60s"
    }
  };
}
function composeDocument(args) {
  const content = contentVolumeName(args.slug);
  const adapters = adaptersVolumeName(args.slug);
  const metrics = args.kind === "demo" ? null : metricsVolumeName(args.slug);
  const volumes = {
    [content]: { external: true },
    [adapters]: { external: true }
  };
  if (metrics !== null) {
    volumes[metrics] = { external: true };
  }
  if (args.dataMount) {
    volumes[args.dataMount.volumeName] = { external: true };
  }
  return {
    name: stackName(args.slug),
    services: Object.fromEntries(coloursToRender(args.activeColour).map((colour) => [
      `ghost-${colour}`,
      ghostService(args, colour, content, adapters, metrics)
    ])),
    ...args.mailNetwork ? { networks: { [args.mailNetwork]: { name: args.mailNetwork, external: true } } } : {},
    // `external: true`: the host-side provisioning step creates and owns
    // these volumes before this stack ever starts — see
    // `infra/tenant/compose.ts`'s own comment on why Compose must never be
    // the thing that first populates one.
    volumes
  };
}
function header(slug) {
  return [
    `# The ${slug} Ghost stack, deployed as \`${stackName(slug)}\` under`,
    `# /opt/branchleft/${stackName(slug)} on an app host.`,
    "#",
    "# Rendered by @branchleft/ghost-platform-render-core. Do not hand-edit on",
    "# the host: every line below is a runtime-isolation control, and a stack",
    "# that omits one still starts, still serves, and silently drops the",
    "# boundary.",
    "#",
    "# `${IMAGE}` is written to /etc/branchleft/<stack>.image.env by",
    "# /usr/local/sbin/branchleft-deploy and is always a digest, never a tag.",
    "# Any `${GHOST_*}` reference comes from /etc/branchleft/<stack>.env,",
    "# which is root-owned 0600 and written by an operator alone."
  ].join("\n");
}
function renderComposeStack(args) {
  const document = composeDocument(args);
  assertRuntimePosture(document, bindAddress(args));
  return `${header(args.slug)}
${toYaml(document)}`;
}
var FORBIDDEN_SERVICE_KEYS = [
  "privileged",
  "cap_add",
  "devices",
  "device_cgroup_rules",
  "network_mode",
  "pid",
  "ipc",
  "userns_mode",
  "cgroup",
  "cgroup_parent",
  "external_links"
];
var FORBIDDEN_SECURITY_OPTS = [
  "seccomp=unconfined",
  "apparmor=unconfined",
  "systempaths=unconfined"
];
var SHELL_SENDS_HEADER = /--header[= ]\s*(['"])X-Forwarded-Proto:\s*https\1/;
function healthProbe(service) {
  const healthcheck = service.healthcheck;
  const test = typeof healthcheck === "object" && healthcheck !== null && !Array.isArray(healthcheck) ? healthcheck.test : void 0;
  if (typeof test === "string") {
    if (test.trim().length === 0)
      return { kind: "missing" };
    return { kind: "ok", sendsHeader: SHELL_SENDS_HEADER.test(test) };
  }
  if (test === void 0)
    return { kind: "missing" };
  if (!Array.isArray(test))
    return { kind: "malformed" };
  if (test.length === 0)
    return { kind: "missing" };
  if (!test.every((element) => typeof element === "string")) {
    return { kind: "malformed" };
  }
  const [form, ...rest] = test;
  if (form === "NONE")
    return { kind: "disabled" };
  if (form === "CMD-SHELL") {
    const command = rest.join(" ");
    if (command.trim().length === 0)
      return { kind: "missing" };
    return { kind: "ok", sendsHeader: SHELL_SENDS_HEADER.test(command) };
  }
  if (form !== "CMD")
    return { kind: "malformed" };
  if (rest.length === 0)
    return { kind: "missing" };
  return {
    kind: "ok",
    sendsHeader: rest.some((element, index) => element === `--header=${HEALTHCHECK_FORWARDED_PROTO}` || element === "--header" && rest[index + 1] === HEALTHCHECK_FORWARDED_PROTO)
  };
}
function assertRuntimePosture(document, expectedBindAddress) {
  if (expectedBindAddress !== "127.0.0.1") {
    validatePrivateIpV4(expectedBindAddress);
  }
  const services = document.services;
  const problems = [];
  for (const [name, service] of Object.entries(services)) {
    const at = (message) => problems.push(`service "${name}": ${message}`);
    for (const key of FORBIDDEN_SERVICE_KEYS) {
      if (key in service)
        at(`must not set \`${key}\``);
    }
    if (service.read_only !== true)
      at("must set `read_only: true`");
    if (service.init !== true)
      at("must set `init: true`");
    if (typeof service.user !== "string" || !/^\d+:\d+$/.test(service.user)) {
      at('must run as a numeric per-tenant `user: "<uid>:<uid>"`');
    }
    if (!Array.isArray(service.cap_drop) || !service.cap_drop.includes("ALL")) {
      at("must set `cap_drop: [ALL]`");
    }
    const securityOpt = Array.isArray(service.security_opt) ? service.security_opt : [];
    if (!securityOpt.includes("no-new-privileges:true")) {
      at("must set `security_opt: [no-new-privileges:true]`");
    }
    for (const opt of securityOpt) {
      if (typeof opt === "string" && FORBIDDEN_SECURITY_OPTS.includes(opt.toLowerCase())) {
        at(`must not opt out of a shipped default (\`${opt}\`)`);
      }
    }
    if (typeof service.pids_limit !== "number")
      at("must set `pids_limit`");
    if (typeof service.mem_limit !== "string")
      at("must set `mem_limit`");
    if (service.memswap_limit !== service.mem_limit) {
      at("must set `memswap_limit` equal to `mem_limit`, or swap is unbounded");
    }
    if (typeof service.cpus !== "string")
      at("must set `cpus`");
    const grace = service.stop_grace_period;
    if (typeof grace !== "string" || !/^\d+s$/.test(grace)) {
      at("must set `stop_grace_period` to whole seconds, or a stop kills Ghost mid-batch");
    }
    const logging = service.logging;
    const loggingOptions = logging?.options;
    if (!loggingOptions?.["max-size"] || !loggingOptions?.["max-file"]) {
      at("must bound its json-file logs with `max-size` and `max-file`");
    }
    const ports = Array.isArray(service.ports) ? service.ports : [];
    for (const port of ports) {
      const parts = typeof port === "string" ? port.split(":") : [];
      if (parts.length !== 3 || parts[0] !== expectedBindAddress) {
        at(`publishes \`${String(port)}\` \u2014 every port must be <app-host-private-ip>:<host-port>:<container-port>`);
        continue;
      }
      const hostPort = Number(parts[1]);
      if (!/^\d+$/.test(parts[1]) || !Number.isInteger(hostPort)) {
        at(`publishes \`${String(port)}\` \u2014 the host port is not a number`);
      }
    }
    const probe = healthProbe(service);
    if (probe.kind === "missing")
      at("must declare a `healthcheck.test`");
    if (probe.kind === "disabled")
      at("must not disable its healthcheck with `test: [NONE]`");
    if (probe.kind === "malformed") {
      at("declares a `healthcheck.test` that is not a string, `CMD` or `CMD-SHELL` form");
    }
    if (probe.kind === "ok" && !probe.sendsHeader) {
      at(`must bind \`${HEALTHCHECK_FORWARDED_PROTO}\` to \`--header\` in its healthcheck, or Ghost answers the probe with a 301 to HTTPS that it cannot follow`);
    }
    const volumes = Array.isArray(service.volumes) ? service.volumes : [];
    for (const volume of volumes) {
      if (typeof volume !== "string" || volume.startsWith("/") || volume.startsWith(".")) {
        at(`mounts \`${String(volume)}\` \u2014 only named volumes, never a host path`);
      } else if (volume.includes("docker.sock")) {
        at("must never receive the Docker socket");
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`render(): rendered stack violates the runtime posture:
- ${problems.join("\n- ")}`);
  }
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/edge.js
var THEME_CSP_UNAVAILABLE = { kind: "unavailable" };
function edgeGate(gate) {
  if (gate.kind === "passphrase") {
    return { kind: "passphrase", argon2idHash: gate.argon2idHash };
  }
  return { kind: "none" };
}
function contentSecurityPolicy(themeCsp) {
  const scriptSrc = themeCsp.kind === "computed" && themeCsp.hashes.length > 0 ? `script-src 'self' ${themeCsp.hashes.map((hash) => `'${hash}'`).join(" ")}` : "script-src 'self'";
  const value = [
    "default-src 'self'",
    "img-src 'self' data: https:",
    "style-src 'self' 'unsafe-inline'",
    scriptSrc,
    "frame-ancestors 'self'"
  ].join("; ");
  return { value, mode: themeCsp.kind === "computed" ? "enforcing" : "report-only" };
}
function renderEdgeSiteBlock(descriptor, zones, limits, themeCsp = THEME_CSP_UNAVAILABLE) {
  const csp = contentSecurityPolicy(themeCsp);
  return {
    displayHostname: new URL(descriptor.siteUrl).host,
    admittedHostname: servedHostnameOf(descriptor, zones),
    gate: edgeGate(descriptor.gate),
    requestBodyMaxSize: limits.edgeRequestBodyMaxSize,
    contentSecurityPolicy: csp.value,
    contentSecurityPolicyMode: csp.mode
  };
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/identity.js
function databaseIdentity(slug, database) {
  return database.kind === "mysql" ? databaseAndUserName(slug) : null;
}
function mediaIdentity(slug, media) {
  if (media.kind !== "s3")
    return null;
  validateMediaBucket(slug, media);
  return mediaBucketName(slug);
}
function renderIdentity(descriptor) {
  return {
    slug: descriptor.slug,
    uid: descriptor.uid,
    stackName: stackName(descriptor.slug),
    contentVolume: contentVolumeName(descriptor.slug),
    adaptersVolume: adaptersVolumeName(descriptor.slug),
    appHostPrivateIp: descriptor.appHostIp,
    databaseName: databaseIdentity(descriptor.slug, descriptor.database),
    mediaBucket: mediaIdentity(descriptor.slug, descriptor.media)
  };
}

// node_modules/.pnpm/@branchleft+ghost-platform-render-core@0.4.0/node_modules/@branchleft/ghost-platform-render-core/dist/runtime.js
var DEFAULT_UPLOAD_CEILING_MIB = 128;
var DEFAULT_RSS_BUDGET_MIB = 512;
var MIB = 1024 * 1024;
var MIN_UPLOAD_CEILING_MIB = 16;
var UPLOAD_CEILING_DIVISOR = 4;
function uploadLimits(uploadCeilingMib = DEFAULT_UPLOAD_CEILING_MIB, rssBudgetMib = DEFAULT_RSS_BUDGET_MIB) {
  if (!Number.isInteger(uploadCeilingMib) || uploadCeilingMib < MIN_UPLOAD_CEILING_MIB) {
    throw new Error(`uploadCeilingMib must be an integer of at least ${MIN_UPLOAD_CEILING_MIB}, got ${uploadCeilingMib}.`);
  }
  if (uploadCeilingMib % UPLOAD_CEILING_DIVISOR !== 0) {
    throw new Error(`uploadCeilingMib must be a multiple of ${UPLOAD_CEILING_DIVISOR} so every derived limit is a whole number of MiB, got ${uploadCeilingMib}.`);
  }
  if (!Number.isInteger(rssBudgetMib) || rssBudgetMib <= 0) {
    throw new Error(`rssBudgetMib must be a positive integer, got ${rssBudgetMib}.`);
  }
  return {
    tmpfsSize: `${uploadCeilingMib}m`,
    themeCompressedBytes: uploadCeilingMib / 4 * MIB,
    themeEntryUncompressedBytes: uploadCeilingMib / 4 * MIB,
    themeTotalUncompressedBytes: uploadCeilingMib / 2 * MIB,
    edgeRequestBodyMaxSize: `${uploadCeilingMib / 2}MiB`,
    memoryLimit: `${rssBudgetMib + uploadCeilingMib}m`
  };
}

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
var SECRETS_ENV_MODE = 384;
var REQUIRED_SECRET_KEYS = {
  sqlite: [],
  mysql: [SECRET_ENV_KEYS.databasePassword]
};
function requiredSecretKeys(descriptor) {
  const keys = [...REQUIRED_SECRET_KEYS[descriptor.database.kind]];
  if (descriptor.media.kind === "s3") {
    keys.push(SECRET_ENV_KEYS.s3AccessKeyId, SECRET_ENV_KEYS.s3SecretAccessKey);
  }
  if (descriptor.transport.kind === "smtp") {
    keys.push(SECRET_ENV_KEYS.mailPassword);
  }
  if (descriptor.mail.enabled) {
    keys.push(SECRET_ENV_KEYS.bulkEmailApiKey);
  }
  if (descriptor.kind === "tenant") {
    keys.push(SECRET_ENV_KEYS.ownerEmail);
  }
  return keys;
}
function renderSecretsTemplate(descriptor) {
  const path = secretsEnvPath(descriptor.slug);
  const keys = requiredSecretKeys(descriptor);
  const lines = [
    `# Secrets for the ${descriptor.slug} Ghost stack, at ${path}.`,
    "# Root-owned, mode 0600. Written by an operator; no automated path may",
    "# rewrite this file. render() names the keys this tenant needs below \u2014",
    "# it never has a value to put here."
  ];
  if (keys.length === 0) {
    lines.push("# This tenant needs no secret: sqlite + local media + queue transport.");
  } else {
    for (const key of keys) {
      lines.push(`${key}=`);
    }
  }
  return `${lines.join("\n")}
`;
}
var CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;
function renderImageEnv(descriptor) {
  if (CONTROL_CHARACTER.test(descriptor.image)) {
    throw new FieldValidationError("image", "image must not contain a control character \u2014 a trailing newline would start a second EnvironmentFile variable.");
  }
  return `IMAGE=${descriptor.image}
`;
}
function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
function renderProvisionScript(descriptor) {
  const lines = ["#!/bin/sh", "set -eu"];
  if (descriptor.kind === "demo") {
    lines.push(`# ${descriptor.slug}'s slot data directory is host-provisioned once, at demo-host`, "# build time (LLD-2 \xA701) -- there is nothing for this script to do per recycle.");
  } else {
    lines.push(`# Provisions ${descriptor.slug}'s three named volumes before ${stackName(descriptor.slug)}'s`, "# unit is enabled. Idempotent; safe to re-run.", `/root/platform-provision/provision_tenant_volume.py --uid ${shellQuote(String(descriptor.uid))} ${shellQuote(descriptor.slug)}`);
  }
  return `${lines.join("\n")}
`;
}
function renderJson(value) {
  return `${JSON.stringify(value, null, 2)}
`;
}
function dirname(path) {
  const lastSlash = path.lastIndexOf("/");
  return lastSlash <= 0 ? "/" : path.slice(0, lastSlash);
}
function demoDataMount(descriptor) {
  if (descriptor.database.kind !== "sqlite" || descriptor.media.kind !== "local") {
    return null;
  }
  const dataDir = dirname(descriptor.database.path);
  if (descriptor.media.path !== dataDir && !descriptor.media.path.startsWith(`${dataDir}/`)) {
    throw new FieldValidationError("media.path", `media.path "${descriptor.media.path}" must be database.path's own parent directory ("${dataDir}") or a subdirectory of it \u2014 a demo mounts one host-provisioned directory for both, per LLD-2 \xA701's "one directory".`);
  }
  return { volumeName: `ghost-demo-${descriptor.uid}-data`, path: dataDir };
}
function assertAllocationShape(descriptor) {
  validateTenantUid(descriptor.uid);
  validatePort(descriptor.ports.a, "ports.a");
  validatePort(descriptor.ports.b, "ports.b");
  validatePort(descriptor.ports.health, "ports.health");
  validatePrivateIpV4(descriptor.appHostIp);
  validateSlug(descriptor.slug);
  validateSlugAvailability(descriptor.slug);
  validateDigestPinnedRef(descriptor.image);
}
function render(descriptor, zones, themeCsp = THEME_CSP_UNAVAILABLE, options = {}) {
  assertAllocationShape(descriptor);
  const dataMount = demoDataMount(descriptor);
  const limits = uploadLimits();
  const environment = tenantEnvironment(descriptor, limits, secretsEnvPath(descriptor.slug), zones);
  const compose = renderComposeStack({
    kind: descriptor.kind,
    slug: descriptor.slug,
    uid: descriptor.uid,
    appHostPrivateIp: descriptor.appHostIp,
    ports: descriptor.ports,
    environment,
    limits,
    caps: descriptor.caps,
    dataMount,
    mailNetwork: descriptor.mail.enabled ? mailSpoolNetworkName(descriptor.uid) : null,
    ...options.activeColour === void 0 ? {} : { activeColour: options.activeColour }
  });
  const edge = renderEdgeSiteBlock(descriptor, zones, limits, themeCsp);
  const settings = renderSettings(descriptor, zones);
  const identity = renderIdentity(descriptor);
  return [
    { path: "compose.yml", content: compose, mode: 420 },
    { path: "secrets.env", content: renderSecretsTemplate(descriptor), mode: SECRETS_ENV_MODE },
    { path: "image.env", content: renderImageEnv(descriptor), mode: 420 },
    { path: "provision.sh", content: renderProvisionScript(descriptor), mode: 448 },
    { path: "edge.json", content: renderJson(edge), mode: 420 },
    { path: "ghost-settings.json", content: renderJson(settings), mode: 420 },
    { path: "identity.json", content: renderJson(identity), mode: 420 }
  ];
}

// dist/config.js
function requireEnv(env, name) {
  const value = env[name];
  if (!value)
    throw new Error(`Missing required environment variable ${name}`);
  return value;
}
function zonesFromEnv(env) {
  return {
    demoZone: requireEnv(env, "BROKER_DEMO_ZONE"),
    platformZone: requireEnv(env, "BROKER_PLATFORM_ZONE"),
    ownedDomains: requireEnv(env, "BROKER_OWNED_DOMAINS").split(",").map((s) => s.trim()).filter(Boolean),
    demoMailDomain: requireEnv(env, "BROKER_DEMO_MAIL_DOMAIN")
  };
}

// dist/plugins/renderCorePlugin.js
var renderer = {
  real: true,
  async render(descriptor) {
    return render(descriptor, zonesFromEnv(process.env));
  }
};
var renderCorePlugin_default = renderer;
export {
  renderCorePlugin_default as default
};
