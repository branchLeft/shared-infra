import * as pulumi from '@pulumi/pulumi';
import * as gcp from '@pulumi/gcp';

import { region as defaultRegion } from './config';
import type { EdgeSite, HostRedirect } from './siteTypes';

/**
 * The shared Global External Application Load Balancer that fronts every
 * Cloud Run service branchLeft serves on the public internet.
 *
 * This is deliberately *not* website-specific — which is why it lives in this
 * repo rather than in `website/infra`, where it was originally written. Cloud
 * Armor has no attachment point on a Cloud Run service reached via Cloud Run
 * Domain Mapping — it attaches to an LB backend service — so every service
 * that needs WAF or rate limiting has to sit behind this LB. One LB with
 * host-based routing serves all of them, which is what keeps the cost flat
 * (the forwarding rule and the security policy are fixed charges, not
 * per-service ones).
 *
 * Adding a service is one more entry in `sites.ts`: a hostname list and the
 * name of the Cloud Run service to route it to. Everything else — NEG, backend
 * service, certificate, certificate-map entry, URL-map host rule — is derived
 * from that.
 *
 * ## Why the whole edge is here and not split
 *
 * The URL map, certificate map and security policy are singletons that have to
 * know every hostname they serve. Whoever owns the stack that declares them
 * can therefore deploy every hosted site's edge at once, which is why this is
 * not the marketing site's stack: a marketing-site merge must not be able to
 * apply a change to every tenant's edge.
 *
 * The per-site NEGs and backend services are here too, rather than in each
 * product's own stack, because splitting them creates a circular
 * StackReference: a backend service needs the shared security policy's ID, and
 * the shared URL map needs the backend service's ID. Two stacks cannot each
 * read an output of the other.
 *
 * ## No dependency on any product stack
 *
 * A serverless NEG needs only the *name* of a Cloud Run service and its
 * region — both plain strings. Taking them as config rather than as a
 * `gcp.cloudrunv2.Service` object (as the original did, when this code lived
 * in the same program as the service) means this stack has no StackReference
 * to `website`, no import from it, and no ordering coupling to its deploys.
 * The cost of that is real and worth stating: nothing here verifies the named
 * service exists. A typo produces a NEG that resolves to nothing and a backend
 * that 404s, with no error at apply time. `sites.ts` documents the check.
 *
 * ## API enablement is *not* declared in this program
 *
 * `compute.googleapis.com` and `certificatemanager.googleapis.com` are
 * required by everything below, and are already enabled on `branchleft-prod`.
 * They are declared as `gcp.projects.Service` resources in `website/infra`'s
 * `apis.ts` and remain owned there. Declaring them here too would put two
 * stacks in charge of one real resource. If this stack ever has to stand up a
 * project from scratch, enable both APIs by hand first.
 */
// The registry's own shape lives in `siteTypes.ts`, which imports nothing, so
// that the Hetzner Caddy renderer can read `sites.ts` without resolving this
// program's GCP dependency tree. Re-exported here because this is where every
// existing consumer looks for it.
export type { EdgeSite, HostRedirect, PrivateUpstream } from './siteTypes';

/** The DNS records a domain owner must publish before a certificate can issue. */
export interface DnsAuthorizationRecord {
  hostname: string;
  recordName: pulumi.Output<string>;
  recordType: pulumi.Output<string>;
  recordData: pulumi.Output<string>;
}

export interface Edge {
  /** The LB's global anycast IP — the A-record target for every hostname. */
  ipAddress: pulumi.Output<string>;
  /** `_acme-challenge.*` CNAMEs to publish before the certificate can issue. */
  dnsAuthorizationRecords: DnsAuthorizationRecord[];
  /** Certificate Manager resource names, for polling issuance after the apply. */
  certificateNames: pulumi.Output<string[]>;
  /** Cloud Armor policy name, for reading rule verdicts from logs. */
  securityPolicyName: pulumi.Output<string>;
}

/**
 * Requests per IP per minute before the rate-limit rule throttles. Enforcing.
 * Threshold rationale and traffic data: README.md's "Cloud Armor enforcement".
 */
const RATE_LIMIT_REQUESTS = 200;
const RATE_LIMIT_INTERVAL_SEC = 60;

/**
 * OWASP preconfigured WAF expressions, sensitivity 1 (Google's least
 * false-positive-prone level). Each entry's array index sets its Cloud Armor
 * priority (`1000 + i`) — append only, never insert or reorder. See README.md's
 * "Cloud Armor enforcement" for why.
 */
const OWASP_RULESETS = ['sqli-v33-stable', 'xss-v33-stable', 'rce-v33-stable', 'lfi-v33-stable'];

/**
 * The rulesets a site's own legitimate content can trip, which is why
 * `EdgeSite.injectionWafPreviewOnly` exists to exempt a host from enforcing
 * them. `lfi` is deliberately absent: nothing legitimate requests `.env`.
 */
const CONTENT_SENSITIVE_RULESETS = new Set(['sqli-v33-stable', 'xss-v33-stable', 'rce-v33-stable']);

const preconfiguredWaf = (ruleset: string) =>
  `evaluatePreconfiguredWaf('${ruleset}', {'sensitivity': 1})`;

// Cloud Armor does not normalise the Host header, and a request carrying an
// explicit `:443` will not equal the bare hostname. Both uses below therefore
// fail *towards* enforcement rather than towards a bypass: an unrecognised Host
// form matches the enforcing rule and misses the preview-only one.
const hostEquals = (hostname: string) => `request.headers['host'].lower() == '${hostname}'`;

const ALL_SOURCE_IPS = {
  versionedExpr: 'SRC_IPS_V1',
  config: { srcIpRanges: ['*'] },
};

/**
 * TLS floor for every hostname behind this LB. Constants rather than stack
 * config: a `pulumi config set` can weaken these without a code review, and a
 * TLS minimum that can move without one is not a minimum.
 *
 * With no policy attached a target proxy inherits GCP's default, which is the
 * COMPATIBLE profile at TLS 1.0 — an omission reads identically to a decision,
 * so the decision is written down. MODERN keeps the TLS 1.2 CBC suites that
 * RESTRICTED drops; moving to RESTRICTED is the next step up and costs only
 * clients that predate 2015.
 */
const TLS_PROFILE = 'MODERN';
const TLS_MIN_VERSION = 'TLS_1_2';

export function createEdge(sites: EdgeSite[], hostRedirects: HostRedirect[] = []): Edge {
  // Anycast IPv4 the A records point at. Reserved rather than ephemeral so a
  // rebuild of the forwarding rule doesn't change the address and silently
  // break DNS that already points here.
  const ip = new gcp.compute.GlobalAddress('edge-ip', {
    name: 'branchleft-edge-ip',
    addressType: 'EXTERNAL',
    ipVersion: 'IPV4',
  });

  // Hostnames exempted from *enforcing* the injection rules. They get their own
  // preview-mode copies at 1100+ instead, so the exemption still produces the
  // false-positive evidence needed to end it.
  //
  // Restricted to sites this edge actually serves. A site with no
  // `cloudRunService` is skipped below and so gets no URL-map host rule — but
  // an exemption keyed on the Host *header* would still apply to it, and a
  // request carrying that Host matches no rule and falls through to
  // `defaultService`. Exempting a host this edge cannot route therefore turns
  // the injection rules off for that Host on whichever backend the fallthrough
  // lands on, which is the marketing site. `hostEquals` is documented as
  // failing towards enforcement; that only holds while every exempted host has
  // a rule of its own.
  const previewOnlyHosts = sites
    .filter((site) => site.injectionWafPreviewOnly && site.cloudRunService !== undefined)
    .flatMap((site) => site.hostnames);
  const isPreviewOnlyHost = previewOnlyHosts.map(hostEquals).join(' || ');
  const isNotPreviewOnlyHost = previewOnlyHosts.map((h) => `!(${hostEquals(h)})`).join(' && ');

  // One shared policy across all sites — per-site policies would be $5/month
  // each and scale badly; host-scoped *rules* within one policy do not.
  // See README.md's "Cloud Armor enforcement" for the threshold rationale and
  // the traffic evidence behind promoting these rules out of preview.
  const securityPolicy = new gcp.compute.SecurityPolicy('edge-armor', {
    name: 'branchleft-edge-armor',
    description: 'Shared Cloud Armor policy for the branchLeft edge load balancer',
    type: 'CLOUD_ARMOR',
    // Cloud Armor evaluates rules in priority order (lowest number first) and
    // stops at the first *match*, not the first rule that takes action. The
    // rate-limit rule's match (`srcIpRanges: ['*']`) is unconditionally true,
    // so it must sit *after* the WAF rules — reversing this makes the WAF
    // rules permanently unreachable regardless of preview/enforce mode. See
    // README.md's "Cloud Armor enforcement" for confirming evidence.
    rules: [
      ...OWASP_RULESETS.map((ruleset, i) => ({
        action: 'deny(403)',
        priority: 1000 + i,
        description: `OWASP preconfigured: ${ruleset} (sensitivity 1)`,
        match: {
          expr: {
            expression:
              CONTENT_SENSITIVE_RULESETS.has(ruleset) && previewOnlyHosts.length > 0
                ? `${preconfiguredWaf(ruleset)} && ${isNotPreviewOnlyHost}`
                : preconfiguredWaf(ruleset),
          },
        },
        preview: false,
      })),
      // Preview-mode copies of the injection rules, scoped to the hosts the
      // enforcing copies above exclude. Separate rules rather than a wider
      // exemption because an exemption alone would log nothing, leaving no
      // evidence on which to ever enforce. $1/month each.
      ...(previewOnlyHosts.length > 0
        ? OWASP_RULESETS.filter((ruleset) => CONTENT_SENSITIVE_RULESETS.has(ruleset)).map(
            (ruleset, i) => ({
              action: 'deny(403)',
              priority: 1100 + i,
              description: `OWASP preconfigured: ${ruleset} (sensitivity 1, preview-only hosts)`,
              match: {
                expr: {
                  expression: `${preconfiguredWaf(ruleset)} && (${isPreviewOnlyHost})`,
                },
              },
              preview: true,
            })
          )
        : []),
      {
        action: 'throttle',
        priority: 2000,
        description: `Per-IP rate limit: ${RATE_LIMIT_REQUESTS} requests / ${RATE_LIMIT_INTERVAL_SEC}s`,
        match: ALL_SOURCE_IPS,
        rateLimitOptions: {
          conformAction: 'allow',
          exceedAction: 'deny(429)',
          // Keyed on client IP, never on Host. Keying on Host pools all of a
          // site's traffic into one bucket, so a legitimate traffic spike
          // throttles real readers — the opposite of what this is for. Note
          // an HTTP-HEADER key also silently degrades to a single global
          // bucket when the named header is absent.
          enforceOnKey: 'IP',
          rateLimitThreshold: {
            count: RATE_LIMIT_REQUESTS,
            intervalSec: RATE_LIMIT_INTERVAL_SEC,
          },
        },
        preview: false,
      },
      {
        action: 'allow',
        priority: 2147483647,
        description: 'Default: allow',
        match: ALL_SOURCE_IPS,
      },
    ],
  });

  const dnsAuthorizationRecords: DnsAuthorizationRecord[] = [];
  const certificateNames: Array<pulumi.Output<string>> = [];
  const hostRules: gcp.types.input.compute.URLMapHostRule[] = [];
  const pathMatchers: gcp.types.input.compute.URLMapPathMatcher[] = [];
  let defaultService: pulumi.Output<string> | undefined;

  // A hostname can only appear in one URL-map host rule, so a redirect source
  // (e.g. www.example.com) is excluded from the serving host rule below — its
  // own redirect host rule is added after the sites loop. The certificate
  // loop is unaffected: a redirect source still needs its own managed
  // certificate so the TLS/SNI handshake succeeds before the URL map
  // redirects it.
  const redirectFromHosts = new Set(hostRedirects.map((r) => r.from));

  // Created once, outside the loop, so every site's certificate map entry
  // points at the same map and the same target proxy serves all of them.
  const certificateMap = new gcp.certificatemanager.CertificateMap('edge-cert-map', {
    name: 'branchleft-edge-certs',
    description: 'Certificate map for the branchLeft edge load balancer',
  });

  // The URL map's `defaultService` is the first site's backend, and `sites.ts`
  // requires the marketing site stay first so that fallback is never a
  // tenant's service. Skipping GCP-less sites below could silently hand that
  // role to a later entry, so the invariant is asserted rather than assumed.
  if (sites.length > 0 && sites[0].cloudRunService === undefined) {
    throw new Error(
      `the first sites.ts entry (${sites[0].name}) has no cloudRunService, so the URL map's ` +
        'defaultService would fall to a later entry — see "Ordering" in sites.ts'
    );
  }

  for (const site of sites) {
    // A site with no Cloud Run service does not exist on this edge — it is
    // served from Hetzner, or not yet served at all. Skipped before any
    // resource is constructed, mirroring `servableSites` in
    // hetzner/edge/render.ts, which drops sites with no `privateUpstream` for
    // the same reason: an edge must never request a certificate for a
    // hostname it cannot answer a challenge for.
    const cloudRunService = site.cloudRunService;
    if (cloudRunService === undefined) {
      continue;
    }

    // Serverless NEG — the only backend type that can point at Cloud Run.
    // Must be in the same region as the service it targets.
    const neg = new gcp.compute.RegionNetworkEndpointGroup(`${site.name}-neg`, {
      name: `${site.name}-neg`,
      region: site.region ?? defaultRegion,
      networkEndpointType: 'SERVERLESS',
      cloudRun: { service: cloudRunService },
    });

    const backendService = new gcp.compute.BackendService(`${site.name}-backend`, {
      name: `${site.name}-backend`,
      loadBalancingScheme: 'EXTERNAL_MANAGED',
      protocol: 'HTTPS',
      // Cloud Armor's only attachment point. This field is the entire reason
      // the LB exists.
      securityPolicy: securityPolicy.id,
      backends: [{ group: neg.id }],
      // Required to see Cloud Armor's preview-mode verdicts at all — the
      // verdicts are emitted on the load balancer's request logs, so a
      // backend service with logging off makes preview mode unobservable.
      // Full sampling: current traffic is low enough that the log volume is
      // immaterial and a sampled log is a poor basis for tuning a threshold.
      logConfig: { enable: true, sampleRate: 1.0 },
      // Cloud CDN attaches here when doc 07's Tier 3/4 caching question is
      // settled. Off until then so caching behaviour isn't a surprise.
      enableCdn: false,
    });
    // Serverless NEG backends take no health check — Cloud Run handles that.

    defaultService = defaultService ?? backendService.id;

    const servingHosts = site.hostnames.filter((h) => !redirectFromHosts.has(h));
    const pathMatcherName = `${site.name}-paths`;
    hostRules.push({ hosts: servingHosts, pathMatcher: pathMatcherName });
    pathMatchers.push({ name: pathMatcherName, defaultService: backendService.id });

    for (const hostname of site.hostnames) {
      // Slug for Pulumi/GCP resource names: dots aren't valid in either.
      const slug = hostname.replaceAll('.', '-');

      // Issuance is gated entirely on this record resolving — not on Search
      // Console verification, which is neither the mechanism nor sufficient.
      // The record can be published before or after this resource exists; the
      // certificate simply sits in AUTHORIZING until it resolves.
      const authorization = new gcp.certificatemanager.DnsAuthorization(`dns-auth-${slug}`, {
        name: `dns-auth-${slug}`,
        domain: hostname,
        description: `DNS authorization for ${hostname}`,
      });

      dnsAuthorizationRecords.push({
        hostname,
        recordName: authorization.dnsResourceRecords.apply((r) => r[0]?.name ?? ''),
        recordType: authorization.dnsResourceRecords.apply((r) => r[0]?.type ?? ''),
        recordData: authorization.dnsResourceRecords.apply((r) => r[0]?.data ?? ''),
      });

      // One certificate per hostname rather than one multi-domain
      // certificate: a hostname whose DNS authorization hasn't resolved yet
      // then can't hold up issuance for hostnames whose has. That matters
      // during onboarding, when a new site's DNS is the slow part.
      const certificate = new gcp.certificatemanager.Certificate(`cert-${slug}`, {
        name: `cert-${slug}`,
        description: `Managed certificate for ${hostname}`,
        managed: {
          domains: [hostname],
          dnsAuthorizations: [authorization.id],
        },
      });

      certificateNames.push(certificate.name);

      new gcp.certificatemanager.CertificateMapEntry(`cert-entry-${slug}`, {
        name: `cert-entry-${slug}`,
        map: certificateMap.name,
        hostname,
        certificates: [certificate.id],
      });
    }
  }

  if (defaultService === undefined) {
    throw new Error(
      'createEdge produced no backend service: sites.ts is empty, or no entry has a ' +
        'cloudRunService — this edge serves nothing'
    );
  }

  // Canonical-domain redirects (e.g. www → apex), each on its own host rule
  // pointing at a pathMatcher whose only job is a 301. `stripQuery: false`
  // and no `pathRedirect` — this is a bare host swap, every path and query
  // string carries through unchanged.
  for (const redirect of hostRedirects) {
    const slug = redirect.from.replaceAll('.', '-');
    const pathMatcherName = `redirect-${slug}-paths`;
    hostRules.push({ hosts: [redirect.from], pathMatcher: pathMatcherName });
    pathMatchers.push({
      name: pathMatcherName,
      defaultUrlRedirect: {
        hostRedirect: redirect.to,
        httpsRedirect: true,
        redirectResponseCode: 'MOVED_PERMANENTLY_DEFAULT',
        stripQuery: false,
      },
    });
  }

  const urlMap = new gcp.compute.URLMap('edge-url-map', {
    name: 'branchleft-edge',
    // Only reachable by a request whose Host matches no rule above — the
    // certificate map has an entry per known hostname and no PRIMARY
    // fallback, so an unknown hostname fails the TLS handshake before the URL
    // map is ever consulted. Points at the first `sites.ts` entry rather than
    // erroring because the field is required; keep the marketing site first
    // so this fallback is never a tenant's service.
    defaultService,
    hostRules,
    pathMatchers,
  });

  // A certificate map rather than direct certificate references: a target
  // proxy accepts at most 100 direct Certificate Manager references (15 for
  // classic Compute Engine SSL certs), which caps out below the tenant count
  // this LB is meant to reach. A map supports thousands of entries.
  const sslPolicy = new gcp.compute.SSLPolicy('edge-ssl-policy', {
    name: 'branchleft-edge-tls',
    profile: TLS_PROFILE,
    minTlsVersion: TLS_MIN_VERSION,
  });

  const httpsProxy = new gcp.compute.TargetHttpsProxy('edge-https-proxy', {
    name: 'branchleft-edge-https',
    urlMap: urlMap.id,
    certificateMap: pulumi.interpolate`//certificatemanager.googleapis.com/${certificateMap.id}`,
    sslPolicy: sslPolicy.id,
  });

  new gcp.compute.GlobalForwardingRule('edge-https-rule', {
    name: 'branchleft-edge-https',
    loadBalancingScheme: 'EXTERNAL_MANAGED',
    target: httpsProxy.id,
    ipAddress: ip.selfLink,
    portRange: '443',
  });

  // Cloud Run Domain Mapping redirects http:// to https:// for free; the LB
  // does not, so without this pair every plain-HTTP request would hang after
  // the cutover. Both forwarding rules fall inside the flat first-five-rules
  // charge, so this costs nothing extra.
  const redirectUrlMap = new gcp.compute.URLMap('edge-http-redirect', {
    name: 'branchleft-edge-http-redirect',
    defaultUrlRedirect: {
      httpsRedirect: true,
      redirectResponseCode: 'MOVED_PERMANENTLY_DEFAULT',
      stripQuery: false,
    },
  });

  const httpProxy = new gcp.compute.TargetHttpProxy('edge-http-proxy', {
    name: 'branchleft-edge-http',
    urlMap: redirectUrlMap.id,
  });

  new gcp.compute.GlobalForwardingRule('edge-http-rule', {
    name: 'branchleft-edge-http',
    loadBalancingScheme: 'EXTERNAL_MANAGED',
    target: httpProxy.id,
    ipAddress: ip.selfLink,
    portRange: '80',
  });

  return {
    ipAddress: ip.address,
    dnsAuthorizationRecords,
    certificateNames: pulumi.all(certificateNames),
    securityPolicyName: securityPolicy.name,
  };
}
