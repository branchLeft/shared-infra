/**
 * Whether the edge acts on what it detects, and the one place that changes.
 *
 * Both fields start non-enforcing and each is flipped by a pull request, never
 * by a redeploy: `render.ts` derives the Caddy route chain *and* the CrowdSec
 * acquisition file from these two values, and both rendered artifacts are
 * committed, so a flip shows up as a reviewable diff in the files that will be
 * copied onto the host. A redeploy of an unchanged tree cannot change posture.
 *
 * They are separate because the two mechanisms are separate, not because a
 * three-state knob was wanted. `crowdsec` is the WAF and IP-remediation half;
 * `rateLimit` is the per-IP throttle, which is a Caddy module and has no
 * detect mode of its own — the module either throttles or it is absent. The
 * observation instrument for the throttle is therefore the access log, which
 * is enabled in every posture.
 */
export interface EdgePosture {
  /**
   * `detect-only` loads only out-of-band AppSec rules and leaves the IP-decision
   * handler out of the route, so CrowdSec builds decisions that nothing acts
   * on — the same evidence Cloud Armor's preview mode produces, kept for the
   * review the parity gate requires before remediation is enabled.
   *
   * `enforcing` adds the in-band AppSec configuration and the IP-decision
   * handler.
   */
  crowdsec: 'detect-only' | 'enforcing';
  /**
   * `off` renders no `rate_limit` handler at all. `enforcing` renders it at the
   * threshold below.
   */
  rateLimit: 'off' | 'enforcing';
}

export const POSTURE: EdgePosture = {
  crowdsec: 'detect-only',
  rateLimit: 'off',
};

/**
 * The throttle the captured Cloud Armor policy records: 200 requests per IP
 * per 60 seconds, 429 on exceed. Constants rather than stack config for the
 * reason `edge.ts`'s TLS floor is: a value that can move without a code review
 * is not a threshold.
 */
export const RATE_LIMIT_EVENTS = 200;
export const RATE_LIMIT_WINDOW_SECONDS = 60;

/**
 * TLS floor for every hostname. Absent from the captured Cloud Armor baseline
 * because on GCP it lived on the target proxy's SSL policy rather than in the
 * security policy, so the parity gate cannot check this line against that
 * artifact — it is checked against `edge.ts`'s `TLS_MIN_VERSION` by reading.
 */
export const TLS_PROTOCOLS = ['tls1.2', 'tls1.3'] as const;
