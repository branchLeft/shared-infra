/**
 * Whether the edge acts on what it detects, and the one place that changes.
 *
 * Both fields start non-enforcing and each is flipped by a pull request, never
 * by a redeploy: `render.ts` derives the Caddy route chain *and* the CrowdSec
 * acquisition file from these two values, and both rendered artifacts are
 * committed, so a flip shows up as a reviewable diff in the files that will be
 * copied onto the host. A redeploy of an unchanged tree cannot change posture.
 *
 * They are separate because the mechanisms are separate, not because a
 * multi-state knob was wanted. `crowdsec` is the WAF and IP-remediation half.
 * The other two are both the Caddy `rate_limit` module, which has no detect
 * mode of its own — it either throttles or it is absent. The observation
 * instrument for a throttle is therefore the access log, which is enabled in
 * every posture.
 *
 * `rateLimit` and `membersMagicLinkRateLimit` are separate fields rather than
 * one, because they are the same mechanism protecting different things at
 * opposite risk profiles, and holding them behind one flag made the cheap
 * control hostage to the expensive one. The magic-link throttle is bounded to
 * a single POST path, its threshold is derived below from first principles,
 * and its worst failure is a member seeing a generic portal error. The general
 * throttle applies to every request on every hostname at a threshold inherited
 * from a Cloud Armor rule that has never actually enforced (it is live at
 * `preview: true`), and its worst failure is 429s for legitimate readers.
 * One decision each.
 *
 * Two properties of the module worth knowing before reasoning about either:
 *
 * - **Counters are in-memory, per Caddy process.** Every edge deploy resets
 *   every client's budget. Harmless at this estate's traffic, and the reason
 *   sustained-attack behaviour cannot be reasoned about across a restart.
 * - **Both zones key on the direct peer** (`{http.request.remote.host}`), which
 *   is correct only while this edge is the first hop. See the key's own comment
 *   in `render.ts`: putting any CDN in front inverts a per-IP throttle into an
 *   estate-wide outage, so the key and the no-CDN assumption move together.
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
   * The general per-IP page-serving throttle. `off` renders no general
   * `rate_limit` handler at all; `enforcing` renders it at `RATE_LIMIT_EVENTS`
   * below.
   *
   * Deliberately still `off`. Its threshold is inherited from the captured
   * Cloud Armor policy, and that rule has never enforced anything — it is live
   * at `preview: true`, so 200/60s is a number no traffic has ever been
   * measured against. Enabling it needs a threshold derived from this edge's
   * own access log (the instrument named above), not the inherited one:
   * `edge1` averages well under 1 req/s but has 1-minute bursts two orders of
   * magnitude above that, and nothing currently attributes those to one client
   * or to many. Tracked in branchLeft/workspace#323.
   */
  rateLimit: 'off' | 'enforcing';
  /**
   * The tighter throttle on Ghost's members magic-link send path, in its own
   * zone with its own counter. `off` renders no handler and no matcher for it.
   *
   * `enforcing`, because every request on that path makes the platform send
   * email from `mx1`, so the cost of a flood lands on deliverability — the one
   * asset here that is slow and uncertain to recover — rather than on compute.
   * It also does the one thing Ghost cannot do for itself: `membersAuthEnumeration`
   * in Ghost's `spam-prevention.js` counts per instance, so a client that sends
   * one request to tenant A and one to tenant B trips neither instance's
   * counter, while this zone is global across every hostname the edge serves.
   */
  membersMagicLinkRateLimit: 'off' | 'enforcing';
}

export const POSTURE: EdgePosture = {
  crowdsec: 'detect-only',
  rateLimit: 'off',
  membersMagicLinkRateLimit: 'enforcing',
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
 * The members magic-link send path (`/members/api/send-magic-link`) is a
 * different threat class from page-serving: every request makes the platform
 * send email from `mx1`, so the cost of a flood lands on deliverability, not
 * on compute. The threshold below is sized from plausible legitimate use of
 * that one endpoint by a small publication, not from the page-serving figure
 * above and not from what is convenient to trip in a test:
 *
 * - A member sends at most two requests per login or signup attempt: the
 *   first, and one resend if the email is slow to arrive. Clicking resend a
 *   third time before troubleshooting elsewhere is not the common case.
 * - The tenant base is small UK public-interest local outlets, not a large
 *   title, so the realistic multi-person case is a handful of members behind
 *   one shared address -- an office, a library, a school -- opening the same
 *   link within the same minute after it goes out in a newsletter or gets
 *   shared in a group chat. Two such members retrying once each is already a
 *   generous bound for that case.
 *
 * Five events per 60 seconds covers two members at two attempts each with a
 * full request of headroom, while sitting under 3% of the page-serving
 * threshold above -- "far below", the same standard that threshold was set to.
 *
 * The zone this is enforced in (`hetzner/edge/render.ts`) is global across
 * every hostname this edge serves, unlike the per-site zone above. That is
 * deliberate and is the one thing this control adds that Ghost's own
 * per-instance limiter cannot: `membersAuthEnumeration` in Ghost's
 * `spam-prevention.js` counts per Ghost instance, so a client that sends one
 * request to tenant A and one to tenant B never trips either instance's own
 * counter. A single edge-wide bucket does. It does not, and cannot, defeat a
 * rotating-source attack -- an attacker with enough distinct source addresses
 * still gets one attempt per address before any counter trips. It raises the
 * cost of the lazy version of this attack, not the cost of the competent one.
 *
 * Two costs accepted rather than left unstated: a throttled member sees
 * Ghost's generic portal error, not a specific wait time, because Caddy's
 * `rate_limit` answers a bodyless 429 and Ghost's own JSON-error parsing
 * falls back to it (doc 12 §1 has the verified detail); and the zone's
 * memory is swept, not hard-capped, same as the general zone above.
 */
export const MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS = 5;
export const MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS = 60;

/**
 * TLS floor for every hostname. Absent from the captured Cloud Armor baseline
 * because on GCP it lived on the target proxy's SSL policy rather than in the
 * security policy, so the parity gate cannot check this line against that
 * artifact — it is checked against `edge.ts`'s `TLS_MIN_VERSION` by reading.
 */
export const TLS_PROTOCOLS = ['tls1.2', 'tls1.3'] as const;
