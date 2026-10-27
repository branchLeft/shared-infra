// Narrative moved to hetzner/edge/posture.md, "Module header".
export interface EdgePosture {
  // Narrative moved to hetzner/edge/posture.md, "crowdsec".
  crowdsec: 'detect-only' | 'inband-only' | 'enforcing';
  // Narrative moved to hetzner/edge/posture.md, "rateLimit".
  rateLimit: 'off' | 'enforcing';
  // Narrative moved to hetzner/edge/posture.md, "membersMagicLinkRateLimit".
  membersMagicLinkRateLimit: 'off' | 'enforcing';
}

export const POSTURE: EdgePosture = {
  crowdsec: 'inband-only',
  rateLimit: 'off',
  membersMagicLinkRateLimit: 'enforcing',
};

/**
 * The throttle the captured Cloud Armor policy recorded, back when the GCP
 * edge this one replaced still existed: 200 requests per IP per 60 seconds,
 * 429 on exceed. A constant rather than stack config, same reasoning as the
 * TLS floor below: a value that can move without a code review is not a
 * threshold.
 */
export const RATE_LIMIT_EVENTS = 200;
export const RATE_LIMIT_WINDOW_SECONDS = 60;

// Narrative moved to hetzner/edge/posture.md, "Members magic-link send path".
export const MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS = 5;
export const MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS = 60;

/**
 * TLS floor for every hostname. On the GCP edge this replaced, the
 * equivalent value lived on the target proxy's SSL policy rather than in the
 * Cloud Armor security policy; that program (`edge.ts`) was deleted once it
 * described infrastructure that no longer existed.
 */
export const TLS_PROTOCOLS = ['tls1.2', 'tls1.3'] as const;
