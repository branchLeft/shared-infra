/**
 * Refuses any OVHcloud project but the one the stack's committed config allows.
 *
 * OVHcloud addresses a Public Cloud project by an explicit id, and a resource
 * that omits `serviceName` silently falls back to the `OVH_CLOUD_PROJECT_SERVICE`
 * environment variable. So the project a run addresses is whatever that
 * variable holds, which the workflow sets and a stack file does not. The
 * allowed id is committed in the stack config; this guard compares the two
 * and returns the id every resource is then given explicitly.
 *
 * There is no live read of the project as `hetzner/projectGuard.ts` does:
 * hcloud has no way to ask a token which project it is, whereas an OVHcloud
 * service account is confined to one project by its IAM policy and a wrong
 * project id fails at the API. What stays worth guarding is the id this
 * program is told to address.
 *
 * Neither id is printed: a failed preview is the output that gets pasted into
 * an issue, and the message needs only to say which side is wrong.
 */

/** What the probe stack file carries until the owner supplies the project id. */
export const UNSET_MARKER = 'UNSET';

/** A Public Cloud project id: 32 lower-case hex characters. */
const PROJECT_ID = /^[0-9a-f]{32}$/;

export const PROJECT_ENV = 'OVH_CLOUD_PROJECT_SERVICE';

/**
 * Throws unless `addressed` is exactly `allowed`, and `allowed` is a real id.
 * Returns the allowed id for the caller to pass as every `serviceName`.
 */
export function assertProject(allowed: string, addressed: string | undefined): string {
  if (allowed === UNSET_MARKER) {
    throw new Error(
      `allowedProjectId is not set: the stack config still carries ${UNSET_MARKER}. ` +
        'The project id is supplied by the owner and committed in the stack file; nothing is created until it is.'
    );
  }
  if (!PROJECT_ID.test(allowed)) {
    throw new Error(
      'allowedProjectId must be a 32-character lower-case hex project id; the stack config holds something else.'
    );
  }
  if (addressed === undefined || addressed === '') {
    throw new Error(
      `${PROJECT_ENV} is not set, so nothing says which project this run addresses. ` +
        'The workflow must set it to the allowed project id.'
    );
  }
  if (addressed !== allowed) {
    throw new Error(
      `the project in ${PROJECT_ENV} is not the allowed project in the stack config. ` +
        'Applying would create resources in the wrong project; fix the variable and re-run.'
    );
  }
  return allowed;
}
