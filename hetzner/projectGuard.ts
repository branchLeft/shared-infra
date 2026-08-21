import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

/**
 * Fails a preview that is pointed at the mail project.
 *
 * hcloud has no fine-grained IAM: a token has full power over everything in
 * its project, and nothing in the API tells a caller which project it is
 * holding — there is no project endpoint to ask. This guard therefore checks
 * a sentinel rather than an identity: it rules the mail project *out* by what
 * is visible in it, and cannot rule the estate project *in*. An empty project
 * passes whether it is the estate's or the lab's. So the only thing that
 * keeps the estate's resources out of the
 * mail project is the operator setting the right token, and the failure mode
 * when they do not is silent success at the wrong thing — the estate's state
 * is empty before its first apply in the new project, so a mail-project token
 * plans a clean create of the whole estate *inside the mail project*, and
 * every one of those creates succeeds.
 *
 * The reverse mistake is loud and needs no guard: the mail stack's state
 * already names mx1 by id, so an estate token makes the provider read that id,
 * miss, and plan a replacement — which no operator confirms by accident.
 * That asymmetry is why this guard is one-directional.
 *
 * `RUNBOOK-hetzner-lab-project.md` has always carried this as a manual step
 * ("if this prints mx1, the token was created in the production project").
 * A check that only runs when someone remembers to run it is not the control;
 * this one runs on every preview and every apply, in the program, where it
 * cannot be omitted by forgetting to wire a CI job.
 *
 * It has no bypass, which makes one operation impossible: tearing the estate's
 * own resources back out of the mail project. That was needed exactly once, to
 * move them, and `RUNBOOK-estate-project-move.md` sequences it before this
 * file exists rather than building an escape hatch that would then stand open
 * for good. Nothing after that move has any business applying either of these
 * programs against the mail project — `mail/` is a different Pulumi project
 * and this guard never sees it.
 */

/**
 * Servers whose presence proves the token addresses the mail project.
 *
 * Names rather than ids: an id would have to be recovered from an account
 * nothing here can query, and would go stale the first time the host is
 * rebuilt, at which point the guard would pass against the very project it
 * exists to refuse.
 */
const MAIL_PROJECT_SERVERS: readonly string[] = ['mx1'];

/** The mail-project servers visible to whichever token is in use. */
export function mailProjectServersIn(serverNames: readonly string[]): string[] {
  const seen = new Set(serverNames);
  return MAIL_PROJECT_SERVERS.filter((name) => seen.has(name));
}

/**
 * Throws unless the token's project is free of mail-project servers.
 *
 * An empty project passes, and has to: that is exactly the state of the estate
 * project between its creation and its first apply.
 *
 * The message names only the sentinel it matched, never the server list it was
 * given. That list is the mail project's inventory, and a preview's output is
 * the kind of thing that gets pasted into an issue.
 */
export function assertEstateProject(serverNames: readonly string[]): void {
  const found = mailProjectServersIn(serverNames);
  if (found.length === 0) {
    return;
  }
  throw new Error(
    `hcloud:token addresses the mail project, not the estate project — it can see ${found.join(', ')}. ` +
      'Applying with it would create estate resources inside the mail project. ' +
      "Set the estate project's token with `pulumi config set --secret hcloud:token` " +
      'and re-run; see hetzner/README.md, "Three projects, and why the boundary matters".'
  );
}

/**
 * The assertion as the data source hands it over.
 *
 * Split out from `verifyEstateProject` below so that the shape-reading —
 * which field holds the list, which field holds the name — is covered by a
 * test rather than only by an apply against a live account. Getting that
 * wrong reads as a guard that passes everything.
 */
export function checkServersResult(result: { servers: { name: string }[] }): boolean {
  assertEstateProject(result.servers.map((server) => server.name));
  return true;
}

/**
 * Reads the token's project and asserts it is not the mail project.
 *
 * Exported as a stack output by both callers rather than left as a loose
 * `apply`. The Node runtime does await module-scope work before a deployment
 * completes, so a loose one would run too — but an output is awaited by
 * construction, survives a refactor that stops importing the module for its
 * side effect, and leaves `pulumi stack output` able to show that the check is
 * wired at all. It is a constant `true`, so it never adds a diff.
 */
export function verifyEstateProject(): pulumi.Output<boolean> {
  return pulumi.output(hcloud.getServers()).apply(checkServersResult);
}
