import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { checkProjectResults } from './projectGuard';
import { PROJECTS, TOKEN_CONFIG_NAMESPACE, tokenConfigKey, type ProjectName } from './projects';

/**
 * The explicit hcloud provider for a stack in the tenants, demos or dns
 * project, and the guard that proves its token belongs there.
 *
 * Why not the default provider: it takes its token from `hcloud:token` or,
 * failing that, from `HCLOUD_TOKEN` in the environment — and a workstation
 * shell can carry an `HCLOUD_TOKEN` for a different project for its whole
 * lifetime. With five projects, "whichever token the shell happened to have"
 * is the failure this module exists to remove. Each project's token is read
 * from its own config key, `hcloud-projects:<name>Token`, and nowhere else.
 *
 * That only holds if no resource can quietly fall back to the default
 * provider, so the stack must disable it — `pulumi:disable-default-providers`
 * naming `hcloud` — and `projectProvider` refuses to build a provider for a
 * stack that has not. A resource that forgets `{ provider }` then fails the
 * preview instead of landing wherever the ambient token points.
 *
 * The provider's resource name is fixed per project. Renaming it changes the
 * provider's URN, and every resource under it would plan against a new
 * provider instance.
 */

export interface ProjectProvider {
  readonly provider: hcloud.Provider;
  /** Constant `true`; export it as a stack output so the guard is awaited. */
  readonly verified: pulumi.Output<boolean>;
}

/** Whether `pulumi:disable-default-providers` covers hcloud. */
export function defaultHcloudProviderDisabled(disabled: unknown): boolean {
  return Array.isArray(disabled) && (disabled.includes('hcloud') || disabled.includes('*'));
}

export function providerResourceName(name: ProjectName): string {
  return `hcloud-${name}`;
}

export function projectProvider(name: ProjectName): ProjectProvider {
  const project = PROJECTS[name];
  if (!project.explicitProvider) {
    throw new Error(
      `the ${name} project's existing stacks use the default hcloud provider; moving a live ` +
        `resource to another provider instance can plan a replacement, so projectProvider ` +
        `serves only the projects built fresh (tenants, demos, dns)`
    );
  }
  const disabled = new pulumi.Config('pulumi').getObject<unknown>('disable-default-providers');
  if (!defaultHcloudProviderDisabled(disabled)) {
    throw new Error(
      `this stack has not disabled the default hcloud provider, so a resource created without ` +
        `{ provider } would use whatever HCLOUD_TOKEN the shell holds. Add ` +
        `\`pulumi:disable-default-providers: ["hcloud"]\` to the stack's config`
    );
  }
  const key = tokenConfigKey(name);
  const token = new pulumi.Config(TOKEN_CONFIG_NAMESPACE).requireSecret(key);
  const provider = new hcloud.Provider(providerResourceName(name), { token });
  const fix = `Set the ${name} project's token with \`pulumi config set --secret ${TOKEN_CONFIG_NAMESPACE}:${key}\``;
  const verified = pulumi
    .all([hcloud.getServers({}, { provider }), hcloud.getFirewalls({}, { provider })])
    .apply(([servers, firewalls]) => checkProjectResults(name, servers, firewalls, fix));
  return { provider, verified };
}
