import { describe, expect, it } from 'vitest';

import { SHARED_TENANT_ABUSE_CONTACT, SHARED_TENANT_FILES } from './sharedTenantFiles';

describe('the abuse contact on the shared tenant domain', () => {
  it('is the abuse role mailbox, pinned so a change to it is a deliberate one', () => {
    expect(SHARED_TENANT_ABUSE_CONTACT).toBe('abuse@branchleft.co.uk');
  });

  it('is on branchleft.co.uk, a domain the estate controls', () => {
    expect(SHARED_TENANT_ABUSE_CONTACT).toMatch(/^[a-z][a-z0-9._-]*@branchleft\.co\.uk$/);
  });

  it('is the Contact line of the served security.txt, and appears nowhere else in the files', () => {
    const files = SHARED_TENANT_FILES['sites-tenant-signals'] ?? [];
    const security = files.find((file) => file.path === '/.well-known/security.txt');
    expect(security?.body).toContain(`Contact: mailto:${SHARED_TENANT_ABUSE_CONTACT}\n`);
    const others = files.filter((file) => file.path !== '/.well-known/security.txt');
    for (const file of others) {
      expect(file.body).not.toContain(SHARED_TENANT_ABUSE_CONTACT);
    }
  });
});
