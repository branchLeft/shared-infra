// Run by dockerHarness.test.ts as a separate process, so that a real signal and
// a real process exit reach the harness. Node strips the TypeScript types.
import { startContainer } from '../dockerHarness.ts';

const [mode, name] = process.argv.slice(2);

await startContainer({
  name,
  label: 'branchleft.agent=docker-harness-test',
  image: 'caddy:test',
  containerPort: 8081,
  mountSource: '/tmp/Caddyfile',
  mountTarget: '/etc/caddy/Caddyfile',
});

// 'forget' ends here without removing the container: the exit sweep must.
console.log(mode);
