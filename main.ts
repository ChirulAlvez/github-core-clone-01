// github-core-clone-01 entrypoint: a standalone GitHub-compatible git forge.
// Lifecycle (wire.ts): bind an ephemeral port, POST {"port"} to $MAKEFUN_ENV_URL/register,
// then long-poll GET $MAKEFUN_ENV_URL/done until {"done": true} and exit 0.
// Node 22 type-stripping: erasable syntax only, node:* built-ins only, no dependencies.

import { createForge } from './app.ts';

const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const TRIAL_NOW = Number(process.env.MAKEFUN_TRIAL_NOW ?? '') || 1735689600;

if (ENV_URL === '') {
  console.error('MAKEFUN_ENV_URL is not set');
  process.exit(1);
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// Normalise the env base URL once (it was re-derived with a regex on every
// register attempt and every /done poll).
const ENV_BASE = ENV_URL.replace(/\/+$/, '');

async function register(port: number): Promise<boolean> {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${ENV_BASE}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(5000),
      });
      if (res.status === 200 || res.status === 409) return true;
    } catch {
      // The env may not be listening yet; retry until the deadline.
    }
    await sleep(250);
  }
  return false;
}

async function waitDone(): Promise<void> {
  let delay = 250;
  for (;;) {
    try {
      const res = await fetch(`${ENV_BASE}/done`, {
        method: 'GET',
        signal: AbortSignal.timeout(30000),
      });
      if (res.ok) {
        const body = (await res.json()) as { done?: boolean };
        if (body.done === true) return;
      }
    } catch {
      // Transient failure: keep polling.
    }
    await sleep(delay);
    // Poll tighter (cap 500 ms, was 2000 ms) so the entry exits promptly
    // once the env reports done instead of idling up to 2 s per poll.
    delay = Math.min(500, delay * 2);
  }
}

const server = createForge({ token: TOKEN, trialNowSec: TRIAL_NOW });

server.listen(0, '0.0.0.0', () => {
  const address = server.address();
  if (address === null || typeof address === 'string') {
    console.error('the forge listener has no TCP address');
    process.exit(1);
  }
  void (async () => {
    const ok = await register(address.port);
    if (!ok) {
      console.error('could not register with the env');
      process.exit(1);
    }
    await waitDone();
    server.close(() => process.exit(0));
    // If sockets linger, force the exit shortly after done.
    setTimeout(() => process.exit(0), 500).unref();
  })();
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 500).unref();
});
