import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  InMemoryFiberClient,
  InMemoryWgAdapter,
  IpPoolAllocator,
  type TunnelSession,
  VpnManager,
  assertValidWgPublicKey,
  parseWgTransferOutput,
  toHexQuantity
} from '../src/index.js';

function fakeWgKey(): string {
  return randomBytes(32).toString('base64');
}

function makeManager(nowRef = { ms: 1_000_000 }) {
  const fiber = new InMemoryFiberClient();
  const wg = new InMemoryWgAdapter();
  const ipPool = new IpPoolAllocator('10.66.0', 2, 4); // small 3-IP pool for exhaustion tests
  const serverPublicKey = fakeWgKey();
  const manager = new VpnManager(
    fiber,
    wg,
    ipPool,
    {
      serverPublicKey,
      endpoint: '203.0.113.10:51820',
      dns: '1.1.1.1',
      subnetPrefix: '10.66.0',
      currency: 'Fibt',
      invoiceTtlSeconds: 600
    },
    undefined,
    () => nowRef.ms
  );
  return { fiber, wg, ipPool, manager, nowRef, serverPublicKey };
}

test('validates WireGuard Curve25519 keys and rejects malformed or injected values', () => {
  assert.doesNotThrow(() => assertValidWgPublicKey(fakeWgKey()));
  assert.throws(() => assertValidWgPublicKey('not-a-key'), /invalid WireGuard/);
  assert.throws(() => assertValidWgPublicKey(`${fakeWgKey()}; rm -rf /`), /invalid WireGuard/);
});

test('parses wg show transfer output cleanly', () => {
  const target = fakeWgKey();
  const other = fakeWgKey();
  const raw = `${other}\t1024\t2048\n${target}\t524288\t1048576\n`;
  assert.deepEqual(parseWgTransferOutput(raw, target), { rxBytes: 524288, txBytes: 1048576 });
  assert.deepEqual(parseWgTransferOutput(raw, fakeWgKey()), { rxBytes: 0, txBytes: 0 });
});

test('formats FNN hex quantities cleanly', () => {
  assert.equal(toHexQuantity(1_000_000_000n), '0x3b9aca00');
});

test('refuses tunnel activation until Fiber invoice is paid and avoids leaking IPs to unpaid spam', async () => {
  const { fiber, wg, ipPool, manager } = makeManager();

  // 5 unpaid requests against a 3-IP pool must not exhaust the pool.
  const pending: TunnelSession[] = [];
  for (let i = 0; i < 5; i++) {
    pending.push(await manager.requestTunnel({ clientPublicKey: fakeWgKey(), tierId: '1h-500mb' }));
  }
  assert.equal(ipPool.activeCount(), 0);

  await assert.rejects(() => manager.activatePaidTunnel(pending[0].sessionId), /not settled/);
  assert.equal(ipPool.activeCount(), 0);
  assert.equal(wg.peers.size, 0);

  fiber.setInvoiceStatus(pending[0].paymentHash, 'Paid');
  const { session, config } = await manager.activatePaidTunnel(pending[0].sessionId);

  assert.equal(session.status, 'active');
  assert.equal(session.assignedIp, '10.66.0.2');
  assert.equal(ipPool.activeCount(), 1);
  assert.equal(wg.peers.size, 1);
  assert.match(config, /Address = 10\.66\.0\.2\/32/);
  assert.match(config, /Endpoint = 203\.0\.113\.10:51820/);
});

test('prevents concurrent double-activation of the same paid session', async () => {
  const { fiber, ipPool, manager } = makeManager();
  const req = await manager.requestTunnel({ clientPublicKey: fakeWgKey(), tierId: '1h-500mb' });
  fiber.setInvoiceStatus(req.paymentHash, 'Paid');

  // Slow down addPeer slightly to expose concurrent activation races.
  const slowWg = (manager as unknown as { wg: InMemoryWgAdapter }).wg;
  const origAdd = slowWg.addPeer.bind(slowWg);
  slowWg.addPeer = async (k: string, ip: string) => {
    await new Promise((r) => setTimeout(r, 30));
    return origAdd(k, ip);
  };

  const [r1, r2] = await Promise.allSettled([
    manager.activatePaidTunnel(req.sessionId),
    manager.activatePaidTunnel(req.sessionId)
  ]);

  assert.equal(r1.status, 'fulfilled');
  assert.equal(r2.status, 'rejected');
  assert.equal(ipPool.activeCount(), 1);
});

test('cuts off peer and recycles IP when byte quota is exceeded', async () => {
  const { fiber, wg, ipPool, manager } = makeManager();
  const clientKey = fakeWgKey();
  const req = await manager.requestTunnel({ clientPublicKey: clientKey, tierId: '1h-500mb' });
  fiber.setInvoiceStatus(req.paymentHash, 'Paid');
  await manager.activatePaidTunnel(req.sessionId);

  assert.equal(ipPool.activeCount(), 1);
  wg.setTransfer(clientKey, 300 * 1024 * 1024, 210 * 1024 * 1024); // 510 MB > 500 MB

  const { expiredSessions } = await manager.enforceQuotas();
  assert.deepEqual(expiredSessions, [req.sessionId]);
  assert.equal(wg.peers.size, 0);
  assert.equal(ipPool.activeCount(), 0);
  assert.equal(manager.getSession(req.sessionId)?.status, 'expired');
});

test('cuts off peer and recycles IP when duration expires', async () => {
  const { fiber, wg, ipPool, manager, nowRef } = makeManager();
  const clientKey = fakeWgKey();
  const req = await manager.requestTunnel({ clientPublicKey: clientKey, tierId: '1h-500mb' });
  fiber.setInvoiceStatus(req.paymentHash, 'Paid');
  await manager.activatePaidTunnel(req.sessionId);

  nowRef.ms += 3600 * 1000 + 1;
  const { expiredSessions } = await manager.enforceQuotas();

  assert.deepEqual(expiredSessions, [req.sessionId]);
  assert.equal(wg.peers.size, 0);
  assert.equal(ipPool.activeCount(), 0);
});

test('prevents activating two tunnels for the same client public key', async () => {
  const { fiber, ipPool, manager } = makeManager();
  const clientKey = fakeWgKey();
  const s1 = await manager.requestTunnel({ clientPublicKey: clientKey, tierId: '1h-500mb' });
  const s2 = await manager.requestTunnel({ clientPublicKey: clientKey, tierId: '1h-500mb' });

  fiber.setInvoiceStatus(s1.paymentHash, 'Paid');
  fiber.setInvoiceStatus(s2.paymentHash, 'Paid');

  await manager.activatePaidTunnel(s1.sessionId);
  await assert.rejects(() => manager.activatePaidTunnel(s2.sessionId), /already has an active tunnel/);
  assert.equal(ipPool.activeCount(), 1);
});
