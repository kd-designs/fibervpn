import { randomBytes } from 'node:crypto';
import {
  InMemoryFiberClient,
  InMemoryWgAdapter,
  IpPoolAllocator,
  SHANNONS_PER_CKB,
  VpnManager
} from '../src/index.js';

async function main() {
  const fiber = new InMemoryFiberClient();
  const wg = new InMemoryWgAdapter();
  const ipPool = new IpPoolAllocator('10.66.0', 2, 254);

  const serverPublicKey = randomBytes(32).toString('base64');
  const clientPublicKey = randomBytes(32).toString('base64');

  const manager = new VpnManager(fiber, wg, ipPool, {
    serverPublicKey,
    endpoint: '203.0.113.10:51820',
    dns: '1.1.1.1',
    subnetPrefix: '10.66.0',
    currency: 'Fibt',
    invoiceTtlSeconds: 600
  });

  console.log('FiberVPN v0.1.0 local simulation\n');

  const req = await manager.requestTunnel({ clientPublicKey, tierId: '1h-500mb' });
  console.log(`[1] Tunnel requested (1h / 500 MB)`);
  console.log(`    Invoice: ${req.invoiceAddress}`);
  console.log(`    Price:   ${Number(req.amountShannons / SHANNONS_PER_CKB)} CKB`);

  try {
    await manager.activatePaidTunnel(req.sessionId);
  } catch (err) {
    console.log(`[2] Unpaid activation blocked: ${(err as Error).message}`);
  }

  fiber.setInvoiceStatus(req.paymentHash, 'Paid');
  const { session, config } = await manager.activatePaidTunnel(req.sessionId);
  console.log(`[3] Fiber invoice settled -> WireGuard peer added (${session.assignedIp})`);
  console.log(`    Active peers: ${wg.peers.size} | Pool used: ${ipPool.activeCount()}`);
  console.log('\n--- Generated WireGuard Client Config ---');
  console.log(config.trim());
  console.log('---------------------------------------\n');

  wg.setTransfer(clientPublicKey, 400 * 1024 * 1024, 120 * 1024 * 1024);
  const { expiredSessions } = await manager.enforceQuotas();
  console.log(`[4] Quota exceeded (520 MB / 500 MB) -> Peer disconnected: ${expiredSessions.join(', ')}`);
  console.log(`    Active peers: ${wg.peers.size} | Pool used: ${ipPool.activeCount()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
