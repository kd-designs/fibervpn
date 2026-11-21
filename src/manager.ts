import { randomUUID } from 'node:crypto';
import { SHANNONS_PER_CKB } from './fiber-rpc.js';
import type { FiberClient, GatewayInfo, TunnelSession, VpnTier, WireGuardAdapter } from './types.js';
import { IpPoolAllocator, assertValidWgPublicKey, buildClientConfig } from './wireguard.js';

export function defaultTiers(): VpnTier[] {
  return [
    {
      id: '1h-500mb',
      label: '1 Hour / 500 MB',
      durationSeconds: 3600,
      maxBytes: 500 * 1024 * 1024,
      priceShannons: 10n * SHANNONS_PER_CKB
    },
    {
      id: '24h-5gb',
      label: '24 Hours / 5 GB',
      durationSeconds: 86400,
      maxBytes: 5 * 1024 * 1024 * 1024,
      priceShannons: 50n * SHANNONS_PER_CKB
    }
  ];
}

export class VpnManager {
  private readonly sessions = new Map<string, TunnelSession>();
  private readonly tiers = new Map<string, VpnTier>();
  private readonly inFlight = new Set<string>();

  constructor(
    private readonly fiber: FiberClient,
    private readonly wg: WireGuardAdapter,
    private readonly ipPool: IpPoolAllocator,
    private readonly gateway: GatewayInfo,
    tiers: VpnTier[] = defaultTiers(),
    private readonly nowMs: () => number = () => Date.now()
  ) {
    assertValidWgPublicKey(gateway.serverPublicKey);
    for (const tier of tiers) {
      this.tiers.set(tier.id, tier);
    }
  }

  async requestTunnel(params: { clientPublicKey: string; tierId: string }): Promise<TunnelSession> {
    assertValidWgPublicKey(params.clientPublicKey);
    const tier = this.tiers.get(params.tierId);
    if (!tier) {
      throw new Error(`unknown VPN tier: ${params.tierId}`);
    }

    for (const existing of this.sessions.values()) {
      if (existing.clientPublicKey === params.clientPublicKey && existing.status === 'active') {
        throw new Error('client public key already has an active tunnel');
      }
    }

    const sessionId = randomUUID();
    const invoice = await this.fiber.createInvoice({
      amountShannons: tier.priceShannons,
      description: `FiberVPN ${tier.id} (${sessionId.slice(0, 8)})`,
      expirySeconds: this.gateway.invoiceTtlSeconds,
      currency: this.gateway.currency
    });

    const createdAtMs = this.nowMs();
    const session: TunnelSession = {
      sessionId,
      tierId: tier.id,
      clientPublicKey: params.clientPublicKey,
      paymentHash: invoice.paymentHash,
      invoiceAddress: invoice.invoiceAddress,
      amountShannons: tier.priceShannons,
      status: 'awaiting_payment',
      createdAtMs,
      invoiceExpiresAtMs: createdAtMs + this.gateway.invoiceTtlSeconds * 1000,
      bytesLimit: tier.maxBytes,
      bytesUsed: 0
    };

    this.sessions.set(sessionId, session);
    return { ...session };
  }

  async activatePaidTunnel(sessionId: string): Promise<{ session: TunnelSession; config: string }> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`unknown session: ${sessionId}`);
    }
    if (session.status !== 'awaiting_payment') {
      throw new Error(`session ${sessionId} is already ${session.status}`);
    }
    if (this.inFlight.has(sessionId)) {
      throw new Error(`session ${sessionId} activation already in progress`);
    }

    const now = this.nowMs();
    if (now >= session.invoiceExpiresAtMs) {
      session.status = 'expired';
      throw new Error(`invoice for session ${sessionId} expired`);
    }

    const tier = this.tiers.get(session.tierId)!;

    this.inFlight.add(sessionId);
    let allocatedIp: string | undefined;
    try {
      const status = await this.fiber.getInvoiceStatus(session.paymentHash);
      if (status !== 'Paid' && status !== 'Received') {
        throw new Error(`invoice not settled (status: ${status})`);
      }

      // Allocate an IP only after payment settles so unpaid requests cannot exhaust the pool.
      for (const existing of this.sessions.values()) {
        if (existing.sessionId !== sessionId && existing.clientPublicKey === session.clientPublicKey && existing.status === 'active') {
          throw new Error('client public key already has an active tunnel');
        }
      }
      allocatedIp = this.ipPool.allocate();
      await this.wg.addPeer(session.clientPublicKey, allocatedIp);

      session.assignedIp = allocatedIp;
      session.status = 'active';
      session.activatedAtMs = this.nowMs();
      session.expiresAtMs = session.activatedAtMs + tier.durationSeconds * 1000;

      const config = buildClientConfig({
        assignedIp: allocatedIp,
        gateway: this.gateway
      });

      return { session: { ...session }, config };
    } catch (err) {
      if (allocatedIp) {
        this.ipPool.release(allocatedIp);
      }
      throw err;
    } finally {
      this.inFlight.delete(sessionId);
    }
  }

  async enforceQuotas(): Promise<{ expiredSessions: string[] }> {
    const now = this.nowMs();
    const expiredSessions: string[] = [];

    for (const session of this.sessions.values()) {
      if (session.status === 'awaiting_payment' && now >= session.invoiceExpiresAtMs) {
        session.status = 'expired';
        expiredSessions.push(session.sessionId);
        continue;
      }

      if (session.status !== 'active') continue;

      const transfer = await this.wg.getPeerTransfer(session.clientPublicKey);
      session.bytesUsed = transfer.rxBytes + transfer.txBytes;

      const timeUp = session.expiresAtMs !== undefined && now >= session.expiresAtMs;
      const quotaReached = session.bytesUsed >= session.bytesLimit;

      if (timeUp || quotaReached) {
        await this.wg.removePeer(session.clientPublicKey);
        if (session.assignedIp) {
          this.ipPool.release(session.assignedIp);
        }
        session.status = 'expired';
        expiredSessions.push(session.sessionId);
      }
    }

    return { expiredSessions };
  }

  getSession(sessionId: string): TunnelSession | undefined {
    const s = this.sessions.get(sessionId);
    return s ? { ...s } : undefined;
  }
}
