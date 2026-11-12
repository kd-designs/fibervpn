import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { GatewayInfo, PeerTransfer, WireGuardAdapter } from './types.js';

const execFileAsync = promisify(execFile);

const WG_KEY_PATTERN = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

export function assertValidWgPublicKey(key: string): void {
  if (typeof key !== 'string' || !WG_KEY_PATTERN.test(key)) {
    throw new Error('invalid WireGuard Curve25519 public key');
  }
  const raw = Buffer.from(key, 'base64');
  if (raw.length !== 32) {
    throw new Error('WireGuard public key must decode to 32 bytes');
  }
}

export class IpPoolAllocator {
  private readonly allocated = new Set<string>();

  constructor(
    private readonly subnetPrefix = '10.66.0',
    private readonly minHost = 2,
    private readonly maxHost = 254
  ) {
    if (minHost < 2 || maxHost > 254 || minHost > maxHost) {
      throw new Error('invalid host range for /24 pool');
    }
  }

  allocate(): string {
    for (let host = this.minHost; host <= this.maxHost; host++) {
      const ip = `${this.subnetPrefix}.${host}`;
      if (!this.allocated.has(ip)) {
        this.allocated.add(ip);
        return ip;
      }
    }
    throw new Error('VPN IP address pool exhausted');
  }

  release(ip: string): void {
    this.allocated.delete(ip);
  }

  activeCount(): number {
    return this.allocated.size;
  }
}

export function buildClientConfig(params: {
  assignedIp: string;
  gateway: GatewayInfo;
  clientPrivateKeyPlaceholder?: string;
}): string {
  const priv = params.clientPrivateKeyPlaceholder ?? '<YOUR_LOCAL_PRIVATE_KEY>';
  return [
    '[Interface]',
    `PrivateKey = ${priv}`,
    `Address = ${params.assignedIp}/32`,
    `DNS = ${params.gateway.dns}`,
    '',
    '[Peer]',
    `PublicKey = ${params.gateway.serverPublicKey}`,
    `Endpoint = ${params.gateway.endpoint}`,
    'AllowedIPs = 0.0.0.0/0, ::/0',
    'PersistentKeepalive = 25',
    ''
  ].join('\n');
}

export function parseWgTransferOutput(stdout: string, targetPublicKey: string): PeerTransfer {
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [pubKey, rxStr, txStr] = trimmed.split(/\s+/);
    if (pubKey === targetPublicKey) {
      const rxBytes = Number(rxStr);
      const txBytes = Number(txStr);
      if (Number.isFinite(rxBytes) && Number.isFinite(txBytes)) {
        return { rxBytes, txBytes };
      }
    }
  }
  return { rxBytes: 0, txBytes: 0 };
}

export class WgCliAdapter implements WireGuardAdapter {
  constructor(private readonly iface = 'wg0') {}

  async addPeer(publicKey: string, assignedIp: string): Promise<void> {
    assertValidWgPublicKey(publicKey);
    await execFileAsync('wg', ['set', this.iface, 'peer', publicKey, 'allowed-ips', `${assignedIp}/32`]);
  }

  async removePeer(publicKey: string): Promise<void> {
    assertValidWgPublicKey(publicKey);
    await execFileAsync('wg', ['set', this.iface, 'peer', publicKey, 'remove']);
  }

  async getPeerTransfer(publicKey: string): Promise<PeerTransfer> {
    assertValidWgPublicKey(publicKey);
    const { stdout } = await execFileAsync('wg', ['show', this.iface, 'transfer']);
    return parseWgTransferOutput(stdout, publicKey);
  }
}

export class InMemoryWgAdapter implements WireGuardAdapter {
  readonly peers = new Map<string, { assignedIp: string; transfer: PeerTransfer }>();

  async addPeer(publicKey: string, assignedIp: string): Promise<void> {
    assertValidWgPublicKey(publicKey);
    this.peers.set(publicKey, { assignedIp, transfer: { rxBytes: 0, txBytes: 0 } });
  }

  async removePeer(publicKey: string): Promise<void> {
    this.peers.delete(publicKey);
  }

  async getPeerTransfer(publicKey: string): Promise<PeerTransfer> {
    const peer = this.peers.get(publicKey);
    return peer ? { ...peer.transfer } : { rxBytes: 0, txBytes: 0 };
  }

  setTransfer(publicKey: string, rxBytes: number, txBytes: number): void {
    const peer = this.peers.get(publicKey);
    if (!peer) {
      throw new Error(`peer not active: ${publicKey}`);
    }
    peer.transfer = { rxBytes, txBytes };
  }
}
