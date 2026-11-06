export type FiberCurrency = 'Fibb' | 'Fibt';

export type FiberInvoiceStatus = 'Open' | 'Received' | 'Paid' | 'Cancelled' | 'Expired';

export type TunnelStatus = 'awaiting_payment' | 'active' | 'expired';

export interface VpnTier {
  id: string;
  label: string;
  durationSeconds: number;
  maxBytes: number;
  priceShannons: bigint;
}

export interface FiberInvoice {
  paymentHash: string;
  invoiceAddress: string;
  amountShannons: bigint;
  status: FiberInvoiceStatus;
}

export interface FiberClient {
  createInvoice(params: {
    amountShannons: bigint;
    description: string;
    expirySeconds: number;
    currency: FiberCurrency;
  }): Promise<FiberInvoice>;
  getInvoiceStatus(paymentHash: string): Promise<FiberInvoiceStatus>;
}

export interface PeerTransfer {
  rxBytes: number;
  txBytes: number;
}

export interface WireGuardAdapter {
  addPeer(publicKey: string, assignedIp: string): Promise<void>;
  removePeer(publicKey: string): Promise<void>;
  getPeerTransfer(publicKey: string): Promise<PeerTransfer>;
}

export interface GatewayInfo {
  serverPublicKey: string;
  endpoint: string;
  dns: string;
  subnetPrefix: string;
  currency: FiberCurrency;
  invoiceTtlSeconds: number;
}

export interface TunnelSession {
  sessionId: string;
  tierId: string;
  clientPublicKey: string;
  paymentHash: string;
  invoiceAddress: string;
  amountShannons: bigint;
  status: TunnelStatus;
  createdAtMs: number;
  invoiceExpiresAtMs: number;
  assignedIp?: string;
  activatedAtMs?: number;
  expiresAtMs?: number;
  bytesLimit: number;
  bytesUsed: number;
}
